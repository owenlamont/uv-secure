import asyncio
from asyncio.subprocess import PIPE
from collections.abc import Sequence
from enum import Enum
from functools import cache
from pathlib import Path

from anyio import Path as APath
from httpx import AsyncClient, Headers
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version
from rich.console import Console

from uv_secure import __version__
from uv_secure.caching.cache_manager import CacheManager
from uv_secure.configuration import (
    config_cli_arg_factory,
    config_file_factory,
    Configuration,
    OutputFormat,
    override_config,
)
from uv_secure.configuration.exceptions import UvSecureConfigurationError
from uv_secure.directory_scanner import get_dependency_file_to_config_map
from uv_secure.directory_scanner.directory_scanner import (
    get_dependency_files_to_config_map,
)
from uv_secure.output_formatters import ColumnsFormatter, JsonFormatter, OutputFormatter
from uv_secure.output_models import (
    DependencyOutput,
    FileResultOutput,
    MaintenanceIssueOutput,
    ScanResultsOutput,
    VulnerabilityOutput,
)
from uv_secure.package_info import (
    Dependency,
    download_package_indexes,
    download_packages,
    PackageIndex,
    PackageInfo,
    parse_pylock_toml_file,
    parse_requirements_txt_file,
    parse_uv_lock_file,
    ParseResult,
    ProjectState,
    Vulnerability,
)


USER_AGENT = f"uv-secure/{__version__} (contact: owenrlamont@gmail.com)"
GLOBAL_UV_TOOL_LABEL = "uv (global tool)"


@cache
def get_specifier_sets(specifiers: tuple[str, ...]) -> tuple[SpecifierSet, ...]:
    """Convert string specifiers into cached ``SpecifierSet`` instances.

    Args:
        specifiers: Version spec strings such as ``">=1,<2"``.

    Returns:
        tuple[SpecifierSet, ...]: Parsed specifiers.
    """
    return tuple(SpecifierSet(spec) for spec in specifiers)


def _convert_vulnerability_to_output(vuln: Vulnerability) -> VulnerabilityOutput:
    """Convert vulnerability metadata into renderer-friendly output.

    Returns:
        VulnerabilityOutput: Structured vulnerability information.
    """
    return VulnerabilityOutput(
        id=vuln.id,
        details=vuln.details,
        fix_versions=vuln.fixed_in,
        aliases=vuln.aliases,
        link=vuln.link,
    )


def _convert_maintenance_to_output(
    package_info: PackageInfo, package_index: PackageIndex
) -> MaintenanceIssueOutput | None:
    """Convert maintenance metadata into renderer-friendly output.

    Returns:
        MaintenanceIssueOutput | None: Maintenance issues when applicable.
    """
    age_days = package_info.age.total_seconds() / 86400.0 if package_info.age else None
    return MaintenanceIssueOutput(
        yanked=package_info.info.yanked,
        yanked_reason=package_info.info.yanked_reason,
        age_days=age_days,
        status=package_index.status.value,
        status_reason=package_index.project_status.reason,
    )


def _process_package_metadata(
    package_info: PackageInfo | BaseException,
    package_index: PackageIndex | BaseException,
    dependency_name: str,
    config: Configuration,
    ignore_packages: dict[str, tuple[SpecifierSet, ...]],
) -> DependencyOutput | str | None:
    """Process package metadata into output rows.

    Returns:
        DependencyOutput | str | None: Output, error string, or ``None`` to skip.
    """
    # Handle download exceptions
    if isinstance(package_info, BaseException) or isinstance(
        package_index, BaseException
    ):
        ex = package_info if isinstance(package_info, BaseException) else package_index
        return f"{dependency_name} raised exception: {ex}"

    # Check if package should be skipped
    if _should_skip_package(package_info, ignore_packages):
        return None

    # Filter and check vulnerabilities based on config
    if _should_check_vulnerabilities(package_info, config):
        _filter_vulnerabilities(package_info, config)
        vulns = [
            _convert_vulnerability_to_output(v) for v in package_info.vulnerabilities
        ]
    else:
        vulns = []

    # Check if we should include maintenance issues
    pkg_index = (
        package_index
        if _should_check_maintenance_issues(package_info, config)
        else None
    )
    maintenance_issues = (
        [_convert_maintenance_to_output(package_info, package_index)]
        if pkg_index is not None
        and _has_maintenance_issues(package_index, package_info, config)
        else None
    )

    return DependencyOutput(
        name=package_info.info.name,
        version=package_info.info.version,
        direct=package_info.direct_dependency,
        vulns=vulns,
        maintenance_issues=maintenance_issues[0] if maintenance_issues else None,
    )


def _should_skip_package(
    package: PackageInfo, ignore_packages: dict[str, tuple[SpecifierSet, ...]]
) -> bool:
    """Check whether the package should be skipped.

    Returns:
        bool: True if the package matches an ignore rule.
    """
    if package.info.name not in ignore_packages:
        return False

    specifiers = ignore_packages[package.info.name]
    return len(specifiers) == 0 or any(
        specifier.contains(package.info.version) for specifier in specifiers
    )


def _should_check_vulnerabilities(package: PackageInfo, config: Configuration) -> bool:
    """Determine whether vulnerabilities should be evaluated.

    Returns:
        bool: True when vulnerability checks should include this package.
    """
    return (
        package.direct_dependency is not False
        or not config.vulnerability_criteria.check_direct_dependencies_only
    )


def _should_check_maintenance_issues(
    package_info: PackageInfo, config: Configuration
) -> bool:
    """Check whether maintenance criteria should be applied.

    Returns:
        bool: True when maintenance rules should run for the package.
    """
    return (
        package_info.direct_dependency is not False
        or not config.maintainability_criteria.check_direct_dependencies_only
    )


def _filter_vulnerabilities(package: PackageInfo, config: Configuration) -> None:
    """Filter out ignored and withdrawn vulnerabilities."""
    ignore_vulnerabilities = config.vulnerability_criteria.ignore_vulnerabilities
    package.vulnerabilities = [
        vuln
        for vuln in package.vulnerabilities
        if (
            ignore_vulnerabilities is None
            or (
                vuln.id not in ignore_vulnerabilities
                and not (
                    vuln.aliases
                    and any(alias in ignore_vulnerabilities for alias in vuln.aliases)
                )
            )
        )
        and vuln.withdrawn is None
    ]


def _has_maintenance_issues(
    package_index: PackageIndex, package_info: PackageInfo, config: Configuration
) -> bool:
    """Check whether a package violates maintenance criteria.

    Returns:
        bool: True if any configured maintenance rule is broken.
    """
    found_rejected_archived_package = (
        config.maintainability_criteria.forbid_archived
        and package_index.status == ProjectState.ARCHIVED
    )
    found_rejected_deprecated_package = (
        config.maintainability_criteria.forbid_deprecated
        and package_index.status == ProjectState.DEPRECATED
    )
    found_rejected_quarantined_package = (
        config.maintainability_criteria.forbid_quarantined
        and package_index.status == ProjectState.QUARANTINED
    )
    found_rejected_yanked_package = (
        config.maintainability_criteria.forbid_yanked and package_info.info.yanked
    )
    found_over_age_package = (
        config.maintainability_criteria.max_package_age is not None
        and package_info.age is not None
        and package_info.age > config.maintainability_criteria.max_package_age
    )
    return (
        found_rejected_archived_package
        or found_rejected_deprecated_package
        or found_rejected_quarantined_package
        or found_rejected_yanked_package
        or found_over_age_package
    )


async def _parse_dependency_file(dependency_file_path: APath) -> ParseResult:
    """Parse a dependency file based on its name.

    Returns:
        ParseResult: Normalized dependency information extracted from the file.
    """
    if dependency_file_path.name == "uv.lock":
        return await parse_uv_lock_file(dependency_file_path)
    if dependency_file_path.name == "requirements.txt":
        return await parse_requirements_txt_file(dependency_file_path)
    # Assume dependency_file_path.name == "pyproject.toml"
    return await parse_pylock_toml_file(dependency_file_path)


def _build_ignore_packages(
    config: Configuration,
) -> dict[str, tuple[SpecifierSet, ...]]:
    """Build the ignore packages mapping from configuration values.

    Returns:
        dict[str, tuple[SpecifierSet, ...]]: Package names mapped to specifiers.
    """
    if config.ignore_packages is None:
        return {}
    return {
        name: get_specifier_sets(tuple(specifiers))
        for name, specifiers in config.ignore_packages.items()
    }


def _extract_uv_version(raw_output: str) -> str | None:
    """Parse the uv CLI version from ``uv --version`` output.

    Returns:
        str | None: Parsed version string when identifiable, else ``None``.
    """

    tokens = [token.strip(" ,") for token in raw_output.split() if token.strip()]
    for token in tokens:
        if token.lower() == "uv":
            continue
        try:
            Version(token)
        except InvalidVersion:
            continue
        return token
    return None


async def _detect_uv_version() -> str | None:
    """Return the installed uv CLI version or ``None`` when unavailable."""

    try:
        process = await asyncio.create_subprocess_exec(
            "uv", "--version", stdout=PIPE, stderr=PIPE
        )
    except FileNotFoundError:
        return None

    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        return None

    decoded = stdout.decode(errors="ignore").strip()
    if not decoded:
        decoded = stderr.decode(errors="ignore").strip()
    if not decoded:
        return None

    return _extract_uv_version(decoded)


async def _check_global_uv_tool(
    config: Configuration, http_client: AsyncClient, cache_manager: CacheManager | None
) -> FileResultOutput | None:
    """Check vulnerabilities for the globally installed uv CLI.

    Returns:
        FileResultOutput | None: Results specific to the ``uv`` executable or
        ``None`` when the CLI is unavailable/ignored.
    """

    uv_version = await _detect_uv_version()
    if uv_version is None:
        return None

    dependency = Dependency(name="uv", version=uv_version, direct=True)
    package_infos, package_indexes = await asyncio.gather(
        download_packages([dependency], http_client, cache_manager),
        download_package_indexes([dependency], http_client, cache_manager),
    )

    ignore_packages = _build_ignore_packages(config)
    package_info = package_infos[0]
    package_index = package_indexes[0]
    result = _process_package_metadata(
        package_info, package_index, dependency.name, config, ignore_packages
    )

    if result is None:
        return None

    if isinstance(result, str):
        return FileResultOutput(file_path=GLOBAL_UV_TOOL_LABEL, error=result)

    has_findings = bool(result.vulns) or result.maintenance_issues is not None
    if not has_findings:
        return None

    return FileResultOutput(
        file_path=GLOBAL_UV_TOOL_LABEL, dependencies=[result], ignored_count=0
    )


async def _evaluate_dependency_files(
    file_apaths: tuple[APath, ...],
    lock_to_config_map: dict[APath, Configuration],
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
) -> list[FileResultOutput]:
    """Gather dependency results for dependency files and the uv CLI.

    Returns:
        list[FileResultOutput]: Combined scan results for dependency files and
        the optional ``uv`` check.
    """

    uv_config = next(
        (config for config in lock_to_config_map.values() if config.check_uv_tool), None
    )
    uv_task: asyncio.Task[FileResultOutput | None] | None = None
    if uv_config is not None:
        uv_task = asyncio.create_task(
            _check_global_uv_tool(uv_config, http_client, cache_manager)
        )

    file_results = list(
        await asyncio.gather(
            *[
                check_dependencies(
                    dependency_file_path,
                    lock_to_config_map[APath(dependency_file_path)],
                    http_client,
                    cache_manager,
                )
                for dependency_file_path in file_apaths
            ]
        )
    )

    if uv_task is not None:
        uv_result = await uv_task
        if uv_result is not None:
            file_results.append(uv_result)

    return file_results


async def check_dependencies(
    dependency_file_path: APath,
    config: Configuration,
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
) -> FileResultOutput:
    """Check dependencies for vulnerabilities and build structured output.

    Args:
        dependency_file_path: Path to ``pylock.toml``, ``requirements.txt``, or
            ``uv.lock``.
        config: Configuration to apply.
        http_client: HTTP client for downloads.
        cache_manager: Cache manager.

    Returns:
        FileResultOutput: Structured dependency results.
    """
    file_path_str = dependency_file_path.as_posix()

    # Load and parse dependencies
    if not await dependency_file_path.exists():
        return FileResultOutput(
            file_path=file_path_str,
            error=f"File {dependency_file_path} does not exist.",
        )

    try:
        parse_result = await _parse_dependency_file(dependency_file_path)
    except Exception as e:  # pragma: no cover - defensive, surfaced to user
        return FileResultOutput(
            file_path=file_path_str,
            error=f"Failed to parse {dependency_file_path}: {e}",
        )
    dependencies = parse_result.dependencies
    ignored_count = parse_result.ignored_count

    if len(dependencies) == 0:
        return FileResultOutput(
            file_path=file_path_str, dependencies=[], ignored_count=ignored_count
        )

    # Download package info and indexes concurrently
    package_infos_task = asyncio.create_task(
        download_packages(dependencies, http_client, cache_manager)
    )
    package_indexes_task = asyncio.create_task(
        download_package_indexes(dependencies, http_client, cache_manager)
    )
    package_infos, package_indexes = await asyncio.gather(
        package_infos_task, package_indexes_task
    )

    package_metadata: list[
        tuple[PackageInfo | BaseException, PackageIndex | BaseException]
    ] = list(zip(package_infos, package_indexes, strict=True))

    ignore_packages = _build_ignore_packages(config)
    dependency_outputs: list[DependencyOutput] = []

    # Process each package
    for idx, (package_info, package_index) in enumerate(package_metadata):
        result = _process_package_metadata(
            package_info, package_index, dependencies[idx].name, config, ignore_packages
        )

        # Handle error
        if isinstance(result, str):
            return FileResultOutput(file_path=file_path_str, error=result)

        # Handle successful output (None means skip)
        if result is not None:
            dependency_outputs.append(result)

    return FileResultOutput(
        file_path=file_path_str,
        dependencies=dependency_outputs,
        ignored_count=ignored_count,
    )


class RunStatus(Enum):
    NO_VULNERABILITIES = (0,)
    MAINTENANCE_ISSUES_FOUND = 1
    VULNERABILITIES_FOUND = 2
    RUNTIME_ERROR = 3


async def _resolve_file_paths_and_configs(
    file_paths: Sequence[Path] | None, config_path: Path | None
) -> tuple[tuple[APath, ...], dict[APath, Configuration]]:
    """Resolve dependency file paths and associated configs.

    Args:
        file_paths: Optional explicit file paths or directories.
        config_path: Optional configuration file to apply to all paths.

    Returns:
        tuple[tuple[APath, ...], dict[APath, Configuration]]: Normalized paths and
        matching configurations.

    Raises:
        ValueError: Raised when the provided paths are invalid.
        UvSecureConfigurationError: Propagated if a configuration file is invalid.
    """
    file_apaths: tuple[APath, ...] = (
        (APath(),) if not file_paths else tuple(APath(file) for file in file_paths)
    )

    if len(file_apaths) == 1 and await file_apaths[0].is_dir():
        lock_to_config_map = await get_dependency_file_to_config_map(file_apaths[0])
        file_apaths = tuple(lock_to_config_map.keys())
    else:
        if config_path is not None:
            try:
                possible_config = await config_file_factory(APath(config_path))
            except UvSecureConfigurationError as exc:  # pragma: no cover - passthrough
                raise UvSecureConfigurationError(str(exc)) from exc
            config = possible_config if possible_config is not None else Configuration()
            lock_to_config_map = dict.fromkeys(file_apaths, config)
        elif all(
            file_path.name in {"pylock.toml", "requirements.txt", "uv.lock"}
            for file_path in file_apaths
        ):
            lock_to_config_map = await get_dependency_files_to_config_map(file_apaths)
            file_apaths = tuple(lock_to_config_map.keys())
        else:
            raise ValueError(
                "file_paths must either reference a single project root directory "
                "or a sequence of uv.lock / pylock.toml / requirements.txt file paths"
            )

    return file_apaths, lock_to_config_map


def _apply_cli_config_overrides(
    lock_to_config_map: dict[APath, Configuration],
    aliases: bool | None,
    desc: bool | None,
    ignore_vulns: str | None,
    ignore_pkgs: list[str] | None,
    forbid_archived: bool | None,
    forbid_deprecated: bool | None,
    forbid_quarantined: bool | None,
    forbid_yanked: bool | None,
    check_direct_dependency_vulnerabilities_only: bool | None,
    check_direct_dependency_maintenance_issues_only: bool | None,
    max_package_age: int | None,
    format_type: str | None,
    check_uv_tool: bool | None,
) -> dict[APath, Configuration]:
    """Apply CLI overrides to lock-to-config mapping.

    Returns:
        dict[APath, Configuration]: Updated mapping with overrides applied.
    """
    if any(
        (
            aliases,
            desc,
            ignore_vulns,
            ignore_pkgs,
            forbid_archived,
            forbid_deprecated,
            forbid_quarantined,
            forbid_yanked,
            check_direct_dependency_vulnerabilities_only,
            check_direct_dependency_maintenance_issues_only,
            max_package_age is not None,
            format_type is not None,
            check_uv_tool is not None,
        )
    ):
        cli_config = config_cli_arg_factory(
            aliases,
            check_direct_dependency_maintenance_issues_only,
            check_direct_dependency_vulnerabilities_only,
            desc,
            forbid_archived,
            forbid_deprecated,
            forbid_quarantined,
            forbid_yanked,
            max_package_age,
            ignore_vulns,
            ignore_pkgs,
            OutputFormat(format_type) if format_type else None,
            check_uv_tool,
        )
        return {
            lock_file: override_config(config, cli_config)
            for lock_file, config in lock_to_config_map.items()
        }
    return lock_to_config_map


async def _build_http_client(
    cache_path: Path,
    cache_ttl_seconds: float,
    disable_cache: bool,
    client_headers: Headers,
    console: Console,
) -> tuple[AsyncClient, CacheManager | None]:
    """Construct an HTTP client with optional persistent caching.

    Returns:
        tuple[AsyncClient, CacheManager | None]:
        Client instance and cache manager (``None`` when caching is disabled).
    """
    if disable_cache:
        return AsyncClient(timeout=10, headers=client_headers), None

    await APath(cache_path).mkdir(parents=True, exist_ok=True)

    cache_manager = CacheManager(cache_path, cache_ttl_seconds)
    await cache_manager.init()
    client = AsyncClient(timeout=10, headers=client_headers)
    return client, cache_manager


def _determine_file_status(file_result: FileResultOutput) -> int:
    """Determine a single file's status code.

    Returns:
        int: ``0`` no issues, ``1`` maintenance issues, ``2`` vulnerabilities,
            ``3`` error.
    """
    if file_result.error:
        return 3

    has_vulns = any(len(dep.vulns) > 0 for dep in file_result.dependencies)
    has_maintenance = any(
        dep.maintenance_issues is not None for dep in file_result.dependencies
    )

    if has_vulns:
        return 2
    if has_maintenance:
        return 1
    return 0


def _determine_final_status(file_results: list[FileResultOutput]) -> RunStatus:
    """Determine final run status from file results.

    Returns:
        RunStatus: Aggregated status derived from individual file results.
    """
    statuses = [_determine_file_status(result) for result in file_results]

    if 3 in statuses:
        return RunStatus.RUNTIME_ERROR
    if 2 in statuses:
        return RunStatus.VULNERABILITIES_FOUND
    if 1 in statuses:
        return RunStatus.MAINTENANCE_ISSUES_FOUND
    return RunStatus.NO_VULNERABILITIES


async def check_lock_files(
    file_paths: Sequence[Path] | None,
    aliases: bool | None,
    desc: bool | None,
    cache_path: Path,
    cache_ttl_seconds: float,
    disable_cache: bool,
    forbid_archived: bool | None,
    forbid_deprecated: bool | None,
    forbid_quarantined: bool | None,
    forbid_yanked: bool | None,
    max_package_age: int | None,
    ignore_vulns: str | None,
    ignore_pkgs: list[str] | None,
    check_direct_dependency_vulnerabilities_only: bool | None,
    check_direct_dependency_maintenance_issues_only: bool | None,
    config_path: Path | None,
    format_type: str | None,
    check_uv_tool: bool | None,
) -> RunStatus:
    """Scan dependency files for vulnerabilities and maintenance issues.

    Args:
        file_paths: Explicit dependency files or directories to search.
        aliases: Whether to display vulnerability aliases.
        desc: Whether to display vulnerability descriptions.
        cache_path: Path to the on-disk HTTP cache.
        cache_ttl_seconds: Cache TTL in seconds.
        disable_cache: Whether HTTP caching is disabled.
        forbid_archived: Reject archived packages when True.
        forbid_deprecated: Reject deprecated packages when True.
        forbid_quarantined: Reject quarantined packages when True.
        forbid_yanked: Reject yanked packages when True.
        max_package_age: Maximum package age in days.
        ignore_vulns: Comma-separated vulnerability IDs to ignore.
        ignore_pkgs: Package ignore strings.
        check_direct_dependency_vulnerabilities_only: Restrict vulnerability checks to
            direct dependencies.
        check_direct_dependency_maintenance_issues_only: Restrict maintenance checks to
            direct dependencies.
        config_path: Optional configuration file path.
        format_type: Output format override ("columns" or "json").
        check_uv_tool: Toggle scanning the globally installed uv CLI for
            vulnerabilities.

    Returns:
        RunStatus: Result of the scan.
    """
    console = Console()

    try:
        file_apaths, lock_to_config_map = await _resolve_file_paths_and_configs(
            file_paths, config_path
        )
    except ValueError:
        console.print(
            "[bold red]Error:[/] file_paths must either reference a single "
            "project root directory or a sequence of uv.lock / pylock.toml / "
            "requirements.txt file paths"
        )
        return RunStatus.RUNTIME_ERROR

    lock_to_config_map = _apply_cli_config_overrides(
        lock_to_config_map,
        aliases,
        desc,
        ignore_vulns,
        ignore_pkgs,
        forbid_archived,
        forbid_deprecated,
        forbid_quarantined,
        forbid_yanked,
        check_direct_dependency_vulnerabilities_only,
        check_direct_dependency_maintenance_issues_only,
        max_package_age,
        format_type,
        check_uv_tool,
    )

    client_headers = Headers({"User-Agent": USER_AGENT})
    http_client, cache_manager = await _build_http_client(
        cache_path, cache_ttl_seconds, disable_cache, client_headers, console
    )

    try:
        async with http_client:
            file_results = await _evaluate_dependency_files(
                file_apaths, lock_to_config_map, http_client, cache_manager
            )
    finally:
        if cache_manager is not None:
            await cache_manager.close()

    # Build scan results output
    scan_results = ScanResultsOutput(files=file_results)

    # Use first config for formatter (they should all have same display settings)
    config = next(iter(lock_to_config_map.values()))

    # Choose formatter based on format from configuration
    formatter: OutputFormatter
    if config.format.value == "json":
        formatter = JsonFormatter()
    else:
        formatter = ColumnsFormatter(config)

    # Format and print output
    output = formatter.format(scan_results)
    console.print(output)

    return _determine_final_status(file_results)
