import asyncio
from collections.abc import Sequence
from enum import Enum
from functools import cache
from pathlib import Path
import sys

from anyio import Path as APath
import anysqlite
from asyncer import create_task_group
from hishel import AsyncSqliteStorage
from hishel.httpx import AsyncCacheClient
from httpx import AsyncClient, Headers
from packaging.specifiers import SpecifierSet
from rich.console import Console

from uv_secure import __version__
from uv_secure.configuration import (
    config_cli_arg_factory,
    config_file_factory,
    Configuration,
    OutputFormat,
    override_config,
)
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


if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup


USER_AGENT = f"uv-secure/{__version__} (contact: owenrlamont@gmail.com)"


class ManagedAsyncSqliteStorage(AsyncSqliteStorage):
    """AsyncSqliteStorage that ensures the underlying connection is closed."""

    async def close(self) -> None:
        """Close the storage and underlying sqlite connection if present."""
        connection = getattr(self, "connection", None)
        if connection is not None:
            await connection.close()
            self.connection = None
        await super().close()


@cache
def get_specifier_sets(specifiers: tuple[str, ...]) -> tuple[SpecifierSet, ...]:
    """Converts a tuple of version specifiers to a tuple of SpecifierSets

    Args:
        specifiers: tuple of version specifiers

    Returns:
        tuple of SpecifierSets
    """
    return tuple(SpecifierSet(spec) for spec in specifiers)


def _convert_vulnerability_to_output(vuln: Vulnerability) -> VulnerabilityOutput:
    """Convert Vulnerability to VulnerabilityOutput"""
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
    """Convert maintenance issue data to MaintenanceIssueOutput"""
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
    """Process a single package's metadata and return output or error

    Returns:
        DependencyOutput if successful
        str if error occurred
        None if package should be skipped
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
    """Check if package should be skipped based on ignore configuration"""
    if package.info.name not in ignore_packages:
        return False

    specifiers = ignore_packages[package.info.name]
    return len(specifiers) == 0 or any(
        specifier.contains(package.info.version) for specifier in specifiers
    )


def _should_check_vulnerabilities(package: PackageInfo, config: Configuration) -> bool:
    """Check if package should be checked for vulnerabilities"""
    return (
        package.direct_dependency is not False
        or not config.vulnerability_criteria.check_direct_dependencies_only
    )


def _should_check_maintenance_issues(
    package_info: PackageInfo, config: Configuration
) -> bool:
    """Check if package should be checked for maintenance issues"""
    return (
        package_info.direct_dependency is not False
        or not config.maintainability_criteria.check_direct_dependencies_only
    )


def _filter_vulnerabilities(package: PackageInfo, config: Configuration) -> None:
    """Filter out ignored and withdrawn vulnerabilities from package"""
    package.vulnerabilities = [
        vuln
        for vuln in package.vulnerabilities
        if (
            config.vulnerability_criteria.ignore_vulnerabilities is None
            or vuln.id not in config.vulnerability_criteria.ignore_vulnerabilities
        )
        and vuln.withdrawn is None
    ]


def _has_maintenance_issues(
    package_index: PackageIndex, package_info: PackageInfo, config: Configuration
) -> bool:
    """Check if package has maintenance issues"""
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
    """Parse dependency file based on its type"""
    if dependency_file_path.name == "uv.lock":
        return await parse_uv_lock_file(dependency_file_path)
    if dependency_file_path.name == "requirements.txt":
        return await parse_requirements_txt_file(dependency_file_path)
    # Assume dependency_file_path.name == "pyproject.toml"
    return await parse_pylock_toml_file(dependency_file_path)


def _build_ignore_packages(
    config: Configuration,
) -> dict[str, tuple[SpecifierSet, ...]]:
    """Build the ignore packages mapping from configuration"""
    if config.ignore_packages is None:
        return {}
    return {
        name: get_specifier_sets(tuple(specifiers))
        for name, specifiers in config.ignore_packages.items()
    }


async def check_dependencies(
    dependency_file_path: APath,
    config: Configuration,
    http_client: AsyncClient,
    disable_cache: bool,
) -> FileResultOutput:
    """Checks dependencies for vulnerabilities and builds structured output

    Args:
        dependency_file_path: PEP751 pylock.toml, requirements.txt, or uv.lock file path
        config: uv-secure configuration object
        http_client: HTTP client for making requests
        disable_cache: flag whether to disable cache for HTTP requests

    Returns:
        FileResultOutput with structured dependency results
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
    async with create_task_group() as tg:
        package_infos = tg.soonify(download_packages)(
            dependencies, http_client, disable_cache
        )
        package_indexes = tg.soonify(download_package_indexes)(
            dependencies, http_client, disable_cache
        )

    package_metadata: list[
        tuple[PackageInfo | BaseException, PackageIndex | BaseException]
    ] = list(zip(package_infos.value, package_indexes.value, strict=True))

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
    """Resolve file paths and their associated configurations"""
    file_apaths: tuple[APath, ...] = (
        (APath(),) if not file_paths else tuple(APath(file) for file in file_paths)
    )

    if len(file_apaths) == 1 and await file_apaths[0].is_dir():
        lock_to_config_map = await get_dependency_file_to_config_map(file_apaths[0])
        file_apaths = tuple(lock_to_config_map.keys())
    else:
        if config_path is not None:
            possible_config = await config_file_factory(APath(config_path))
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
) -> dict[APath, Configuration]:
    """Apply CLI configuration overrides to lock-to-config mapping"""
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
        )
        return {
            lock_file: override_config(config, cli_config)
            for lock_file, config in lock_to_config_map.items()
        }
    return lock_to_config_map


def _determine_file_status(file_result: FileResultOutput) -> int:
    """Determine status code for a single file result

    Returns:
        0: No issues, 1: Maintenance issues found, 2: Vulnerabilities found, 3: Error
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
    """Determine final run status from file results"""
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
) -> RunStatus:
    """Checks PEP751 pylock.toml, requirements.txt, and uv.lock files for issues

    Check specified or discovered uv.lock and requirements.txt files for maintenance
    issues or known vulnerabilities

    Args:
        file_paths: paths to files or directory to process
        aliases: flag whether to show vulnerability aliases
        desc: flag whether to show vulnerability descriptions
        cache_path: path to cache directory
        cache_ttl_seconds: time in seconds to cache
        disable_cache: flag whether to disable cache
        forbid_archived: flag whether to forbid archived dependencies
        forbid_deprecated: flag whether to forbid deprecated dependencies
        forbid_quarantined: flag whether to forbid quarantined dependencies
        forbid_yanked: flag whether to forbid yanked dependencies
        max_package_age: maximum age of dependencies in days
        ignore_vulns: Vulnerabilities IDs to ignore
        ignore_pkgs: list of package names to ignore
        check_direct_dependency_vulnerabilities_only: flag checking direct dependency
            vulnerabilities only
        check_direct_dependency_maintenance_issues_only: flag checking direct dependency
            maintenance issues only
        config_path: path to configuration file
        format_type: output format type ("columns" or "json") - for backwards
            compatibility. None means use config file setting.

    Returns:
        RunStatus indicating the result of the scan
    """
    console = Console()

    try:
        file_apaths, lock_to_config_map = await _resolve_file_paths_and_configs(
            file_paths, config_path
        )
    except (ExceptionGroup, ValueError) as e:
        if isinstance(e, ExceptionGroup):
            for exc in e.exceptions:
                console.print(f"[bold red]Error:[/] {exc}")
        else:
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
    )

    client_headers = Headers({"User-Agent": USER_AGENT})
    timeout_seconds = 10

    storage: ManagedAsyncSqliteStorage | None
    connection: anysqlite.Connection | None = None
    if disable_cache:
        http_client_cm: AsyncClient = AsyncClient(
            timeout=timeout_seconds, headers=client_headers
        )
        storage = None
    else:
        # Antivirus tools (e.g. Windows Defender) negate file-cache benefits unless the
        # cache directory is excluded from realtime scanning.
        cache_path.mkdir(parents=True, exist_ok=True)
        gitignore_path = cache_path / ".gitignore"
        if not gitignore_path.exists():
            gitignore_path.write_text(
                "# Automatically created by Hishel\n*", encoding="utf-8"
            )
        connection = await anysqlite.connect(str(cache_path / "uv-secure-cache.db"))
        storage = ManagedAsyncSqliteStorage(
            connection=connection,
            default_ttl=cache_ttl_seconds,
            refresh_ttl_on_access=False,
        )
        http_client_cm = AsyncCacheClient(
            timeout=timeout_seconds, headers=client_headers, storage=storage
        )

    try:
        async with http_client_cm as http_client:
            file_results = list(
                await asyncio.gather(
                    *[
                        check_dependencies(
                            dependency_file_path,
                            lock_to_config_map[APath(dependency_file_path)],
                            http_client,
                            disable_cache,
                        )
                        for dependency_file_path in file_apaths
                    ]
                )
            )
    finally:
        if storage is not None:
            await storage.close()

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
