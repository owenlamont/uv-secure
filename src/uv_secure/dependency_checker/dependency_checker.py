import asyncio
from collections.abc import Iterable, Sequence
from enum import Enum
from functools import cache
from pathlib import Path
import sys

from anyio import Path as APath
from asyncer import create_task_group
from hishel import AsyncCacheClient, AsyncFileStorage
from httpx import Headers
import humanize
import inflect
from packaging.specifiers import SpecifierSet
from rich.console import Console, ConsoleRenderable
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from uv_secure import __version__
from uv_secure.configuration import (
    config_cli_arg_factory,
    config_file_factory,
    Configuration,
    override_config,
)
from uv_secure.directory_scanner import get_dependency_file_to_config_map
from uv_secure.directory_scanner.directory_scanner import (
    get_dependency_files_to_config_map,
)
from uv_secure.package_info import (
    download_package_indexes,
    download_packages,
    PackageIndex,
    PackageInfo,
    parse_pylock_toml_file,
    parse_requirements_txt_file,
    parse_uv_lock_file,
    ProjectState,
    Vulnerability,
)


if sys.version_info < (3, 11):
    from exceptiongroup import ExceptionGroup


USER_AGENT = f"uv-secure/{__version__} (contact: owenrlamont@gmail.com)"


def _create_package_hyperlink(package_name: str) -> Text:
    """Create hyperlink for package name"""
    return Text.assemble(
        (package_name, f"link https://pypi.org/project/{package_name}")
    )


def _create_version_hyperlink(package_name: str, version: str) -> Text:
    """Create hyperlink for package version"""
    return Text.assemble(
        (version, f"link https://pypi.org/project/{package_name}/{version}/")
    )


def _create_vulnerability_id_hyperlink(vuln: Vulnerability) -> Text:
    """Create hyperlink for vulnerability ID"""
    return Text.assemble((vuln.id, f"link {vuln.link}")) if vuln.link else Text(vuln.id)


def _create_fix_versions_text(package_name: str, vuln: Vulnerability) -> Text:
    """Create text with fix version hyperlinks"""
    if not vuln.fixed_in:
        return Text("")

    return Text(", ").join(
        [
            Text.assemble(
                (fix_ver, f"link https://pypi.org/project/{package_name}/{fix_ver}/")
            )
            for fix_ver in vuln.fixed_in
        ]
    )


def _get_alias_hyperlink(alias: str, package_name: str) -> str | None:
    """Get hyperlink URL for vulnerability alias"""
    if alias.startswith("CVE-"):
        return f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={alias}"
    if alias.startswith("GHSA-"):
        return f"https://github.com/advisories/{alias}"
    if alias.startswith("PYSEC-"):
        return (
            "https://github.com/pypa/advisory-database/blob/main/"
            f"vulns/{package_name}/{alias}.yaml"
        )
    if alias.startswith("OSV-"):
        return f"https://osv.dev/vulnerability/{alias}"
    return None


def _create_aliases_text(vuln: Vulnerability, package_name: str) -> Text:
    """Create text with alias hyperlinks"""
    if not vuln.aliases:
        return Text("")

    alias_links = []
    for alias in vuln.aliases:
        hyperlink = _get_alias_hyperlink(alias, package_name)
        if hyperlink:
            alias_links.append(Text.assemble((alias, f"link {hyperlink}")))
        else:
            alias_links.append(Text(alias))

    return Text(", ").join(alias_links) if alias_links else Text("")


def _create_vulnerability_row_renderables(
    package: PackageInfo, vuln: Vulnerability, config: Configuration
) -> list[Text]:
    """Create renderables for a vulnerability table row"""
    renderables = [
        _create_package_hyperlink(package.info.name),
        _create_version_hyperlink(package.info.name, package.info.version),
        _create_vulnerability_id_hyperlink(vuln),
        _create_fix_versions_text(package.info.name, vuln),
    ]

    if config.vulnerability_criteria.aliases:
        renderables.append(_create_aliases_text(vuln, package.info.name))

    if config.vulnerability_criteria.desc:
        renderables.append(Text(vuln.details))

    return renderables


def _render_vulnerability_table(
    config: Configuration, vulnerable_packages: Iterable[PackageInfo]
) -> Table:
    table = Table(
        title="Vulnerable Dependencies",
        show_header=True,
        row_styles=["none", "dim"],
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Package", min_width=8, max_width=40)
    table.add_column("Version", min_width=10, max_width=20)
    table.add_column("Vulnerability ID", style="bold cyan", min_width=20, max_width=24)
    table.add_column("Fix Versions", min_width=10, max_width=20)
    if config.vulnerability_criteria.aliases:
        table.add_column("Aliases", min_width=20, max_width=24)
    if config.vulnerability_criteria.desc:
        table.add_column("Details", min_width=8)

    for package in vulnerable_packages:
        for vuln in package.vulnerabilities:
            renderables = _create_vulnerability_row_renderables(package, vuln, config)
            table.add_row(*renderables)

    return table


def _render_issue_table(
    config: Configuration,
    maintenance_issue_packages: Iterable[tuple[PackageInfo, PackageIndex]],
) -> Table:
    table = Table(
        title="Maintenance Issues",
        show_header=True,
        row_styles=["none", "dim"],
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Package", min_width=8, max_width=40)
    table.add_column("Version", min_width=10, max_width=20)
    table.add_column("Yanked", style="bold cyan", min_width=10, max_width=10)
    table.add_column("Yanked Reason", min_width=20, max_width=24)
    table.add_column("Age", min_width=20, max_width=24)
    table.add_column("Status", min_width=10, max_width=16)
    table.add_column("Reason", min_width=20, max_width=40)
    for package, pkg_index in maintenance_issue_packages:
        renderables: list[Text] = [
            Text.assemble(
                (
                    package.info.name,
                    f"link https://pypi.org/project/{package.info.name}",
                )
            ),
            Text.assemble(
                (
                    package.info.version,
                    f"link https://pypi.org/project/{package.info.name}/"
                    f"{package.info.version}/",
                )
            ),
            Text(str(package.info.yanked)),
            Text(package.info.yanked_reason)
            if package.info.yanked_reason
            else Text("Unknown"),
            Text(humanize.precisedelta(package.age, minimum_unit="days"))
            if package.age
            else Text("Unknown"),
            Text(pkg_index.project_status.status.value),
            Text(pkg_index.project_status.reason or ""),
        ]
        table.add_row(*renderables)
    return table


@cache
def get_specifier_sets(specifiers: tuple[str, ...]) -> tuple[SpecifierSet, ...]:
    """Converts a tuple of version specifiers to a tuple of SpecifierSets

    Args:
        specifiers: tuple of version specifiers

    Returns:
        tuple of SpecifierSets
    """
    return tuple(SpecifierSet(spec) for spec in specifiers)


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
        and package_index.project_status.status == ProjectState.ARCHIVED
    )
    found_rejected_deprecated_package = (
        config.maintainability_criteria.forbid_deprecated
        and package_index.project_status.status == ProjectState.DEPRECATED
    )
    found_rejected_quarantined_package = (
        config.maintainability_criteria.forbid_quarantined
        and package_index.project_status.status == ProjectState.QUARANTINED
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


async def _parse_dependency_file(dependency_file_path: APath) -> list:
    """Parse dependency file based on its type"""
    if dependency_file_path.name == "uv.lock":
        return await parse_uv_lock_file(dependency_file_path)
    if dependency_file_path.name == "requirements.txt":
        return await parse_requirements_txt_file(dependency_file_path)
    # Assume dependency_file_path.name == "pyproject.toml"
    return await parse_pylock_toml_file(dependency_file_path)


def _generate_summary_outputs(
    vulnerable_count: int,
    maintenance_issue_packages: list[tuple[PackageInfo, PackageIndex]],
    total_dependencies: int,
    config: Configuration,
    vulnerable_packages: list[PackageInfo],
) -> tuple[int, list[ConsoleRenderable]]:
    """Generate summary outputs and determine status"""
    console_outputs: list[ConsoleRenderable] = []
    inf = inflect.engine()
    total_plural = inf.plural("dependency", total_dependencies)
    vulnerable_plural = inf.plural("vulnerability", vulnerable_count)

    status = 0
    if vulnerable_count > 0:
        console_outputs.append(
            Panel.fit(
                f"[bold red]Vulnerabilities detected![/]\n"
                f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
                f"Vulnerable: [bold]{vulnerable_count}[/] {vulnerable_plural}"
            )
        )
        table = _render_vulnerability_table(config, vulnerable_packages)
        console_outputs.append(table)
        status = 2

    issue_count = len(maintenance_issue_packages)
    issue_plural = inf.plural("issue", issue_count)
    if len(maintenance_issue_packages) > 0:
        console_outputs.append(
            Panel.fit(
                f"[bold yellow]Maintenance Issues detected![/]\n"
                f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
                f"Issues: [bold]{issue_count}[/] {issue_plural}"
            )
        )
        table = _render_issue_table(config, maintenance_issue_packages)
        console_outputs.append(table)
        status = max(status, 1)

    if status == 0:
        console_outputs.append(
            Panel.fit(
                f"[bold green]No vulnerabilities or maintenance issues detected![/]\n"
                f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
                f"All dependencies appear safe!"
            )
        )

    return status, console_outputs


def _process_package_for_vulnerabilities(
    package: PackageInfo,
    config: Configuration,
    ignore_packages: dict[str, tuple[SpecifierSet, ...]],
) -> int:
    """Process a single package for vulnerabilities and return count found"""
    if not _should_check_vulnerabilities(package, config):
        return 0

    _filter_vulnerabilities(package, config)
    return len(package.vulnerabilities)


def _process_package_for_maintenance_issues(
    package_index: PackageIndex, package_info: PackageInfo, config: Configuration
) -> bool:
    """Process a single package for maintenance issues and return if found"""
    return _should_check_maintenance_issues(
        package_info, config
    ) and _has_maintenance_issues(package_index, package_info, config)


def _warn_about_direct_dependencies(
    dependency_file_path: APath, packages: list, config: Configuration
) -> Text | None:
    """Check if we need to warn about missing direct dependency information"""
    has_none_direct_dependency = any(
        isinstance(package, PackageInfo) and package.direct_dependency is None
        for package in packages
    )
    if has_none_direct_dependency and (
        config.vulnerability_criteria.check_direct_dependencies_only
        or config.maintainability_criteria.check_direct_dependencies_only
    ):
        return Text.from_markup(
            f"[bold yellow]Warning:[/] {dependency_file_path} doesn't contain "
            "the necessary information to determine direct dependencies."
        )
    return None


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


async def _load_dependencies_with_errors(
    dependency_file_path: APath,
) -> tuple[int, list, list[ConsoleRenderable]]:
    """Load dependencies from a lock/requirements file and capture errors.

    Returns a tuple of (status_code, dependencies, outputs). A status code of 3
    indicates a runtime error; 0 indicates success (which may still result in an
    empty dependency list).
    """
    outputs: list[ConsoleRenderable] = []
    if not await dependency_file_path.exists():
        outputs.append(
            Text.from_markup(
                f"[bold red]Error:[/] File {dependency_file_path} does not exist."
            )
        )
        return 3, [], outputs

    try:
        dependencies = await _parse_dependency_file(dependency_file_path)
    except Exception as e:  # pragma: no cover - defensive, surfaced to user
        outputs.append(
            Text.from_markup(
                f"[bold red]Error:[/] Failed to parse {dependency_file_path}: {e}"
            )
        )
        return 3, [], outputs

    return 0, dependencies, outputs


def _accumulate_from_metadata(
    package_metadata: Iterable[
        tuple[PackageInfo | BaseException, PackageIndex | BaseException]
    ],
    dependencies: Sequence,
    config: Configuration,
    ignore_packages: dict[str, tuple[SpecifierSet, ...]],
) -> tuple[
    int,
    int,
    list[PackageInfo],
    list[tuple[PackageInfo, PackageIndex]],
    list[ConsoleRenderable],
]:
    """Accumulate vulnerability and maintenance results across all packages.

    Returns (error_status, vuln_count, vulnerable_pkgs, maintenance_issue_pkgs,
    outputs). If error_status is 3, an error occurred and outputs contain the
    relevant message.
    """
    vuln_count = 0
    vulnerable_pkgs: list[PackageInfo] = []
    maintenance_issue_pkgs: list[tuple[PackageInfo, PackageIndex]] = []
    outputs: list[ConsoleRenderable] = []

    for idx, (package_info, package_index) in enumerate(package_metadata):
        if isinstance(package_info, BaseException) or isinstance(
            package_index, BaseException
        ):
            ex = (
                package_info
                if isinstance(package_info, BaseException)
                else package_index
            )
            outputs.append(
                Text.from_markup(
                    f"[bold red]Error:[/] {dependencies[idx]} raised exception: {ex}"
                )
            )
            return 3, 0, [], [], outputs

        if _should_skip_package(package_info, ignore_packages):
            outputs.append(
                Text.from_markup(
                    f"[bold yellow]Skipping {package_info.info.name} "
                    f"({package_info.info.version}) as it is ignored[/]"
                )
            )
            continue

        added = _process_package_for_vulnerabilities(
            package_info, config, ignore_packages
        )
        if added > 0:
            vuln_count += added
            vulnerable_pkgs.append(package_info)

        if _process_package_for_maintenance_issues(package_index, package_info, config):
            maintenance_issue_pkgs.append((package_info, package_index))

    return 0, vuln_count, vulnerable_pkgs, maintenance_issue_pkgs, outputs


async def check_dependencies(
    dependency_file_path: APath,
    config: Configuration,
    http_client: AsyncCacheClient,
    disable_cache: bool,
) -> tuple[int, Iterable[ConsoleRenderable]]:
    """Checks dependencies for vulnerabilities and summarizes the results

    Args:
        dependency_file_path: PEP751 pylock.toml, requirements.txt, or uv.lock file path
        config: uv-secure configuration object
        http_client: HTTP client for making requests
        disable_cache: flag whether to disable cache for HTTP requests

    Returns:
        tuple with status code and output for console to render
    """
    console_outputs: list[ConsoleRenderable] = []

    status, dependencies, initial_outputs = await _load_dependencies_with_errors(
        dependency_file_path
    )
    console_outputs.extend(initial_outputs)
    if status == 3:
        return 3, console_outputs
    if len(dependencies) == 0:
        return 0, console_outputs

    console_outputs.append(
        Text.from_markup(
            f"[bold cyan]Checking {dependency_file_path} dependencies for "
            "vulnerabilities ...[/]\n"
        )
    )

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

    total_dependencies = len(package_metadata)
    vulnerable_count = 0
    vulnerable_packages = []
    maintenance_issue_packages: list[tuple[PackageInfo, PackageIndex]] = []

    ignore_packages = _build_ignore_packages(config)

    # Check if we need to warn about direct dependencies
    warning = _warn_about_direct_dependencies(
        dependency_file_path, package_infos.value, config
    )
    if warning:
        console_outputs.append(warning)

    (
        err_status,
        vuln_added,
        newly_vulnerable_packages,
        newly_maintenance_issue_packages,
        loop_outputs,
    ) = _accumulate_from_metadata(
        package_metadata, dependencies, config, ignore_packages
    )
    console_outputs.extend(loop_outputs)
    if err_status == 3:
        return 3, console_outputs
    vulnerable_count += vuln_added
    vulnerable_packages.extend(newly_vulnerable_packages)
    maintenance_issue_packages.extend(newly_maintenance_issue_packages)

    status, summary_outputs = _generate_summary_outputs(
        vulnerable_count,
        maintenance_issue_packages,
        total_dependencies,
        config,
        vulnerable_packages,
    )
    console_outputs.extend(summary_outputs)

    return status, console_outputs


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
        )
        return {
            lock_file: override_config(config, cli_config)
            for lock_file, config in lock_to_config_map.items()
        }
    return lock_to_config_map


def _determine_final_status(status_outputs: list[tuple[int, Iterable]]) -> RunStatus:
    """Determine final run status from individual check results"""
    maintenance_issues_found = False
    vulnerabilities_found = False
    runtime_error = False

    for status, _ in status_outputs:
        if status == 1:
            maintenance_issues_found = True
        elif status == 2:
            vulnerabilities_found = True
        elif status == 3:
            runtime_error = True

    if runtime_error:
        return RunStatus.RUNTIME_ERROR
    if vulnerabilities_found:
        return RunStatus.VULNERABILITIES_FOUND
    if maintenance_issues_found:
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


    Returns:
        True if vulnerabilities were found, False otherwise.
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
    )

    # I found antivirus programs (specifically Windows Defender) can almost fully
    # negate the benefits of using a file cache if you don't exclude the virus checker
    # from checking the cache dir given it is frequently read from
    storage = AsyncFileStorage(base_path=cache_path, ttl=cache_ttl_seconds)
    async with AsyncCacheClient(
        timeout=10, headers=Headers({"User-Agent": USER_AGENT}), storage=storage
    ) as http_client:
        status_outputs = list(
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

    for _, console_output in status_outputs:
        console.print(*console_output)

    return _determine_final_status(status_outputs)
