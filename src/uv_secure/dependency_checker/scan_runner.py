import asyncio
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from anyio import Path as APath
from httpx import AsyncClient, Headers
from rich.console import Console

from uv_secure.caching.cache_manager import CacheManager
from uv_secure.configuration import (
    config_cli_arg_factory,
    config_file_factory,
    Configuration,
    OutputFormat,
    override_config,
    SeverityLevel,
)
from uv_secure.configuration.exceptions import UvSecureConfigurationError
from uv_secure.configuration.toml_fixer import fix_unused_ignores_in_toml_config
from uv_secure.dependency_checker.file_checker import check_dependencies
from uv_secure.dependency_checker.status import RunStatus
from uv_secure.dependency_checker.tool_audit import (
    check_global_uv_tool,
    check_installed_uv_secure_package,
    GLOBAL_UV_SECURE_PACKAGE_LABEL,
    GLOBAL_UV_TOOL_LABEL,
)
from uv_secure.directory_scanner import get_dependency_file_and_source_maps
from uv_secure.directory_scanner.directory_scanner import (
    get_dependency_files_and_source_maps,
)
from uv_secure.output_formatters import ColumnsFormatter, JsonFormatter, OutputFormatter
from uv_secure.output_models import ErrorOutput, FileResultOutput, ScanResultsOutput


@dataclass(frozen=True)
class UnusedIgnoreAnalysis:
    unused_ignore_ids: set[str]
    unmatched_ignore_packages: set[str]
    matched_but_clean_ignore_packages: set[str]
    unused_vulnerability_ignore_sources: dict[str, set[str]]
    unused_package_ignore_sources: dict[str, set[str]]

    @property
    def unused_ignore_packages(self) -> set[str]:
        """Return the union of all unused package-ignore names."""
        return self.unmatched_ignore_packages | self.matched_but_clean_ignore_packages


@dataclass(frozen=True)
class UnusedIgnorePolicyResult:
    status: RunStatus
    analysis: UnusedIgnoreAnalysis | None = None
    fix_error_message: str | None = None
    fixed_summary: tuple[int, int, int] | None = None


def _determine_file_status(file_result: FileResultOutput) -> int:
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
    statuses = [_determine_file_status(result) for result in file_results]

    if 3 in statuses:
        return RunStatus.RUNTIME_ERROR
    if 2 in statuses:
        return RunStatus.VULNERABILITIES_FOUND
    if 1 in statuses:
        return RunStatus.MAINTENANCE_ISSUES_FOUND
    return RunStatus.NO_VULNERABILITIES


def _find_unused_ignore_vulnerability_ids(
    lock_to_config_map: dict[APath, Configuration],
    used_ignore_vulnerabilities_by_scope: dict[str, set[str]],
) -> set[str]:
    all_used_ignore_ids = {
        ignore_id
        for used_ignore_ids in used_ignore_vulnerabilities_by_scope.values()
        for ignore_id in used_ignore_ids
    }
    unused_ignore_ids: set[str] = set()
    for config in lock_to_config_map.values():
        if config.vulnerability_criteria.allow_unused_ignores:
            continue
        configured_ignore_ids = config.vulnerability_criteria.ignore_vulnerabilities
        if not configured_ignore_ids:
            continue
        unused_ignore_ids.update(configured_ignore_ids - all_used_ignore_ids)

    return unused_ignore_ids


def _format_config_source(
    config_source: APath | None, ignore_defined_via_cli: bool
) -> str:
    if ignore_defined_via_cli:
        return "CLI"
    if config_source is None:
        return "default configuration"
    return config_source.as_posix()


def _format_unused_ignore_with_sources(
    ignore_ids: set[str], ignore_sources: dict[str, set[str]]
) -> str:
    return ", ".join(
        (
            f"{ignore_id} (configured via: "
            f"{', '.join(sorted(ignore_sources[ignore_id]))})"
        )
        for ignore_id in sorted(ignore_ids)
    )


def _collect_unused_ignore_vulnerability_sources(
    unused_ignore_ids: set[str],
    lock_to_config_map: dict[APath, Configuration],
    lock_to_config_source_map: dict[APath, APath | None],
    ignore_vulns: str | None,
) -> dict[str, set[str]]:
    ignore_sources: dict[str, set[str]] = {}
    ignore_defined_via_cli = ignore_vulns is not None
    for lock_file, config in lock_to_config_map.items():
        if config.vulnerability_criteria.allow_unused_ignores:
            continue
        configured_ignore_ids = config.vulnerability_criteria.ignore_vulnerabilities
        if configured_ignore_ids is None:
            continue
        matching_ids = configured_ignore_ids & unused_ignore_ids
        if not matching_ids:
            continue
        source = _format_config_source(
            lock_to_config_source_map.get(lock_file), ignore_defined_via_cli
        )
        for ignore_id in matching_ids:
            ignore_sources.setdefault(ignore_id, set()).add(source)
    return ignore_sources


def _find_unused_ignore_package_ids(
    lock_to_config_map: dict[APath, Configuration],
    matched_ignore_packages_by_scope: dict[str, set[str]],
    used_ignore_packages_by_scope: dict[str, set[str]],
) -> tuple[set[str], set[str]]:
    all_matched_ignore_packages = {
        package_name
        for matched_ignore_packages in matched_ignore_packages_by_scope.values()
        for package_name in matched_ignore_packages
    }
    all_used_ignore_packages = {
        package_name
        for used_ignore_packages in used_ignore_packages_by_scope.values()
        for package_name in used_ignore_packages
    }
    unmatched_ignore_packages: set[str] = set()
    matched_but_clean_ignore_packages: set[str] = set()
    for config in lock_to_config_map.values():
        if config.vulnerability_criteria.allow_unused_ignores:
            continue
        configured_ignore_packages = set(config.ignore_packages or {})
        if not configured_ignore_packages:
            continue
        unmatched_ignore_packages.update(
            configured_ignore_packages - all_matched_ignore_packages
        )
        matched_but_clean_ignore_packages.update(
            (configured_ignore_packages & all_matched_ignore_packages)
            - all_used_ignore_packages
        )

    return unmatched_ignore_packages, matched_but_clean_ignore_packages


def _collect_unused_ignore_package_sources(
    unused_ignore_packages: set[str],
    lock_to_config_map: dict[APath, Configuration],
    lock_to_config_source_map: dict[APath, APath | None],
    ignore_pkgs: list[str] | None,
) -> dict[str, set[str]]:
    ignore_sources: dict[str, set[str]] = {}
    ignore_defined_via_cli = ignore_pkgs is not None
    for lock_file, config in lock_to_config_map.items():
        if config.vulnerability_criteria.allow_unused_ignores:
            continue
        configured_ignore_packages = set(config.ignore_packages or {})
        matching_packages = configured_ignore_packages & unused_ignore_packages
        if not matching_packages:
            continue
        source = _format_config_source(
            lock_to_config_source_map.get(lock_file), ignore_defined_via_cli
        )
        for package_name in matching_packages:
            ignore_sources.setdefault(package_name, set()).add(source)
    return ignore_sources


def _analyze_unused_ignores(
    lock_to_config_map: dict[APath, Configuration],
    lock_to_config_source_map: dict[APath, APath | None],
    used_ignore_vulnerabilities_by_scope: dict[str, set[str]],
    matched_ignore_packages_by_scope: dict[str, set[str]],
    used_ignore_packages_by_scope: dict[str, set[str]],
    ignore_vulns: str | None,
    ignore_pkgs: list[str] | None,
) -> UnusedIgnoreAnalysis:
    unused_ignore_ids = _find_unused_ignore_vulnerability_ids(
        lock_to_config_map, used_ignore_vulnerabilities_by_scope
    )
    unmatched_ignore_packages, matched_but_clean_ignore_packages = (
        _find_unused_ignore_package_ids(
            lock_to_config_map,
            matched_ignore_packages_by_scope,
            used_ignore_packages_by_scope,
        )
    )
    unused_vulnerability_ignore_sources = _collect_unused_ignore_vulnerability_sources(
        unused_ignore_ids, lock_to_config_map, lock_to_config_source_map, ignore_vulns
    )
    unused_package_ignore_sources = _collect_unused_ignore_package_sources(
        unmatched_ignore_packages | matched_but_clean_ignore_packages,
        lock_to_config_map,
        lock_to_config_source_map,
        ignore_pkgs,
    )
    return UnusedIgnoreAnalysis(
        unused_ignore_ids=unused_ignore_ids,
        unmatched_ignore_packages=unmatched_ignore_packages,
        matched_but_clean_ignore_packages=matched_but_clean_ignore_packages,
        unused_vulnerability_ignore_sources=unused_vulnerability_ignore_sources,
        unused_package_ignore_sources=unused_package_ignore_sources,
    )


def _build_unused_ignore_message(analysis: UnusedIgnoreAnalysis) -> str:
    unused_ignore_display = _format_unused_ignore_with_sources(
        analysis.unused_ignore_ids, analysis.unused_vulnerability_ignore_sources
    )
    unmatched_package_display = _format_unused_ignore_with_sources(
        analysis.unmatched_ignore_packages, analysis.unused_package_ignore_sources
    )
    matched_but_clean_package_display = _format_unused_ignore_with_sources(
        analysis.matched_but_clean_ignore_packages,
        analysis.unused_package_ignore_sources,
    )
    message_parts: list[str] = []
    if unused_ignore_display:
        message_parts.append(
            f"unused vulnerability ignore IDs: {unused_ignore_display}"
        )
    if unmatched_package_display:
        message_parts.append(
            "unused package ignore IDs (no matching scanned package): "
            f"{unmatched_package_display}"
        )
    if matched_but_clean_package_display:
        message_parts.append(
            "unused package ignore IDs (matched package would have no findings): "
            f"{matched_but_clean_package_display}"
        )
    return "Found " + "; ".join(message_parts)


def _collect_fix_targets_by_source(
    analysis: UnusedIgnoreAnalysis,
    lock_to_config_map: dict[APath, Configuration],
    lock_to_config_source_map: dict[APath, APath | None],
    ignore_vulns: str | None,
    ignore_pkgs: list[str] | None,
) -> dict[APath, tuple[set[str], set[str]]]:
    fix_targets: defaultdict[APath, tuple[set[str], set[str]]] = defaultdict(
        lambda: (set(), set())
    )

    for lock_file, config in lock_to_config_map.items():
        config_source = lock_to_config_source_map.get(lock_file)
        if (
            config_source is None
            or not config.fix
            or config.vulnerability_criteria.allow_unused_ignores
        ):
            continue
        vulnerability_ids = (
            set()
            if ignore_vulns is not None
            else set(config.vulnerability_criteria.ignore_vulnerabilities or set())
        ) & analysis.unused_ignore_ids
        package_names = (
            set() if ignore_pkgs is not None else set(config.ignore_packages or {})
        ) & analysis.unused_ignore_packages
        if not vulnerability_ids and not package_names:
            continue
        source_vulnerability_ids, source_package_names = fix_targets[config_source]
        source_vulnerability_ids.update(vulnerability_ids)
        source_package_names.update(package_names)
    return dict(fix_targets)


def _record_unused_ignore_error(
    config: Configuration,
    scan_results: ScanResultsOutput,
    console: Console,
    analysis: UnusedIgnoreAnalysis,
) -> RunStatus:
    unused_ignore_message = _build_unused_ignore_message(analysis)
    if config.format.value == "json":
        scan_results.errors.append(
            ErrorOutput(code="unused_ignores", message=unused_ignore_message)
        )
    else:
        console.print(f"[bold red]Error:[/] {unused_ignore_message}")
    return RunStatus.UNUSED_IGNORES_FOUND


async def _apply_unused_ignore_fixes(
    fix_targets_by_source: dict[APath, tuple[set[str], set[str]]],
) -> tuple[dict[APath, set[str]], dict[APath, set[str]], int]:
    removed_vulnerability_ids_by_source: dict[APath, set[str]] = {}
    removed_package_names_by_source: dict[APath, set[str]] = {}
    modified_files = 0

    for config_source in sorted(
        fix_targets_by_source, key=lambda path: path.as_posix()
    ):
        vulnerability_ids, package_names = fix_targets_by_source[config_source]
        fix_result = await fix_unused_ignores_in_toml_config(
            config_source, vulnerability_ids, package_names
        )
        if fix_result.modified:
            modified_files += 1
        if fix_result.removed_vulnerability_ids:
            removed_vulnerability_ids_by_source[config_source] = (
                fix_result.removed_vulnerability_ids
            )
        if fix_result.removed_package_ignores:
            removed_package_names_by_source[config_source] = (
                fix_result.removed_package_ignores
            )
    return (
        removed_vulnerability_ids_by_source,
        removed_package_names_by_source,
        modified_files,
    )


def _apply_removed_ignores_to_in_memory_configuration(
    lock_to_config_map: dict[APath, Configuration],
    lock_to_config_source_map: dict[APath, APath | None],
    removed_vulnerability_ids_by_source: dict[APath, set[str]],
    removed_package_names_by_source: dict[APath, set[str]],
) -> None:
    for lock_file, config in lock_to_config_map.items():
        config_source = lock_to_config_source_map.get(lock_file)
        if config_source is None:
            continue
        removed_vulnerability_ids = removed_vulnerability_ids_by_source.get(
            config_source
        )
        if removed_vulnerability_ids:
            configured_ignore_ids = config.vulnerability_criteria.ignore_vulnerabilities
            if configured_ignore_ids is not None:
                config.vulnerability_criteria.ignore_vulnerabilities = (
                    configured_ignore_ids - removed_vulnerability_ids
                )
        removed_package_names = removed_package_names_by_source.get(config_source)
        if removed_package_names:
            configured_ignore_packages = config.ignore_packages
            if configured_ignore_packages is not None:
                config.ignore_packages = {
                    package_name: specifiers
                    for package_name, specifiers in configured_ignore_packages.items()
                    if package_name not in removed_package_names
                }


async def _evaluate_unused_ignore_policy(
    lock_to_config_map: dict[APath, Configuration],
    lock_to_config_source_map: dict[APath, APath | None],
    used_ignore_vulnerabilities_by_scope: dict[str, set[str]],
    matched_ignore_packages_by_scope: dict[str, set[str]],
    used_ignore_packages_by_scope: dict[str, set[str]],
    ignore_vulns: str | None,
    ignore_pkgs: list[str] | None,
    final_status: RunStatus,
) -> UnusedIgnorePolicyResult:
    if final_status == RunStatus.RUNTIME_ERROR:
        return UnusedIgnorePolicyResult(status=final_status)

    analysis = _analyze_unused_ignores(
        lock_to_config_map,
        lock_to_config_source_map,
        used_ignore_vulnerabilities_by_scope,
        matched_ignore_packages_by_scope,
        used_ignore_packages_by_scope,
        ignore_vulns,
        ignore_pkgs,
    )
    if not analysis.unused_ignore_ids and not analysis.unused_ignore_packages:
        return UnusedIgnorePolicyResult(status=final_status)
    if not any(current_config.fix for current_config in lock_to_config_map.values()):
        return UnusedIgnorePolicyResult(
            status=RunStatus.UNUSED_IGNORES_FOUND, analysis=analysis
        )

    fix_targets_by_source = _collect_fix_targets_by_source(
        analysis,
        lock_to_config_map,
        lock_to_config_source_map,
        ignore_vulns,
        ignore_pkgs,
    )
    try:
        (
            removed_vulnerability_ids_by_source,
            removed_package_names_by_source,
            modified_files,
        ) = await _apply_unused_ignore_fixes(fix_targets_by_source)
    except (OSError, PermissionError) as exc:
        return UnusedIgnorePolicyResult(
            status=RunStatus.RUNTIME_ERROR,
            fix_error_message=f"Failed applying --fix updates: {exc}",
        )

    _apply_removed_ignores_to_in_memory_configuration(
        lock_to_config_map,
        lock_to_config_source_map,
        removed_vulnerability_ids_by_source,
        removed_package_names_by_source,
    )
    post_fix_analysis = _analyze_unused_ignores(
        lock_to_config_map,
        lock_to_config_source_map,
        used_ignore_vulnerabilities_by_scope,
        matched_ignore_packages_by_scope,
        used_ignore_packages_by_scope,
        ignore_vulns,
        ignore_pkgs,
    )
    removed_vulnerability_count = sum(
        len(removed_ids) for removed_ids in removed_vulnerability_ids_by_source.values()
    )
    removed_package_count = sum(
        len(removed_names) for removed_names in removed_package_names_by_source.values()
    )
    if (
        not post_fix_analysis.unused_ignore_ids
        and not post_fix_analysis.unused_ignore_packages
    ):
        return UnusedIgnorePolicyResult(
            status=final_status,
            fixed_summary=(
                removed_vulnerability_count,
                removed_package_count,
                modified_files,
            ),
        )
    return UnusedIgnorePolicyResult(
        status=RunStatus.UNUSED_IGNORES_FOUND,
        analysis=post_fix_analysis,
        fixed_summary=(
            removed_vulnerability_count,
            removed_package_count,
            modified_files,
        ),
    )


def _apply_unused_ignore_policy_result(
    policy_result: UnusedIgnorePolicyResult,
    config: Configuration,
    scan_results: ScanResultsOutput,
    console: Console,
) -> RunStatus:
    final_status = policy_result.status
    if policy_result.fix_error_message is not None:
        if config.format.value == "json":
            scan_results.errors.append(
                ErrorOutput(code="fix_error", message=policy_result.fix_error_message)
            )
        else:
            console.print(f"[bold red]Error:[/] {policy_result.fix_error_message}")
    if policy_result.fixed_summary is not None and config.format.value != "json":
        removed_vulnerability_count, removed_package_count, modified_files = (
            policy_result.fixed_summary
        )
        if modified_files:
            console.print(
                "[green]Fixed:[/] removed "
                f"{removed_vulnerability_count} vulnerability ignore ID(s) and "
                f"{removed_package_count} package ignore entry(ies) from "
                f"{modified_files} config file(s)."
            )
    if (
        final_status == RunStatus.UNUSED_IGNORES_FOUND
        and policy_result.analysis is not None
    ):
        return _record_unused_ignore_error(
            config, scan_results, console, policy_result.analysis
        )
    return final_status


async def _resolve_file_paths_and_configs(
    file_paths: Sequence[Path] | None, config_path: Path | None
) -> tuple[tuple[APath, ...], dict[APath, Configuration], dict[APath, APath | None]]:
    file_apaths: tuple[APath, ...] = (
        (APath(),) if not file_paths else tuple(APath(file) for file in file_paths)
    )

    if len(file_apaths) == 1 and await file_apaths[0].is_dir():
        (
            lock_to_config_map,
            lock_to_config_source_map,
        ) = await get_dependency_file_and_source_maps(file_apaths[0])
        file_apaths = tuple(lock_to_config_map.keys())
    else:
        if config_path is not None:
            try:
                possible_config = await config_file_factory(APath(config_path))
            except UvSecureConfigurationError as exc:  # pragma: no cover - passthrough
                raise UvSecureConfigurationError(str(exc)) from exc
            config = possible_config if possible_config is not None else Configuration()
            lock_to_config_map = dict.fromkeys(file_apaths, config)
            lock_to_config_source_map = dict.fromkeys(
                file_apaths, APath(config_path) if possible_config is not None else None
            )
        elif all(
            file_path.name in {"pylock.toml", "requirements.txt", "uv.lock"}
            for file_path in file_apaths
        ):
            (
                lock_to_config_map,
                lock_to_config_source_map,
            ) = await get_dependency_files_and_source_maps(file_apaths)
            file_apaths = tuple(lock_to_config_map.keys())
        else:
            raise ValueError(
                "file_paths must either reference a single project root directory "
                "or a sequence of uv.lock / pylock.toml / requirements.txt file paths"
            )

    return file_apaths, lock_to_config_map, lock_to_config_source_map


def _apply_cli_config_overrides(
    lock_to_config_map: dict[APath, Configuration],
    aliases: bool | None,
    desc: bool | None,
    show_severity: bool | None,
    ignore_vulns: str | None,
    severity: SeverityLevel | None,
    ignore_unfixed: bool | None,
    allow_unused_ignores: bool | None,
    fix: bool | None,
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
    check_uv_secure: bool | None,
) -> dict[APath, Configuration]:
    if any(
        (
            aliases is not None,
            desc is not None,
            show_severity is not None,
            ignore_vulns,
            severity is not None,
            ignore_unfixed is not None,
            allow_unused_ignores is not None,
            fix is not None,
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
            check_uv_secure is not None,
        )
    ):
        cli_config = config_cli_arg_factory(
            aliases,
            check_direct_dependency_maintenance_issues_only,
            check_direct_dependency_vulnerabilities_only,
            desc,
            show_severity,
            severity,
            ignore_unfixed,
            allow_unused_ignores,
            fix,
            forbid_archived,
            forbid_deprecated,
            forbid_quarantined,
            forbid_yanked,
            max_package_age,
            ignore_vulns,
            ignore_pkgs,
            OutputFormat(format_type) if format_type else None,
            check_uv_tool,
            check_uv_secure,
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
) -> tuple[AsyncClient, CacheManager | None]:
    if disable_cache:
        return AsyncClient(timeout=10, headers=client_headers), None

    await APath(cache_path).mkdir(parents=True, exist_ok=True)
    cache_manager = CacheManager(cache_path, cache_ttl_seconds)
    await cache_manager.init()
    client = AsyncClient(timeout=10, headers=client_headers)
    return client, cache_manager


async def _evaluate_dependency_files(
    file_apaths: tuple[APath, ...],
    lock_to_config_map: dict[APath, Configuration],
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
) -> tuple[
    list[FileResultOutput],
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, set[str]],
]:
    uv_config = next(
        (config for config in lock_to_config_map.values() if config.check_uv_tool), None
    )
    uv_secure_config = next(
        (config for config in lock_to_config_map.values() if config.check_uv_secure),
        None,
    )
    used_ignore_vulnerabilities_by_scope: dict[str, set[str]] = {}
    matched_ignore_packages_by_scope: dict[str, set[str]] = {}
    used_ignore_packages_by_scope: dict[str, set[str]] = {}
    uv_task: asyncio.Task[FileResultOutput | None] | None = None
    uv_secure_task: asyncio.Task[FileResultOutput | None] | None = None
    if uv_config is not None:
        uv_used_ignore_vulnerabilities: set[str] = set()
        uv_matched_ignore_packages: set[str] = set()
        uv_used_ignore_packages: set[str] = set()
        used_ignore_vulnerabilities_by_scope[GLOBAL_UV_TOOL_LABEL] = (
            uv_used_ignore_vulnerabilities
        )
        matched_ignore_packages_by_scope[GLOBAL_UV_TOOL_LABEL] = (
            uv_matched_ignore_packages
        )
        used_ignore_packages_by_scope[GLOBAL_UV_TOOL_LABEL] = uv_used_ignore_packages
        uv_task = asyncio.create_task(
            check_global_uv_tool(
                uv_config,
                http_client,
                cache_manager,
                uv_used_ignore_vulnerabilities,
                uv_matched_ignore_packages,
                uv_used_ignore_packages,
            )
        )
    if uv_secure_config is not None:
        uv_secure_used_ignore_vulnerabilities: set[str] = set()
        uv_secure_matched_ignore_packages: set[str] = set()
        uv_secure_used_ignore_packages: set[str] = set()
        used_ignore_vulnerabilities_by_scope[GLOBAL_UV_SECURE_PACKAGE_LABEL] = (
            uv_secure_used_ignore_vulnerabilities
        )
        matched_ignore_packages_by_scope[GLOBAL_UV_SECURE_PACKAGE_LABEL] = (
            uv_secure_matched_ignore_packages
        )
        used_ignore_packages_by_scope[GLOBAL_UV_SECURE_PACKAGE_LABEL] = (
            uv_secure_used_ignore_packages
        )
        uv_secure_task = asyncio.create_task(
            check_installed_uv_secure_package(
                uv_secure_config,
                http_client,
                cache_manager,
                uv_secure_used_ignore_vulnerabilities,
                uv_secure_matched_ignore_packages,
                uv_secure_used_ignore_packages,
            )
        )

    used_ignore_vulnerabilities_for_dependency_files: list[set[str]] = [
        set() for _ in file_apaths
    ]
    used_ignore_packages_for_dependency_files: list[set[str]] = [
        set() for _ in file_apaths
    ]
    matched_ignore_packages_for_dependency_files: list[set[str]] = [
        set() for _ in file_apaths
    ]
    file_results = list(
        await asyncio.gather(
            *[
                check_dependencies(
                    dependency_file_path,
                    lock_to_config_map[APath(dependency_file_path)],
                    http_client,
                    cache_manager,
                    used_ignore_vulnerabilities_for_dependency_files[idx],
                    matched_ignore_packages_for_dependency_files[idx],
                    used_ignore_packages_for_dependency_files[idx],
                )
                for idx, dependency_file_path in enumerate(file_apaths)
            ]
        )
    )
    used_ignore_vulnerabilities_by_scope.update(
        {
            file_path.as_posix(): used_ignore_vulnerabilities_for_dependency_files[idx]
            for idx, file_path in enumerate(file_apaths)
        }
    )
    used_ignore_packages_by_scope.update(
        {
            file_path.as_posix(): used_ignore_packages_for_dependency_files[idx]
            for idx, file_path in enumerate(file_apaths)
        }
    )
    matched_ignore_packages_by_scope.update(
        {
            file_path.as_posix(): matched_ignore_packages_for_dependency_files[idx]
            for idx, file_path in enumerate(file_apaths)
        }
    )

    if uv_task is not None:
        uv_result = await uv_task
        if uv_result is not None:
            file_results.append(uv_result)
    if uv_secure_task is not None:
        uv_secure_result = await uv_secure_task
        if uv_secure_result is not None:
            file_results.append(uv_secure_result)

    return (
        file_results,
        used_ignore_vulnerabilities_by_scope,
        matched_ignore_packages_by_scope,
        used_ignore_packages_by_scope,
    )


async def check_lock_files(
    file_paths: Sequence[Path] | None,
    aliases: bool | None,
    desc: bool | None,
    show_severity: bool | None,
    cache_path: Path,
    cache_ttl_seconds: float,
    disable_cache: bool,
    forbid_archived: bool | None,
    forbid_deprecated: bool | None,
    forbid_quarantined: bool | None,
    forbid_yanked: bool | None,
    max_package_age: int | None,
    ignore_vulns: str | None,
    severity: SeverityLevel | None,
    ignore_unfixed: bool | None,
    allow_unused_ignores: bool | None,
    fix: bool | None,
    ignore_pkgs: list[str] | None,
    check_direct_dependency_vulnerabilities_only: bool | None,
    check_direct_dependency_maintenance_issues_only: bool | None,
    config_path: Path | None,
    format_type: str | None,
    check_uv_tool: bool | None,
    check_uv_secure: bool | None,
    user_agent: str,
) -> RunStatus:
    """Scan dependency files for vulnerabilities and maintenance issues.

    Returns:
        RunStatus: Final status for the scan invocation.
    """
    console = Console()

    try:
        (
            file_apaths,
            lock_to_config_map,
            lock_to_config_source_map,
        ) = await _resolve_file_paths_and_configs(file_paths, config_path)
    except ValueError:
        error_message = (
            "file_paths must either reference a single project root directory "
            "or a sequence of uv.lock / pylock.toml / requirements.txt file paths"
        )
        if format_type == OutputFormat.JSON.value:
            scan_results = ScanResultsOutput(
                errors=[ErrorOutput(code="invalid_file_paths", message=error_message)]
            )
            console.print(
                JsonFormatter().format(scan_results),
                soft_wrap=True,
                markup=False,
                highlight=False,
            )
        else:
            console.print(f"[bold red]Error:[/] {error_message}")
        return RunStatus.RUNTIME_ERROR

    lock_to_config_map = _apply_cli_config_overrides(
        lock_to_config_map,
        aliases,
        desc,
        show_severity,
        ignore_vulns,
        severity,
        ignore_unfixed,
        allow_unused_ignores,
        fix,
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
        check_uv_secure,
    )

    client_headers = Headers({"User-Agent": user_agent})
    http_client, cache_manager = await _build_http_client(
        cache_path, cache_ttl_seconds, disable_cache, client_headers
    )

    try:
        async with http_client:
            (
                file_results,
                used_ignore_vulnerabilities_by_scope,
                matched_ignore_packages_by_scope,
                used_ignore_packages_by_scope,
            ) = await _evaluate_dependency_files(
                file_apaths, lock_to_config_map, http_client, cache_manager
            )
    finally:
        if cache_manager is not None:
            await cache_manager.close()

    scan_results = ScanResultsOutput(files=file_results)
    config = next(iter(lock_to_config_map.values()))

    final_status = _determine_final_status(file_results)
    policy_result = await _evaluate_unused_ignore_policy(
        lock_to_config_map,
        lock_to_config_source_map,
        used_ignore_vulnerabilities_by_scope,
        matched_ignore_packages_by_scope,
        used_ignore_packages_by_scope,
        ignore_vulns,
        ignore_pkgs,
        final_status,
    )
    final_status = _apply_unused_ignore_policy_result(
        policy_result, config, scan_results, console
    )

    formatter: OutputFormatter
    if config.format.value == "json":
        formatter = JsonFormatter()
    else:
        formatter = ColumnsFormatter(config)

    output = formatter.format(scan_results)
    if config.format.value == "json":
        console.print(output, soft_wrap=True, markup=False, highlight=False)
    else:
        console.print(output)

    return final_status
