import asyncio
from collections.abc import Sequence
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
from uv_secure.dependency_checker.file_checker import check_dependencies
from uv_secure.dependency_checker.status import RunStatus
from uv_secure.dependency_checker.tool_audit import (
    check_global_uv_tool,
    check_installed_uv_secure_package,
    GLOBAL_UV_SECURE_PACKAGE_LABEL,
    GLOBAL_UV_TOOL_LABEL,
)
from uv_secure.directory_scanner import get_dependency_file_to_config_map
from uv_secure.directory_scanner.directory_scanner import (
    get_dependency_files_to_config_map,
)
from uv_secure.output_formatters import ColumnsFormatter, JsonFormatter, OutputFormatter
from uv_secure.output_models import FileResultOutput, ScanResultsOutput


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
    unused_ignore_ids: set[str] = set()
    for dependency_file_path, config in lock_to_config_map.items():
        if config.vulnerability_criteria.allow_unused_ignores:
            continue
        configured_ignore_ids = config.vulnerability_criteria.ignore_vulnerabilities
        if not configured_ignore_ids:
            continue
        used_for_scope = used_ignore_vulnerabilities_by_scope.get(
            dependency_file_path.as_posix(), set()
        )
        unused_ignore_ids.update(configured_ignore_ids - used_for_scope)

    return unused_ignore_ids


async def _resolve_file_paths_and_configs(
    file_paths: Sequence[Path] | None, config_path: Path | None
) -> tuple[tuple[APath, ...], dict[APath, Configuration]]:
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
    severity: SeverityLevel | None,
    ignore_unfixed: bool | None,
    allow_unused_ignores: bool | None,
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
            aliases,
            desc,
            ignore_vulns,
            severity is not None,
            ignore_unfixed is not None,
            allow_unused_ignores is not None,
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
            severity,
            ignore_unfixed,
            allow_unused_ignores,
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
) -> tuple[list[FileResultOutput], dict[str, set[str]]]:
    uv_config = next(
        (config for config in lock_to_config_map.values() if config.check_uv_tool), None
    )
    uv_secure_config = next(
        (config for config in lock_to_config_map.values() if config.check_uv_secure),
        None,
    )
    used_ignore_vulnerabilities_by_scope: dict[str, set[str]] = {}
    uv_task: asyncio.Task[FileResultOutput | None] | None = None
    uv_secure_task: asyncio.Task[FileResultOutput | None] | None = None
    if uv_config is not None:
        uv_used_ignore_vulnerabilities: set[str] = set()
        used_ignore_vulnerabilities_by_scope[GLOBAL_UV_TOOL_LABEL] = (
            uv_used_ignore_vulnerabilities
        )
        uv_task = asyncio.create_task(
            check_global_uv_tool(
                uv_config, http_client, cache_manager, uv_used_ignore_vulnerabilities
            )
        )
    if uv_secure_config is not None:
        uv_secure_used_ignore_vulnerabilities: set[str] = set()
        used_ignore_vulnerabilities_by_scope[GLOBAL_UV_SECURE_PACKAGE_LABEL] = (
            uv_secure_used_ignore_vulnerabilities
        )
        uv_secure_task = asyncio.create_task(
            check_installed_uv_secure_package(
                uv_secure_config,
                http_client,
                cache_manager,
                uv_secure_used_ignore_vulnerabilities,
            )
        )

    used_ignore_vulnerabilities_for_dependency_files: list[set[str]] = [
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

    if uv_task is not None:
        uv_result = await uv_task
        if uv_result is not None:
            file_results.append(uv_result)
    if uv_secure_task is not None:
        uv_secure_result = await uv_secure_task
        if uv_secure_result is not None:
            file_results.append(uv_secure_result)

    return file_results, used_ignore_vulnerabilities_by_scope


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
    severity: SeverityLevel | None,
    ignore_unfixed: bool | None,
    allow_unused_ignores: bool | None,
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
        severity,
        ignore_unfixed,
        allow_unused_ignores,
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
            ) = await _evaluate_dependency_files(
                file_apaths, lock_to_config_map, http_client, cache_manager
            )
    finally:
        if cache_manager is not None:
            await cache_manager.close()

    scan_results = ScanResultsOutput(files=file_results)
    config = next(iter(lock_to_config_map.values()))

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

    final_status = _determine_final_status(file_results)
    if final_status == RunStatus.RUNTIME_ERROR:
        return final_status

    unused_ignore_ids = _find_unused_ignore_vulnerability_ids(
        lock_to_config_map, used_ignore_vulnerabilities_by_scope
    )
    if unused_ignore_ids:
        unused_ignore_display = ", ".join(sorted(unused_ignore_ids))
        console.print(
            "[bold red]Error:[/] Found unused vulnerability ignore IDs: "
            f"{unused_ignore_display}"
        )
        return RunStatus.UNUSED_IGNORES_FOUND

    return final_status
