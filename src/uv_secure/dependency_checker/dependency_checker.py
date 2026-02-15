from collections.abc import Sequence
from pathlib import Path

from uv_secure import __version__
from uv_secure.configuration import SeverityLevel
from uv_secure.dependency_checker.file_checker import check_dependencies
from uv_secure.dependency_checker.scan_runner import (
    check_lock_files as run_lock_file_scan,
)
from uv_secure.dependency_checker.status import RunStatus


USER_AGENT = f"uv-secure/{__version__} (contact: owenrlamont@gmail.com)"


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
    ignore_pkgs: list[str] | None,
    check_direct_dependency_vulnerabilities_only: bool | None,
    check_direct_dependency_maintenance_issues_only: bool | None,
    config_path: Path | None,
    format_type: str | None,
    check_uv_tool: bool | None,
    check_uv_secure: bool | None,
) -> RunStatus:
    """Scan dependency files for vulnerabilities and maintenance issues.

    Returns:
        RunStatus: Final scanner status.
    """

    return await run_lock_file_scan(
        file_paths=file_paths,
        aliases=aliases,
        desc=desc,
        show_severity=show_severity,
        cache_path=cache_path,
        cache_ttl_seconds=cache_ttl_seconds,
        disable_cache=disable_cache,
        forbid_archived=forbid_archived,
        forbid_deprecated=forbid_deprecated,
        forbid_quarantined=forbid_quarantined,
        forbid_yanked=forbid_yanked,
        max_package_age=max_package_age,
        ignore_vulns=ignore_vulns,
        severity=severity,
        ignore_unfixed=ignore_unfixed,
        allow_unused_ignores=allow_unused_ignores,
        ignore_pkgs=ignore_pkgs,
        check_direct_dependency_vulnerabilities_only=(
            check_direct_dependency_vulnerabilities_only
        ),
        check_direct_dependency_maintenance_issues_only=(
            check_direct_dependency_maintenance_issues_only
        ),
        config_path=config_path,
        format_type=format_type,
        check_uv_tool=check_uv_tool,
        check_uv_secure=check_uv_secure,
        user_agent=USER_AGENT,
    )


__all__ = ["USER_AGENT", "RunStatus", "check_dependencies", "check_lock_files"]
