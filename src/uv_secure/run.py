from pathlib import Path
import sys

import typer

from uv_secure import __version__
from uv_secure.configuration import OutputFormat, SeverityLevel
from uv_secure.configuration.exceptions import UvSecureConfigurationError
from uv_secure.dependency_checker import check_lock_files, RunStatus
from uv_secure.output_formatters import JsonFormatter
from uv_secure.output_models import ErrorOutput, ScanResultsOutput


DEFAULT_HTTPX_CACHE_TTL_SECONDS = 24.0 * 60.0 * 60.0


app = typer.Typer()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"uv-secure {__version__}")
        raise typer.Exit()


_file_path_args = typer.Argument(
    None,
    help=(
        "One or more dependency files (uv.lock, pylock.toml, requirements.txt), "
        "or a single project root directory. Defaults to the current working "
        "directory when omitted."
    ),
)


_aliases_option = typer.Option(
    None,
    "--aliases/--no-aliases",
    help="Enable or disable vulnerability aliases in output.",
)


_desc_option = typer.Option(
    None,
    "--desc/--no-desc",
    help="Enable or disable vulnerability descriptions in output.",
)

_show_severity_option = typer.Option(
    None,
    "--show-severity/--no-show-severity",
    help="Enable or disable severity values in columns output.",
)

_cache_path_option = typer.Option(
    Path.home() / ".cache/uv-secure",
    "--cache-path",
    help="Directory for cached HTTP responses.",
    show_default="~/.cache/uv-secure",
)

_cache_ttl_seconds_option = typer.Option(
    DEFAULT_HTTPX_CACHE_TTL_SECONDS,
    "--cache-ttl-seconds",
    help=(
        "Cache TTL in seconds for HTTP responses. Ignored when --disable-cache is set."
    ),
)

_disable_cache_option = typer.Option(
    False, "--disable-cache", help="Disable the HTTP cache for this run."
)

_forbid_archived_option = typer.Option(
    None, "--forbid-archived", help="Report archived packages as maintenance issues."
)

_forbid_deprecated_option = typer.Option(
    None,
    "--forbid-deprecated",
    help="Report deprecated packages as maintenance issues.",
)

_forbid_quarantined_option = typer.Option(
    None,
    "--forbid-quarantined",
    help="Report quarantined packages as maintenance issues.",
)

_forbid_yanked_option = typer.Option(
    None, "--forbid-yanked", help="Report yanked packages as maintenance issues."
)

_check_direct_dependency_vulnerabilities_only_option = typer.Option(
    None,
    "--check-direct-dependency-vulnerabilities-only",
    help="Only scan direct dependencies for vulnerabilities.",
)

_check_direct_dependency_maintenance_issues_only_option = typer.Option(
    None,
    "--check-direct-dependency-maintenance-issues-only",
    help="Only scan direct dependencies for maintenance issues.",
)

_max_package_age_option = typer.Option(
    None,
    "--max-age-days",
    help="Report a maintenance issue when package age exceeds this many days.",
)

_ignore_vulns_option = typer.Option(
    None,
    "--ignore-vulns",
    help=(
        "Comma-separated vulnerability IDs and/or aliases to suppress, e.g. "
        "VULN-123,CVE-2024-12345."
    ),
)

_severity_option = typer.Option(
    None,
    "--severity",
    help=(
        "Only include vulnerabilities at or above this severity "
        "(low/medium/high/critical). Vulnerabilities with unknown severity are "
        "still included."
    ),
)

_ignore_unfixed_option = typer.Option(
    None,
    "--ignore-unfixed",
    help="Ignore vulnerabilities that have no known fix version.",
)

_allow_unused_ignores_option = typer.Option(
    None,
    "--allow-unused-ignores",
    help=(
        "Allow ignore-vulns and ignore-pkgs entries that are unused in this run "
        "(no matching target or no suppressed findings)."
    ),
)

_fix_option = typer.Option(
    None,
    "--fix/--no-fix",
    help="Apply safe automatic fixes for unused ignore entries in TOML config files.",
)

_config_option = typer.Option(
    None,
    "--config",
    help=(
        "Path to a configuration file (uv-secure.toml, .uv-secure.toml, or "
        "pyproject.toml). CLI options override config values."
    ),
)

_version_option = typer.Option(
    None,
    "--version",
    callback=_version_callback,
    is_eager=True,
    help="Show the application version",
)


_ignore_pkg_options = typer.Option(
    None,
    "--ignore-pkgs",
    metavar="PKG:SPEC1|SPEC2|…",
    help=(
        "Suppress vulnerabilities and maintenance issues for matching packages. "
        "Syntax: name or name:spec1|spec2|…  "
        "e.g. foo or foo:>=1.0,<1.5|==4.5.*"
    ),
)


_format_option = typer.Option(
    None, "--format", help=("Output format: columns (default) or json.")
)

_check_uv_tool_option = typer.Option(
    None,
    "--check-uv-tool/--no-check-uv-tool",
    help=(
        "Enable or disable scanning the globally installed uv CLI (enabled by default)."
    ),
)

_check_uv_secure_option = typer.Option(
    None,
    "--check-uv-secure/--no-check-uv-secure",
    help=(
        "Enable or disable scanning the installed uv-secure package "
        "(enabled by default)."
    ),
)


@app.command()
def main(
    file_paths: list[Path] | None = _file_path_args,
    aliases: bool | None = _aliases_option,
    desc: bool | None = _desc_option,
    show_severity: bool | None = _show_severity_option,
    cache_path: Path = _cache_path_option,
    cache_ttl_seconds: float = _cache_ttl_seconds_option,
    disable_cache: bool = _disable_cache_option,
    forbid_archived: bool | None = _forbid_archived_option,
    forbid_deprecated: bool | None = _forbid_deprecated_option,
    forbid_quarantined: bool | None = _forbid_quarantined_option,
    forbid_yanked: bool | None = _forbid_yanked_option,
    max_package_age: int | None = _max_package_age_option,
    ignore_vulns: str | None = _ignore_vulns_option,
    severity: SeverityLevel | None = _severity_option,
    ignore_unfixed: bool | None = _ignore_unfixed_option,
    allow_unused_ignores: bool | None = _allow_unused_ignores_option,
    fix: bool | None = _fix_option,
    ignore_pkgs: list[str] | None = _ignore_pkg_options,
    check_direct_dependency_vulnerabilities_only: bool
    | None = _check_direct_dependency_vulnerabilities_only_option,
    check_direct_dependency_maintenance_issues_only: bool
    | None = _check_direct_dependency_maintenance_issues_only_option,
    config_path: Path | None = _config_option,
    version: bool = _version_option,
    format_type: OutputFormat | None = _format_option,
    check_uv_tool: bool | None = _check_uv_tool_option,
    check_uv_secure: bool | None = _check_uv_secure_option,
) -> None:
    """Parse dependency manifests and display vulnerability summaries."""  # noqa: DOC501
    # Use uvloop or winloop if present
    try:
        if sys.platform in {"win32", "cygwin", "cli"}:
            from winloop import run  # ty: ignore[unresolved-import]
        else:
            from uvloop import run  # ty: ignore[unresolved-import]
    except ImportError:
        from asyncio import run

    try:
        run_status = run(
            check_lock_files(
                file_paths,
                aliases,
                desc,
                show_severity,
                cache_path,
                cache_ttl_seconds,
                disable_cache,
                forbid_archived,
                forbid_deprecated,
                forbid_quarantined,
                forbid_yanked,
                max_package_age,
                ignore_vulns,
                severity,
                ignore_unfixed,
                allow_unused_ignores,
                fix,
                ignore_pkgs,
                check_direct_dependency_vulnerabilities_only,
                check_direct_dependency_maintenance_issues_only,
                config_path,
                format_type.value if format_type is not None else None,
                check_uv_tool,
                check_uv_secure,
            )
        )
    except UvSecureConfigurationError as exc:
        if format_type == OutputFormat.JSON:
            scan_results = ScanResultsOutput(
                errors=[ErrorOutput(code="configuration_error", message=str(exc))]
            )
            typer.echo(JsonFormatter().format(scan_results))
        else:
            typer.echo(f"Error: {exc}")
        raise typer.Exit(code=3) from exc
    if run_status == RunStatus.MAINTENANCE_ISSUES_FOUND:
        raise typer.Exit(code=1)
    if run_status == RunStatus.VULNERABILITIES_FOUND:
        raise typer.Exit(code=2)
    if run_status == RunStatus.RUNTIME_ERROR:
        raise typer.Exit(code=3)
    if run_status == RunStatus.UNUSED_IGNORES_FOUND:
        raise typer.Exit(code=4)


if __name__ == "__main__":
    app()  # pragma: no cover
