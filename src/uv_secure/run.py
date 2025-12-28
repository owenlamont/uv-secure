from pathlib import Path
import sys

import typer

from uv_secure import __version__
from uv_secure.configuration import OutputFormat
from uv_secure.configuration.exceptions import UvSecureConfigurationError
from uv_secure.dependency_checker import check_lock_files, RunStatus


DEFAULT_HTTPX_CACHE_TTL_SECONDS = 24.0 * 60.0 * 60.0


app = typer.Typer()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"uv-secure {__version__}")
        raise typer.Exit()


_file_path_args = typer.Argument(
    None,
    help=(
        "Paths to the uv.lock, PEP751 pylock.toml, or requirements.txt files "
        "or a single project root level directory (defaults to working directory "
        "if not set)"
    ),
)


_aliases_option = typer.Option(
    None,
    "--aliases",
    help="Flag whether to include vulnerability aliases in the vulnerabilities table",
)


_desc_option = typer.Option(
    None,
    "--desc",
    help=(
        "Flag whether to include vulnerability detailed description in the "
        "vulnerabilities table"
    ),
)

_cache_path_option = typer.Option(
    Path.home() / ".cache/uv-secure",
    "--cache-path",
    help="Path to the cache directory for vulnerability http requests",
    show_default="~/.cache/uv-secure",
)

_cache_ttl_seconds_option = typer.Option(
    DEFAULT_HTTPX_CACHE_TTL_SECONDS,
    "--cache-ttl-seconds",
    help="Time to live in seconds for the vulnerability http requests cache",
)

_disable_cache_option = typer.Option(
    False,
    "--disable-cache",
    help="Flag whether to disable caching for vulnerability http requests",
)

_forbid_archived_option = typer.Option(
    None,
    "--forbid-archived",
    help="Flag whether disallow archived package versions from being dependencies",
)

_forbid_deprecated_option = typer.Option(
    None,
    "--forbid-deprecated",
    help="Flag whether disallow deprecated package versions from being dependencies",
)

_forbid_quarantined_option = typer.Option(
    None,
    "--forbid-quarantined",
    help="Flag whether disallow quarantined package versions from being dependencies",
)

_forbid_yanked_option = typer.Option(
    None,
    "--forbid-yanked",
    help="Flag whether disallow yanked package versions from being dependencies",
)

_check_direct_dependency_vulnerabilities_only_option = typer.Option(
    None,
    "--check-direct-dependency-vulnerabilities-only",
    help="Flag whether to only test only direct dependencies for vulnerabilities",
)

_check_direct_dependency_maintenance_issues_only_option = typer.Option(
    None,
    "--check-direct-dependency-maintenance-issues-only",
    help="Flag whether to only test only direct dependencies for maintenance issues",
)

_max_package_age_option = typer.Option(
    None, "--max-age-days", help="Maximum age threshold for packages in days"
)

_ignore_vulns_option = typer.Option(
    None,
    "--ignore-vulns",
    help=(
        "Comma-separated list of vulnerability IDs or aliases to ignore, e.g. "
        "VULN-123,CVE-2024-12345"
    ),
)

_config_option = typer.Option(
    None,
    "--config",
    help=(
        "Optional path to a configuration file (uv-secure.toml, .uv-secure.toml, or "
        "pyproject.toml)"
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
        "Dependency with optional version specifiers. "
        "Syntax: name:spec1|spec2|…  "
        "e.g. foo:>=1.0,<1.5|==4.5.*"
    ),
)


_format_option = typer.Option(
    None,
    "--format",
    help=(
        "Output format: 'columns' for table output (default) or 'json' for JSON output"
    ),
)

_check_uv_tool_option = typer.Option(
    None,
    "--check-uv-tool/--no-check-uv-tool",
    help=(
        "Enable or disable scanning the globally installed uv CLI for vulnerabilities"
        " (enabled by default)"
    ),
)


@app.command()
def main(
    file_paths: list[Path] | None = _file_path_args,
    aliases: bool | None = _aliases_option,
    desc: bool | None = _desc_option,
    cache_path: Path = _cache_path_option,
    cache_ttl_seconds: float = _cache_ttl_seconds_option,
    disable_cache: bool = _disable_cache_option,
    forbid_archived: bool | None = _forbid_archived_option,
    forbid_deprecated: bool | None = _forbid_deprecated_option,
    forbid_quarantined: bool | None = _forbid_quarantined_option,
    forbid_yanked: bool | None = _forbid_yanked_option,
    max_package_age: int | None = _max_package_age_option,
    ignore_vulns: str | None = _ignore_vulns_option,
    ignore_pkgs: list[str] | None = _ignore_pkg_options,
    check_direct_dependency_vulnerabilities_only: bool
    | None = _check_direct_dependency_vulnerabilities_only_option,
    check_direct_dependency_maintenance_issues_only: bool
    | None = _check_direct_dependency_maintenance_issues_only_option,
    config_path: Path | None = _config_option,
    version: bool = _version_option,
    format_type: OutputFormat | None = _format_option,
    check_uv_tool: bool | None = _check_uv_tool_option,
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
                cache_path,
                cache_ttl_seconds,
                disable_cache,
                forbid_archived,
                forbid_deprecated,
                forbid_quarantined,
                forbid_yanked,
                max_package_age,
                ignore_vulns,
                ignore_pkgs,
                check_direct_dependency_vulnerabilities_only,
                check_direct_dependency_maintenance_issues_only,
                config_path,
                format_type.value if format_type is not None else None,
                check_uv_tool,
            )
        )
    except UvSecureConfigurationError as exc:
        typer.echo(f"Error: {exc}")
        raise typer.Exit(code=3) from exc
    if run_status == RunStatus.MAINTENANCE_ISSUES_FOUND:
        raise typer.Exit(code=1)
    if run_status == RunStatus.VULNERABILITIES_FOUND:
        raise typer.Exit(code=2)
    if run_status == RunStatus.RUNTIME_ERROR:
        raise typer.Exit(code=3)


if __name__ == "__main__":
    app()  # pragma: no cover
