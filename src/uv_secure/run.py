from pathlib import Path
import sys
from typing import Optional

import typer

from uv_secure.__version__ import __version__
from uv_secure.dependency_checker import check_lock_files, RunStatus


app = typer.Typer()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"uv-secure {__version__}")
        raise typer.Exit()


_file_path_args = typer.Argument(
    None,
    help=(
        "Paths to the uv.lock or uv generated requirements.txt files or a single "
        "project root level directory (defaults to working directory if not set)"
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

_disable_cache_option = typer.Option(
    None,
    "--disable-cache",
    help="Flag whether to disable caching for vulnerability http requests",
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

_ignore_option = typer.Option(
    None,
    "--ignore",
    "-i",
    help="Comma-separated list of vulnerability IDs to ignore, e.g. VULN-123,VULN-456",
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
    help="Show the application's version",
)


@app.command()
def main(
    file_paths: Optional[list[Path]] = _file_path_args,
    aliases: Optional[bool] = _aliases_option,
    desc: Optional[bool] = _desc_option,
    disable_cache: Optional[bool] = _disable_cache_option,
    forbid_yanked: Optional[bool] = _forbid_yanked_option,
    max_package_age: Optional[int] = _max_package_age_option,
    ignore: Optional[str] = _ignore_option,
    check_direct_dependency_vulnerabilities_only: Optional[
        bool
    ] = _check_direct_dependency_vulnerabilities_only_option,
    check_direct_dependency_maintenance_issues_only: Optional[
        bool
    ] = _check_direct_dependency_maintenance_issues_only_option,
    config_path: Optional[Path] = _config_option,
    version: bool = _version_option,
) -> None:
    """Parse uv.lock files, check vulnerabilities, and display summary."""

    # Use uvloop or winloop if present
    try:
        if sys.platform in {"win32", "cygwin", "cli"}:
            from winloop import run
        else:
            from uvloop import run
    except ImportError:
        from asyncio import run

    run_status = run(
        check_lock_files(
            file_paths,
            aliases,
            desc,
            disable_cache,
            forbid_yanked,
            max_package_age,
            ignore,
            check_direct_dependency_vulnerabilities_only,
            check_direct_dependency_maintenance_issues_only,
            config_path,
        )
    )
    if run_status == RunStatus.MAINTENANCE_ISSUES_FOUND:
        raise typer.Exit(code=1)
    if run_status == RunStatus.VULNERABILITIES_FOUND:
        raise typer.Exit(code=2)
    if run_status == RunStatus.RUNTIME_ERROR:
        raise typer.Exit(code=3)


if __name__ == "__main__":
    app()  # pragma: no cover
