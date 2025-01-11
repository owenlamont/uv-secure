from pathlib import Path
import sys
from typing import Optional

import typer

from uv_secure.__version__ import __version__
from uv_secure.dependency_checker import check_lock_files, RunStatus


if sys.platform in ("win32", "cygwin", "cli"):
    from winloop import run
else:
    from uvloop import run
# from asyncio import run  # uncomment for local dev and debugging


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


_ignore_option = typer.Option(
    None,
    "--ignore",
    "-i",
    help="Comma-separated list of vulnerability IDs to ignore, e.g. VULN-123,VULN-456",
)

_version_option = typer.Option(
    None,
    "--version",
    callback=_version_callback,
    is_eager=True,
    help="Show the application's version",
)

_config_option = typer.Option(
    None,
    "--config",
    help=(
        "Optional path to a configuration file (uv-secure.toml, .uv-secure.toml, or "
        "pyproject.toml)"
    ),
)


@app.command()
def main(
    file_paths: Optional[list[Path]] = _file_path_args,
    aliases: Optional[bool] = _aliases_option,
    desc: Optional[bool] = _desc_option,
    ignore: Optional[str] = _ignore_option,
    config_path: Optional[Path] = _config_option,
    version: bool = _version_option,
) -> None:
    """Parse uv.lock files, check vulnerabilities, and display summary."""
    run_status = run(check_lock_files(file_paths, aliases, desc, ignore, config_path))
    if run_status == RunStatus.VULNERABILITIES_FOUND:
        raise typer.Exit(code=1)
    if run_status == RunStatus.RUNTIME_ERROR:
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()  # pragma: no cover
