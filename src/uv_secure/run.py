from pathlib import Path
from typing import Optional

import typer

from uv_secure.__version__ import __version__
from uv_secure.dependency_checker import check_dependencies


app = typer.Typer()


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"uv-secure {__version__}")
        raise typer.Exit()


_uv_lock_path_args = typer.Argument(None, help="Paths to the uv.lock files")


_ignore_option = typer.Option(
    "",
    "--ignore",
    "-i",
    help="Comma-separated list of vulnerability IDs to ignore, e.g. VULN-123,VULN-456",
)

_version_option = typer.Option(
    None,
    "--version",
    callback=version_callback,
    is_eager=True,
    help="Show the application's version",
)


@app.command()
def main(
    uv_lock_paths: Optional[list[Path]] = _uv_lock_path_args,
    ignore: str = _ignore_option,
    version: bool = _version_option,
) -> None:
    """Parse uv.lock files, check vulnerabilities, and display summary."""
    if not uv_lock_paths:
        uv_lock_paths = [Path("./uv.lock")]
    ignore_ids = [vuln_id.strip() for vuln_id in ignore.split(",") if vuln_id.strip()]

    for uv_lock_path in uv_lock_paths:
        status = check_dependencies(uv_lock_path, ignore_ids)
        if status != 0:
            raise typer.Exit(code=status)


if __name__ == "__main__":
    app()
