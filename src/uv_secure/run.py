import asyncio
from pathlib import Path
import re
import sys
from typing import Optional

import httpx
import inflect
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import typer

from uv_secure.__version__ import __version__


app = typer.Typer()

# Conditional import for toml
if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


class Dependency(BaseModel):
    name: str
    version: str


class Vulnerability(BaseModel):
    id: str
    details: str
    fixed_in: Optional[list[str]] = None
    aliases: Optional[list[str]] = None
    link: Optional[str] = None
    source: Optional[str] = None
    summary: Optional[str] = None
    withdrawn: Optional[str] = None


def parse_uv_lock_file(file_path: Path) -> list[Dependency]:
    """Parses a uv.lock TOML file and extracts package PyPi dependencies"""
    with file_path.open("rb") as f:
        data = toml.load(f)

    package_data = data.get("package", [])
    return [
        Dependency(name=package["name"], version=package["version"])
        for package in package_data
        if package.get("source", {}).get("registry") == "https://pypi.org/simple"
    ]


def canonicalize_name(name: str) -> str:
    """Converts a package name to its canonical form for PyPI URLs"""
    return re.sub(r"[_.]+", "-", name).lower()


async def fetch_vulnerabilities(
    client: httpx.AsyncClient, dependency: Dependency
) -> tuple[Dependency, list[Vulnerability]]:
    """Queries the PyPi JSON API for vulnerabilities of a given dependency."""
    canonical_name = canonicalize_name(dependency.name)
    url = f"https://pypi.org/pypi/{canonical_name}/{dependency.version}/json"
    try:
        response = await client.get(url)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = [
                Vulnerability(**v) for v in data.get("vulnerabilities", [])
            ]
            return dependency, vulnerabilities
        typer.echo(
            f"Warning: Could not fetch data for {dependency.name}=={dependency.version}"
        )
    except httpx.RequestError as e:
        typer.echo(f"Error fetching {dependency.name}=={dependency.version}: {e}")
    return dependency, []


async def check_all_vulnerabilities(
    dependencies: list[Dependency],
) -> list[tuple[Dependency, list[Vulnerability]]]:
    """Fetch vulnerabilities for all dependencies concurrently."""
    async with httpx.AsyncClient(timeout=10) as client:
        tasks = [fetch_vulnerabilities(client, dep) for dep in dependencies]
        return await asyncio.gather(*tasks)


def check_dependencies(uv_lock_path: Path, ignore_ids: list[str]) -> int:
    """Checks dependencies for vulnerabilities and summarizes the results."""
    console = Console()
    inf = inflect.engine()

    if not uv_lock_path.exists():
        console.print(f"[bold red]Error:[/] File {uv_lock_path} does not exist.")
        raise typer.Exit(1)

    dependencies = parse_uv_lock_file(uv_lock_path)
    console.print("[bold cyan]Checking dependencies for vulnerabilities...[/]")

    results = asyncio.run(check_all_vulnerabilities(dependencies))

    total_dependencies = len(results)
    vulnerable_count = 0
    vulnerabilities_found = []

    for dep, vulnerabilities in results:
        # Filter out ignored vulnerabilities
        filtered_vulnerabilities = [
            vuln for vuln in vulnerabilities if vuln.id not in ignore_ids
        ]
        if filtered_vulnerabilities:
            vulnerable_count += 1
            vulnerabilities_found.append((dep, filtered_vulnerabilities))

    inf = inflect.engine()
    total_plural = inf.plural("dependency", total_dependencies)
    vulnerable_plural = inf.plural("dependency", vulnerable_count)

    if vulnerable_count > 0:
        console.print(
            Panel.fit(
                f"[bold red]Vulnerabilities detected![/]\n"
                f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
                f"Vulnerable: [bold]{vulnerable_count}[/] {vulnerable_plural}"
            )
        )

        table = Table(
            title="Vulnerable Dependencies",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Package", style="dim", width=20)
        table.add_column("Version", style="dim", width=10)
        table.add_column("Vulnerability ID", style="bold cyan", width=25)
        table.add_column("Details", width=40)

        for dep, vulnerabilities in vulnerabilities_found:
            for vuln in vulnerabilities:
                vuln_id_hyperlink = (
                    Text.assemble((vuln.id, f"link {vuln.link}"))
                    if vuln.link
                    else Text(vuln.id)
                )
                table.add_row(dep.name, dep.version, vuln_id_hyperlink, vuln.details)

        console.print(table)
        return 1  # Exit with failure status

    console.print(
        Panel.fit(
            f"[bold green]No vulnerabilities detected![/]\n"
            f"Checked: [bold]{total_dependencies}[/] {total_plural}\n"
            f"All dependencies appear safe!"
        )
    )
    return 0  # Exit successfully


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"uv-secure {__version__}")
        raise typer.Exit()


_uv_lock_path_option = typer.Option(
    Path("./uv.lock"), "--uv-lock-path", "-p", help="Path to the uv.lock file"
)


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
    uv_lock_path: Path = _uv_lock_path_option,
    ignore: str = _ignore_option,
    version: bool = _version_option,
) -> int:
    """Parse a uv.lock file, check vulnerabilities, and display summary."""
    ignore_ids = [vuln_id.strip() for vuln_id in ignore.split(",") if vuln_id.strip()]
    return check_dependencies(uv_lock_path, ignore_ids)


if __name__ == "__main__":
    app()
