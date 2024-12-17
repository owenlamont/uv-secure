import asyncio
from pathlib import Path
import re
import sys
from typing import Optional

import httpx
from pydantic import BaseModel
import typer


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


def check_dependencies(uv_lock_path: Path) -> None:
    if not uv_lock_path.exists():
        typer.echo(f"Error: File {uv_lock_path} does not exist.")
        raise typer.Exit(1)
    dependencies = parse_uv_lock_file(uv_lock_path)
    typer.echo("Checking dependencies for vulnerabilities...")
    results = asyncio.run(check_all_vulnerabilities(dependencies))
    for dep, vulnerabilities in results:
        if vulnerabilities:
            typer.echo(f"Vulnerabilities found for {dep.name}=={dep.version}:")
            for vuln in vulnerabilities:
                fixed_in = (
                    ", ".join(vuln.fixed_in) if vuln.fixed_in else "Not specified"
                )
                typer.echo(f"- {vuln.id}: {vuln.details} (Fixed in: {fixed_in})")
                typer.echo(f"  Source: {vuln.source}, Link: {vuln.link}")
        else:
            typer.echo(f"No known vulnerabilities for {dep.name}=={dep.version}")


@app.command()
def main(uv_lock_path: Path) -> None:
    """Parse a uv.lock file and list its dependencies"""
    check_dependencies(uv_lock_path)


if __name__ == "__main__":
    app()
