import sys
from typing import Optional

from anyio import Path
from pydantic import BaseModel
import typer


if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


class Dependency(BaseModel):
    name: str
    version: str
    first_order: bool = False


async def parse_requirements_txt_file(file_path: Path) -> list[Dependency]:
    """Parse a requirements.txt file and extracts package PyPi dependencies"""
    data = await file_path.read_text()
    lines = data.splitlines()
    if (
        len(lines) == 0
        or lines[0].strip()
        != "# This file was autogenerated by uv via the following command:"
    ):
        typer.echo(
            f"Ignoring {file_path} as it doesn't appear to be a uv generated "
            "requirements.txt file"
        )
        return []
    dependencies = []
    dependency: Optional[Dependency] = None
    for line in lines:
        if "==" in line:
            if dependency is not None:
                dependencies.append(dependency)
                dependency = None
            name, version = line.split("==")
            dependency = Dependency(name=name.strip(), version=version.strip())
        elif (" -r " in line or " (pyproject.toml)" in line) and dependency is not None:
            dependency.first_order = True
    if dependency is not None:
        dependencies.append(dependency)
    return dependencies


async def parse_uv_lock_file(file_path: Path) -> list[Dependency]:
    """Parses a uv.lock TOML file and extracts package PyPi dependencies"""
    data = toml.loads(await file_path.read_text())

    first_order_dependencies: set[str] = set()
    dependencies = {}
    package_data = data.get("package", [])
    for package in package_data:
        source = package.get("source", {})
        if source.get("registry") == "https://pypi.org/simple":
            dependencies[package["name"]] = Dependency(
                name=package["name"], version=package["version"]
            )
        elif source.get("editable") == "." or source.get("virtual") == ".":
            for dependency in package.get("dependencies", []):
                first_order_dependencies.add(dependency["name"])
            dev_dependencies = package.get("dev-dependencies", {})
            for group_dependencies in dev_dependencies.values():
                for dependency in group_dependencies:
                    first_order_dependencies.add(dependency["name"])

    dependency_list = list(dependencies.values())
    for dependency in dependency_list:
        dependency.first_order = dependency.name in first_order_dependencies
    return dependency_list
