import sys

from anyio import Path
from pydantic import BaseModel
import stamina


if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


class Dependency(BaseModel):
    name: str
    version: str
    direct: bool | None = False


# Disable stamina retry hooks to silence retry warnings in the console
stamina.instrumentation.set_on_retry_hooks([])


@stamina.retry(on=Exception, attempts=3)
async def parse_pylock_toml_file(file_path: Path) -> list[Dependency]:
    """Parses a PEP751 pylock.toml file and extracts package PyPi dependencies"""
    data = await file_path.read_text()
    toml_data = toml.loads(data)
    dependencies = []
    packages = toml_data.get("packages", [])

    for package in packages:
        package_name = package.get("name")
        package_version = package.get("version")
        index = package.get("index", "")

        # Only include packages from PyPI registry
        if package_name and package_version and index == "https://pypi.org/simple":
            dependency = Dependency(
                name=package_name,
                version=package_version,
                direct=None,  # Cannot determine direct dependencies from pylock.toml
            )
            dependencies.append(dependency)

    return dependencies


@stamina.retry(on=Exception, attempts=3)
async def parse_requirements_txt_file(file_path: Path) -> list[Dependency]:
    """Parse a requirements.txt file and extracts package PyPi dependencies"""
    data = await file_path.read_text()
    lines = data.splitlines()
    if len(lines) == 0:
        return []
    dependencies = []
    dependency: Dependency | None = None
    for line in lines:
        if "==" in line:
            if dependency is not None:
                dependencies.append(dependency)
            if line.count("==") != 1:
                raise ValueError(
                    f"dependencies must be fully pinned, found: {line.strip()}"
                )
            name, version = line.split("==", 1)
            if "*" in version:
                raise ValueError(
                    f"dependencies must be fully pinned, found: {line.strip()}"
                )
            dependency = Dependency(name=name.strip(), version=version.strip())
        elif (" -r " in line or " (pyproject.toml)" in line) and dependency is not None:
            dependency.direct = True
        elif line.strip() and not line.strip().startswith("#"):
            raise ValueError(
                f"dependencies must be fully pinned, found: {line.strip()}"
            )
    if dependency is not None:
        dependencies.append(dependency)
    return dependencies


@stamina.retry(on=Exception, attempts=3)
async def parse_uv_lock_file(file_path: Path) -> list[Dependency]:
    """Parses a uv.lock TOML file and extracts package PyPi dependencies"""
    data = toml.loads(await file_path.read_text())

    direct_dependencies: set[str] = set()
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
                direct_dependencies.add(dependency["name"])
            dev_dependencies = package.get("dev-dependencies", {})
            for group_dependencies in dev_dependencies.values():
                for dependency in group_dependencies:
                    direct_dependencies.add(dependency["name"])

    dependency_list = list(dependencies.values())
    for dependency in dependency_list:
        dependency.direct = dependency.name in direct_dependencies
    return dependency_list
