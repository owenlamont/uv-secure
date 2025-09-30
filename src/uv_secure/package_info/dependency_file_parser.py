import sys

from anyio import Path
from packaging.requirements import Requirement
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


class ParseResult(BaseModel):
    dependencies: list[Dependency]
    ignored_count: int
    file_path: str | None = None
    error: str | None = None


# Disable stamina retry hooks to silence retry warnings in the console
stamina.instrumentation.set_on_retry_hooks([])


@stamina.retry(on=Exception, attempts=3)
async def parse_pylock_toml_file(file_path: Path) -> ParseResult:
    """Parses a PEP751 pylock.toml file and extracts package PyPi dependencies"""
    data = await file_path.read_text()
    toml_data = toml.loads(data)
    dependencies = []
    ignored_count = 0
    packages = toml_data.get("packages", [])

    for package in packages:
        package_name = package.get("name")
        package_version = package.get("version")
        index = package.get("index", "")

        if package_name and package_version:
            if index == "https://pypi.org/simple":
                # Only include packages from PyPI registry
                # Cannot determine direct dependencies from pylock.toml
                dependency = Dependency(
                    name=package_name, version=package_version, direct=None
                )
                dependencies.append(dependency)
            else:
                # Count non-PyPI packages as ignored
                ignored_count += 1

    return ParseResult(dependencies=dependencies, ignored_count=ignored_count)


def _validate_requirement_line(line: str, requirement: Requirement) -> None:
    """Validate that a requirement line is properly pinned"""
    stripped = line.strip()

    if requirement.marker is not None or requirement.url is not None:
        raise ValueError(f"dependencies must be fully pinned, found: {stripped}")

    specifiers = list(requirement.specifier)
    if (
        len(specifiers) != 1
        or specifiers[0].operator != "=="
        or "*" in specifiers[0].version
    ):
        raise ValueError(f"dependencies must be fully pinned, found: {stripped}")


def _parse_requirement_line(line: str) -> Requirement | None:
    """Parse a single requirement line and return Requirement object if valid"""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    requirement_str = line.split("#", 1)[0].strip()
    try:
        requirement = Requirement(requirement_str)
    except Exception as exc:  # pragma: no cover - packaging raises various errors
        raise ValueError(
            f"dependencies must be fully pinned, found: {stripped}"
        ) from exc

    _validate_requirement_line(line, requirement)
    return requirement


def _is_direct_dependency_marker(line: str) -> bool:
    """Check if line contains markers indicating direct dependencies"""
    return " -r " in line or " (pyproject.toml)" in line


@stamina.retry(on=Exception, attempts=3)
async def parse_requirements_txt_file(file_path: Path) -> ParseResult:
    """Parse a requirements.txt file and extracts package PyPi dependencies"""
    data = await file_path.read_text()
    lines = data.splitlines()
    if len(lines) == 0:
        return ParseResult(dependencies=[], ignored_count=0)

    dependencies: list[Dependency] = []
    dependency: Dependency | None = None

    for line in lines:
        if _is_direct_dependency_marker(line) and dependency is not None:
            dependency.direct = True
            continue

        requirement = _parse_requirement_line(line)
        if requirement is None:
            continue

        if dependency is not None:
            dependencies.append(dependency)

        specifiers = list(requirement.specifier)
        dependency = Dependency(name=requirement.name, version=specifiers[0].version)

    if dependency is not None:
        dependencies.append(dependency)

    return ParseResult(dependencies=dependencies, ignored_count=0)


def _extract_direct_dependencies_from_package(package: dict) -> set[str]:
    """Extract direct dependencies from a package with editable/virtual source"""
    direct_dependencies: set[str] = set()

    for dependency in package.get("dependencies", []):
        direct_dependencies.add(dependency["name"])

    dev_dependencies = package.get("dev-dependencies", {})
    for group_dependencies in dev_dependencies.values():
        for dependency in group_dependencies:
            direct_dependencies.add(dependency["name"])

    return direct_dependencies


def _process_uv_lock_package(
    package: dict, dependencies: dict[str, Dependency], direct_dependencies: set[str]
) -> int:
    """Process a single package from uv.lock and return ignored count"""
    source = package.get("source", {})

    if source.get("registry") == "https://pypi.org/simple":
        dependencies[package["name"]] = Dependency(
            name=package["name"], version=package["version"]
        )
        return 0
    if source.get("editable") == "." or source.get("virtual") == ".":
        extracted_deps = _extract_direct_dependencies_from_package(package)
        direct_dependencies.update(extracted_deps)
        return 0
    # Count non-PyPI packages as ignored (has a source but not PyPI)
    return 1 if "name" in package else 0


def _mark_direct_dependencies(
    dependencies: dict[str, Dependency], direct_dependencies: set[str]
) -> list[Dependency]:
    """Mark dependencies as direct and return as list"""
    dependency_list = list(dependencies.values())
    for dependency in dependency_list:
        dependency.direct = dependency.name in direct_dependencies
    return dependency_list


@stamina.retry(on=Exception, attempts=3)
async def parse_uv_lock_file(file_path: Path) -> ParseResult:
    """Parses a uv.lock TOML file and extracts package PyPi dependencies"""
    data = toml.loads(await file_path.read_text())

    direct_dependencies: set[str] = set()
    dependencies: dict[str, Dependency] = {}
    ignored_count = 0

    package_data = data.get("package", [])
    for package in package_data:
        ignored_count += _process_uv_lock_package(
            package, dependencies, direct_dependencies
        )

    dependency_list = _mark_direct_dependencies(dependencies, direct_dependencies)
    return ParseResult(dependencies=dependency_list, ignored_count=ignored_count)
