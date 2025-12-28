import sys
from urllib.parse import urlparse

from anyio import Path
from packaging.requirements import Requirement
from pydantic import BaseModel
import stamina


if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml  # ty: ignore[unresolved-import]


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


def _normalize_registry_url(url: str) -> str | None:
    """Return a canonical registry URL or ``None`` when parsing fails.

    Normalization trims trailing slashes, lowercases scheme/host, removes default
    ports, and collapses ``/simple/`` to ``/simple`` for stable comparisons.
    """

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else None
    if host is None:
        return None

    port = parsed.port
    if port is not None:
        is_default_https = scheme == "https" and port == 443
        is_default_http = scheme == "http" and port == 80
        if not (is_default_http or is_default_https):
            host = f"{host}:{port}"

    path = parsed.path or ""
    normalized_path = path.rstrip("/")
    if normalized_path.endswith("/simple"):
        normalized_path = "/simple"

    return f"{scheme}://{host}{normalized_path}"


def _is_pypi_registry(registry: str | None) -> bool:
    """Check whether a registry URL points to the official PyPI simple index.

    Returns:
        bool: True when the registry resolves to the canonical PyPI simple URL.
    """

    if registry is None:
        return False

    normalized = _normalize_registry_url(registry)
    return normalized in {
        "https://pypi.org/simple",
        "http://pypi.org/simple",
        "https://pypi.python.org/simple",
        "http://pypi.python.org/simple",
    }


@stamina.retry(on=Exception, attempts=3)
async def parse_pylock_toml_file(file_path: Path) -> ParseResult:
    """Parse a PEP 751 ``pylock.toml`` file and extract dependencies.

    Args:
        file_path: Path to the ``pylock.toml`` file.

    Returns:
        ParseResult: Dependencies plus ignored-count metadata.
    """
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
            if _is_pypi_registry(index):
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
    """Validate that a requirement line is properly pinned.

    Args:
        line: Original requirements line.
        requirement: Parsed requirement object.

    Raises:
        ValueError: Raised when markers, URLs, or unpinned specifiers are present.
    """
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
    """Parse a requirement line and ensure it is pinned.

    Args:
        line: Raw requirements line.

    Returns:
        Requirement | None: Parsed requirement for pinned dependencies,
            otherwise ``None``.

    Raises:
        ValueError: Raised when requirement parsing fails or is not fully pinned.
    """
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
    """Check if a requirements line is a direct-dependency marker.

    Args:
        line: Raw requirements line.

    Returns:
        bool: True when the line marks the previous dependency as direct.
    """
    return " -r " in line or " (pyproject.toml)" in line


@stamina.retry(on=Exception, attempts=3)
async def parse_requirements_txt_file(file_path: Path) -> ParseResult:
    """Parse a ``requirements.txt`` file and extract PyPI dependencies.

    Args:
        file_path: Path to the requirements file.

    Returns:
        ParseResult: Fully pinned dependencies discovered in the file.
    """
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
    """Extract direct dependencies from a package with editable/virtual source.

    Args:
        package: ``uv.lock`` package entry.

    Returns:
        set[str]: Names of dependencies that should be marked as direct.
    """
    direct_dependencies: set[str] = set()

    direct_dependencies.update(
        dependency["name"] for dependency in package.get("dependencies", [])
    )

    dev_dependencies = package.get("dev-dependencies", {})
    for group_dependencies in dev_dependencies.values():
        direct_dependencies.update(
            dependency["name"] for dependency in group_dependencies
        )

    return direct_dependencies


def _process_uv_lock_package(
    package: dict, dependencies: dict[str, Dependency], direct_dependencies: set[str]
) -> int:
    """Process a single ``uv.lock`` package.

    Args:
        package: Package entry from ``uv.lock``.
        dependencies: Mapping of dependency name to ``Dependency`` model.
        direct_dependencies: Names marked as direct dependencies.

    Returns:
        int: Number of ignored dependencies contributed by this package.
    """
    source = package.get("source", {})

    if _is_pypi_registry(source.get("registry")):
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
    """Mark dependencies as direct and return them as a list.

    Args:
        dependencies: Dependency mapping.
        direct_dependencies: Names identified as direct.

    Returns:
        list[Dependency]: Dependencies with the ``direct`` flag set.
    """
    dependency_list = list(dependencies.values())
    for dependency in dependency_list:
        dependency.direct = dependency.name in direct_dependencies
    return dependency_list


@stamina.retry(on=Exception, attempts=3)
async def parse_uv_lock_file(file_path: Path) -> ParseResult:
    """Parse a ``uv.lock`` TOML file and extract PyPI dependencies.

    Args:
        file_path: Path to the ``uv.lock`` file.

    Returns:
        ParseResult: Dependencies plus ignored-count metadata.
    """
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
