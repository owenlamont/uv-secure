import asyncio
from datetime import timedelta
from enum import Enum

from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict, Field

from uv_secure.package_info.cache import cache
from uv_secure.package_info.dependency_file_parser import Dependency
from uv_secure.package_utils import canonicalize_name


class ProjectState(str, Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"
    QUARANTINED = "quarantined"


class ProjectStatus(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: ProjectState = ProjectState.ACTIVE
    reason: str | None = None


class PackageIndex(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(min_length=1)
    project_status: ProjectStatus = Field(
        default_factory=lambda: ProjectStatus(status=ProjectState.ACTIVE),
        alias="project-status",
    )

    @property
    def status(self) -> ProjectState:
        """Convenience accessor for the enum status."""
        return self.project_status.status


def _build_request_headers(
    disable_cache: bool, base_headers: dict[str, str] | None = None
) -> dict[str, str] | None:
    """Construct request headers respecting cache settings.

    Args:
        disable_cache: Whether caching is disabled.
        base_headers: Headers to extend.

    Returns:
        dict[str, str] | None: Headers with cache directives when needed.
    """
    if not disable_cache:
        return base_headers
    headers: dict[str, str] = {} if base_headers is None else dict(base_headers)
    headers.setdefault("Cache-Control", "no-cache, no-store")
    return headers


async def _download_package_index(
    http_client: AsyncClient,
    dependency: Dependency,
    disable_cache: bool,
    ttl: timedelta,
) -> PackageIndex:
    """Query the PyPI Simple JSON API for dependency status.

    Args:
        http_client: HTTP client.
        dependency: Dependency to query.
        disable_cache: Whether caching is disabled.
        ttl: Cache TTL.

    Returns:
        PackageIndex: Parsed metadata for the dependency.

    Raises:
        TypeError: Raised if the package index is not a ``PackageIndex`` instance.
    """
    key = f"package_index:{dependency.name}"
    if not disable_cache:
        cached = await cache.get(key)
        if isinstance(cached, PackageIndex):
            return cached

    canonical_name = canonicalize_name(dependency.name)
    url = f"https://pypi.org/simple/{canonical_name}/"
    headers = _build_request_headers(
        disable_cache, {"Accept": "application/vnd.pypi.simple.v1+json"}
    )

    async def _fetch() -> PackageIndex:
        response = await http_client.get(url, headers=headers)
        response.raise_for_status()
        return PackageIndex.model_validate_json(response.content)

    if disable_cache:
        return await _fetch()

    async with cache.lock(f"lock:{key}", ttl.total_seconds()):
        cached = await cache.get(key)
        if isinstance(cached, PackageIndex):
            return cached

        package_index = await _fetch()
        await cache.set(key, package_index, expire=ttl)
        if isinstance(package_index, PackageIndex):
            return package_index
        raise TypeError("Fetch failed to return PackageIndex")


async def download_package_indexes(
    dependencies: list[Dependency],
    http_client: AsyncClient,
    disable_cache: bool,
    ttl: timedelta,
) -> list[PackageIndex | BaseException]:
    """Fetch package-index metadata concurrently.

    Args:
        dependencies: Dependencies to query.
        http_client: HTTP client.
        disable_cache: Whether caching is disabled.
        ttl: Cache TTL.

    Returns:
        list[PackageIndex | BaseException]: Results or exceptions for each dependency.
    """
    tasks = [
        _download_package_index(http_client, dep, disable_cache, ttl)
        for dep in dependencies
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)
