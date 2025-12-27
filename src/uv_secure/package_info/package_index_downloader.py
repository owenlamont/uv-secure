import asyncio
from enum import Enum
from typing import Any

from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict, Field

from uv_secure.caching.cache_manager import CacheManager
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
    cache_manager: CacheManager | None, base_headers: dict[str, str] | None = None
) -> dict[str, str] | None:
    """Construct request headers respecting cache settings.

    Args:
        cache_manager: Cache manager.
        base_headers: Headers to extend.

    Returns:
        dict[str, str] | None: Headers with cache directives when needed.
    """
    if cache_manager is not None:
        return base_headers
    headers: dict[str, str] = {} if base_headers is None else dict(base_headers)
    headers.setdefault("Cache-Control", "no-cache, no-store")
    return headers


async def _download_package_index(
    http_client: AsyncClient, dependency: Dependency, cache_manager: CacheManager | None
) -> PackageIndex:
    """Query the PyPI Simple JSON API for dependency status.

    Args:
        http_client: HTTP client.
        dependency: Dependency to query.
        cache_manager: Cache manager.

    Returns:
        PackageIndex: Parsed metadata for the dependency.
    """
    canonical_name = canonicalize_name(dependency.name)

    async def fetch_from_api() -> dict[str, Any]:
        url = f"https://pypi.org/simple/{canonical_name}/"
        headers = _build_request_headers(
            cache_manager, {"Accept": "application/vnd.pypi.simple.v1+json"}
        )
        response = await http_client.get(url, headers=headers)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        # Parse and dump to ensure we only cache the fields we need
        return PackageIndex.model_validate(data).model_dump(mode="json", by_alias=True)

    if cache_manager:
        key = f"index/{canonical_name}"
        data = await cache_manager.get_or_compute(key, fetch_from_api)
    else:
        data = await fetch_from_api()

    return PackageIndex.model_validate(data)


async def download_package_indexes(
    dependencies: list[Dependency],
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
) -> list[PackageIndex | BaseException]:
    """Fetch package-index metadata concurrently.

    Args:
        dependencies: Dependencies to query.
        http_client: HTTP client.
        cache_manager: Cache manager.

    Returns:
        list[PackageIndex | BaseException]: Results or exceptions for each dependency.
    """
    tasks = [
        _download_package_index(http_client, dep, cache_manager) for dep in dependencies
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)
