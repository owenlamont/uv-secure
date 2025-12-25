import asyncio
from enum import Enum

from cashews import Cache
from httpx import AsyncClient
from pydantic import BaseModel, ConfigDict, Field

from uv_secure.package_info.cache_utils import get_cached_model
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
    cache: Cache,
    cache_ttl_seconds: float,
    disable_cache: bool,
) -> PackageIndex:
    """Query the PyPI Simple JSON API for dependency status.

    Args:
        http_client: HTTP client.
        dependency: Dependency to query.
        cache: Cache instance for HTTP responses.
        cache_ttl_seconds: Cache TTL in seconds.
        disable_cache: Whether caching is disabled.

    Returns:
        PackageIndex: Parsed metadata for the dependency.
    """
    canonical_name = canonicalize_name(dependency.name)
    url = f"https://pypi.org/simple/{canonical_name}/"
    headers = _build_request_headers(
        disable_cache, {"Accept": "application/vnd.pypi.simple.v1+json"}
    )
    cache_key = f"pypi:simple:{canonical_name}"

    async def fetcher() -> bytes:
        response = await http_client.get(url, headers=headers)
        response.raise_for_status()
        return response.content

    return await get_cached_model(
        cache,
        cache_key,
        cache_ttl_seconds,
        disable_cache,
        fetcher,
        PackageIndex.model_validate_json,
        lambda model: model.model_dump_json(by_alias=True).encode(),
    )


async def download_package_indexes(
    dependencies: list[Dependency],
    http_client: AsyncClient,
    cache: Cache,
    cache_ttl_seconds: float,
    disable_cache: bool,
) -> list[PackageIndex | BaseException]:
    """Fetch package-index metadata concurrently.

    Args:
        dependencies: Dependencies to query.
        http_client: HTTP client.
        cache: Cache instance for HTTP responses.
        cache_ttl_seconds: Cache TTL in seconds.
        disable_cache: Whether caching is disabled.

    Returns:
        list[PackageIndex | BaseException]: Results or exceptions for each dependency.
    """
    tasks = [
        _download_package_index(
            http_client, dep, cache, cache_ttl_seconds, disable_cache
        )
        for dep in dependencies
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)
