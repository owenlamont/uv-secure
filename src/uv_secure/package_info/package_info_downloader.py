import asyncio
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from httpx import AsyncClient
from pydantic import BaseModel

from uv_secure.caching.cache_manager import CacheManager
from uv_secure.package_info.dependency_file_parser import Dependency


class Downloads(BaseModel):
    last_day: int | None = None
    last_month: int | None = None
    last_week: int | None = None


class Info(BaseModel):
    author: str | None = None
    author_email: str | None = None
    bugtrack_url: str | None = None
    classifiers: list[str]
    description: str
    description_content_type: str | None = None
    docs_url: str | None = None
    download_url: str | None = None
    downloads: Downloads
    dynamic: list[str] | str | None = None
    home_page: str | None = None
    keywords: str | list[str] | None = None
    license: str | None = None
    license_expression: str | None = None
    license_files: list[str] | None = None
    maintainer: str | None = None
    maintainer_email: str | None = None
    name: str
    package_url: str | None = None
    platform: str | None = None
    project_url: str | None = None
    project_urls: dict[str, str] | None = None
    provides_extra: list[str] | None = None
    release_url: str
    requires_dist: list[str] | None = None
    requires_python: str | None = None
    summary: str | None = None
    version: str
    yanked: bool
    yanked_reason: str | None = None


class Digests(BaseModel):
    blake2b_256: str
    md5: str
    sha256: str


class Url(BaseModel):
    comment_text: str | None = None
    digests: Digests
    downloads: int
    filename: str
    has_sig: bool
    md5_digest: str
    packagetype: str
    python_version: str
    requires_python: str | None = None
    size: int
    upload_time: datetime
    upload_time_iso_8601: datetime
    url: str
    yanked: bool
    yanked_reason: str | None = None


class Vulnerability(BaseModel):
    id: str
    details: str
    fixed_in: list[str] | None = None
    aliases: list[str] | None = None
    link: str | None = None
    source: str | None = None
    summary: str | None = None
    withdrawn: str | None = None


class PackageInfo(BaseModel):
    info: Info
    last_serial: int
    urls: list[Url]
    vulnerabilities: list[Vulnerability]
    direct_dependency: bool | None = False

    @property
    def age(self) -> timedelta | None:
        """Return age of the package"""
        release_date = min(
            (url.upload_time_iso_8601 for url in self.urls), default=None
        )
        if release_date is None:
            return None
        return datetime.now(tz=timezone.utc) - release_date


def canonicalize_name(name: str) -> str:
    """Convert a package name to its canonical form for PyPI URLs.

    Args:
        name: Raw package name.

    Returns:
        str: Lowercase hyphenated package name accepted by PyPI APIs.
    """
    return re.sub(r"[_.]+", "-", name).lower()


async def _download_package(
    http_client: AsyncClient, dependency: Dependency, cache_manager: CacheManager | None
) -> PackageInfo:
    """Query the PyPI JSON API for vulnerabilities of a dependency.

    Args:
        http_client: HTTP client.
        dependency: Dependency to download.
        cache_manager: Cache manager.

    Returns:
        PackageInfo: Parsed package metadata including vulnerabilities.
    """
    canonical_name = canonicalize_name(dependency.name)

    async def fetch_from_api() -> dict[str, Any]:
        url = f"https://pypi.org/pypi/{canonical_name}/{dependency.version}/json"
        headers = {}
        if cache_manager is None:
            headers["Cache-Control"] = "no-cache, no-store"

        response = await http_client.get(url, headers=headers or None)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        # Parse and dump to ensure we only cache the fields we need
        return PackageInfo.model_validate(data).model_dump(mode="json", by_alias=True)

    if cache_manager:
        key = f"info/{canonical_name}/{dependency.version}"
        data = await cache_manager.get_or_compute(key, fetch_from_api)
    else:
        data = await fetch_from_api()

    package_info = PackageInfo.model_validate(data)
    package_info.direct_dependency = dependency.direct
    return package_info


async def download_packages(
    dependencies: list[Dependency],
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
) -> list[PackageInfo | BaseException]:
    """Fetch package metadata for all dependencies concurrently.

    Args:
        dependencies: Dependencies to download.
        http_client: HTTP client.
        cache_manager: Cache manager.

    Returns:
        list[PackageInfo | BaseException]: Metadata or exception per dependency.
    """
    tasks = [_download_package(http_client, dep, cache_manager) for dep in dependencies]
    return await asyncio.gather(*tasks, return_exceptions=True)
