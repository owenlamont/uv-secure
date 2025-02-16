import asyncio
from datetime import datetime, timedelta, timezone
import re
from typing import Optional, Union

from hishel import AsyncCacheClient, AsyncFileStorage
from pydantic import BaseModel

from uv_secure.package_info.dependency_file_parser import Dependency


class Downloads(BaseModel):
    last_day: Optional[int] = None
    last_month: Optional[int] = None
    last_week: Optional[int] = None


class Info(BaseModel):
    author: Optional[str] = None
    author_email: Optional[str] = None
    bugtrack_url: Optional[str] = None
    classifiers: list[str]
    description: str
    description_content_type: Optional[str] = None
    docs_url: Optional[str] = None
    download_url: Optional[str] = None
    downloads: Downloads
    dynamic: Optional[Union[list[str], str]] = None
    home_page: Optional[str] = None
    keywords: Optional[Union[str, list[str]]] = None
    license: Optional[str] = None
    license_expression: Optional[str] = None
    license_files: Optional[list[str]] = None
    maintainer: Optional[str] = None
    maintainer_email: Optional[str] = None
    name: str
    package_url: Optional[str] = None
    platform: Optional[str] = None
    project_url: Optional[str] = None
    project_urls: Optional[dict[str, str]] = None
    provides_extra: Optional[list[str]] = None
    release_url: str
    requires_dist: Optional[list[str]] = None
    requires_python: Optional[str] = None
    summary: Optional[str] = None
    version: str
    yanked: bool
    yanked_reason: Optional[str] = None


class Digests(BaseModel):
    blake2b_256: str
    md5: str
    sha256: str


class Url(BaseModel):
    comment_text: Optional[str] = None
    digests: Digests
    downloads: int
    filename: str
    has_sig: bool
    md5_digest: str
    packagetype: str
    python_version: str
    requires_python: Optional[str] = None
    size: int
    upload_time: datetime
    upload_time_iso_8601: datetime
    url: str
    yanked: bool
    yanked_reason: Optional[str] = None


class Vulnerability(BaseModel):
    id: str
    details: str
    fixed_in: Optional[list[str]] = None
    aliases: Optional[list[str]] = None
    link: Optional[str] = None
    source: Optional[str] = None
    summary: Optional[str] = None
    withdrawn: Optional[str] = None


class PackageInfo(BaseModel):
    info: Info
    last_serial: int
    urls: list[Url]
    vulnerabilities: list[Vulnerability]
    direct_dependency: bool = False

    @property
    def age(self) -> Optional[timedelta]:
        """Return age of the package"""
        release_date = min(
            (url.upload_time_iso_8601 for url in self.urls), default=None
        )
        if release_date is None:
            return None
        return datetime.now(tz=timezone.utc) - release_date


def _canonicalize_name(name: str) -> str:
    """Converts a package name to its canonical form for PyPI URLs"""
    return re.sub(r"[_.]+", "-", name).lower()


async def _download_package(
    client: AsyncCacheClient, dependency: Dependency, disable_cache: bool
) -> PackageInfo:
    """Queries the PyPi JSON API for vulnerabilities of a given dependency."""
    canonical_name = _canonicalize_name(dependency.name)
    url = f"https://pypi.org/pypi/{canonical_name}/{dependency.version}/json"
    response = await client.get(
        url, extensions={"cache_disabled": True} if disable_cache else None
    )
    response.raise_for_status()
    return PackageInfo(**response.json(), direct_dependency=dependency.direct)


async def download_packages(
    dependencies: list[Dependency], storage: AsyncFileStorage, disable_cache: bool
) -> list[Union[PackageInfo, BaseException]]:
    """Fetch vulnerabilities for all dependencies concurrently."""
    async with AsyncCacheClient(timeout=10, storage=storage) as client:
        tasks = [_download_package(client, dep, disable_cache) for dep in dependencies]
        return await asyncio.gather(*tasks, return_exceptions=True)
