import asyncio
from datetime import datetime, timedelta, timezone
import re

from httpx import AsyncClient
from pydantic import BaseModel

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
    """Converts a package name to its canonical form for PyPI URLs"""
    return re.sub(r"[_.]+", "-", name).lower()


def _build_request_headers(
    disable_cache: bool, base_headers: dict[str, str] | None = None
) -> dict[str, str] | None:
    if not disable_cache:
        return base_headers
    headers: dict[str, str] = {} if base_headers is None else dict(base_headers)
    headers.setdefault("Cache-Control", "no-cache, no-store")
    return headers


async def _download_package(
    http_client: AsyncClient, dependency: Dependency, disable_cache: bool
) -> PackageInfo:
    """Queries the PyPi JSON API for vulnerabilities of a given dependency."""
    canonical_name = canonicalize_name(dependency.name)
    url = f"https://pypi.org/pypi/{canonical_name}/{dependency.version}/json"
    response = await http_client.get(url, headers=_build_request_headers(disable_cache))
    response.raise_for_status()
    package_info = PackageInfo.model_validate_json(response.content)
    package_info.direct_dependency = dependency.direct
    return package_info


async def download_packages(
    dependencies: list[Dependency], http_client: AsyncClient, disable_cache: bool
) -> list[PackageInfo | BaseException]:
    """Fetch vulnerabilities for all dependencies concurrently."""
    tasks = [_download_package(http_client, dep, disable_cache) for dep in dependencies]
    return await asyncio.gather(*tasks, return_exceptions=True)
