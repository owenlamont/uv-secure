import asyncio

from httpx import AsyncClient, HTTPStatusError
from packaging.version import InvalidVersion, Version

from uv_secure import __version__
from uv_secure.caching.cache_manager import CacheManager
from uv_secure.configuration import Configuration
from uv_secure.dependency_checker.osv import enrich_vulnerability_severity_data
from uv_secure.dependency_checker.package_processing import (
    build_ignore_packages,
    process_package_metadata,
)
from uv_secure.dependency_checker.uv_tool import detect_uv_version
from uv_secure.output_models import FileResultOutput
from uv_secure.package_info import (
    Dependency,
    download_package_indexes,
    download_packages,
    PackageInfo,
)
from uv_secure.package_utils import canonicalize_name


GLOBAL_UV_TOOL_LABEL = "uv (global tool)"
GLOBAL_UV_SECURE_PACKAGE_LABEL = "uv-secure (installed package)"


def detect_uv_secure_version() -> str | None:
    """Return the installed ``uv-secure`` package version when valid."""

    try:
        Version(__version__)
    except InvalidVersion:
        return None
    return __version__


def _is_missing_pypi_release_version(
    package_info: PackageInfo | BaseException, package_name: str, package_version: str
) -> bool:
    if not isinstance(package_info, HTTPStatusError):
        return False
    if package_info.response.status_code != 404:
        return False
    request_url = str(package_info.request.url)
    expected_suffix = f"/pypi/{canonicalize_name(package_name)}/{package_version}/json"
    return request_url.endswith(expected_suffix)


async def check_global_uv_tool(
    config: Configuration,
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
    used_ignore_vulnerabilities: set[str] | None = None,
    matched_ignore_packages: set[str] | None = None,
    used_ignore_packages: set[str] | None = None,
) -> FileResultOutput | None:
    """Check vulnerabilities for the globally installed uv CLI.

    Returns:
        FileResultOutput | None: Global tool result or ``None`` when no findings.
    """

    uv_version = await detect_uv_version()
    if uv_version is None:
        return None
    used_ignore_tracker = (
        used_ignore_vulnerabilities
        if used_ignore_vulnerabilities is not None
        else set()
    )
    used_ignore_packages_tracker = (
        used_ignore_packages if used_ignore_packages is not None else set()
    )
    matched_ignore_packages_tracker = (
        matched_ignore_packages if matched_ignore_packages is not None else set()
    )

    dependency = Dependency(name="uv", version=uv_version, direct=True)
    package_infos, package_indexes = await asyncio.gather(
        download_packages([dependency], http_client, cache_manager),
        download_package_indexes([dependency], http_client, cache_manager),
    )
    await enrich_vulnerability_severity_data(package_infos, http_client, cache_manager)

    ignore_packages = build_ignore_packages(config)
    package_info = package_infos[0]
    package_index = package_indexes[0]
    if _is_missing_pypi_release_version(
        package_info, dependency.name, dependency.version
    ):
        return None
    result = process_package_metadata(
        package_info,
        package_index,
        dependency.name,
        config,
        ignore_packages,
        used_ignore_tracker,
        matched_ignore_packages_tracker,
        used_ignore_packages_tracker,
    )

    if result is None:
        return None

    if isinstance(result, str):
        return FileResultOutput(file_path=GLOBAL_UV_TOOL_LABEL, error=result)

    has_findings = bool(result.vulns) or result.maintenance_issues is not None
    if not has_findings:
        return None

    return FileResultOutput(
        file_path=GLOBAL_UV_TOOL_LABEL, dependencies=[result], ignored_count=0
    )


async def check_installed_uv_secure_package(
    config: Configuration,
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
    used_ignore_vulnerabilities: set[str] | None = None,
    matched_ignore_packages: set[str] | None = None,
    used_ignore_packages: set[str] | None = None,
) -> FileResultOutput | None:
    """Check vulnerabilities for the installed ``uv-secure`` package.

    Returns:
        FileResultOutput | None: Installed package result or ``None`` when no findings.
    """

    uv_secure_version = detect_uv_secure_version()
    if uv_secure_version is None:
        return None
    used_ignore_tracker = (
        used_ignore_vulnerabilities
        if used_ignore_vulnerabilities is not None
        else set()
    )
    used_ignore_packages_tracker = (
        used_ignore_packages if used_ignore_packages is not None else set()
    )
    matched_ignore_packages_tracker = (
        matched_ignore_packages if matched_ignore_packages is not None else set()
    )

    dependency = Dependency(name="uv-secure", version=uv_secure_version, direct=True)
    package_infos, package_indexes = await asyncio.gather(
        download_packages([dependency], http_client, cache_manager),
        download_package_indexes([dependency], http_client, cache_manager),
    )
    await enrich_vulnerability_severity_data(package_infos, http_client, cache_manager)

    ignore_packages = build_ignore_packages(config)
    package_info = package_infos[0]
    package_index = package_indexes[0]
    if _is_missing_pypi_release_version(
        package_info, dependency.name, dependency.version
    ):
        return None
    result = process_package_metadata(
        package_info,
        package_index,
        dependency.name,
        config,
        ignore_packages,
        used_ignore_tracker,
        matched_ignore_packages_tracker,
        used_ignore_packages_tracker,
    )

    if result is None:
        return None

    if isinstance(result, str):
        return FileResultOutput(file_path=GLOBAL_UV_SECURE_PACKAGE_LABEL, error=result)

    has_findings = bool(result.vulns) or result.maintenance_issues is not None
    if not has_findings:
        return None

    return FileResultOutput(
        file_path=GLOBAL_UV_SECURE_PACKAGE_LABEL, dependencies=[result], ignored_count=0
    )
