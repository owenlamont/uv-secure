from collections.abc import AsyncIterator
from pathlib import Path

from anyio import Path as APath
from cashews import Cache
from httpx import AsyncClient, Headers
import pytest
import pytest_asyncio
from pytest_httpx import HTTPXMock

from uv_secure.configuration import (
    Configuration,
    MaintainabilityCriteria,
    VulnerabilityCriteria,
)
from uv_secure.dependency_checker import check_dependencies, USER_AGENT
from uv_secure.http_cache import RequestCache


@pytest_asyncio.fixture
async def http_client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        timeout=10, headers=Headers({"User-Agent": USER_AGENT})
    ) as client:
        yield client


@pytest_asyncio.fixture
async def memory_request_cache() -> AsyncIterator[RequestCache]:
    backend = Cache()
    backend.setup("mem://")
    await backend.init()
    request_cache = RequestCache(backend, 86400.0, namespace="test")
    try:
        yield request_cache
    finally:
        await backend.clear()
        await backend.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alias", "expected_hyperlink"),
    [
        pytest.param(
            "CVE-2024-12345",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345",
            id="CVE alias",
        ),
        pytest.param(
            "GHSA-q2x7-8rv6-6q7h",
            "https://github.com/advisories/GHSA-q2x7-8rv6-6q7h",
            id="GHSA alias",
        ),
        pytest.param(
            "PYSEC-12345",
            "https://github.com/pypa/advisory-database/blob/main/vulns/example-package/PYSEC-12345.yaml",
            id="PYSEC alias",
        ),
        pytest.param(
            "OSV-12345", "https://osv.dev/vulnerability/OSV-12345", id="OSV alias"
        ),
        pytest.param("Unrecognised-alias-12345", None, id="Unrecognised alias"),
    ],
)
async def test_check_dependencies_alias_hyperlinks(
    alias: str,
    expected_hyperlink: str,
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    http_client: AsyncClient,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "A minimal package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "example-package",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.9",
                "summary": "A minimal package example",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "VULN-123",
                    "details": "Test vulnerability",
                    "fixed_in": ["1.0.1"],
                    "aliases": [alias],
                    "link": "https://example.com/vuln-123",
                }
            ],
        },
    )

    result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
        http_client,
        True,
    )

    # Verify structured output
    assert result.error is None
    assert len(result.dependencies) == 1
    dep = result.dependencies[0]
    assert dep.name == "example-package"
    assert dep.vulns is not None
    assert len(dep.vulns) == 1
    vuln = dep.vulns[0]
    assert vuln.id == "VULN-123"
    assert vuln.aliases is not None
    assert alias in vuln.aliases


@pytest.mark.asyncio
async def test_check_dependencies_no_fix_versions(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    http_client: AsyncClient,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "Example package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "example-package",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.9",
                "summary": "Example package for testing",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "VULN-NO-FIX",
                    "details": "Vulnerability with no fix available",
                    "fixed_in": None,
                    "aliases": ["CVE-2024-99999"],
                    "link": "https://example.com/vuln-no-fix",
                }
            ],
        },
    )

    result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
        http_client,
        True,
    )

    # Verify structured output
    assert result.error is None
    assert len(result.dependencies) == 1
    dep = result.dependencies[0]
    assert dep.vulns is not None
    assert len(dep.vulns) == 1
    vuln = dep.vulns[0]
    assert vuln.id == "VULN-NO-FIX"
    assert vuln.fix_versions is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("proj_status", "flag_field"),
    [
        pytest.param("archived", "forbid_archived", id="Archived forbidden"),
        pytest.param("deprecated", "forbid_deprecated", id="Deprecated forbidden"),
        pytest.param("quarantined", "forbid_quarantined", id="Quarantined forbidden"),
    ],
)
async def test_maintenance_issue_forbidden_status_triggers_issue(
    proj_status: str,
    flag_field: str,
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    http_client: AsyncClient,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": proj_status, "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    if flag_field == "forbid_archived":
        maintain = MaintainabilityCriteria(forbid_archived=True)
    elif flag_field == "forbid_deprecated":
        maintain = MaintainabilityCriteria(forbid_deprecated=True)
    else:
        maintain = MaintainabilityCriteria(forbid_quarantined=True)
    result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(maintainability_criteria=maintain),
        http_client,
        True,
    )

    # Verify structured output
    assert result.error is None
    assert len(result.dependencies) == 1
    dep = result.dependencies[0]
    assert dep.maintenance_issues is not None
    assert dep.maintenance_issues.status == proj_status
    assert dep.maintenance_issues.status_reason == "test"


@pytest.mark.asyncio
async def test_maintenance_issue_not_reported_when_not_forbidden(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    http_client: AsyncClient,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": "archived", "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    result = await check_dependencies(
        APath(temp_uv_lock_file), Configuration(), http_client, True
    )

    # Verify structured output - no maintenance issues reported
    assert result.error is None
    assert len(result.dependencies) == 1
    dep = result.dependencies[0]
    assert dep.maintenance_issues is None


@pytest.mark.asyncio
async def test_maintenance_issue_forbidden_status_unknown_reason_shows_unknown(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    http_client: AsyncClient,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={"name": "example-package", "project-status": {"status": "archived"}},
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(
            maintainability_criteria=MaintainabilityCriteria(forbid_archived=True)
        ),
        http_client,
        True,
    )

    # Verify structured output
    assert result.error is None
    assert len(result.dependencies) == 1
    dep = result.dependencies[0]
    assert dep.maintenance_issues is not None
    assert dep.maintenance_issues.status == "archived"
    assert dep.maintenance_issues.status_reason is None


@pytest.mark.asyncio
async def test_check_dependencies_no_aliases(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    http_client: AsyncClient,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "Example package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "example-package",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.9",
                "summary": "Example package for testing",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "VULN-NO-ALIASES",
                    "details": "Vulnerability with no aliases",
                    "fixed_in": ["2.0.0"],
                    "aliases": None,
                    "link": "https://example.com/vuln-no-aliases",
                }
            ],
        },
    )

    result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
        http_client,
        True,
    )

    # Verify structured output
    assert result.error is None
    assert len(result.dependencies) == 1
    dep = result.dependencies[0]
    assert dep.vulns is not None
    assert len(dep.vulns) == 1
    vuln = dep.vulns[0]
    assert vuln.id == "VULN-NO-ALIASES"
    assert vuln.aliases is None


@pytest.mark.asyncio
async def test_request_cache_serves_cached_responses(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    http_client: AsyncClient,
    memory_request_cache: RequestCache,
) -> None:
    first_result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(),
        http_client,
        False,
        memory_request_cache,
    )

    assert first_result.error is None
    assert len(first_result.dependencies) == 1
    assert len(httpx_mock.get_requests()) == 2

    cached_result = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(),
        http_client,
        False,
        memory_request_cache,
    )

    assert cached_result.error is None
    assert cached_result.dependencies == first_result.dependencies
    assert len(httpx_mock.get_requests()) == 2
