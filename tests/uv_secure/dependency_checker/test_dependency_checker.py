from pathlib import Path

from anyio import Path as APath
from hishel import AsyncCacheClient, AsyncFileStorage
from httpx import Headers
import pytest
from pytest_httpx import HTTPXMock
from rich.table import Table
from rich.text import Text

from uv_secure.configuration import (
    Configuration,
    MaintainabilityCriteria,
    VulnerabilityCriteria,
)
from uv_secure.dependency_checker import check_dependencies, USER_AGENT


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
) -> None:
    """Test that aliases generate the correct hyperlink in Rich renderables."""
    # Mock the response to include the alias
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

    storage = AsyncFileStorage(base_path=Path.home() / ".cache/uv-secure", ttl=86400.0)
    async with AsyncCacheClient(
        timeout=10, storage=storage, headers=Headers({"User-Agent": USER_AGENT})
    ) as http_client:
        status, renderables = await check_dependencies(
            APath(temp_uv_lock_file),
            Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
            http_client,
            True,
        )

    assert status == 2
    for renderable in renderables:
        if not isinstance(renderable, Table):
            continue
        for column in renderable.columns:
            if column.header != "Aliases":
                continue
            cells = list(column.cells)
            assert len(cells) == 1
            cell = cells[0]
            assert isinstance(cell, Text)
            assert alias in cell.plain
            if expected_hyperlink is not None:
                assert expected_hyperlink in cell.markup


@pytest.mark.asyncio
async def test_check_dependencies_no_fix_versions(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test vulnerability with no fix versions available."""
    # Mock the response with vulnerability that has no fixed_in versions
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
                    "fixed_in": None,  # No fix available
                    "aliases": ["CVE-2024-99999"],
                    "link": "https://example.com/vuln-no-fix",
                }
            ],
        },
    )

    storage = AsyncFileStorage(base_path=Path.home() / ".cache/uv-secure", ttl=86400.0)
    async with AsyncCacheClient(
        timeout=10, storage=storage, headers=Headers({"User-Agent": USER_AGENT})
    ) as http_client:
        status, renderables = await check_dependencies(
            APath(temp_uv_lock_file),
            Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
            http_client,
            True,
        )

    assert status == 2
    renderables_list = list(renderables)
    assert len(renderables_list) == 3
    assert isinstance(renderables_list[2], Table)


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
) -> None:
    """When a project status is forbidden, we report a maintenance issue."""
    # Simple JSON API project status
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": proj_status, "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    storage = AsyncFileStorage(base_path=Path.home() / ".cache/uv-secure", ttl=86400.0)
    async with AsyncCacheClient(
        timeout=10, storage=storage, headers=Headers({"User-Agent": USER_AGENT})
    ) as http_client:
        if flag_field == "forbid_archived":
            maintain = MaintainabilityCriteria(forbid_archived=True)
        elif flag_field == "forbid_deprecated":
            maintain = MaintainabilityCriteria(forbid_deprecated=True)
        else:
            maintain = MaintainabilityCriteria(forbid_quarantined=True)
        status, renderables = await check_dependencies(
            APath(temp_uv_lock_file),
            Configuration(maintainability_criteria=maintain),
            http_client,
            True,
        )

    # Maintenance issues only => exit status 1 and include the issues table
    assert status == 1
    renderables_list = list(renderables)
    assert len(renderables_list) >= 3
    assert isinstance(renderables_list[-1], Table)


@pytest.mark.asyncio
async def test_maintenance_issue_not_reported_when_not_forbidden(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
) -> None:
    """Archived but not forbidden should not be reported as a maintenance issue."""
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": "archived", "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    storage = AsyncFileStorage(base_path=Path.home() / ".cache/uv-secure", ttl=86400.0)
    async with AsyncCacheClient(
        timeout=10, storage=storage, headers=Headers({"User-Agent": USER_AGENT})
    ) as http_client:
        status, renderables = await check_dependencies(
            APath(temp_uv_lock_file), Configuration(), http_client, True
        )

    # No vulnerabilities/issues => exit status 0 and success panel present
    assert status == 0
    renderables_list = list(renderables)
    # Expect at least the "Checking ..." line and the success panel
    assert len(renderables_list) >= 2


@pytest.mark.asyncio
async def test_check_dependencies_no_aliases(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test vulnerability with no aliases available."""
    # Mock the response with vulnerability that has no aliases
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
                    "aliases": None,  # No aliases available
                    "link": "https://example.com/vuln-no-aliases",
                }
            ],
        },
    )

    storage = AsyncFileStorage(base_path=Path.home() / ".cache/uv-secure", ttl=86400.0)
    async with AsyncCacheClient(
        timeout=10, storage=storage, headers=Headers({"User-Agent": USER_AGENT})
    ) as http_client:
        status, renderables = await check_dependencies(
            APath(temp_uv_lock_file),
            Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
            http_client,
            True,
        )

    assert status == 2
    renderables_list = list(renderables)
    assert len(renderables_list) == 3
    assert isinstance(renderables_list[2], Table)
