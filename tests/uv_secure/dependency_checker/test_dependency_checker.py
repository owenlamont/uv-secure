from pathlib import Path

from anyio import Path as APath
import pytest
from pytest_httpx import HTTPXMock
from rich.table import Table
from rich.text import Text

from uv_secure.configuration import Configuration, VulnerabilityCriteria
from uv_secure.dependency_checker import check_dependencies


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
    alias: str, expected_hyperlink: str, temp_uv_lock_file: Path, httpx_mock: HTTPXMock
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

    status, renderables = await check_dependencies(
        APath(temp_uv_lock_file),
        Configuration(vulnerability_criteria=VulnerabilityCriteria(aliases=True)),
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
