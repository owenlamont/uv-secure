from pathlib import Path

from anyio import Path as APath
import pytest
from pytest_httpx import HTTPXMock
from rich.text import Text

from uv_secure.configuration import Configuration
from uv_secure.dependency_checker import check_dependencies


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alias", "expected_hyperlink"),
    [
        (
            "CVE-2024-12345",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345",
        ),
        ("GHSA-q2x7-8rv6-6q7h", "https://github.com/advisories/GHSA-q2x7-8rv6-6q7h"),
        (
            "PYSEC-12345",
            "https://github.com/pypa/advisory-database/blob/main/vulns/example-package/PYSEC-12345.yaml",
        ),
        ("OSV-12345", "https://osv.dev/vulnerability/OSV-12345"),
        ("Unrecognised-alias-12345", "Unrecognised-alias-12345"),
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
            "vulnerabilities": [
                {
                    "id": "VULN-123",
                    "details": "Test vulnerability",
                    "fixed_in": ["1.0.1"],
                    "aliases": [alias],
                    "link": "https://example.com/vuln-123",
                }
            ]
        },
    )

    # Call `check_dependencies` directly
    status, renderables = await check_dependencies(
        APath(temp_uv_lock_file), Configuration(aliases=True)
    )

    # Assertions
    assert status == 1
    for renderable in renderables:
        if isinstance(renderable, Text):
            # Check for the alias and its hyperlink metadata
            assert alias in str(renderable)
            hyperlink_spans = [
                span for span in renderable._spans if expected_hyperlink in span.meta
            ]
            assert hyperlink_spans, f"Hyperlink for {alias} not found"
