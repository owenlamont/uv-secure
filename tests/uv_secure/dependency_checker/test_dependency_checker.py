import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from anyio import Path as APath
import anysqlite
from hishel import AsyncSqliteStorage
from hishel.httpx import AsyncCacheClient
from httpx import AsyncClient, Headers
import pytest
from pytest_httpx import HTTPXMock

from uv_secure.configuration import (
    Configuration,
    MaintainabilityCriteria,
    VulnerabilityCriteria,
)
from uv_secure.dependency_checker import check_dependencies, USER_AGENT
from uv_secure.dependency_checker.dependency_checker import (
    _check_global_uv_tool,
    _detect_uv_version,
    _extract_uv_version,
)
from uv_secure.output_models import DependencyOutput


@asynccontextmanager
async def cached_http_client() -> AsyncIterator[AsyncCacheClient]:
    connection = await anysqlite.connect(":memory:")
    storage = AsyncSqliteStorage(
        connection=connection, default_ttl=86400.0, refresh_ttl_on_access=False
    )
    async with AsyncCacheClient(
        timeout=10, storage=storage, headers=Headers({"User-Agent": USER_AGENT})
    ) as http_client:
        try:
            yield http_client
        finally:
            await connection.close()


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

    async with cached_http_client() as http_client:
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

    async with cached_http_client() as http_client:
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
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": proj_status, "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    async with cached_http_client() as http_client:
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
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": "archived", "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    async with cached_http_client() as http_client:
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
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={"name": "example-package", "project-status": {"status": "archived"}},
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )

    async with cached_http_client() as http_client:
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

    async with cached_http_client() as http_client:
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


def test_extract_uv_version_parses_tokens() -> None:
    assert _extract_uv_version("uv dev build 0.10.0 extra") == "0.10.0"


def test_extract_uv_version_returns_none_for_invalid_string() -> None:
    assert _extract_uv_version("uv-dev build") is None


class _FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self.stdout, self.stderr


@pytest.mark.asyncio
async def test_detect_uv_version_reads_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"uv 1.2.3", b"", 0)

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await _detect_uv_version() == "1.2.3"


@pytest.mark.asyncio
async def test_detect_uv_version_reads_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"", b"uv 2.0.1", 0)

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await _detect_uv_version() == "2.0.1"


@pytest.mark.asyncio
async def test_detect_uv_version_handles_non_zero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"uv 3.0.0", b"", 1)

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await _detect_uv_version() is None


@pytest.mark.asyncio
async def test_detect_uv_version_handles_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        raise FileNotFoundError

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await _detect_uv_version() is None


@pytest.mark.asyncio
async def test_detect_uv_version_returns_none_when_output_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_create_process(*_: object, **__: object) -> _FakeProcess:
        await asyncio.sleep(0)
        return _FakeProcess(b"", b"", 0)

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.asyncio.create_subprocess_exec",
        _fake_create_process,
    )

    assert await _detect_uv_version() is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_none_when_detection_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return None

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._detect_uv_version",
        _fake_detect,
    )

    async with AsyncClient() as client:
        result = await _check_global_uv_tool(Configuration(), client, False)
    assert result is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_none_when_metadata_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return "0.9.9"

    async def _fake_download(*_: object, **__: object) -> list[str]:
        await asyncio.sleep(0)
        return ["payload"]

    def _fake_process(*_: object, **__: object) -> None:
        return None

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._detect_uv_version",
        _fake_detect,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.download_packages",
        _fake_download,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.download_package_indexes",
        _fake_download,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._process_package_metadata",
        _fake_process,
    )

    async with AsyncClient() as client:
        result = await _check_global_uv_tool(Configuration(), client, False)
    assert result is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_none_when_no_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return "0.9.9"

    async def _fake_download(*_: object, **__: object) -> list[str]:
        await asyncio.sleep(0)
        return ["payload"]

    dependency_output = DependencyOutput(name="uv", version="0.9.9", direct=True)

    def _fake_process(*_: object, **__: object) -> DependencyOutput:
        return dependency_output

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._detect_uv_version",
        _fake_detect,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.download_packages",
        _fake_download,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.download_package_indexes",
        _fake_download,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._process_package_metadata",
        _fake_process,
    )

    async with AsyncClient() as client:
        result = await _check_global_uv_tool(Configuration(), client, False)
    assert result is None


@pytest.mark.asyncio
async def test_check_global_uv_returns_error_output_when_metadata_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_detect() -> str | None:
        await asyncio.sleep(0)
        return "0.9.9"

    async def _fake_download(*_: object, **__: object) -> list[str]:
        await asyncio.sleep(0)
        return ["payload"]

    def _fake_process(*_: object, **__: object) -> str:
        return "boom"

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._detect_uv_version",
        _fake_detect,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.download_packages",
        _fake_download,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker.download_package_indexes",
        _fake_download,
    )
    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._process_package_metadata",
        _fake_process,
    )

    async with AsyncClient() as client:
        result = await _check_global_uv_tool(Configuration(), client, False)
    assert result is not None
    assert result.file_path == "uv (global tool)"
    assert result.error == "boom"
