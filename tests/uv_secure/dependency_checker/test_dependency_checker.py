from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from anyio import Path as APath
import anysqlite
from hishel import AsyncSqliteStorage
from hishel.httpx import AsyncCacheClient
from httpx import Headers
import pytest
from pytest_httpx import HTTPXMock

from uv_secure.configuration import (
    Configuration,
    MaintainabilityCriteria,
    VulnerabilityCriteria,
)
from uv_secure.dependency_checker.dependency_checker import (
    check_dependencies,
    USER_AGENT,
)


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

from uv_secure.dependency_checker.dependency_checker import (
    ManagedAsyncSqliteStorage,
    _apply_cli_config_overrides,
    _determine_final_status,
    _should_skip_package,
    _filter_vulnerabilities,
    _has_maintenance_issues,
    check_lock_files,
    RunStatus,
)
from uv_secure.output_models import (
    FileResultOutput,
    DependencyOutput,
    VulnerabilityOutput,
    MaintenanceIssueOutput,
)
from uv_secure.configuration import (
    Configuration,
    MaintainabilityCriteria,
    VulnerabilityCriteria,
)
from uv_secure.package_info import (
    PackageInfo,
    PackageIndex,
    ProjectState,
    Vulnerability,
)

class TestManagedAsyncSqliteStorage:
    @pytest.mark.asyncio
    async def test_close_closes_connection(self, mocker):
        """Ensure ManagedAsyncSqliteStorage.close() properly closes the connection."""
        mock_conn = mocker.AsyncMock()
        storage = ManagedAsyncSqliteStorage(connection=mock_conn)
        await storage.close()
        mock_conn.close.assert_awaited_once()
        assert storage.connection is None

    @pytest.mark.asyncio
    async def test_close_without_connection_safe(self):
        """Ensure calling close() without a connection does not raise errors."""
        storage = ManagedAsyncSqliteStorage()
        await storage.close()

@pytest.mark.parametrize(
    ("ignore_map", "version", "expected"),
    [
        pytest.param({}, "1.0.0", False, id="not ignored"),
        pytest.param({"foo": ()}, "1.0.0", True, id="empty specifiers means ignore"),
        pytest.param(
            {"foo": tuple()},
            "2.0.0",
            True,
            id="explicit empty spec tuple also ignored",
        ),
    ],
)
def test_should_skip_package(ignore_map, version, expected, mocker):
    pkg_info = mocker.Mock()
    pkg_info.info.name = "foo"
    pkg_info.info.version = version
    result = _should_skip_package(pkg_info, ignore_map)
    assert result == expected

    """Ensure ignored and withdrawn vulnerabilities are removed."""
    vuln1 = Vulnerability(
        id="A", details="", withdrawn=None, aliases=None, link=None, fixed_in=None
    )
    vuln2 = Vulnerability(
        id="B", details="", withdrawn="yes", aliases=None, link=None, fixed_in=None
    )
    vuln3 = Vulnerability(
        id="C", details="", withdrawn=None, aliases=None, link=None, fixed_in=None
    )
    pkg_info = mocker.Mock()
    pkg_info.vulnerabilities = [vuln1, vuln2, vuln3]
    config = Configuration(
        vulnerability_criteria=VulnerabilityCriteria(ignore_vulnerabilities={"C"})
    )
    _filter_vulnerabilities(pkg_info, config)
    remaining_ids = {v.id for v in pkg_info.vulnerabilities}
    assert remaining_ids == {"A"}

@pytest.mark.parametrize(
    ("state", "expected"),
    [
        pytest.param(ProjectState.ARCHIVED, True, id="archived forbidden"),
        pytest.param(ProjectState.ACTIVE, False, id="active allowed"),
    ],
)
def test_has_maintenance_issues_detects_conditions(state, expected, mocker):
    """Validate maintenance issue logic."""
    pkg_index = mocker.Mock(status=state)
    pkg_info = mocker.Mock()
    pkg_info.info.yanked = False
    pkg_info.age = None
    config = Configuration(
        maintainability_criteria=MaintainabilityCriteria(forbid_archived=True)
    )
    assert _has_maintenance_issues(pkg_index, pkg_info, config) == expected

@pytest.mark.parametrize(
    "file_results,expected_status",
    [
        pytest.param(
            [FileResultOutput(file_path="a", error="err")],
            RunStatus.RUNTIME_ERROR,
            id="runtime error",
        ),
        pytest.param(
            [
                FileResultOutput(
                    file_path="a",
                    dependencies=[
                        DependencyOutput(
                            name="x",
                            version="1.0.0",
                            direct=True,
                            vulns=[
                                VulnerabilityOutput(
                                    id="v",
                                    details="",
                                    fix_versions=None,
                                    aliases=None,
                                    link=None,
                                )
                            ],
                            maintenance_issues=None,
                        )
                    ],
                )
            ],
            RunStatus.VULNERABILITIES_FOUND,
            id="vulns found",
        ),
        pytest.param(
            [
                FileResultOutput(
                    file_path="a",
                    dependencies=[
                        DependencyOutput(
                            name="x",
                            version="1.0.0",
                            direct=True,
                            vulns=[],
                            maintenance_issues=MaintenanceIssueOutput(
                                status="archived", status_reason="test", yanked=False
                            ),
                        )
                    ],
                )
            ],
            RunStatus.MAINTENANCE_ISSUES_FOUND,
            id="maintenance found",
        ),
        pytest.param(
            [FileResultOutput(file_path="a", dependencies=[])],
            RunStatus.NO_VULNERABILITIES,
            id="no issues",
        ),
    ],
)
def test_determine_final_status(file_results, expected_status):
    """Ensure final run status is determined correctly."""
    result = _determine_final_status(file_results)
    assert result == expected_status

def test_apply_cli_config_overrides_applies_when_needed(mocker):
    """Ensure overrides are applied when parameters are passed."""
    mock_config = Configuration()
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.config_cli_arg_factory",
        return_value="cli_conf",
    )
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.override_config",
        return_value="merged",
    )

    result = _apply_cli_config_overrides(
        {"lock": mock_config},
        aliases=True,
        desc=None,
        ignore_vulns=None,
        ignore_pkgs=None,
        forbid_archived=None,
        forbid_deprecated=None,
        forbid_quarantined=None,
        forbid_yanked=None,
        check_direct_dependency_vulnerabilities_only=None,
        check_direct_dependency_maintenance_issues_only=None,
        max_package_age=None,
        format_type=None,
    )

    assert list(result.values()) == ["merged"]


def test_apply_cli_config_overrides_skips_when_no_changes():
    mapping = {"lock": Configuration()}
    result = _apply_cli_config_overrides(
        mapping,
        aliases=None,
        desc=None,
        ignore_vulns=None,
        ignore_pkgs=None,
        forbid_archived=None,
        forbid_deprecated=None,
        forbid_quarantined=None,
        forbid_yanked=None,
        check_direct_dependency_vulnerabilities_only=None,
        check_direct_dependency_maintenance_issues_only=None,
        max_package_age=None,
        format_type=None,
    )

    assert result is mapping

@pytest.mark.asyncio
async def test_check_lock_files_integration_success(mocker):
    # Patch functions used inside check_lock_files
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.get_dependency_file_to_config_map",
        return_value={"f": Configuration()},
    )
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.get_dependency_files_to_config_map",
        return_value={"f": Configuration()},
    )
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.config_file_factory",
        return_value=None,
    )

    # Patch APath where it is actually used in dependency_checker.py
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker._resolve_file_paths_and_configs",
        return_value=([APath("f")], {APath("f"): Configuration()}),
    )

    # Patch check_dependencies to return a valid FileResultOutput
    mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.check_dependencies",
        side_effect=lambda *_args, **_kwargs: FileResultOutput(
            file_path="f", dependencies=[], error=None
        ),
    )

    # Patch Console to avoid printing
    mock_console = mocker.patch(
        "uv_secure.dependency_checker.dependency_checker.Console"
    )

    # Run the function
    result = await check_lock_files(
        file_paths=[Path("f")],
        aliases=None,
        desc=None,
        cache_path=Path("cache"),
        cache_ttl_seconds=60.0,
        disable_cache=True,
        forbid_archived=None,
        forbid_deprecated=None,
        forbid_quarantined=None,
        forbid_yanked=None,
        max_package_age=None,
        ignore_vulns=None,
        ignore_pkgs=None,
        check_direct_dependency_vulnerabilities_only=None,
        check_direct_dependency_maintenance_issues_only=None,
        config_path=None,
        format_type="json",
    )

    # Validate result
    assert result == RunStatus.NO_VULNERABILITIES
    mock_console.return_value.print.assert_called()
