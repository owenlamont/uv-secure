import asyncio
from collections.abc import Callable, Generator
import gc
from pathlib import Path
from textwrap import dedent

from httpx import Request, RequestError
import pytest
from pytest_httpx import HTTPXMock

from uv_secure.dependency_checker import USER_AGENT
from uv_secure.package_info.cache import cache


DEFAULT_TEST_UV_VERSION = "0.9.9"


@pytest.fixture(autouse=True)
def cache_cleanup() -> Generator[None, None, None]:
    yield
    # Force close any open backends
    if hasattr(cache, "_backends"):
        print(f"DEBUG: Cleaning up {len(cache._backends)} backends")
        try:
            for backend in list(cache._backends.values()):
                if (
                    hasattr(backend, "close")
                    and hasattr(backend, "_cache")
                    and hasattr(backend._cache, "close")
                ):
                    print(f"DEBUG: Closing backend {backend}")
                    backend._cache.close()
        except Exception as e:
            print(f"DEBUG: Error closing: {e}")
        cache._backends.clear()
    gc.collect()


@pytest.fixture(autouse=True)
def _stub_uv_cli_version(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake_version() -> str | None:
        await asyncio.sleep(0)
        return DEFAULT_TEST_UV_VERSION

    monkeypatch.setattr(
        "uv_secure.dependency_checker.dependency_checker._detect_uv_version",
        _fake_version,
    )


@pytest.fixture
def uv_http_responses(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=f"https://pypi.org/pypi/uv/{DEFAULT_TEST_UV_VERSION}/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "uv CLI",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "uv",
                "project_urls": {},
                "provides_extra": [],
                "release_url": f"https://pypi.org/project/uv/{DEFAULT_TEST_UV_VERSION}/",
                "requires_python": ">=3.9",
                "summary": "stub uv release",
                "version": DEFAULT_TEST_UV_VERSION,
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [],
        },
        is_optional=True,
        is_reusable=True,
    )
    httpx_mock.add_response(
        url="https://pypi.org/simple/uv/",
        json={"name": "uv", "project-status": {"status": "active", "reason": None}},
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
        is_optional=True,
        is_reusable=True,
    )


@pytest.fixture
def temp_uv_lock_file(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_uv_lock_file_trailing_slash(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org/simple/" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_uv_lock_file_default_port(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org:443/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_uv_lock_file_nondefault_port(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org:444/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_uv_lock_file_direct_indirect_dependencies(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "direct-dependency"
        version = "1.0.0"
        source = { registry = "https://pypi.org/simple" }
        dependencies = [
            { name = "indirect-dependency" },
        ]

        [[package]]
        name = "indirect-dependency"
        version = "1.5.0"
        source = { registry = "https://pypi.org/simple" }

        [[package]]
        name = "main-package"
        version = "0.1.0"
        source = { editable = "." }
        dependencies = [
            { name = "direct-dependency" },
        ]

        [[package]]
        name = "my-git-package"
        version = "0.1.0"
        source = { git = "https://github.com/myorg/my-package", rev = "9c3d1e8f8ab2" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_uv_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        # This file was autogenerated by uv via the following command:
        #    uv pip compile pyproject.toml -o requirements.txt
        example-package==1.0.0
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_uv_empty_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        # This file was autogenerated by uv via the following command:
        #    uv pip compile pyproject.toml -o requirements.txt
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_uv_requirements_txt_file_direct_indirect_dependencies(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        # This file was autogenerated by uv via the following command:
        #    uv pip compile pyproject.toml -o requirements.txt
        direct-dependency==1.0.0
            # via main-package (pyproject.toml)
        indirect-dependency==1.5.0
            # via direct-dependency
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_non_uv_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package==1.0.0
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_unpinned_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package==1.0.0
        another-package>=0.1
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_wildcard_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package==1.*
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_comment_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package==1.0.0  # pinned version
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_extras_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package[extra]==1.0.0
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_env_marker_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package==1.0.0; python_version < '3.8'
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_hash_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    requirements_txt_data = """
        example-package==1.0.0 --hash=sha256:1234567890abcdef
    """
    uv_requirements_txt_path.write_text(dedent(requirements_txt_data).strip())
    return uv_requirements_txt_path


@pytest.fixture
def temp_empty_requirements_txt_file(tmp_path: Path) -> Path:
    uv_requirements_txt_path = tmp_path / "requirements.txt"
    uv_requirements_txt_path.write_text("")
    return uv_requirements_txt_path


@pytest.fixture
def temp_uv_secure_toml_file_ignored_vulnerability(tmp_path: Path) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        [vulnerability_criteria]
        ignore_vulnerabilities = ["VULN-123"]
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_uv_secure_toml_file_ignored_package(tmp_path: Path) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        [ignore_packages]
        example-package = []
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_uv_secure_toml_file_direct_dependency_vulnerabilities_only(
    tmp_path: Path,
) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        [vulnerability_criteria]
        check_direct_dependencies_only = true
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_uv_secure_toml_file_direct_dependency_maintenance_issues_only(
    tmp_path: Path,
) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        [maintainability_criteria]
        max_package_age = "P1000D"
        forbid_yanked = true
        check_direct_dependencies_only = true
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_uv_secure_toml_file_all_columns_enabled(tmp_path: Path) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        [vulnerability_criteria]
        aliases = true
        desc = true
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled(
    tmp_path: Path,
) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        [vulnerability_criteria]
        aliases = true
        desc = true

        [maintainability_criteria]
        max_package_age = "P1000D"
        forbid_yanked = true
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_uv_secure_toml_file_json_format(tmp_path: Path) -> Path:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
        format = "json"
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_pyproject_toml_file_json_format(tmp_path: Path) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    pyproject_toml_data = """
        [tool.uv-secure]
        format = "json"
    """
    pyproject_toml_path.write_text(dedent(pyproject_toml_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_dot_uv_secure_toml_file(tmp_path: Path) -> Path:
    uv_secure_toml_path = tmp_path / ".uv-secure.toml"
    uv_lock_data = ""
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_nested_uv_secure_toml_file_ignored_vulnerability(tmp_path: Path) -> Path:
    nested_uv_lock_path = tmp_path / "nested_project"
    uv_secure_toml_path = nested_uv_lock_path / "uv-secure.toml"
    uv_lock_data = """
    [vulnerability_criteria]
    ignore_vulnerabilities = ["VULN-123"]
    """
    uv_secure_toml_path.write_text(dedent(uv_lock_data).strip())
    return uv_secure_toml_path


@pytest.fixture
def temp_pyproject_toml_file(tmp_path: Path) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure]
    """
    pyproject_toml_path.write_text(dedent(uv_lock_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_pyproject_toml_file_direct_dependency_vulnerabilities_only(
    tmp_path: Path,
) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure.vulnerability_criteria]
    check_direct_dependencies_only = true
    """
    pyproject_toml_path.write_text(dedent(uv_lock_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_pyproject_toml_file_direct_dependency_maintenance_issues_only(
    tmp_path: Path,
) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure.maintainability_criteria]
    max_package_age = "P1000D"
    forbid_yanked = true
    check_direct_dependencies_only = true
    """
    pyproject_toml_path.write_text(dedent(uv_lock_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_pyproject_toml_file_extra_columns_enabled(tmp_path: Path) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure.vulnerability_criteria]
    aliases = true
    desc = true
    """
    pyproject_toml_path.write_text(dedent(uv_lock_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_pyproject_toml_file_ignored_vulnerability(tmp_path: Path) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure.vulnerability_criteria]
    ignore_vulnerabilities = ["VULN-123"]
    """
    pyproject_toml_path.write_text(dedent(uv_lock_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_pyproject_toml_file_ignored_package(tmp_path: Path) -> Path:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure.ignore_packages]
    example-package = [">=1.0, <2.0"]
    """
    pyproject_toml_path.write_text(dedent(uv_lock_data).strip())
    return pyproject_toml_path


@pytest.fixture
def temp_nested_pyproject_toml_file_no_config(tmp_path: Path) -> Path:
    pyproject_toml_path = tmp_path / "nested_project" / "pyproject.toml"
    uv_lock_data = ""
    pyproject_toml_path.write_text(uv_lock_data)
    return pyproject_toml_path


@pytest.fixture
def temp_nested_uv_lock_file(tmp_path: Path) -> Path:
    nested_uv_lock_path = tmp_path / "nested_project"
    nested_uv_lock_path.mkdir()
    uv_lock_path = nested_uv_lock_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "example-package"
    version = "2.0.0"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_double_nested_uv_lock_file(tmp_path: Path) -> Path:
    double_nested_uv_lock_path = tmp_path / "nested_project" / "double_nested_project"
    double_nested_uv_lock_path.mkdir(parents=True)
    uv_lock_path = double_nested_uv_lock_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "example-package"
    version = "2.0.0"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def no_vulnerabilities_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        headers={"cache-control": "max-age=900, public"},
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
            "vulnerabilities": [],
        },
    )
    return httpx_mock


@pytest.fixture
def no_vulnerabilities_response_header_check(httpx_mock: HTTPXMock) -> HTTPXMock:
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
            "vulnerabilities": [],
        },
        match_headers={"User-Agent": USER_AGENT},
    )
    return httpx_mock


@pytest.fixture
def no_vulnerabilities_response_direct_dependency(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/direct-dependency/1.0.0/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "A minimal package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "direct-dependency",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/direct-dependency/1.0.0/",
                "requires_python": ">=3.9",
                "summary": "A minimal package example",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [],
        },
    )
    return httpx_mock


@pytest.fixture
def one_vulnerability_response(httpx_mock: HTTPXMock) -> HTTPXMock:
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
                    "aliases": ["CVE-2024-12345"],
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": ["1.0.1"],
                    "link": "https://example.com/vuln-123",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def withdrawn_vulnerability_response(httpx_mock: HTTPXMock) -> HTTPXMock:
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
                    "aliases": ["CVE-2024-12345"],
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": None,
                    "link": "https://example.com/vuln-123",
                    "withdrawn": "2024-06-28T16:39:06Z",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def one_vulnerability_response_indirect_dependency(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/indirect-dependency/1.5.0/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "A minimal package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "indirect-dependency",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/indirect-dependency/1.5.0/",
                "requires_python": ">=3.9",
                "summary": "A minimal package example",
                "version": "1.5.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [
                {
                    "aliases": ["CVE-2024-12345"],
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": ["1.5.1"],
                    "link": "https://example.com/vuln-123",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def one_maintenance_issue_response_indirect_dependency(
    httpx_mock: HTTPXMock,
) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/indirect-dependency/1.5.0/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "A minimal package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "indirect-dependency",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/indirect-dependency/1.5.0/",
                "requires_python": ">=3.9",
                "summary": "A minimal package example",
                "version": "1.5.0",
                "yanked": True,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [],
        },
    )
    return httpx_mock


@pytest.fixture
def old_yanked_package_response(httpx_mock: HTTPXMock) -> HTTPXMock:
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
                "yanked": True,
                "yanked_reason": "Broken API",
            },
            "last_serial": 1,
            "urls": [
                {
                    "comment_text": "",
                    "digests": {
                        "blake2b_256": (
                            "0bf785273299ab57117850cc0a936c64151171fac4da49bc6fba0dad98"
                            "4a7c5f"
                        ),
                        "md5": "8626f021f29631950dfad7b4c6435fc4",
                        "sha256": (
                            "8a3df80e2b2378aef598a83c1392efd47967afec4242021a0b06b4c7cb"
                            "c61a92"
                        ),
                    },
                    "downloads": -1,
                    "filename": "example-package-1.0.0-py3-none-any.whl",
                    "has_sig": False,
                    "md5_digest": "8626f021f29631950dfad7b4c6435fc4",
                    "packagetype": "bdist_wheel",
                    "python_version": "py3",
                    "requires_python": ">=3.7",
                    "size": 15662,
                    "upload_time": "2021-01-19T23:44:28",
                    "upload_time_iso_8601": "2021-01-19T23:44:28.833863Z",
                    "url": (
                        "https://files.pythonhosted.org/packages/0b/f7/"
                        "85273299ab57117850cc0a936c64151171fac4da49bc6fba0dad984a7c5f/"
                        "example-package-1.0.0-py3-none-any.whl"
                    ),
                    "yanked": True,
                    "yanked_reason": "Broken API",
                }
            ],
            "vulnerabilities": [],
        },
    )
    return httpx_mock


@pytest.fixture
def yanked_package_no_reason_given_response(httpx_mock: HTTPXMock) -> HTTPXMock:
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
                "yanked": True,
            },
            "last_serial": 1,
            "urls": [
                {
                    "comment_text": "",
                    "digests": {
                        "blake2b_256": (
                            "0bf785273299ab57117850cc0a936c64151171fac4da49bc6fba0dad98"
                            "4a7c5f"
                        ),
                        "md5": "8626f021f29631950dfad7b4c6435fc4",
                        "sha256": (
                            "8a3df80e2b2378aef598a83c1392efd47967afec4242021a0b06b4c7cb"
                            "c61a92"
                        ),
                    },
                    "downloads": -1,
                    "filename": "example-package-1.0.0-py3-none-any.whl",
                    "has_sig": False,
                    "md5_digest": "8626f021f29631950dfad7b4c6435fc4",
                    "packagetype": "bdist_wheel",
                    "python_version": "py3",
                    "requires_python": ">=3.7",
                    "size": 15662,
                    "upload_time": "2024-01-19T23:44:28",
                    "upload_time_iso_8601": "2024-01-19T23:44:28.833863Z",
                    "url": (
                        "https://files.pythonhosted.org/packages/0b/f7/"
                        "85273299ab57117850cc0a936c64151171fac4da49bc6fba0dad984a7c5f/"
                        "example-package-1.0.0-py3-none-any.whl"
                    ),
                    "yanked": True,
                }
            ],
            "vulnerabilities": [],
        },
    )
    return httpx_mock


@pytest.fixture
def old_yanked_package_with_vulnerability_response(httpx_mock: HTTPXMock) -> HTTPXMock:
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
                "yanked": True,
                "yanked_reason": "Broken API",
            },
            "last_serial": 1,
            "urls": [
                {
                    "comment_text": "",
                    "digests": {
                        "blake2b_256": (
                            "0bf785273299ab57117850cc0a936c64151171fac4da49bc6fba0dad98"
                            "4a7c5f"
                        ),
                        "md5": "8626f021f29631950dfad7b4c6435fc4",
                        "sha256": (
                            "8a3df80e2b2378aef598a83c1392efd47967afec4242021a0b06b4c7cb"
                            "c61a92"
                        ),
                    },
                    "downloads": -1,
                    "filename": "example-package-1.0.0-py3-none-any.whl",
                    "has_sig": False,
                    "md5_digest": "8626f021f29631950dfad7b4c6435fc4",
                    "packagetype": "bdist_wheel",
                    "python_version": "py3",
                    "requires_python": ">=3.7",
                    "size": 15662,
                    "upload_time": "2021-01-19T23:44:28",
                    "upload_time_iso_8601": "2021-01-19T23:44:28.833863Z",
                    "url": (
                        "https://files.pythonhosted.org/packages/0b/f7/"
                        "85273299ab57117850cc0a936c64151171fac4da49bc6fba0dad984a7c5f/"
                        "example-package-1.0.0-py3-none-any.whl"
                    ),
                    "yanked": True,
                    "yanked_reason": "Broken API",
                }
            ],
            "vulnerabilities": [
                {
                    "aliases": ["CVE-2024-12345"],
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": ["1.0.1"],
                    "link": "https://example.com/vuln-123",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def temp_uv_lock_file_jinja2(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "jinja2"
    version = "3.1.4"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def jinja2_two_longer_vulnerability_responses(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/jinja2/3.1.4/json",
        json={
            "info": {
                "author_email": "example@example.com",
                "classifiers": [],
                "description": "Jinja2 templating",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "jinja2",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/jinja2/3.1.4/",
                "requires_python": ">=3.9",
                "summary": "Jinja2 templating",
                "version": "3.1.4",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [
                {
                    "aliases": ["CVE-2024-56326"],
                    "details": (
                        "An oversight in how the Jinja sandboxed environment detects "
                        "calls to `str.format` allows an attacker that controls the "
                        "content of a template to execute arbitrary Python code.\n\nTo "
                        "exploit the vulnerability, an attacker needs to control the "
                        "content of a template. Whether that is the case depends on "
                        "the type of application using Jinja. This vulnerability "
                        "impacts users of applications which execute untrusted "
                        "templates.\n\nJinja's sandbox does catch calls to "
                        "`str.format` and ensures they don't escape the sandbox. "
                        "However, it's possible to store a reference to a malicious "
                        "string's `format` method, then pass that to a filter that "
                        "calls it. No such filters are built-in to Jinja, but could be "
                        "present through custom filters in an application. After the "
                        "fix, such indirect calls are also handled by the sandbox."
                    ),
                    "fixed_in": ["3.1.5"],
                    "id": "GHSA-q2x7-8rv6-6q7h",
                    "link": "https://osv.dev/vulnerability/GHSA-q2x7-8rv6-6q7h",
                    "source": "osv",
                    "summary": None,
                    "withdrawn": None,
                },
                {
                    "aliases": ["CVE-2024-56201"],
                    "details": (
                        "A bug in the Jinja compiler allows an attacker that controls "
                        "both the content and filename of a template to execute "
                        "arbitrary Python code, regardless of if Jinja's sandbox is "
                        "used.\n\nTo exploit the vulnerability, an attacker needs to "
                        "control both the filename and the contents of a template. "
                        "Whether that is the case depends on the type of application "
                        "using Jinja. This vulnerability impacts users of applications "
                        "which execute untrusted templates where the template author "
                        "can also choose the template filename."
                    ),
                    "fixed_in": ["3.1.5"],
                    "id": "GHSA-gmj6-6f8f-6699",
                    "link": "https://osv.dev/vulnerability/GHSA-gmj6-6f8f-6699",
                    "source": "osv",
                    "summary": None,
                    "withdrawn": None,
                },
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def one_vulnerability_response_v2(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/2.0.0/json",
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
                "release_url": "https://pypi.org/project/example-package/2.0.0/",
                "requires_python": ">=3.9",
                "summary": "A minimal package example",
                "version": "2.0.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": ["2.0.1"],
                    "link": "https://example.com/vuln-123",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def package_version_not_found_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json", status_code=404
    )
    return httpx_mock


@pytest.fixture
def missing_vulnerability_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_exception(
        RequestError(
            "Request failed",
            request=Request("GET", "https://pypi.org/pypi/example-package/1.0.0/json"),
        )
    )
    return httpx_mock


@pytest.fixture(scope="session", autouse=True)
def wide_console() -> Generator:
    mp = pytest.MonkeyPatch()
    mp.setenv("COLUMNS", "400")
    yield mp
    mp.undo()


@pytest.fixture
def set_console_width(monkeypatch: pytest.MonkeyPatch) -> Callable[[int], None]:
    def _set_width(width: int) -> None:
        monkeypatch.setenv("COLUMNS", str(width))

    return _set_width


@pytest.fixture
def temp_uv_pylock_toml_file(tmp_path: Path) -> Path:
    pylock_toml_path = tmp_path / "pylock.toml"
    pylock_toml_data = """
        # This file was autogenerated by uv via the following command:
        #    uv export --format pylock.toml -o pylock.toml
        lock-version = "1.0"
        created-by = "uv"
        requires-python = ">=3.10"

        [[packages]]
        name = "example-package"
        version = "1.0.0"
        index = "https://pypi.org/simple"
    """
    pylock_toml_path.write_text(dedent(pylock_toml_data).strip())
    return pylock_toml_path


@pytest.fixture
def temp_uv_empty_pylock_toml_file(tmp_path: Path) -> Path:
    pylock_toml_path = tmp_path / "pylock.toml"
    pylock_toml_data = """
        # This file was autogenerated by uv via the following command:
        #    uv export --format pylock.toml -o pylock.toml
        lock-version = "1.0"
        created-by = "uv"
        requires-python = ">=3.10"
    """
    pylock_toml_path.write_text(dedent(pylock_toml_data).strip())
    return pylock_toml_path


@pytest.fixture
def temp_corrupted_uv_lock_file(tmp_path: Path) -> Path:
    """Create a ``uv.lock`` file that will cause parsing errors.

    Args:
        tmp_path: Temporary directory provided by pytest.

    Returns:
        Path: Path to the corrupted ``uv.lock`` file.
    """
    uv_lock_path = tmp_path / "uv.lock"
    # This will cause TOML parsing errors
    corrupted_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org/simple"  # Missing closing brace
        invalid toml syntax here
    """
    uv_lock_path.write_text(dedent(corrupted_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_corrupted_requirements_txt_file(tmp_path: Path) -> Path:
    """Create a ``requirements.txt`` file that will cause parsing errors.

    Args:
        tmp_path: Temporary directory provided by pytest.

    Returns:
        Path: Path to the malformed ``requirements.txt`` file.
    """
    requirements_path = tmp_path / "requirements.txt"
    # This will cause parsing errors when splitting on "=="
    # because there are multiple "==" characters
    corrupted_data = """
        # This file was autogenerated by uv via the following command:
        #    uv pip compile pyproject.toml -o requirements.txt
        example-package==1.0.0==invalid-extra-equals
        another-package===triple-equals
    """
    requirements_path.write_text(dedent(corrupted_data).strip())
    return requirements_path


@pytest.fixture
def temp_corrupted_pylock_toml_file(tmp_path: Path) -> Path:
    """Create a ``pylock.toml`` file that will cause parsing errors.

    Args:
        tmp_path: Temporary directory provided by pytest.

    Returns:
        Path: Path to the invalid ``pylock.toml`` file.
    """
    pylock_path = tmp_path / "pylock.toml"
    # This will cause TOML parsing errors
    corrupted_data = """
        # This file was autogenerated by uv via the following command:
        #    uv export --format pylock.toml -o pylock.toml
        lock-version = "1.0"
        created-by = "uv"
        requires-python = ">=3.10"

        [[packages]]
        name = "example-package"
        version = "1.0.0"
        index = "https://pypi.org/simple"
        invalid toml syntax here [
    """
    pylock_path.write_text(dedent(corrupted_data).strip())
    return pylock_path


# Specific fixtures for PyPI Simple JSON API


@pytest.fixture
def pypi_simple_example_package(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={"name": "example-package", "project-status": {"status": "active"}},
    )
    return httpx_mock


@pytest.fixture
def pypi_simple_example_package_twice(httpx_mock: HTTPXMock) -> HTTPXMock:
    # Two calls expected in the same test (e.g. scanning two lock files)
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={"name": "example-package", "project-status": {"status": "active"}},
    )
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={"name": "example-package", "project-status": {"status": "active"}},
    )
    return httpx_mock


@pytest.fixture
def pypi_simple_jinja2(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/simple/jinja2/",
        json={"name": "jinja2", "project-status": {"status": "active"}},
    )
    return httpx_mock


@pytest.fixture
def pypi_simple_direct_and_indirect(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/simple/direct-dependency/",
        json={"name": "direct-dependency", "project-status": {"status": "active"}},
    )
    httpx_mock.add_response(
        url="https://pypi.org/simple/indirect-dependency/",
        json={"name": "indirect-dependency", "project-status": {"status": "active"}},
    )
    return httpx_mock


@pytest.fixture
def temp_uv_lock_file_with_non_pypi_deps(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org/simple" }

        [[package]]
        name = "git-package"
        version = "0.1.0"
        source = { git = "https://github.com/example/git-package.git", tag = "v0.1.0" }

        [[package]]
        name = "private-package"
        version = "2.0.0"
        source = { registry = "https://private-registry.com/simple" }

        [[package]]
        name = "local-package"
        version = "0.1.0"
        source = { editable = "." }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def temp_pylock_toml_file_with_non_pypi_deps(tmp_path: Path) -> Path:
    pylock_toml_path = tmp_path / "pylock.toml"
    pylock_toml_data = """
        lock-version = "1.0"
        created-by = "uv"
        requires-python = ">=3.10"

        [[packages]]
        name = "example-package"
        version = "1.0.0"
        index = "https://pypi.org/simple"

        [[packages]]
        name = "git-package"
        version = "0.1.0"
        index = "https://github.com/example/git-package.git"

        [[packages]]
        name = "private-package"
        version = "2.0.0"
        index = "https://private-registry.com/simple"
    """
    pylock_toml_path.write_text(dedent(pylock_toml_data).strip())
    return pylock_toml_path


@pytest.fixture
def temp_uv_lock_file_only_non_pypi_deps(tmp_path: Path) -> Path:
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "git-package"
        version = "0.1.0"
        source = { git = "https://github.com/example/git-package.git", tag = "v0.1.0" }

        [[package]]
        name = "private-package"
        version = "2.0.0"
        source = { registry = "https://private-registry.com/simple" }

        [[package]]
        name = "local-package"
        version = "0.1.0"
        source = { editable = "." }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path


@pytest.fixture
def vulnerability_no_fix_versions_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    """Configure a vulnerability response with no available fixes.

    Args:
        httpx_mock: HTTPXMock fixture to configure.

    Returns:
        HTTPXMock: Mock primed with a PyPI response lacking fix versions.
    """
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
                    "id": "VULN-NO-FIX",
                    "details": "Vulnerability with no fix available",
                    "fixed_in": [],
                    "aliases": ["CVE-2024-12345"],
                    "link": "https://example.com/v",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def vulnerability_multiple_alias_types_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    """Configure a vulnerability response exercising all alias types.

    Args:
        httpx_mock: HTTPXMock fixture to configure.

    Returns:
        HTTPXMock: Mock primed with alias-heavy PyPI vulnerability data.
    """
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
                    "id": "VULN-ALIASES",
                    "details": "Vulnerability with all alias types",
                    "fixed_in": ["1.0.1"],
                    "aliases": [
                        "CVE-2024-12345",
                        "GHSA-xxxx-yyyy-zzzz",
                        "PYSEC-2024-12345",
                        "OSV-2024-12345",
                        "UNKNOWN-FORMAT-123",
                    ],
                    "link": "https://example.com/v",
                }
            ],
        },
    )
    return httpx_mock


@pytest.fixture
def vulnerability_no_aliases_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    """Configure a vulnerability response with no aliases.

    Args:
        httpx_mock: HTTPXMock fixture to configure.

    Returns:
        HTTPXMock: Mock primed with a vulnerability lacking alias metadata.
    """
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
                    "id": "VULN-NO-ALIASES",
                    "details": "Vulnerability with no aliases",
                    "fixed_in": ["1.0.1"],
                    "aliases": [],
                    "link": "https://example.com/v",
                }
            ],
        },
    )
    return httpx_mock
