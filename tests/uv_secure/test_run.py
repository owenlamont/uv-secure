import os
from pathlib import Path

from httpx import Request, RequestError
import pytest
from pytest_httpx import HTTPXMock
from typer.testing import CliRunner

from uv_secure import app


runner = CliRunner()


@pytest.fixture
def temp_uv_lock_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "example-package"
    version = "1.0.0"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(uv_lock_data)
    return uv_lock_path


@pytest.fixture
def temp_uv_secure_toml_file_ignored_vulnerability(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_lock_data = """
    ignore_vulnerabilities = ["VULN-123"]
    """
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_dot_uv_secure_toml_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_secure_toml_path = tmp_path / ".uv-secure.toml"
    uv_lock_data = ""
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_nested_uv_secure_toml_file_ignored_vulnerability(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    nested_uv_lock_path = tmp_path / "nested_project"
    uv_secure_toml_path = nested_uv_lock_path / "uv-secure.toml"
    uv_lock_data = """
    ignore_vulnerabilities = ["VULN-123"]
    """
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_pyproject_toml_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_secure_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure]
    """
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_pyproject_toml_file_ignored_vulnerability(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_secure_toml_path = tmp_path / "pyproject.toml"
    uv_lock_data = """
    [tool.uv-secure]
    ignore_vulnerabilities = ["VULN-123"]
    """
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_nested_pyproject_toml_file_no_config(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_secure_toml_path = tmp_path / "nested_project" / "pyproject.toml"
    uv_lock_data = ""
    uv_secure_toml_path.write_text(uv_lock_data)
    return uv_secure_toml_path


@pytest.fixture
def temp_nested_uv_lock_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    nested_uv_lock_path = tmp_path / "nested_project"
    nested_uv_lock_path.mkdir()
    uv_lock_path = nested_uv_lock_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "example-package"
    version = "2.0.0"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(uv_lock_data)
    return uv_lock_path


@pytest.fixture
def temp_double_nested_uv_lock_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    double_nested_uv_lock_path = tmp_path / "nested_project" / "double_nested_project"
    double_nested_uv_lock_path.mkdir(parents=True)
    uv_lock_path = double_nested_uv_lock_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "example-package"
    version = "2.0.0"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(uv_lock_data)
    return uv_lock_path


@pytest.fixture
def no_vulnerabilities_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={"vulnerabilities": []},
    )
    return httpx_mock


@pytest.fixture
def one_vulnerability_response(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "vulnerabilities": [
                {
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": ["1.0.1"],
                    "link": "https://example.com/vuln-123",
                }
            ]
        },
    )
    return httpx_mock


@pytest.fixture
def temp_uv_lock_file_jinja2(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single jinja2 dependency."""
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
    [[package]]
    name = "jinja2"
    version = "3.1.4"
    source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(uv_lock_data)
    return uv_lock_path


@pytest.fixture
def jinja2_two_longer_vulnerability_responses(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/jinja2/3.1.4/json",
        json={
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
            ]
        },
    )
    return httpx_mock


@pytest.fixture
def one_vulnerability_response_v2(httpx_mock: HTTPXMock) -> HTTPXMock:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/2.0.0/json",
        json={
            "vulnerabilities": [
                {
                    "id": "VULN-123",
                    "details": "A critical vulnerability in example-package.",
                    "fixed_in": ["2.0.1"],
                    "link": "https://example.com/vuln-123",
                }
            ]
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


def test_app_version() -> None:
    result = runner.invoke(app, "--version")
    assert result.exit_code == 0
    assert "uv-secure " in result.output


def test_bad_file_name() -> None:
    result = runner.invoke(app, "i_dont_exist.txt")
    assert result.exit_code == 2
    assert "Error" in result.output


def test_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, [str(tmp_path / "uv.lock")])
    assert result.exit_code == 2
    assert "Error" in result.output


def test_app_no_vulnerabilities(
    temp_uv_lock_file: Path, no_vulnerabilities_response: HTTPXMock
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file)])

    assert result.exit_code == 0
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_app_no_vulnerabilities_relative_lock_file_path(
    tmp_path: Path, temp_uv_lock_file: Path, no_vulnerabilities_response: HTTPXMock
) -> None:
    os.chdir(tmp_path)
    result = runner.invoke(app, ["uv.lock"])

    assert result.exit_code == 0
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_app_no_vulnerabilities_relative_no_specified_path(
    tmp_path: Path, temp_uv_lock_file: Path, no_vulnerabilities_response: HTTPXMock
) -> None:
    os.chdir(tmp_path)
    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_app_failed_vulnerability_request(
    temp_uv_lock_file: Path, missing_vulnerability_response: HTTPXMock
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file)])

    assert result.exit_code == 0
    assert "Error fetching example-package==1.0.0: Request failed" in result.output
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_app_package_not_found(
    temp_uv_lock_file: Path, package_version_not_found_response: HTTPXMock
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file)])

    assert result.exit_code == 0
    assert "Warning: Could not fetch data for example-package==1.0.0" in result.output
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_check_dependencies_with_vulnerability(
    temp_uv_lock_file: Path, one_vulnerability_response: HTTPXMock
) -> None:
    """Test check_dependencies with a single dependency and a single vulnerability."""
    result = runner.invoke(app, [str(temp_uv_lock_file)])

    assert result.exit_code == 1
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 dependency" in result.output
    assert "example-package │" in result.output
    assert "VULN-123" in result.output
    assert "A critical" in result.output
    assert "vulnerability in" in result.output
    assert "example-package." in result.output


def test_check_dependencies_with_two_longer_vulnerabilities(
    temp_uv_lock_file_jinja2: Path, jinja2_two_longer_vulnerability_responses: HTTPXMock
) -> None:
    """Test check_dependencies with a single dependency and a single vulnerability."""
    result = runner.invoke(app, [str(temp_uv_lock_file_jinja2)])

    assert result.exit_code == 1
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 dependency" in result.output
    assert "jinja2" in result.output
    assert "3.1.4" in result.output
    assert "GHSA-q2x7-8rv6-6q7h" in result.output
    assert "GHSA-gmj6-6f8f-6699" in result.output


def test_app_with_arg_ignored_vulnerability(
    temp_uv_lock_file: Path, one_vulnerability_response: HTTPXMock
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--ignore", "VULN-123"])

    assert result.exit_code == 0
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_check_dependencies_with_vulnerability_pyproject_toml_argument_override(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_ignored_vulnerability: Path,
    one_vulnerability_response: HTTPXMock,
) -> None:
    """Test check_dependencies with a single dependency and a single vulnerability."""
    result = runner.invoke(app, [str(temp_uv_lock_file), "--ignore", "VULN-NOT-HERE"])

    assert result.exit_code == 1
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 dependency" in result.output
    assert "example-package │" in result.output
    assert "VULN-123" in result.output
    assert "A critical" in result.output
    assert "vulnerability in" in result.output
    assert "example-package." in result.output


def test_app_with_uv_secure_toml_ignored_vulnerability(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_ignored_vulnerability: Path,
    one_vulnerability_response: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--config",
            temp_uv_secure_toml_file_ignored_vulnerability,
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_app_with_pyproject_toml_ignored_vulnerability(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_ignored_vulnerability: Path,
    one_vulnerability_response: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--config",
            temp_pyproject_toml_file_ignored_vulnerability,
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output


def test_app_multiple_lock_files_no_vulnerabilities(
    temp_uv_lock_file: Path, temp_nested_uv_lock_file: Path, httpx_mock: HTTPXMock
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={"vulnerabilities": []},
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/2.0.0/json",
        json={"vulnerabilities": []},
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), str(temp_nested_uv_lock_file)])

    assert result.exit_code == 0
    assert result.output.count("No vulnerabilities detected!") == 2
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 1


def test_app_multiple_lock_files_one_vulnerabilities(
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), str(temp_nested_uv_lock_file)])
    assert result.exit_code == 1
    assert result.output.count("No vulnerabilities detected!") == 1
    assert result.output.count("Vulnerabilities detected!") == 1


def test_app_multiple_lock_files_one_nested_ignored_vulnerability(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    temp_dot_uv_secure_toml_file: Path,
    temp_nested_uv_secure_toml_file_ignored_vulnerability: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 0
    assert result.output.count("No vulnerabilities detected!") == 2
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 1


def test_app_multiple_lock_files_no_root_config_one_nested_ignored_vulnerability(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    temp_double_nested_uv_lock_file: Path,
    temp_nested_uv_secure_toml_file_ignored_vulnerability: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 0
    assert result.output.count("No vulnerabilities detected!") == 2
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 2


def test_app_multiple_lock_files_one_nested_ignored_vulnerability_pass_lock_files(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    temp_double_nested_uv_lock_file: Path,
    temp_nested_uv_secure_toml_file_ignored_vulnerability: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), str(temp_double_nested_uv_lock_file)]
    )

    assert result.exit_code == 0
    assert result.output.count("No vulnerabilities detected!") == 2
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 2


def test_app_multiple_lock_files_one_vulnerabilities_ignored_nested_pyproject_toml(
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    temp_pyproject_toml_file: Path,
    temp_nested_pyproject_toml_file_no_config: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), str(temp_nested_uv_lock_file)])
    assert result.exit_code == 1
    assert result.output.count("No vulnerabilities detected!") == 1
    assert result.output.count("Vulnerabilities detected!") == 1
