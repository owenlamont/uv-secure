from pathlib import Path

from _pytest.capture import CaptureFixture
import pytest
from pytest_httpx import HTTPXMock
from pytest_mock import MockFixture
from typer.testing import CliRunner

from uv_secure import app, check_dependencies


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


def test_app(mocker: MockFixture) -> None:
    mock_check_dependencies = mocker.patch("uv_secure.run.check_dependencies")
    result = runner.invoke(app, ("--uv-lock-path", "uv.lock"))
    mock_check_dependencies.assert_called_once_with(Path("uv.lock"), [])
    assert result.exit_code == 0


def test_app_version() -> None:
    result = runner.invoke(app, "--version")
    assert result.exit_code == 0
    assert "uv-secure " in result.output


def test_check_dependencies_no_vulnerabilities(
    temp_uv_lock_file: Path, httpx_mock: HTTPXMock, capsys: CaptureFixture[str]
) -> None:
    """Test check_dependencies with a single dependency and no vulnerabilities."""
    # Mock PyPI JSON API response with no vulnerabilities
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={"vulnerabilities": []},
    )

    # Run the check_dependencies function
    exit_code = check_dependencies(temp_uv_lock_file, ignore_ids=[])

    # Capture the console output
    captured = capsys.readouterr()

    # Assertions
    assert exit_code == 0
    assert "No vulnerabilities detected!" in captured.out
    assert "Checked: 1 dependency" in captured.out
    assert "All dependencies appear safe!" in captured.out


def test_check_dependencies_with_vulnerability(
    temp_uv_lock_file: Path, httpx_mock: HTTPXMock, capsys: CaptureFixture[str]
) -> None:
    """Test check_dependencies with a single dependency and a single vulnerability."""
    # Mock PyPI JSON API response with one vulnerability
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

    # Run the check_dependencies function
    exit_code = check_dependencies(temp_uv_lock_file, ignore_ids=[])

    # Capture the console output
    captured = capsys.readouterr()

    # Assertions
    assert exit_code == 1
    assert "Vulnerabilities detected!" in captured.out
    assert "Checked: 1 dependency" in captured.out
    assert "Vulnerable: 1 dependency" in captured.out
    assert "example-package" in captured.out
    assert "VULN-123" in captured.out
    assert "A critical vulnerability in" in captured.out
    assert "example-package." in captured.out
