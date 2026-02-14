import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from textwrap import dedent
from typing import Any

from freezegun import freeze_time
from httpx import Request, RequestError
import pytest
from pytest_httpx import HTTPXMock
from pytest_mock import MockerFixture
from typer.testing import CliRunner

from uv_secure import __version__, app


runner = CliRunner()


pytestmark = pytest.mark.usefixtures("uv_http_responses", "uv_secure_http_responses")


def assert_no_markup_escape_artifacts(output: str) -> None:
    """Ensure Rich markup artifacts or double escapes are absent from output."""

    assert "\x1b\x1b" not in output
    assert "[/]" not in output


def assert_table_rendered(output: str, title: str) -> None:
    """Ensure a Rich table with the given title is present in output."""

    assert title in output
    top_left_candidates = {"┏", "┌", "╭"}
    bottom_right_candidates = {"┘", "┛", "╯"}
    assert any(char in output for char in top_left_candidates)
    assert any(char in output for char in bottom_right_candidates)


def get_file_output(output: dict[str, Any], file_path: str) -> dict[str, Any]:
    """Return JSON entry for ``file_path``.

    Raises:
        AssertionError: When the requested file entry is absent.
    """

    files: list[dict[str, Any]] = output["files"]
    for file_entry in files:
        if file_entry["file_path"] == file_path:
            return file_entry
    raise AssertionError(f"Missing file entry for {file_path}")


def test_get_file_output_missing_entry() -> None:
    with pytest.raises(AssertionError):
        get_file_output({"files": []}, "missing.json")


def test_get_file_output_skips_non_matching_entry() -> None:
    files = [
        {"file_path": "ignore", "dependencies": []},
        {"file_path": "target", "dependencies": []},
    ]
    result = get_file_output({"files": files}, "target")
    assert result["file_path"] == "target"


def test_app_version() -> None:
    result = runner.invoke(app, "--version")
    assert result.exit_code == 0
    pattern = r"uv-secure \d+\.\d+\.\d+"
    assert re.search(pattern, result.output), (
        f"Expected semantic version pattern, got: {result.output!r}"
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_bad_file_name() -> None:
    result = runner.invoke(app, ["i_dont_exist.txt", "--disable-cache"])
    assert result.exit_code == 3
    assert "Error" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_bad_file_name_json_error_envelope() -> None:
    result = runner.invoke(
        app, ["i_dont_exist.txt", "--disable-cache", "--format", "json"]
    )
    assert result.exit_code == 3
    output = json.loads(result.output)
    assert output["files"] == []
    assert output["errors"][0]["code"] == "invalid_file_paths"


def test_bad_pyproject_toml_config_file(tmp_path: Path) -> None:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    pyproject_toml_contents = """
        [tool.uv-secure]
        aliases = true
        desc = true
    """
    pyproject_toml_path.write_text(dedent(pyproject_toml_contents).strip())
    result = runner.invoke(app, [str(tmp_path / "uv.lock"), "--disable-cache"])
    assert "Error: Parsing uv-secure configuration at: " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_bad_pyproject_toml_config_file_json_error_envelope(tmp_path: Path) -> None:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    pyproject_toml_contents = """
        [tool.uv-secure]
        aliases = true
        desc = true
    """
    pyproject_toml_path.write_text(dedent(pyproject_toml_contents).strip())
    result = runner.invoke(
        app, [str(tmp_path / "uv.lock"), "--disable-cache", "--format", "json"]
    )
    assert result.exit_code == 3
    output = json.loads(result.output)
    assert output["files"] == []
    assert output["errors"][0]["code"] == "configuration_error"


def test_bad_uv_secure_toml_config_file(tmp_path: Path) -> None:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_secure_toml = """
        aliases = true
        desc = true
    """
    uv_secure_toml_path.write_text(dedent(uv_secure_toml).strip())
    result = runner.invoke(app, [str(tmp_path / "uv.lock"), "--disable-cache"])
    assert "Error: Parsing uv-secure configuration at: " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, [str(tmp_path / "uv.lock"), "--disable-cache"])
    assert result.exit_code == 3
    assert "Error" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_non_uv_requirements_txt_file(
    temp_non_uv_requirements_txt_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_non_uv_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_unpinned_requirements_txt_file(
    temp_unpinned_requirements_txt_file: Path,
) -> None:
    result = runner.invoke(
        app, [str(temp_unpinned_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 3
    assert "Failed to parse" in result.output
    assert "dependencies must be fully pinned" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_wildcard_requirements_txt_file(
    temp_wildcard_requirements_txt_file: Path,
) -> None:
    result = runner.invoke(
        app, [str(temp_wildcard_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 3
    assert "Failed to parse" in result.output
    assert "dependencies must be fully pinned" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_comment_requirements_txt_file(
    temp_comment_requirements_txt_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_comment_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_extras_requirements_txt_file(
    temp_extras_requirements_txt_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_extras_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_env_marker_requirements_txt_file(
    temp_env_marker_requirements_txt_file: Path,
) -> None:
    result = runner.invoke(
        app, [str(temp_env_marker_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 3
    assert "Failed to parse" in result.output
    assert "dependencies must be fully pinned" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_hash_requirements_txt_file(temp_hash_requirements_txt_file: Path) -> None:
    result = runner.invoke(
        app, [str(temp_hash_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 3
    assert "Failed to parse" in result.output
    assert "dependencies must be fully pinned" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_no_vulnerabilities(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_agent_headers(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response_header_check: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])
    assert result.exit_code == 0
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_reports_uv_tool_vulnerability(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    async def _fake_version() -> str | None:
        await asyncio.sleep(0)
        return "0.9.5"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_version
    )

    httpx_mock.add_response(
        url="https://pypi.org/pypi/uv/0.9.5/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "Vulnerable uv",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "uv",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/uv/0.9.5/",
                "requires_python": ">=3.9",
                "summary": "uv release",
                "version": "0.9.5",
                "yanked": False,
            },
            "last_serial": 42,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "UV-ALERT",
                    "details": "Remote code execution",
                    "fixed_in": ["0.9.6"],
                    "link": "https://example.com/uv-alert",
                }
            ],
        },
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "uv (global tool)" in result.output
    assert "UV-ALERT" in result.output
    assert "0.9.5" in result.output


def test_app_disable_uv_tool_flag_skips_check(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    uv_called = False
    uv_secure_called = False

    async def _fake_version() -> str | None:
        nonlocal uv_called
        uv_called = True
        await asyncio.sleep(0)
        return "0.9.9"

    def _fake_uv_secure_version() -> str | None:
        nonlocal uv_secure_called
        uv_secure_called = True
        return __version__

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_version
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--no-check-uv-tool"]
    )

    assert result.exit_code == 0
    assert uv_called is False
    assert uv_secure_called is True
    assert "uv (global tool)" not in result.output
    assert "uv-secure (installed package)" not in result.output

    asyncio.run(_fake_version())
    _fake_uv_secure_version()


def test_app_config_disables_uv_tool_check(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    config_path = temp_uv_lock_file.with_name("uv-secure.toml")
    config_path.write_text("check_uv_tool = false\n")

    uv_called = False
    uv_secure_called = False

    async def _fake_version() -> str | None:
        nonlocal uv_called
        uv_called = True
        await asyncio.sleep(0)
        return "0.9.9"

    def _fake_uv_secure_version() -> str | None:
        nonlocal uv_secure_called
        uv_secure_called = True
        return __version__

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_version
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--config", str(config_path)]
    )

    assert result.exit_code == 0
    assert uv_called is False
    assert uv_secure_called is True

    asyncio.run(_fake_version())
    _fake_uv_secure_version()


def test_app_disable_uv_secure_flag_skips_check(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    uv_called = False
    uv_secure_called = False

    async def _fake_version() -> str | None:
        nonlocal uv_called
        uv_called = True
        await asyncio.sleep(0)
        return "0.9.9"

    def _fake_uv_secure_version() -> str | None:
        nonlocal uv_secure_called
        uv_secure_called = True
        return __version__

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_version
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--no-check-uv-secure"]
    )

    assert result.exit_code == 0
    assert uv_called is True
    assert uv_secure_called is False
    assert "uv-secure (installed package)" not in result.output

    asyncio.run(_fake_version())
    _fake_uv_secure_version()


def test_app_config_disables_uv_secure_check(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    config_path = temp_uv_lock_file.with_name("uv-secure.toml")
    config_path.write_text("check_uv_secure = false\n")

    uv_called = False
    uv_secure_called = False

    async def _fake_version() -> str | None:
        nonlocal uv_called
        uv_called = True
        await asyncio.sleep(0)
        return "0.9.9"

    def _fake_uv_secure_version() -> str | None:
        nonlocal uv_secure_called
        uv_secure_called = True
        return __version__

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_version
    )
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--config", str(config_path)]
    )

    assert result.exit_code == 0
    assert uv_called is True
    assert uv_secure_called is False

    asyncio.run(_fake_version())
    _fake_uv_secure_version()


def test_app_reports_uv_secure_package_vulnerability(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    def _fake_uv_secure_version() -> str | None:
        return "9.9.9"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )

    httpx_mock.add_response(
        url="https://pypi.org/pypi/uv-secure/9.9.9/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "Vulnerable uv-secure",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "uv-secure",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/uv-secure/9.9.9/",
                "requires_python": ">=3.10",
                "summary": "uv-secure release",
                "version": "9.9.9",
                "yanked": False,
            },
            "last_serial": 42,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "UV-SECURE-ALERT",
                    "details": "Privilege escalation",
                    "fixed_in": ["9.9.10"],
                    "link": "https://example.com/uv-secure-alert",
                }
            ],
        },
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "uv-secure (installed package)" in result.output
    assert "UV-SECURE-ALERT" in result.output
    assert "9.9.9" in result.output


def test_app_invalid_uv_secure_local_version_is_skipped(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.__version__", "local-dev-build"
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "uv-secure (installed package)" not in result.output
    assert "No vulnerabilities or maintenance issues detected!" in result.output


def test_app_unpublished_uv_secure_version_is_skipped(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    def _fake_uv_secure_version() -> str | None:
        return "9999.0.0"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )

    httpx_mock.add_response(
        url="https://pypi.org/pypi/uv-secure/9999.0.0/json",
        status_code=404,
        json={"message": "Not Found"},
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "uv-secure (installed package)" not in result.output
    assert "No vulnerabilities or maintenance issues detected!" in result.output


def test_app_ignore_pkgs_skips_uv_secure_package_check(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    def _fake_uv_secure_version() -> str | None:
        return "9.9.8"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/uv-secure/9.9.8/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "Vulnerable uv-secure",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "uv-secure",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/uv-secure/9.9.8/",
                "requires_python": ">=3.10",
                "summary": "uv-secure release",
                "version": "9.9.8",
                "yanked": False,
            },
            "last_serial": 42,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "UV-SECURE-ALERT",
                    "details": "Privilege escalation",
                    "fixed_in": ["9.9.9"],
                    "link": "https://example.com/uv-secure-alert",
                }
            ],
        },
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--ignore-pkgs", "uv-secure"]
    )

    assert result.exit_code == 0
    assert "uv-secure (installed package)" not in result.output
    assert "No vulnerabilities or maintenance issues detected!" in result.output


def test_app_non_404_uv_secure_error_is_reported(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    def _fake_uv_secure_version() -> str | None:
        return "9.9.7"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_secure_version",
        _fake_uv_secure_version,
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/uv-secure/9.9.7/json",
        status_code=500,
        json={"message": "Server error"},
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 3
    assert "uv-secure raised exception:" in result.output


def test_app_unpublished_uv_tool_version_is_skipped(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    mocker: MockerFixture,
) -> None:
    async def _fake_uv_version() -> str | None:
        await asyncio.sleep(0)
        return "9999.0.0"

    mocker.patch(
        "uv_secure.dependency_checker.tool_audit.detect_uv_version", _fake_uv_version
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/uv/9999.0.0/json",
        status_code=404,
        json={"message": "Not Found"},
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "uv (global tool)" not in result.output


def test_app_no_vulnerabilities_requirements_txt(
    temp_uv_requirements_txt_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_requirements_txt_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_no_vulnerabilities_pylock_toml(
    temp_uv_pylock_toml_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_pylock_toml_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_vulnerabilities_pylock_toml(
    temp_uv_pylock_toml_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_pylock_toml_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert_table_rendered(result.output, "Vulnerable Dependencies")
    assert_no_markup_escape_artifacts(result.output)


def test_app_empty_requirements_txt(temp_uv_empty_requirements_txt_file: Path) -> None:
    result = runner.invoke(
        app, [str(temp_uv_empty_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 0 dependencies" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_empty_pylock_toml(temp_uv_empty_pylock_toml_file: Path) -> None:
    result = runner.invoke(
        app, [str(temp_uv_empty_pylock_toml_file), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 0 dependencies" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_no_vulnerabilities_requirements_txt_no_specified_path(
    tmp_path: Path,
    temp_uv_requirements_txt_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    os.chdir(tmp_path)
    result = runner.invoke(app, ["--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_no_vulnerabilities_pylock_toml_no_specified_path(
    tmp_path: Path,
    temp_uv_pylock_toml_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    os.chdir(tmp_path)
    result = runner.invoke(app, ["--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_no_vulnerabilities_relative_lock_file_path(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    os.chdir(tmp_path)
    result = runner.invoke(app, ["uv.lock", "--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_no_vulnerabilities_relative_no_specified_path(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    os.chdir(tmp_path)
    result = runner.invoke(app, ["--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


@freeze_time(datetime(2025, 1, 30, tzinfo=timezone.utc))
def test_app_maintenance_issues_cli_args(
    temp_uv_lock_file: Path,
    old_yanked_package_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--forbid-yanked",
            "--max-age-days",
            "1000",
            "--disable-cache",
        ],
    )

    assert result.exit_code == 1
    assert "Maintenance Issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Issues: 1 issue" in result.output
    assert "Maintenance Issues" in result.output
    assert "Broken API" in result.output
    assert "4 years and 11.01 days" in result.output
    # New columns present and values for project status
    assert "Status" in result.output
    assert "Reason" in result.output
    assert "active" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


@freeze_time(datetime(2025, 1, 30, tzinfo=timezone.utc))
def test_app_yanked_no_reason_cli_args(
    temp_uv_lock_file: Path,
    yanked_package_no_reason_given_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--forbid-yanked", "--disable-cache"]
    )

    assert result.exit_code == 1
    assert "Maintenance Issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Issues: 1 issue" in result.output
    assert "Maintenance Issues" in result.output
    assert "Unknown" in result.output
    assert "1 year and 11.01 days" in result.output
    # New columns present and values for project status
    assert "Status" in result.output
    assert "Reason" in result.output
    assert "active" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_failed_vulnerability_request(
    temp_uv_lock_file: Path,
    missing_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 3
    assert "Error: example-package raised exception: Request failed" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_package_not_found(
    temp_uv_lock_file: Path,
    package_version_not_found_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 3
    assert (
        "Error: example-package raised exception: Client error '404 Not Found' "
        "for url 'https://pypi.org/pypi/example-package/1.0.0/json'"
    ) in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_json_format_failed_vulnerability_request(
    temp_uv_lock_file: Path,
    missing_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test JSON format output is valid even when request fails"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--format", "json", "--disable-cache"]
    )

    assert result.exit_code == 3

    output = json.loads(result.output)
    assert "files" in output
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    assert "error" in file_result
    assert "example-package" in file_result["error"]
    assert "Request failed" in file_result["error"]
    assert file_result["dependencies"] == []
    assert file_result["ignored_count"] == 0


def test_json_format_package_not_found(
    temp_uv_lock_file: Path,
    package_version_not_found_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test JSON format output is valid even when package is not found"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--format", "json", "--disable-cache"]
    )

    assert result.exit_code == 3

    output = json.loads(result.output)
    assert "files" in output
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    assert "error" in file_result
    assert "example-package" in file_result["error"]
    assert "404 Not Found" in file_result["error"]
    assert file_result["dependencies"] == []
    assert file_result["ignored_count"] == 0


@pytest.mark.parametrize(
    "extra_cli_args",
    [
        pytest.param([], id="Default arguments"),
        pytest.param(["--aliases"], id="Add Aliases column"),
        pytest.param(["--desc"], id="Add details column"),
        pytest.param(["--aliases", "--desc"], id="Add details column"),
        pytest.param(
            ["--forbid-yanked", "--max-age-days", "1000"], id="Maintenance criteria"
        ),
    ],
)
@freeze_time(datetime(2025, 1, 30, tzinfo=timezone.utc))
def test_check_dependencies_with_vulnerability(
    extra_cli_args: list[str],
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), *extra_cli_args, "--disable-cache"]
    )

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message
    if "--aliases" in extra_cli_args:
        assert "Aliases" in result.output
        assert "CVE-2024-12345" in result.output
    if "--desc" in extra_cli_args:
        assert "Details" in result.output
        assert "A critical vulnerability in example-package.  " in result.output


def test_check_dependencies_with_vulnerability_narrow_console_vulnerability_ids_visible(
    temp_uv_lock_file_jinja2: Path,
    jinja2_two_longer_vulnerability_responses: HTTPXMock,
    pypi_simple_jinja2: HTTPXMock,
    set_console_width: Callable[[int], None],
) -> None:
    set_console_width(80)
    result = runner.invoke(
        app, [str(temp_uv_lock_file_jinja2), "--aliases", "--desc", "--disable-cache"]
    )

    assert result.exit_code == 2
    assert "GHSA-q2x7-8rv6-6q7h" in result.output
    assert "GHSA-gmj6-6f8f-6699" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_check_dependencies_with_two_longer_vulnerabilities(
    temp_uv_lock_file_jinja2: Path,
    jinja2_two_longer_vulnerability_responses: HTTPXMock,
    pypi_simple_jinja2: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file_jinja2), "--disable-cache"])

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 2 vulnerabilities" in result.output
    assert result.output.count("jinja2") == 2
    assert result.output.count("3.1.4") == 2
    assert result.output.count("3.1.5") == 2
    assert "GHSA-q2x7-8rv6-6q7h" in result.output
    assert "GHSA-gmj6-6f8f-6699" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_arg_ignored_vulnerability(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--ignore-vulns", "VULN-123", "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_arg_ignored_package_no_specifiers(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [str(temp_uv_lock_file), "--ignore-pkgs", "example-package", "--disable-cache"],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 0 dependencies" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_arg_ignored_package_with_specifiers(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--ignore-pkgs",
            "example-package:>=0.5,<0.6|>=1.0,<2",
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 0 dependencies" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_arg_ignored_package_with_specifiers_no_match(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--ignore-pkgs",
            "example-package:>=0.5,<0.6",
            "--disable-cache",
        ],
    )

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_arg_withdrawn_vulnerability(
    temp_uv_lock_file: Path,
    withdrawn_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_check_dependencies_with_vulnerability_pyproject_all_columns_configured(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_extra_columns_enabled: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert "Aliases" in result.output
    assert "CVE-2024-12345" in result.output
    assert "Details" in result.output
    assert "A critical vulnerability in example-package.  " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_check_dependencies_with_vulnerability_uv_secure_all_columns_configured(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_all_columns_enabled: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert "Aliases" in result.output
    assert "CVE-2024-12345" in result.output
    assert "Details" in result.output
    assert "A critical vulnerability in example-package.  " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


@freeze_time(datetime(2025, 1, 30, tzinfo=timezone.utc))
def test_check_dependencies_with_vulnerability_and_maintenance_issues_uv_secure(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled: Path,
    old_yanked_package_with_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert "Aliases" in result.output
    assert "CVE-2024-12345" in result.output
    assert "Details" in result.output
    assert "A critical vulnerability in example-package." in result.output
    assert "Maintenance Issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Issues: 1 issue" in result.output
    assert "Maintenance Issues" in result.output
    assert "Broken API" in result.output
    assert "4 years and 11.01 days" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_check_dependencies_with_custom_caching(
    temp_uv_lock_file: Path,
    tmp_path: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    cache_dir = tmp_path / ".uv-secure"
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--cache-path",
            cache_dir.as_posix(),
            "--cache-ttl-seconds",
            "600",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "error" not in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message

    cache_files = {p.name for p in cache_dir.iterdir()}
    assert "cache.db" in cache_files


def test_check_dependencies_with_vulnerability_pyproject_toml_cli_argument_override(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_ignored_vulnerability: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--ignore-vulns",
            "VULN-NOT-HERE",
            "--aliases",
            "--desc",
            "--disable-cache",
        ],
    )

    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert "Aliases" in result.output
    assert "CVE-2024-12345" in result.output
    assert "Details" in result.output
    assert "A critical vulnerability in example-package.  " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_check_dependencies_with_vulnerability_pyproject_toml_cli_argument_pkg_override(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_ignored_package: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--ignore-pkgs",
            "another-package",
            "--aliases",
            "--desc",
            "--disable-cache",
        ],
    )

    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "example-package" in result.output
    assert "1.0.0" in result.output
    assert "VULN-123" in result.output
    assert "1.0.1" in result.output
    assert "Aliases" in result.output
    assert "CVE-2024-12345" in result.output
    assert "Details" in result.output
    assert "A critical vulnerability in example-package.  " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_uv_secure_toml_ignored_vulnerability(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_ignored_vulnerability: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--config",
            str(temp_uv_secure_toml_file_ignored_vulnerability),
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_uv_secure_toml_ignored_package(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_ignored_package: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--config",
            str(temp_uv_secure_toml_file_ignored_package),
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 0 dependencies" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_pyproject_toml_ignored_vulnerability(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_ignored_vulnerability: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--config",
            str(temp_pyproject_toml_file_ignored_vulnerability),
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_with_pyproject_toml_ignored_package(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_ignored_package: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--config",
            str(temp_pyproject_toml_file_ignored_package),
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 0 dependencies" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_multiple_lock_files_no_vulnerabilities(
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
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
            "vulnerabilities": [],
        },
    )
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
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.9",
                "summary": "A minimal package example",
                "version": "2.0.0",
                "yanked": False,
            },
            "last_serial": 1,
            "urls": [],
            "vulnerabilities": [],
        },
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), str(temp_nested_uv_lock_file), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 2
    )
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 1
    assert result.output.count("Checking ") == 2
    assert_no_markup_escape_artifacts(result.output)


def test_app_multiple_lock_files_one_vulnerabilities(
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), str(temp_nested_uv_lock_file), "--disable-cache"]
    )
    assert result.exit_code == 2
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert result.output.count("Vulnerabilities detected!") == 1
    assert result.output.count("Checking ") == 2
    assert_table_rendered(result.output, "Vulnerable Dependencies")
    assert_no_markup_escape_artifacts(result.output)


def test_app_multiple_lock_files_one_nested_ignored_vulnerability(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    temp_dot_uv_secure_toml_file: Path,
    temp_nested_uv_secure_toml_file_ignored_vulnerability: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(tmp_path), "--disable-cache"])

    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 2
    )
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 1
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_multiple_lock_files_no_root_config_one_nested_ignored_vulnerability(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    temp_double_nested_uv_lock_file: Path,
    temp_nested_uv_secure_toml_file_ignored_vulnerability: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(tmp_path), "--disable-cache"])

    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 2
    )
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 2
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_multiple_lock_files_one_nested_ignored_vulnerability_pass_lock_files(
    tmp_path: Path,
    temp_uv_lock_file: Path,
    temp_double_nested_uv_lock_file: Path,
    temp_nested_uv_secure_toml_file_ignored_vulnerability: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            str(temp_double_nested_uv_lock_file),
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 2
    )
    assert result.output.count("Checked: 1 dependency") == 2
    assert result.output.count("All dependencies appear safe!") == 2
    assert result.output.count("nested_project") == 2
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_app_multiple_lock_files_one_vulnerabilities_ignored_nested_pyproject_toml(
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    temp_pyproject_toml_file: Path,
    temp_nested_pyproject_toml_file_no_config: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), str(temp_nested_uv_lock_file), "--disable-cache"]
    )
    assert result.exit_code == 2
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert result.output.count("Vulnerabilities detected!") == 1
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_lock_vulnerability_full_dependencies_one_vulnerability(
    temp_uv_secure_toml_file_all_columns_enabled: Path,
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file_direct_indirect_dependencies), "--disable-cache"]
    )
    assert result.exit_code == 2
    assert result.output.count("Vulnerable: 1 vulnerability") == 1
    assert result.output.count("indirect-dependency") == 1
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_lock_vulnerability_uv_secure_toml_direct_dependencies_one_vulnerability(
    temp_uv_secure_toml_file_direct_dependency_vulnerabilities_only: Path,
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file_direct_indirect_dependencies), "--disable-cache"]
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_lock_vulnerability_pyproject_toml_direct_dependencies_one_vulnerability(
    temp_pyproject_toml_file_direct_dependency_vulnerabilities_only: Path,
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file_direct_indirect_dependencies), "--disable-cache"]
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_lock_maintenance_full_dependencies_one_issue(
    temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled: Path,
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file_direct_indirect_dependencies), "--disable-cache"]
    )
    assert result.exit_code == 1
    assert result.output.count("Issues: 1 issue") == 1
    assert result.output.count("indirect-dependency") == 1
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_lock_maintenance_uv_secure_toml_direct_dependencies_one_issue(
    temp_uv_secure_toml_file_direct_dependency_maintenance_issues_only: Path,
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file_direct_indirect_dependencies), "--disable-cache"]
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_lock_maintenance_pyproject_toml_direct_dependencies_one_issue(
    temp_pyproject_toml_file_direct_dependency_maintenance_issues_only: Path,
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file_direct_indirect_dependencies), "--disable-cache"]
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_vulnerability_full_dependencies_one_vuln(
    temp_uv_secure_toml_file_all_columns_enabled: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--disable-cache",
        ],
    )
    assert result.exit_code == 2
    assert result.output.count("Vulnerable: 1 vulnerability") == 1
    assert result.output.count("indirect-dependency") == 1
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_vulnerability_uv_secure_toml_direct_dependencies_one_vuln(
    temp_uv_secure_toml_file_direct_dependency_vulnerabilities_only: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_vulnerability_pyproject_toml_direct_dependencies_one_vuln(
    temp_pyproject_toml_file_direct_dependency_vulnerabilities_only: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_vulnerability_uv_secure_toml_cli_override_direct_dependencies_one_vuln(
    temp_uv_secure_toml_file_all_columns_enabled: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--check-direct-dependency-vulnerabilities-only",
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_vulnerability_pyproject_toml_cli_override_direct_dependencies_one_vuln(
    temp_uv_secure_toml_file_all_columns_enabled: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--check-direct-dependency-vulnerabilities-only",
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_maintenance_full_dependencies_one_issue(
    temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--disable-cache",
        ],
    )
    assert result.exit_code == 1
    assert result.output.count("Issues: 1 issue") == 1
    assert result.output.count("indirect-dependency") == 1
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_maintenance_uv_secure_toml_direct_dependencies_one_issue(
    temp_uv_secure_toml_file_direct_dependency_maintenance_issues_only: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_maintenance_pyproject_toml_direct_dependencies_one_issue(
    temp_pyproject_toml_file_direct_dependency_maintenance_issues_only: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_maintenance_uv_secure_toml_cli_override_direct_dependencies_one_issue(
    temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--check-direct-dependency-maintenance-issues-only",
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_reqs_maintenance_pyproject_toml_cli_override_direct_dependencies_one_issue(
    temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled: Path,
    temp_uv_requirements_txt_file_direct_indirect_dependencies: Path,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    one_maintenance_issue_response_indirect_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_requirements_txt_file_direct_indirect_dependencies),
            "--check-direct-dependency-maintenance-issues-only",
            "--disable-cache",
        ],
    )
    assert result.exit_code == 0
    assert (
        result.output.count("No vulnerabilities or maintenance issues detected!") == 1
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_pylock_toml_check_direct_dependency_vulnerabilities_only_warning(
    temp_uv_pylock_toml_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_pylock_toml_file),
            "--check-direct-dependency-vulnerabilities-only",
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert (
        "doesn't contain the necessary information to determine direct dependencies"
        in result.output
    )
    assert "Checked: 1 dependency" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_pylock_toml_check_direct_dependency_maintenance_issues_only_warning(
    temp_uv_pylock_toml_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_pylock_toml_file),
            "--check-direct-dependency-maintenance-issues-only",
            "--disable-cache",
        ],
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert (
        "doesn't contain the necessary information to determine direct dependencies"
        in result.output
    )
    assert "Checked: 1 dependency" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


# Tests for retry logic and file parsing error handling


def test_uv_lock_file_parsing_with_corrupted_file(
    temp_corrupted_uv_lock_file: Path,
) -> None:
    result = runner.invoke(app, [str(temp_corrupted_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 3
    assert "Error" in result.output
    assert "Failed to parse" in result.output
    assert str(temp_corrupted_uv_lock_file) in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_requirements_txt_file_parsing_with_corrupted_file(
    temp_corrupted_requirements_txt_file: Path,
) -> None:
    result = runner.invoke(
        app, [str(temp_corrupted_requirements_txt_file), "--disable-cache"]
    )

    assert result.exit_code == 3
    assert "Error" in result.output
    assert "Failed to parse" in result.output
    assert str(temp_corrupted_requirements_txt_file) in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_pylock_toml_file_parsing_with_corrupted_file(
    temp_corrupted_pylock_toml_file: Path,
) -> None:
    result = runner.invoke(
        app, [str(temp_corrupted_pylock_toml_file), "--disable-cache"]
    )

    assert result.exit_code == 3
    assert "Error" in result.output
    assert "Failed to parse" in result.output
    assert str(temp_corrupted_pylock_toml_file) in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def _simple_status_response(httpx_mock: HTTPXMock, status: str) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/simple/example-package/",
        json={
            "name": "example-package",
            "project-status": {"status": status, "reason": "test"},
        },
        headers={"Content-Type": "application/vnd.pypi.simple.v1+json"},
    )


def test_cli_forbid_archived_triggers_maintenance_issue(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
) -> None:
    _simple_status_response(httpx_mock, "archived")
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--forbid-archived", "--disable-cache"]
    )
    assert result.exit_code == 1
    assert_table_rendered(result.stdout, "Maintenance Issues")
    assert "Status" in result.stdout
    assert "Reason" in result.stdout
    assert "archived" in result.stdout
    assert "test" in result.stdout
    assert_no_markup_escape_artifacts(result.stdout)


def test_cli_forbid_deprecated_triggers_maintenance_issue(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
) -> None:
    _simple_status_response(httpx_mock, "deprecated")
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--forbid-deprecated", "--disable-cache"]
    )
    assert result.exit_code == 1
    assert_table_rendered(result.stdout, "Maintenance Issues")
    assert "Status" in result.stdout
    assert "Reason" in result.stdout
    assert "deprecated" in result.stdout
    assert "test" in result.stdout
    assert_no_markup_escape_artifacts(result.stdout)


def test_cli_forbid_quarantined_triggers_maintenance_issue(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
) -> None:
    _simple_status_response(httpx_mock, "quarantined")
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--forbid-quarantined", "--disable-cache"]
    )
    assert result.exit_code == 1
    assert_table_rendered(result.stdout, "Maintenance Issues")
    assert "Status" in result.stdout
    assert "Reason" in result.stdout
    assert "quarantined" in result.stdout
    assert "test" in result.stdout
    assert_no_markup_escape_artifacts(result.stdout)


def test_app_uv_lock_file_with_ignored_non_pypi_dependencies(
    temp_uv_lock_file_with_non_pypi_deps: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test that non-PyPI dependencies are ignored and count is reported"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file_with_non_pypi_deps), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    # git-package and private-package are ignored
    assert "Ignored: 2 non-pypi dependencies" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output


def test_app_pylock_toml_file_with_ignored_non_pypi_dependencies(
    temp_pylock_toml_file_with_non_pypi_deps: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test that non-PyPI dependencies are ignored and count is reported"""
    result = runner.invoke(
        app, [str(temp_pylock_toml_file_with_non_pypi_deps), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    # git-package and private-package are ignored
    assert "Ignored: 2 non-pypi dependencies" in result.output
    assert "All dependencies appear safe!" in result.output
    assert "[/]" not in result.output


def test_app_uv_lock_file_with_vulnerabilities_and_ignored_non_pypi_dependencies(
    temp_uv_lock_file_with_non_pypi_deps: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test that ignored non-PyPI dependencies count is reported with vulnerabilities"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file_with_non_pypi_deps), "--disable-cache"]
    )

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    assert "Checked: 1 dependency" in result.output
    assert "Vulnerable: 1 vulnerability" in result.output
    assert "Ignored: 2 non-pypi dependencies" in result.output
    assert_table_rendered(result.output, "Vulnerable Dependencies")
    assert_no_markup_escape_artifacts(result.output)


def test_app_uv_lock_file_only_non_pypi_dependencies_shows_ignored_count(
    temp_uv_lock_file_only_non_pypi_deps: Path,
) -> None:
    """Test that when only non-PyPI dependencies exist, ignored count is shown"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file_only_non_pypi_deps), "--disable-cache"]
    )

    assert result.exit_code == 0
    assert "No PyPI dependencies to check" in result.output
    assert "Ignored: 2 non-pypi dependencies" in result.output
    assert "[/]" not in result.output


def test_vulnerability_with_no_fix_versions(
    temp_uv_lock_file: Path,
    vulnerability_no_fix_versions_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test vulnerability with empty fix_versions list"""
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "VULN-NO-FIX" in result.output
    assert "[/]" not in result.output


def test_vulnerability_with_no_fix_versions_ignored_by_cli_flag(
    temp_uv_lock_file: Path,
    vulnerability_no_fix_versions_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--ignore-unfixed"]
    )

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "VULN-NO-FIX" not in result.output
    assert "[/]" not in result.output


def test_vulnerability_with_no_fix_versions_ignored_by_config(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_ignore_unfixed: Path,
    vulnerability_no_fix_versions_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert "VULN-NO-FIX" not in result.output
    assert "[/]" not in result.output


def test_vulnerability_with_fix_versions_not_ignored_by_ignore_unfixed(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--ignore-unfixed"]
    )

    assert result.exit_code == 2
    assert "VULN-123" in result.output
    assert "[/]" not in result.output


def test_severity_cli_filters_known_severity_and_keeps_unknown(
    temp_uv_lock_file: Path,
    vulnerability_mixed_severity_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--severity", "high"]
    )

    assert result.exit_code == 2
    assert "VULN-HIGH" in result.output
    assert "VULN-UNKNOWN" in result.output
    assert "VULN-LOW" not in result.output
    assert "[/]" not in result.output


def test_severity_config_filters_known_severity_and_keeps_unknown(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_severity_high: Path,
    vulnerability_mixed_severity_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "VULN-HIGH" in result.output
    assert "VULN-UNKNOWN" in result.output
    assert "VULN-LOW" not in result.output
    assert "[/]" not in result.output


def test_severity_threshold_parses_numeric_and_unknown_embedded_values(
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
                    "id": "VULN-CRITICAL",
                    "details": "Critical vulnerability",
                    "fixed_in": ["1.0.1"],
                    "severity": "9.1",
                    "link": "https://example.com/vuln-critical",
                },
                {
                    "id": "VULN-HIGH",
                    "details": "High vulnerability",
                    "fixed_in": ["1.0.1"],
                    "severity": "7.5",
                    "link": "https://example.com/vuln-high",
                },
                {
                    "id": "VULN-MEDIUM",
                    "details": "Medium vulnerability",
                    "fixed_in": ["1.0.1"],
                    "severity": "4.2",
                    "link": "https://example.com/vuln-medium",
                },
                {
                    "id": "VULN-LOW",
                    "details": "Low vulnerability",
                    "fixed_in": ["1.0.1"],
                    "severity": "0.5",
                    "link": "https://example.com/vuln-low",
                },
                {
                    "id": "VULN-UNKNOWN",
                    "details": "Unknown vulnerability",
                    "fixed_in": ["1.0.1"],
                    "severity": "not-a-number",
                    "link": "https://example.com/vuln-unknown",
                },
            ],
        },
    )

    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--disable-cache",
            "--severity",
            "critical",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vuln_ids = {
        vuln["id"] for dep in file_result["dependencies"] for vuln in dep["vulns"]
    }
    assert "VULN-CRITICAL" in vuln_ids
    assert "VULN-UNKNOWN" in vuln_ids
    assert "VULN-HIGH" not in vuln_ids
    assert "VULN-MEDIUM" not in vuln_ids
    assert "VULN-LOW" not in vuln_ids

    vulnerability = file_result["dependencies"][0]["vulns"][0]
    assert vulnerability["severity_source_link"] in {
        "https://example.com/vuln-critical",
        "https://example.com/vuln-unknown",
    }


def test_json_severity_enrichment_osv_edge_cases(
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
                {"id": "GHSA-1111-2222-3333", "details": "db important"},
                {"id": "GHSA-aaaa-bbbb-cccc", "details": "db unknown no severity"},
                {"id": "GHSA-4444-5555-6666", "details": "cvss numeric list only"},
                {"id": "GHSA-7777-8888-9999", "details": "osv not found"},
                {"id": "GHSA-dead-beef-cafe", "details": "invalid osv payload"},
            ],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-1111-2222-3333",
        json={
            "id": "GHSA-1111-2222-3333",
            "database_specific": {"severity": "important"},
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-aaaa-bbbb-cccc",
        json={
            "id": "GHSA-aaaa-bbbb-cccc",
            "database_specific": {"severity": "mystery"},
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-4444-5555-6666",
        json={
            "id": "GHSA-4444-5555-6666",
            "severity": [{"score": "bad"}, {"score": "8.7"}, {"score": "7.0"}],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-7777-8888-9999", status_code=404
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-dead-beef-cafe",
        json={"id": "GHSA-dead-beef-cafe", "severity": "invalid-type"},
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--format", "json"]
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vulnerabilities = file_result["dependencies"][0]["vulns"]
    by_id = {v["id"]: v for v in vulnerabilities}

    assert by_id["GHSA-1111-2222-3333"]["severity"] == "high"
    assert by_id["GHSA-4444-5555-6666"]["severity"] == "high"
    assert "severity" not in by_id["GHSA-aaaa-bbbb-cccc"]
    assert "severity" not in by_id["GHSA-7777-8888-9999"]
    assert "severity" not in by_id["GHSA-dead-beef-cafe"]


def test_json_severity_enrichment_with_cache_enabled(
    temp_uv_lock_file: Path,
    tmp_path: Path,
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
            "vulnerabilities": [{"id": "GHSA-cache-1111-2222", "details": "cached"}],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-cache-1111-2222",
        json={
            "id": "GHSA-cache-1111-2222",
            "database_specific": {"severity": "moderate"},
        },
    )

    cache_dir = tmp_path / "cache"
    result = runner.invoke(
        app,
        [str(temp_uv_lock_file), "--format", "json", "--cache-path", str(cache_dir)],
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vuln = file_result["dependencies"][0]["vulns"][0]
    assert vuln["severity"] == "medium"


def test_unused_ignore_vulnerability_fails_by_default(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--ignore-vulns", "VULN-999"]
    )

    assert result.exit_code == 4
    assert "unused vulnerability ignore ids" in result.output.lower()
    assert "VULN-999" in result.output
    assert "[/]" not in result.output


def test_unused_ignore_vulnerability_json_output_stays_valid_json(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--disable-cache",
            "--ignore-vulns",
            "VULN-999",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 4
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    assert file_result["file_path"] == temp_uv_lock_file.as_posix()
    assert output["errors"][0]["code"] == "unused_ignores"


def test_unused_ignore_vulnerability_can_be_allowed_by_cli_flag(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--disable-cache",
            "--ignore-vulns",
            "VULN-999",
            "--allow-unused-ignores",
        ],
    )

    assert result.exit_code == 0
    assert "unused vulnerability ignore IDs" not in result.output.lower()
    assert "[/]" not in result.output


def test_unused_ignore_vulnerability_can_be_allowed_by_config(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_allow_unused_ignores: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    assert "unused vulnerability ignore IDs" not in result.output.lower()
    assert "[/]" not in result.output


def test_unused_ignore_vulnerability_alias_identifier_is_counted_as_used(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [str(temp_uv_lock_file), "--disable-cache", "--ignore-vulns", "CVE-2024-12345"],
    )

    assert result.exit_code == 0
    assert "unused vulnerability ignore ids" not in result.output.lower()
    assert "[/]" not in result.output


def test_unused_ignore_vulnerability_used_in_other_scope_does_not_fail(
    temp_uv_lock_file: Path,
    temp_nested_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    one_vulnerability_response_v2: HTTPXMock,
    pypi_simple_example_package_twice: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            str(temp_nested_uv_lock_file),
            "--disable-cache",
            "--ignore-vulns",
            "VULN-123",
        ],
    )

    assert result.exit_code == 0
    assert "unused vulnerability ignore ids" not in result.output.lower()
    assert "[/]" not in result.output


def test_unused_ignore_package_fails_by_default(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--ignore-pkgs", "missing-pkg"]
    )

    assert result.exit_code == 4
    assert "unused package ignore ids" in result.output.lower()
    assert "missing-pkg" in result.output
    assert "[/]" not in result.output


def test_unused_ignore_package_can_be_allowed_by_cli_flag(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--disable-cache",
            "--ignore-pkgs",
            "missing-pkg",
            "--allow-unused-ignores",
        ],
    )

    assert result.exit_code == 0
    assert "unused package ignore ids" not in result.output.lower()
    assert "[/]" not in result.output


def test_json_severity_enrichment_retries_transient_osv_request_error(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    osv_url = "https://api.osv.dev/v1/vulns/GHSA-retry-1111-2222"
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
            "vulnerabilities": [{"id": "GHSA-retry-1111-2222", "details": "retry me"}],
        },
    )
    httpx_mock.add_exception(
        RequestError("temporary OSV transport error", request=Request("GET", osv_url)),
        url=osv_url,
    )
    httpx_mock.add_response(
        url=osv_url,
        json={"id": "GHSA-retry-1111-2222", "database_specific": {"severity": "high"}},
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--format", "json"]
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vuln = file_result["dependencies"][0]["vulns"][0]
    assert vuln["severity"] == "high"


def test_json_severity_enrichment_retryable_osv_status_is_non_fatal(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    osv_url = "https://api.osv.dev/v1/vulns/GHSA-status-1111-2222"
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
            "vulnerabilities": [{"id": "GHSA-status-1111-2222", "details": "retry me"}],
        },
    )
    httpx_mock.add_response(url=osv_url, status_code=503)
    httpx_mock.add_response(url=osv_url, status_code=503)
    httpx_mock.add_response(url=osv_url, status_code=503)

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--format", "json"]
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vuln = file_result["dependencies"][0]["vulns"][0]
    assert vuln["id"] == "GHSA-status-1111-2222"
    assert "severity" not in vuln


def test_vulnerability_with_all_alias_types(
    temp_uv_lock_file: Path,
    vulnerability_multiple_alias_types_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test vulnerability with CVE, GHSA, PYSEC, OSV, and unknown aliases"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--aliases", "--disable-cache"]
    )

    assert result.exit_code == 2
    assert "CVE-2024-12345" in result.output
    assert "GHSA-xxxx-yyyy-zzzz" in result.output
    assert "PYSEC-2024-12345" in result.output
    assert "OSV-2024-12345" in result.output
    assert "UNKNOWN-FORMAT-123" in result.output
    assert "[/]" not in result.output


def test_vulnerability_with_no_aliases(
    temp_uv_lock_file: Path,
    vulnerability_no_aliases_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test vulnerability with no aliases"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--aliases", "--disable-cache"]
    )

    assert result.exit_code == 2
    assert "VULN-NO-ALIASES" in result.output
    assert "[/]" not in result.output


def test_json_format_no_vulnerabilities(
    temp_uv_lock_file: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test JSON format output with no vulnerabilities"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--format", "json", "--disable-cache"]
    )

    assert result.exit_code == 0
    output = json.loads(result.output)

    assert "files" in output
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    assert temp_uv_lock_file.as_posix() == file_result["file_path"]
    assert "dependencies" in file_result
    assert file_result["ignored_count"] == 0

    # Check that dependencies have expected structure
    for dep in file_result["dependencies"]:
        assert "name" in dep
        assert "version" in dep
        assert "direct" in dep
        assert "vulns" in dep
        assert isinstance(dep["vulns"], list)


def test_json_format_with_vulnerabilities(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test JSON format output with vulnerabilities"""
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--format", "json", "--disable-cache"]
    )

    assert result.exit_code == 2
    output = json.loads(result.output)

    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    deps_with_vulns = [d for d in file_result["dependencies"] if d["vulns"]]

    assert len(deps_with_vulns) > 0

    vuln_dep = deps_with_vulns[0]
    vuln = vuln_dep["vulns"][0]

    assert "id" in vuln
    assert "details" in vuln
    assert vuln["id"] == "VULN-123"


def test_json_format_enriches_severity_from_osv(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "Example package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "example-package",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.10",
                "summary": "Example package release",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 42,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "GHSA-gm62-xv2j-4w53",
                    "details": "OSV-backed vulnerability",
                    "fixed_in": ["2.6.0"],
                    "aliases": ["CVE-2025-66418"],
                    "link": "https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53",
                }
            ],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-gm62-xv2j-4w53",
        json={
            "id": "GHSA-gm62-xv2j-4w53",
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": (
                        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/"
                        "SC:N/SI:N/SA:H"
                    ),
                }
            ],
            "database_specific": {"severity": "HIGH"},
        },
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--format", "json", "--disable-cache"]
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vuln = file_result["dependencies"][0]["vulns"][0]
    assert vuln["severity"] == "high"
    assert (
        vuln["severity_source_link"]
        == "https://osv.dev/vulnerability/GHSA-gm62-xv2j-4w53"
    )


def test_columns_format_shows_severity_column(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "Example package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "example-package",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.10",
                "summary": "Example package release",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 42,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "GHSA-hgf8-39gv-g3f2",
                    "details": "OSV-backed vulnerability",
                    "fixed_in": ["3.1.4"],
                    "aliases": ["CVE-2025-66221"],
                    "link": "https://osv.dev/vulnerability/GHSA-hgf8-39gv-g3f2",
                }
            ],
        },
    )
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/GHSA-hgf8-39gv-g3f2",
        json={
            "id": "GHSA-hgf8-39gv-g3f2",
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": (
                        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/"
                        "SC:N/SI:N/SA:N"
                    ),
                }
            ],
            "database_specific": {"severity": "MODERATE"},
        },
    )

    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "Severity" in result.output
    assert "MEDIUM" in result.output
    assert "[/]" not in result.output


def test_json_format_with_long_vulnerability_details(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Ensure long vulnerability details remain valid JSON output."""
    long_details = (
        "Long vulnerability detail paragraph. " * 40
        + "Include markdown-like sections and punctuation for realism."
    )
    httpx_mock.add_response(
        url="https://pypi.org/pypi/example-package/1.0.0/json",
        json={
            "info": {
                "author_email": "maintainer@example.com",
                "classifiers": [],
                "description": "Example package",
                "description_content_type": "text/plain",
                "downloads": {"last_day": None, "last_month": None, "last_week": None},
                "name": "example-package",
                "project_urls": {},
                "provides_extra": [],
                "release_url": "https://pypi.org/project/example-package/1.0.0/",
                "requires_python": ">=3.10",
                "summary": "Example package release",
                "version": "1.0.0",
                "yanked": False,
            },
            "last_serial": 42,
            "urls": [],
            "vulnerabilities": [
                {
                    "id": "VULN-LONG-DETAILS",
                    "details": long_details,
                    "fixed_in": ["1.0.1"],
                    "aliases": ["CVE-2026-12345"],
                    "link": "https://example.com/vuln-long-details",
                }
            ],
        },
    )

    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--format", "json", "--disable-cache"]
    )

    assert result.exit_code == 2
    output = json.loads(result.output)
    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    vulnerability = file_result["dependencies"][0]["vulns"][0]
    assert vulnerability["id"] == "VULN-LONG-DETAILS"
    assert vulnerability["details"] == long_details


def test_json_format_with_maintenance_issues(
    temp_uv_lock_file: Path,
    old_yanked_package_with_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
    temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled: Path,
) -> None:
    """Test JSON format output with maintenance issues"""
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file),
            "--format",
            "json",
            "--disable-cache",
            "--config",
            str(temp_uv_secure_toml_file_all_columns_and_maintenance_issues_enabled),
        ],
    )

    assert result.exit_code in (1, 2)  # Maintenance or vulnerabilities
    output = json.loads(result.output)

    file_result = get_file_output(output, temp_uv_lock_file.as_posix())
    # Check structure exists
    assert "dependencies" in file_result

    # Find dependency with maintenance issues (fixture should always have one)
    deps_with_maintenance = [
        dep for dep in file_result["dependencies"] if dep.get("maintenance_issues")
    ]
    assert len(deps_with_maintenance) > 0, "Expected maintenance issues in fixture"

    issue = deps_with_maintenance[0]["maintenance_issues"]
    assert "yanked" in issue
    assert isinstance(issue["yanked"], bool)


def test_json_format_with_ignored_dependencies(
    temp_uv_lock_file_with_non_pypi_deps: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test JSON format shows ignored count"""
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file_with_non_pypi_deps),
            "--format",
            "json",
            "--disable-cache",
        ],
    )

    assert result.exit_code == 2
    output = json.loads(result.output)

    file_result = get_file_output(
        output, temp_uv_lock_file_with_non_pypi_deps.as_posix()
    )
    assert file_result["ignored_count"] == 2
    assert len(file_result["dependencies"]) == 1  # Only PyPI deps


def test_json_format_pypi_registry_trailing_slash(
    temp_uv_lock_file_trailing_slash: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Ensure trailing slash registries are still treated as PyPI."""

    result = runner.invoke(
        app,
        [str(temp_uv_lock_file_trailing_slash), "--format", "json", "--disable-cache"],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)

    file_result = get_file_output(output, temp_uv_lock_file_trailing_slash.as_posix())
    assert file_result["ignored_count"] == 0
    assert len(file_result["dependencies"]) == 1
    assert file_result["dependencies"][0]["name"] == "example-package"


def test_json_format_pypi_registry_default_port(
    temp_uv_lock_file_default_port: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Ensure PyPI default port URLs are treated as PyPI."""

    result = runner.invoke(
        app,
        [str(temp_uv_lock_file_default_port), "--format", "json", "--disable-cache"],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)

    file_result = get_file_output(output, temp_uv_lock_file_default_port.as_posix())
    assert file_result["ignored_count"] == 0
    assert len(file_result["dependencies"]) == 1
    assert file_result["dependencies"][0]["name"] == "example-package"


def test_json_format_pypi_registry_nondefault_port(
    temp_uv_lock_file_nondefault_port: Path,
) -> None:
    """Non-default ports on pypi.org should be treated as non-PyPI."""

    result = runner.invoke(
        app,
        [str(temp_uv_lock_file_nondefault_port), "--format", "json", "--disable-cache"],
    )

    # Non-PyPI dependency gets ignored; scan completes with ignored count
    assert result.exit_code == 0
    output = json.loads(result.output)

    file_result = get_file_output(output, temp_uv_lock_file_nondefault_port.as_posix())
    assert file_result["ignored_count"] == 1
    assert len(file_result["dependencies"]) == 0


def test_json_format_direct_dependencies_only(
    temp_uv_lock_file_direct_indirect_dependencies: Path,
    one_vulnerability_response_indirect_dependency: HTTPXMock,
    no_vulnerabilities_response_direct_dependency: HTTPXMock,
    pypi_simple_direct_and_indirect: HTTPXMock,
    temp_uv_secure_toml_file_direct_dependency_vulnerabilities_only: Path,
) -> None:
    """Test JSON format with direct dependencies only filter"""
    result = runner.invoke(
        app,
        [
            str(temp_uv_lock_file_direct_indirect_dependencies),
            "--format",
            "json",
            "--disable-cache",
            "--config",
            str(temp_uv_secure_toml_file_direct_dependency_vulnerabilities_only),
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)

    file_result = get_file_output(
        output, temp_uv_lock_file_direct_indirect_dependencies.as_posix()
    )

    # Should have both direct and indirect dependencies
    direct_deps = [d for d in file_result["dependencies"] if d["direct"]]
    indirect_deps = [d for d in file_result["dependencies"] if not d["direct"]]

    assert len(direct_deps) > 0
    assert len(indirect_deps) > 0

    # Indirect deps should have no vulnerabilities due to filter
    for dep in indirect_deps:
        assert len(dep["vulns"]) == 0


def test_json_format_empty_file(temp_empty_requirements_txt_file: Path) -> None:
    """Test JSON format with empty dependency file"""
    result = runner.invoke(
        app,
        [str(temp_empty_requirements_txt_file), "--format", "json", "--disable-cache"],
    )

    assert result.exit_code == 0
    output = json.loads(result.output)

    file_result = get_file_output(output, temp_empty_requirements_txt_file.as_posix())
    assert len(file_result["dependencies"]) == 0
    assert file_result["ignored_count"] == 0


def test_columns_format_no_maintenance_issues(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "Vulnerabilities detected!" in result.output
    # Columns format should have table output (not JSON)
    assert "{" not in result.output or "Vulnerabilities" in result.output


def test_format_configured_via_uv_secure_toml(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_json_format: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    # JSON format should output JSON
    assert '"files"' in result.output
    assert '"dependencies"' in result.output


def test_format_configured_via_pyproject_toml(
    temp_uv_lock_file: Path,
    temp_pyproject_toml_file_json_format: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 0
    # JSON format should output JSON
    assert '"files"' in result.output
    assert '"dependencies"' in result.output


def test_format_cli_overrides_config_file(
    temp_uv_lock_file: Path,
    temp_uv_secure_toml_file_json_format: Path,
    no_vulnerabilities_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    # Config file says JSON, but CLI says columns
    result = runner.invoke(
        app, [str(temp_uv_lock_file), "--disable-cache", "--format", "columns"]
    )

    assert result.exit_code == 0
    # Should use columns format (CLI override)
    assert "No vulnerabilities or maintenance issues detected!" in result.output
    assert '"files"' not in result.output  # Should not be JSON


def test_columns_format_with_vulnerabilities_no_maintenance_issues(
    temp_uv_lock_file: Path,
    one_vulnerability_response: HTTPXMock,
    pypi_simple_example_package: HTTPXMock,
) -> None:
    """Test columns format with vulnerabilities but no maintenance issues"""
    result = runner.invoke(app, [str(temp_uv_lock_file), "--disable-cache"])

    assert result.exit_code == 2
    assert "VULN-123" in result.output
    assert "Yanked" not in result.output  # No maintenance table
    assert "[/]" not in result.output
