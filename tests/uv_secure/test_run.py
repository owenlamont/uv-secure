from collections.abc import Callable
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from textwrap import dedent

from freezegun import freeze_time
import pytest
from pytest_httpx import HTTPXMock
from typer.testing import CliRunner

from uv_secure import app


runner = CliRunner()


def test_app_version() -> None:
    result = runner.invoke(app, "--version")
    assert result.exit_code == 0
    pattern = r"uv-secure \d+\.\d+\.\d+"
    assert re.search(pattern, result.output), (
        f"Expected semantic version pattern, got: {result.output!r}"
    )
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_bad_file_name() -> None:
    result = runner.invoke(app, "i_dont_exist.txt")
    assert result.exit_code == 3
    assert "Error" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_bad_pyproject_toml_config_file(tmp_path: Path) -> None:
    pyproject_toml_path = tmp_path / "pyproject.toml"
    pyproject_toml_contents = """
        [tool.uv-secure]
        aliases = true
        desc = true
    """
    pyproject_toml_path.write_text(dedent(pyproject_toml_contents).strip())
    result = runner.invoke(app, [str(tmp_path / "uv.lock")])
    assert "Error: Parsing uv-secure configuration at: " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_bad_uv_secure_toml_config_file(tmp_path: Path) -> None:
    uv_secure_toml_path = tmp_path / "uv-secure.toml"
    uv_secure_toml = """
        aliases = true
        desc = true
    """
    uv_secure_toml_path.write_text(dedent(uv_secure_toml).strip())
    result = runner.invoke(app, [str(tmp_path / "uv.lock")])
    assert "Error: Parsing uv-secure configuration at: " in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, [str(tmp_path / "uv.lock")])
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
    result = runner.invoke(app, [str(temp_unpinned_requirements_txt_file)])

    assert result.exit_code == 3
    assert "Failed to parse" in result.output
    assert "dependencies must be fully pinned" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_wildcard_requirements_txt_file(
    temp_wildcard_requirements_txt_file: Path,
) -> None:
    result = runner.invoke(app, [str(temp_wildcard_requirements_txt_file)])

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
    result = runner.invoke(app, [str(temp_env_marker_requirements_txt_file)])

    assert result.exit_code == 3
    assert "Failed to parse" in result.output
    assert "dependencies must be fully pinned" in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_hash_requirements_txt_file(temp_hash_requirements_txt_file: Path) -> None:
    result = runner.invoke(app, [str(temp_hash_requirements_txt_file)])

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
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


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
    result = runner.invoke(app, "--disable-cache")

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
    result = runner.invoke(app, "--disable-cache")

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
    result = runner.invoke(app, "--disable-cache")

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
    assert len(output["files"]) == 1

    file_result = output["files"][0]
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
    assert len(output["files"]) == 1

    file_result = output["files"][0]
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

    cache_files = set(cache_dir.iterdir())
    assert len(cache_files) == 2
    cache_files.remove(cache_dir / ".gitignore")
    assert len(cache_files) == 1


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
        ],
        "--disable-cache",
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
        ],
        "--disable-cache",
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
        ],
        "--disable-cache",
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
        ],
        "--disable-cache",
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
        ],
        "--disable-cache",
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
        ],
        "--disable-cache",
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
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


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
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


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
        [str(temp_uv_lock_file), str(temp_double_nested_uv_lock_file)],
        "--disable-cache",
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
    result = runner.invoke(app, [str(temp_uv_lock_file_direct_indirect_dependencies)])
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
    result = runner.invoke(app, [str(temp_uv_lock_file_direct_indirect_dependencies)])
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
    result = runner.invoke(app, [str(temp_uv_lock_file_direct_indirect_dependencies)])
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
    result = runner.invoke(app, [str(temp_uv_lock_file_direct_indirect_dependencies)])
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
    result = runner.invoke(app, [str(temp_uv_lock_file_direct_indirect_dependencies)])
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
    result = runner.invoke(app, [str(temp_uv_lock_file_direct_indirect_dependencies)])
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
        app, [str(temp_uv_requirements_txt_file_direct_indirect_dependencies)]
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
        app, [str(temp_uv_requirements_txt_file_direct_indirect_dependencies)]
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
        app, [str(temp_uv_requirements_txt_file_direct_indirect_dependencies)]
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
        app, [str(temp_uv_requirements_txt_file_direct_indirect_dependencies)]
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
        app, [str(temp_uv_requirements_txt_file_direct_indirect_dependencies)]
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
        app, [str(temp_uv_requirements_txt_file_direct_indirect_dependencies)]
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
    result = runner.invoke(app, [str(temp_corrupted_uv_lock_file)])

    assert result.exit_code == 3
    assert "Error" in result.output
    assert "Failed to parse" in result.output
    assert str(temp_corrupted_uv_lock_file) in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_requirements_txt_file_parsing_with_corrupted_file(
    temp_corrupted_requirements_txt_file: Path,
) -> None:
    result = runner.invoke(app, [str(temp_corrupted_requirements_txt_file)])

    assert result.exit_code == 3
    assert "Error" in result.output
    assert "Failed to parse" in result.output
    assert str(temp_corrupted_requirements_txt_file) in result.output
    assert "[/]" not in result.output  # Ensure no rich text formatting in error message


def test_pylock_toml_file_parsing_with_corrupted_file(
    temp_corrupted_pylock_toml_file: Path,
) -> None:
    result = runner.invoke(app, [str(temp_corrupted_pylock_toml_file)])

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
    result = runner.invoke(app, [str(temp_uv_lock_file), "--forbid-archived"])
    assert result.exit_code == 1
    assert "Maintenance Issues" in result.stdout
    assert "Status" in result.stdout
    assert "Reason" in result.stdout
    assert "archived" in result.stdout
    assert "test" in result.stdout


def test_cli_forbid_deprecated_triggers_maintenance_issue(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
) -> None:
    _simple_status_response(httpx_mock, "deprecated")
    result = runner.invoke(app, [str(temp_uv_lock_file), "--forbid-deprecated"])
    assert result.exit_code == 1
    assert "Maintenance Issues" in result.stdout
    assert "Status" in result.stdout
    assert "Reason" in result.stdout
    assert "deprecated" in result.stdout
    assert "test" in result.stdout


def test_cli_forbid_quarantined_triggers_maintenance_issue(
    temp_uv_lock_file: Path,
    httpx_mock: HTTPXMock,
    no_vulnerabilities_response: HTTPXMock,
) -> None:
    _simple_status_response(httpx_mock, "quarantined")
    result = runner.invoke(app, [str(temp_uv_lock_file), "--forbid-quarantined"])
    assert result.exit_code == 1
    assert "Maintenance Issues" in result.stdout
    assert "Status" in result.stdout
    assert "Reason" in result.stdout
    assert "quarantined" in result.stdout
    assert "test" in result.stdout


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
    assert "[/]" not in result.output


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
    assert len(output["files"]) == 1

    file_result = output["files"][0]
    assert str(temp_uv_lock_file) in file_result["file_path"]
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

    file_result = output["files"][0]
    deps_with_vulns = [d for d in file_result["dependencies"] if d["vulns"]]

    assert len(deps_with_vulns) > 0

    vuln_dep = deps_with_vulns[0]
    vuln = vuln_dep["vulns"][0]

    assert "id" in vuln
    assert "details" in vuln
    assert vuln["id"] == "VULN-123"


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

    file_result = output["files"][0]
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

    file_result = output["files"][0]
    assert file_result["ignored_count"] == 2
    assert len(file_result["dependencies"]) == 1  # Only PyPI deps


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

    file_result = output["files"][0]

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

    file_result = output["files"][0]
    assert len(file_result["dependencies"]) == 0
    assert file_result["ignored_count"] == 0


def test_columns_format_no_maintenance_issues(
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
