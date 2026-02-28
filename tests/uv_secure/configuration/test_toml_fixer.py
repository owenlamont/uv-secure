from pathlib import Path
from textwrap import dedent

from anyio import Path as APath
import pytest

from uv_secure.configuration.toml_fixer import fix_unused_ignores_in_toml_config


@pytest.mark.asyncio
async def test_fix_unused_ignores_in_toml_config_invalid_toml_returns_no_changes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "uv-secure.toml"
    config_path.write_text("invalid = [")

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"missing-pkg"}
    )

    assert result.modified is False
    assert result.removed_vulnerability_ids == set()
    assert result.removed_package_ignores == set()


@pytest.mark.asyncio
async def test_fix_unused_ignores_in_pyproject_without_uv_secure_section_no_changes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text(
        dedent(
            """
            [tool.other]
            enabled = true
            """
        ).strip()
    )

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"missing-pkg"}
    )

    assert result.modified is False
    assert result.removed_vulnerability_ids == set()
    assert result.removed_package_ignores == set()


@pytest.mark.asyncio
async def test_fix_unused_ignores_in_pyproject_without_tool_section_no_changes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text('name = "demo"')

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"missing-pkg"}
    )

    assert result.modified is False
    assert result.removed_vulnerability_ids == set()
    assert result.removed_package_ignores == set()


@pytest.mark.asyncio
async def test_fix_unused_ignores_without_matching_sections_no_changes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "uv-secure.toml"
    config_path.write_text(
        dedent(
            """
            format = "columns"

            [vulnerability_criteria]
            severity = "high"

            [ignore_packages]
            existing = []
            """
        ).strip()
    )

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"missing-pkg"}
    )

    assert result.modified is False
    assert result.removed_vulnerability_ids == set()
    assert result.removed_package_ignores == set()
    assert config_path.read_text().count("existing = []") == 1


@pytest.mark.asyncio
async def test_fix_unused_ignores_updates_pyproject_vulnerability_and_package_entries(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text(
        dedent(
            """
            [tool.uv-secure.vulnerability_criteria]
            ignore_vulnerabilities = ["VULN-123", "VULN-999"]

            [tool.uv-secure.ignore_packages]
            keep-pkg = []
            remove-pkg = []
            """
        ).strip()
    )

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"remove-pkg"}
    )

    assert result.modified is True
    assert result.removed_vulnerability_ids == {"VULN-999"}
    assert result.removed_package_ignores == {"remove-pkg"}
    updated = config_path.read_text()
    assert "VULN-123" in updated
    assert "VULN-999" not in updated
    assert "keep-pkg = []" in updated
    assert "remove-pkg" not in updated


@pytest.mark.asyncio
async def test_fix_unused_ignores_without_vulnerability_criteria_no_changes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "uv-secure.toml"
    config_path.write_text(
        dedent(
            """
            [ignore_packages]
            keep-pkg = []
            """
        ).strip()
    )

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"missing-pkg"}
    )

    assert result.modified is False
    assert result.removed_vulnerability_ids == set()
    assert result.removed_package_ignores == set()


@pytest.mark.asyncio
async def test_fix_unused_ignores_without_ignore_packages_table_no_changes(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "uv-secure.toml"
    config_path.write_text(
        dedent(
            """
            [vulnerability_criteria]
            ignore_vulnerabilities = ["VULN-123"]
            """
        ).strip()
    )

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), set(), {"missing-pkg"}
    )

    assert result.modified is False
    assert result.removed_vulnerability_ids == set()
    assert result.removed_package_ignores == set()


@pytest.mark.asyncio
async def test_fix_unused_ignores_in_pyproject_inline_tables(tmp_path: Path) -> None:
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text(
        "tool = { uv-secure = { vulnerability_criteria = { "
        'ignore_vulnerabilities = ["VULN-123", "VULN-999"] }, '
        "ignore_packages = { keep-pkg = [], remove-pkg = [] } } }"
    )

    result = await fix_unused_ignores_in_toml_config(
        APath(config_path), {"VULN-999"}, {"remove-pkg"}
    )

    assert result.modified is True
    assert result.removed_vulnerability_ids == {"VULN-999"}
    assert result.removed_package_ignores == {"remove-pkg"}
    updated = config_path.read_text()
    assert "VULN-123" in updated
    assert "VULN-999" not in updated
    assert "keep-pkg = []" in updated
    assert "remove-pkg" not in updated
