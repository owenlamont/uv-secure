from pathlib import Path
from textwrap import dedent

from anyio import Path as APath
import pytest

from uv_secure.configuration import (
    config_file_factory,
    Configuration,
    OutputFormat,
    SeverityLevel,
    VulnerabilityCriteria,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("filename", "file_contents", "expected_configuration"),
    [
        pytest.param(
            "uv-secure.toml",
            "",
            Configuration(),
            id="Empty configuration returns Configuration",
        ),
        pytest.param(
            "uv-secure.toml",
            """
            [vulnerability_criteria]
            aliases = true
            desc = true
            """,
            Configuration(
                vulnerability_criteria=VulnerabilityCriteria(aliases=True, desc=True)
            ),
            id="Enable aliases and description",
        ),
        pytest.param(
            "pyproject.toml",
            """
            [tool.some_tool]
            some_option = true
            some_other_option = true
            """,
            None,
            id="pyproject.toml no uv-secure",
        ),
        pytest.param(
            "uv-secure.toml",
            """
            format = "json"
            """,
            Configuration(format=OutputFormat.JSON),
            id="Format set to JSON in uv-secure.toml",
        ),
        pytest.param(
            "uv-secure.toml",
            """
            check_uv_tool = false
            check_uv_secure = true
            """,
            Configuration(check_uv_tool=False, check_uv_secure=True),
            id="Independent uv and uv-secure check toggles",
        ),
        pytest.param(
            "uv-secure.toml",
            """
            [vulnerability_criteria]
            severity = "high"
            ignore_unfixed = true
            allow_unused_ignores = true
            """,
            Configuration(
                vulnerability_criteria=VulnerabilityCriteria(
                    severity=SeverityLevel.HIGH,
                    ignore_unfixed=True,
                    allow_unused_ignores=True,
                )
            ),
            id="Vulnerability severity and ignore controls",
        ),
        pytest.param(
            "pyproject.toml",
            """
            [tool.uv-secure]
            format = "columns"
            """,
            Configuration(format=OutputFormat.COLUMNS),
            id="Format set to columns in pyproject.toml",
        ),
    ],
)
async def test_check_dependencies_alias_hyperlinks(
    tmp_path: Path,
    filename: str,
    file_contents: str,
    expected_configuration: Configuration | None,
) -> None:
    config_file_path = tmp_path / filename
    config_file_path.write_text(dedent(file_contents).strip())
    config = await config_file_factory(APath(config_file_path))
    assert config == expected_configuration
