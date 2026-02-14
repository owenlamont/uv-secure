import pytest

from uv_secure.configuration import (
    Configuration,
    OutputFormat,
    override_config,
    OverrideConfiguration,
    VulnerabilityCriteria,
)


@pytest.mark.parametrize(
    ("original", "override", "expected"),
    [
        pytest.param(
            Configuration(
                vulnerability_criteria=VulnerabilityCriteria(aliases=False, desc=False)
            ),
            OverrideConfiguration(aliases=True, desc=True),
            Configuration(
                vulnerability_criteria=VulnerabilityCriteria(aliases=True, desc=True)
            ),
            id="aliases and desc override to True",
        ),
        pytest.param(
            Configuration(
                vulnerability_criteria=VulnerabilityCriteria(aliases=True, desc=True)
            ),
            OverrideConfiguration(aliases=False, desc=False),
            Configuration(
                vulnerability_criteria=VulnerabilityCriteria(aliases=False, desc=False)
            ),
            id="aliases and desc override to False",
        ),
        pytest.param(
            Configuration(format=OutputFormat.COLUMNS),
            OverrideConfiguration(format=OutputFormat.JSON),
            Configuration(format=OutputFormat.JSON),
            id="format override to JSON",
        ),
        pytest.param(
            Configuration(format=OutputFormat.JSON),
            OverrideConfiguration(format=OutputFormat.COLUMNS),
            Configuration(format=OutputFormat.COLUMNS),
            id="format override to COLUMNS",
        ),
        pytest.param(
            Configuration(check_uv_secure=True),
            OverrideConfiguration(check_uv_secure=False),
            Configuration(check_uv_secure=False),
            id="check_uv_secure override to False",
        ),
        pytest.param(
            Configuration(check_uv_tool=False),
            OverrideConfiguration(check_uv_tool=True),
            Configuration(check_uv_tool=True),
            id="check_uv_tool override to True",
        ),
    ],
)
def test_override_config(
    original: Configuration, override: OverrideConfiguration, expected: Configuration
) -> None:
    assert override_config(original, override) == expected
