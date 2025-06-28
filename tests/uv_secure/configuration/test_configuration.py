import pytest

from uv_secure.configuration import (
    Configuration,
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
    ],
)
def test_override_config(
    original: Configuration, override: OverrideConfiguration, expected: Configuration
) -> None:
    assert override_config(original, override) == expected
