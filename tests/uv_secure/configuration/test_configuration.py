import pytest

from uv_secure.configuration import (
    CacheSettings,
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
        pytest.param(
            Configuration(),
            OverrideConfiguration(disable_cache=True),
            Configuration(cache_settings=CacheSettings(disable_cache=True)),
            id="Disable caching",
        ),
    ],
)
def test_override_config(
    original: Configuration, override: OverrideConfiguration, expected: Configuration
) -> None:
    assert override_config(original, override) == expected
