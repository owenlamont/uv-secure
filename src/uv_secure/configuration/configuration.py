from datetime import timedelta
from pathlib import Path
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field


DEFAULT_HTTPX_CACHE_TTL = 24.0 * 60.0 * 60.0  # Default cache time to 1 day


class CacheSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cache_path: Path = Path.home() / ".cache/uv-secure"
    disable_cache: bool = False
    ttl_seconds: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = (
        DEFAULT_HTTPX_CACHE_TTL
    )


class MaintainabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_package_age: Optional[timedelta] = None
    forbid_yanked: bool = False
    check_direct_dependencies_only: bool = False


class VulnerabilityCriteria(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aliases: bool = False
    desc: bool = False
    ignore_vulnerabilities: Optional[set[str]] = None
    check_direct_dependencies_only: bool = False


class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cache_settings: CacheSettings = CacheSettings()
    maintainability_criteria: MaintainabilityCriteria = MaintainabilityCriteria()
    vulnerability_criteria: VulnerabilityCriteria = VulnerabilityCriteria()


class OverrideConfiguration(BaseModel):
    aliases: Optional[bool] = None
    check_direct_dependency_maintenance_issues_only: Optional[bool] = None
    check_direct_dependency_vulnerabilities_only: Optional[bool] = None
    desc: Optional[bool] = None
    ignore_vulnerabilities: Optional[set[str]] = None
    forbid_yanked: Optional[bool] = None
    max_package_age: Optional[timedelta] = None
    disable_cache: Optional[bool] = None


def override_config(
    original_config: Configuration, overrides: OverrideConfiguration
) -> Configuration:
    """Override some configuration attributes from an override configuration

    Args:
        original_config: Original unmodified configuration
        overrides: Override attributes to override in original configuration

    Returns:
        Configuration with overridden attributes
    """

    new_configuration = original_config.model_copy()
    if overrides.aliases is not None:
        new_configuration.vulnerability_criteria.aliases = overrides.aliases
    if overrides.check_direct_dependency_maintenance_issues_only is not None:
        new_configuration.maintainability_criteria.check_direct_dependencies_only = (
            overrides.check_direct_dependency_maintenance_issues_only
        )
    if overrides.check_direct_dependency_vulnerabilities_only is not None:
        new_configuration.vulnerability_criteria.check_direct_dependencies_only = (
            overrides.check_direct_dependency_vulnerabilities_only
        )
    if overrides.desc is not None:
        new_configuration.vulnerability_criteria.desc = overrides.desc
    if overrides.ignore_vulnerabilities is not None:
        new_configuration.vulnerability_criteria.ignore_vulnerabilities = (
            overrides.ignore_vulnerabilities
        )
    if overrides.forbid_yanked is not None:
        new_configuration.maintainability_criteria.forbid_yanked = (
            overrides.forbid_yanked
        )
    if overrides.max_package_age is not None:
        new_configuration.maintainability_criteria.max_package_age = (
            overrides.max_package_age
        )
    if overrides.disable_cache is not None:
        new_configuration.cache_settings.disable_cache = overrides.disable_cache

    return new_configuration
