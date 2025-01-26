from pathlib import Path
from typing import Annotated, Optional

from pydantic import BaseModel, Field


DEFAULT_HTTPX_CACHE_TTL = 24.0 * 60.0 * 60.0  # Default cache time to 1 day


class CacheSettings(BaseModel):
    cache_path: Path = Path.home() / ".cache/uv-secure"
    disable_cache: bool = False
    ttl_seconds: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = (
        DEFAULT_HTTPX_CACHE_TTL
    )


class Configuration(BaseModel):
    aliases: bool = False
    desc: bool = False
    ignore_vulnerabilities: Optional[set[str]] = None
    cache_settings: CacheSettings = CacheSettings()


class OverrideConfiguration(BaseModel):
    aliases: Optional[bool] = None
    desc: Optional[bool] = None
    ignore_vulnerabilities: Optional[set[str]] = None
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
        new_configuration.aliases = overrides.aliases
    if overrides.desc is not None:
        new_configuration.desc = overrides.desc
    if overrides.ignore_vulnerabilities is not None:
        new_configuration.ignore_vulnerabilities = overrides.ignore_vulnerabilities
    if overrides.disable_cache is not None:
        new_configuration.cache_settings.disable_cache = overrides.disable_cache

    return new_configuration
