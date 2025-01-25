from pathlib import Path
from typing import Annotated, Optional

from pydantic import BaseModel, Field


DEFAULT_HTTPX_CACHE_TTL = 24.0 * 60.0 * 60.0  # Default cache time to 1 day


class CacheSettings(BaseModel):
    cache_path: Path = Path.home() / ".cache/uv-secure"
    ttl_seconds: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = (
        DEFAULT_HTTPX_CACHE_TTL
    )


class Configuration(BaseModel):
    aliases: Optional[bool] = None
    desc: Optional[bool] = None
    ignore_vulnerabilities: Optional[set[str]] = None
    cache_settings: CacheSettings = CacheSettings()
