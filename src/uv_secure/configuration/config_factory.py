import sys
from typing import Optional

from anyio import Path
from pydantic import BaseModel, Field


if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


class Configuration(BaseModel):
    ignore_vulnerabilities: set[str] = Field(default_factory=set)


def config_cli_arg_factory(ignore: Optional[str] = None) -> Configuration:
    """Factory to create a uv-secure configuration from its command line arguments

    Args:
        ignore: comma separated string of vulnerability ids to ignore

    Returns
    -------
        uv-secure configuration object
    """
    ignore_vulnerabilities = (
        {vuln_id.strip() for vuln_id in ignore.split(",") if vuln_id.strip()}
        if ignore is not None
        else set()
    )
    return Configuration(ignore_vulnerabilities=ignore_vulnerabilities)


async def config_file_factory(config_file: Path) -> Optional[Configuration]:
    """Factory to create a uv-secure configuration from a configuration toml file

    Args:
        config_file: Path to the configuration file (uv-secure.toml, .uv-secure.toml, or
        pyproject.toml)

    Returns
    -------
        uv-secure configuration object or None if no configuration was present
    """
    config_contents = toml.loads(await config_file.read_text())
    if config_file.name == "pyproject.toml":
        if "tool" in config_contents and "uv-secure" in config_contents["tool"]:
            return Configuration(**config_contents["tool"]["uv-secure"])
        return None
    return Configuration(**config_contents)
