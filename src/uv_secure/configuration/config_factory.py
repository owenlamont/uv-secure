from datetime import timedelta
import sys
from typing import Optional

from anyio import Path
from pydantic import ValidationError

from uv_secure.configuration.configuration import Configuration, OverrideConfiguration
from uv_secure.configuration.exceptions import UvSecureConfigurationError


if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


def config_cli_arg_factory(
    aliases: Optional[bool],
    check_direct_dependency_maintenance_issues_only: Optional[bool],
    check_direct_dependency_vulnerabilities_only: Optional[bool],
    desc: Optional[bool],
    disable_cache: Optional[bool],
    forbid_yanked: Optional[bool],
    max_package_age: Optional[int],
    ignore: Optional[str],
) -> OverrideConfiguration:
    """Factory to create a uv-secure configuration from its command line arguments

    Args:
        aliases: Flag whether to show vulnerability aliases in results
        desc: Flag whether to show vulnerability descriptions in results
        disable_cache: Flag whether to disable cache
        forbid_yanked: flag whether to forbid yanked dependencies
        max_package_age: maximum age of dependencies in days
        ignore: comma separated string of vulnerability ids to ignore

    Returns
    -------
        uv-secure override configuration object
    """
    ignore_vulnerabilities = (
        {vuln_id.strip() for vuln_id in ignore.split(",") if vuln_id.strip()}
        if ignore is not None
        else None
    )

    return OverrideConfiguration(
        aliases=aliases,
        check_direct_dependency_maintenance_issues_only=check_direct_dependency_maintenance_issues_only,
        check_direct_dependency_vulnerabilities_only=check_direct_dependency_vulnerabilities_only,
        desc=desc,
        disable_cache=disable_cache,
        forbid_yanked=forbid_yanked,
        max_package_age=timedelta(days=max_package_age) if max_package_age else None,
        ignore_vulnerabilities=ignore_vulnerabilities,
    )


async def config_file_factory(config_file: Path) -> Optional[Configuration]:
    """Factory to create a uv-secure configuration from a configuration toml file

    Args:
        config_file: Path to the configuration file (uv-secure.toml, .uv-secure.toml, or
        pyproject.toml)

    Returns
    -------
        uv-secure configuration object or None if no configuration was present
    """
    try:
        config_contents = toml.loads(await config_file.read_text())
        if config_file.name == "pyproject.toml":
            if "tool" in config_contents and "uv-secure" in config_contents["tool"]:
                return Configuration(**config_contents["tool"]["uv-secure"])
            return None
        return Configuration(**config_contents)
    except ValidationError as e:
        raise UvSecureConfigurationError(
            f"Parsing uv-secure configuration at: {config_file} failed. Check the "
            "configuration is up to date as documented at: "
            "https://github.com/owenlamont/uv-secure and check release notes for "
            "breaking changes."
        ) from e
