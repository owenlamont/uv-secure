from datetime import timedelta
import sys

from anyio import Path
from pydantic import ValidationError

from uv_secure.configuration.configuration import (
    Configuration,
    OutputFormat,
    OverrideConfiguration,
)
from uv_secure.configuration.exceptions import UvSecureConfigurationError


if sys.version_info >= (3, 11):
    import tomllib as toml
else:
    import tomli as toml


def _parse_pkg_versions(raw: list[str] | None) -> dict[str, tuple[str, ...]] | None:
    """Parse package and bar delimited version specifiers

    Parse things like "foo:>=1.0,<1.5|==4.5.*" into
    {"foo": [SpecifierSet(">=1.0,<1.5"), SpecifierSet("==4.5.*")]}

    Args:
        raw: list of strings in the format "NAME:SPEC1|SPEC2|…"

    Returns:
        dictionary mapping package names to lists of SpecifierSets

    Raises:
        typer.BadParameter: If the input format is invalid, e.g. missing colon or no
        specifiers
    """
    if not raw:
        return None
    parsed: dict[str, tuple[str, ...]] = {}
    for item in raw:
        if ":" in item:
            name, spec_expr = item.split(":", 1)
            parsed[name] = tuple(spec_expr.split("|"))
        else:
            parsed[item] = ()
    return parsed


def config_cli_arg_factory(
    aliases: bool | None,
    check_direct_dependency_maintenance_issues_only: bool | None,
    check_direct_dependency_vulnerabilities_only: bool | None,
    desc: bool | None,
    forbid_archived: bool | None,
    forbid_deprecated: bool | None,
    forbid_quarantined: bool | None,
    forbid_yanked: bool | None,
    max_package_age: int | None,
    ignore_vulns: str | None,
    ignore_pkgs: list[str] | None,
    format_type: OutputFormat | None,
) -> OverrideConfiguration:
    """Factory to create a uv-secure configuration from its command line arguments

    Args:
        aliases: Flag whether to show vulnerability aliases in results
        desc: Flag whether to show vulnerability descriptions in results
        disable_cache: Flag whether to disable cache
        forbid_archived: flag whether to forbid archived dependencies
        forbid_deprecated: flag whether to forbid deprecated dependencies
        forbid_quarantined: flag whether to forbid quarantined dependencies
        forbid_yanked: flag whether to forbid yanked dependencies
        max_package_age: maximum age of dependencies in days
        ignore_vulns: comma separated string of vulnerability ids to ignore
        ignore_pkgs: list of package names and version specifiers to ignore
        format_type: output format type (OutputFormat enum value)

    Returns:
        uv-secure override configuration object
    """
    ignore_vulnerabilities = (
        {vuln_id.strip() for vuln_id in ignore_vulns.split(",") if vuln_id.strip()}
        if ignore_vulns is not None
        else None
    )

    return OverrideConfiguration(
        aliases=aliases,
        check_direct_dependency_maintenance_issues_only=check_direct_dependency_maintenance_issues_only,
        check_direct_dependency_vulnerabilities_only=check_direct_dependency_vulnerabilities_only,
        desc=desc,
        forbid_archived=forbid_archived,
        forbid_deprecated=forbid_deprecated,
        forbid_quarantined=forbid_quarantined,
        forbid_yanked=forbid_yanked,
        max_package_age=timedelta(days=max_package_age) if max_package_age else None,
        ignore_vulnerabilities=ignore_vulnerabilities,
        ignore_packages=_parse_pkg_versions(ignore_pkgs),
        format=format_type,
    )


async def config_file_factory(config_file: Path) -> Configuration | None:
    """Factory to create a uv-secure configuration from a configuration toml file

    Args:
        config_file: Path to the configuration file (uv-secure.toml, .uv-secure.toml, or
            pyproject.toml)

    Returns:
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
