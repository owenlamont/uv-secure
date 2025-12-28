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
    import tomli as toml  # ty: ignore[unresolved-import]


def _parse_pkg_versions(raw: list[str] | None) -> dict[str, tuple[str, ...]] | None:
    """Parse colon/bar-delimited package version specifiers.

    Args:
        raw: Strings shaped like ``"name:>=1.0,<2.0|==3.4.*"``.

    Returns:
        dict[str, tuple[str, ...]] | None: Package names mapped to specifier tuples.
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
    check_uv_tool: bool | None,
) -> OverrideConfiguration:
    """Build overrides from CLI arguments.

    Args:
        aliases: Whether to include vulnerability aliases.
        check_direct_dependency_maintenance_issues_only: Limit maintenance checks to
            direct dependencies.
        check_direct_dependency_vulnerabilities_only: Limit vulnerability checks to
            direct dependencies.
        desc: Whether to include vulnerability descriptions.
        forbid_archived: Reject archived packages when True.
        forbid_deprecated: Reject deprecated packages when True.
        forbid_quarantined: Reject quarantined packages when True.
        forbid_yanked: Reject yanked packages when True.
        max_package_age: Maximum allowed package age in days.
        ignore_vulns: Comma-separated vulnerability IDs to ignore.
        ignore_pkgs: Package ignore strings in ``name:spec|spec`` format.
        format_type: Output format override.
        check_uv_tool: Toggle scanning of the globally installed uv CLI.

    Returns:
        OverrideConfiguration: CLI override instance.
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
        check_uv_tool=check_uv_tool,
    )


async def config_file_factory(config_file: Path) -> Configuration | None:
    """Create a configuration object from a file.

    Args:
        config_file: Path to ``uv-secure.toml``, ``.uv-secure.toml``, or
            ``pyproject.toml``.

    Returns:
        Configuration | None: Parsed configuration or ``None`` when not present.

    Raises:
        UvSecureConfigurationError: Raised when the TOML data fails validation.
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
