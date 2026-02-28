from dataclasses import dataclass

from anyio import Path as APath
from tomlkit import dumps, parse
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import Array, InlineTable, Table
from tomlkit.toml_document import TOMLDocument


@dataclass(frozen=True)
class FixAppliedSummary:
    removed_vulnerability_ids: set[str]
    removed_package_ignores: set[str]
    modified: bool


TomlTableLike = TOMLDocument | Table | InlineTable


def _get_uv_secure_root(
    document: TOMLDocument, config_path: APath
) -> TomlTableLike | None:
    if config_path.name != "pyproject.toml":
        return document
    tool_section = document.get("tool")
    if not isinstance(tool_section, Table | InlineTable):
        return None
    uv_secure_section = tool_section.get("uv-secure")
    if not isinstance(uv_secure_section, Table | InlineTable):
        return None
    return uv_secure_section


def _remove_unused_vulnerability_ids(
    root: TomlTableLike, vulnerability_ids: set[str]
) -> tuple[set[str], bool]:
    if not vulnerability_ids:
        return set(), False
    vulnerability_criteria = root.get("vulnerability_criteria")
    if not isinstance(vulnerability_criteria, Table | InlineTable):
        return set(), False
    ignore_vulnerabilities = vulnerability_criteria.get("ignore_vulnerabilities")
    if not isinstance(ignore_vulnerabilities, Array):
        return set(), False

    removed_ids: set[str] = set()
    removed_any = False
    for index in range(len(ignore_vulnerabilities) - 1, -1, -1):
        raw_value = ignore_vulnerabilities[index]
        value = raw_value.value if hasattr(raw_value, "value") else raw_value
        if isinstance(value, str) and value in vulnerability_ids:
            ignore_vulnerabilities.pop(index)
            removed_ids.add(value)
            removed_any = True

    if removed_any and len(ignore_vulnerabilities) == 0:
        empty_array = parse("value = []")["value"]
        vulnerability_criteria["ignore_vulnerabilities"] = empty_array
    return removed_ids, removed_any


def _remove_unused_package_ignores(
    root: TomlTableLike, package_names: set[str]
) -> tuple[set[str], bool]:
    if not package_names:
        return set(), False
    ignore_packages = root.get("ignore_packages")
    if not isinstance(ignore_packages, Table | InlineTable):
        return set(), False

    removed_packages: set[str] = set()
    removed_any = False
    for package_name in package_names:
        if package_name in ignore_packages:
            del ignore_packages[package_name]
            removed_packages.add(package_name)
            removed_any = True
    return removed_packages, removed_any


async def fix_unused_ignores_in_toml_config(
    config_path: APath, vulnerability_ids: set[str], package_names: set[str]
) -> FixAppliedSummary:
    """Remove unused ignore values from uv-secure TOML configuration files.

    Args:
        config_path: Path to ``uv-secure.toml``, ``.uv-secure.toml``, or
            ``pyproject.toml``.
        vulnerability_ids: Vulnerability IDs to remove from ignore lists.
        package_names: Package ignore keys to remove.

    Returns:
        FixAppliedSummary: Summary of applied edits for this file.
    """
    file_contents = await config_path.read_text()
    try:
        document = parse(file_contents)
    except TOMLKitError:
        return FixAppliedSummary(set(), set(), False)

    root = _get_uv_secure_root(document, config_path)
    if root is None:
        return FixAppliedSummary(set(), set(), False)

    removed_vulnerability_ids, vulnerability_changed = _remove_unused_vulnerability_ids(
        root, vulnerability_ids
    )
    removed_package_ignores, packages_changed = _remove_unused_package_ignores(
        root, package_names
    )
    modified = vulnerability_changed or packages_changed
    if modified:
        await config_path.write_text(dumps(document))
    return FixAppliedSummary(
        removed_vulnerability_ids=removed_vulnerability_ids,
        removed_package_ignores=removed_package_ignores,
        modified=modified,
    )
