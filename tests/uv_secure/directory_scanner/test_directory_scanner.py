from pathlib import Path
from textwrap import dedent

from anyio import Path as APath
import pytest

from uv_secure.configuration import Configuration, VulnerabilityCriteria
from uv_secure.directory_scanner import (
    get_dependency_file_to_config_map,
    get_dependency_file_to_config_source_map,
    get_dependency_files_to_config_map,
    get_dependency_files_to_config_source_map,
)
from uv_secure.directory_scanner.directory_scanner import _search_file


@pytest.mark.asyncio
async def test_get_dependency_file_maps_for_root_scan_returns_config_and_sources(
    tmp_path: Path,
) -> None:
    root_dir = tmp_path / "project"
    nested_dir = root_dir / "nested"
    root_dir.mkdir()
    nested_dir.mkdir()

    (root_dir / "uv-secure.toml").write_text(
        dedent(
            """
            [vulnerability_criteria]
            desc = true
            """
        ).strip()
    )
    (nested_dir / "pyproject.toml").write_text(
        dedent(
            """
            [tool.uv-secure.vulnerability_criteria]
            aliases = true
            """
        ).strip()
    )

    root_lock = root_dir / "uv.lock"
    nested_requirements = nested_dir / "requirements.txt"
    root_lock.write_text("")
    nested_requirements.write_text("")

    config_map = await get_dependency_file_to_config_map(APath(root_dir))
    source_map = await get_dependency_file_to_config_source_map(APath(root_dir))

    assert config_map[APath(root_lock)] == Configuration(
        vulnerability_criteria=VulnerabilityCriteria(desc=True)
    )
    assert config_map[APath(nested_requirements)] == Configuration(
        vulnerability_criteria=VulnerabilityCriteria(aliases=True)
    )
    assert source_map[APath(root_lock)] == APath(root_dir / "uv-secure.toml")
    assert source_map[APath(nested_requirements)] == APath(
        nested_dir / "pyproject.toml"
    )


@pytest.mark.asyncio
async def test_get_dependency_files_maps_for_explicit_paths_use_default_without_config(
    tmp_path: Path,
) -> None:
    lock_file = tmp_path / "uv.lock"
    lock_file.write_text("")

    config_map = await get_dependency_files_to_config_map([APath(lock_file)])
    source_map = await get_dependency_files_to_config_source_map([APath(lock_file)])

    assert config_map == {APath(lock_file): Configuration()}
    assert source_map == {APath(lock_file): None}


@pytest.mark.asyncio
async def test_search_file_returns_empty_for_missing_directory(tmp_path: Path) -> None:
    missing_dir = APath(tmp_path / "does-not-exist")

    files = await _search_file(missing_dir, "uv.lock")

    assert files == []
