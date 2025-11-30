import asyncio
from collections.abc import Sequence

from anyio import Path

from uv_secure.configuration import config_file_factory, Configuration


async def _search_file(directory: Path, filename: str) -> list[Path]:
    return [file_path async for file_path in directory.glob(f"**/{filename}")]


async def _find_files(
    directory: Path, filenames: Sequence[str]
) -> dict[str, list[Path]]:
    results = await asyncio.gather(
        *(_search_file(directory, filename) for filename in filenames)
    )
    return dict(zip(filenames, results, strict=False))


async def _resolve_paths(file_paths: Sequence[Path]) -> list[Path]:
    tasks = [asyncio.create_task(path.resolve()) for path in file_paths]
    return await asyncio.gather(*tasks) if tasks else []


def _get_root_dir(file_paths: Sequence[Path]) -> Path:
    if len(file_paths) == 1:
        return file_paths[0].parent

    split_paths = [list(rp.parts) for rp in file_paths]
    min_length = min(len(parts) for parts in split_paths)
    common_prefix_len = 0

    for part_idx in range(min_length):  # pragma: no branch (min_length is always > 0)
        segment_set = {parts[part_idx] for parts in split_paths}
        if len(segment_set) == 1:
            common_prefix_len += 1
        else:
            break

    common_parts = split_paths[0][:common_prefix_len]
    return Path(*common_parts)


async def _fetch_dependency_files(
    root_dir: Path, config_and_lock_files: dict[str, list[Path]]
) -> dict[Path, Configuration]:
    config_file_paths = (
        config_and_lock_files["pyproject.toml"]
        + config_and_lock_files["uv-secure.toml"]
        + config_and_lock_files[".uv-secure.toml"]
    )

    config_tasks = [
        asyncio.create_task(config_file_factory(path)) for path in config_file_paths
    ]
    configs = await asyncio.gather(*config_tasks) if config_tasks else []
    path_config_map = {
        p.parent: c
        for p, c in zip(config_file_paths, configs, strict=False)
        if c is not None
    }

    dependency_file_paths = (
        config_and_lock_files.get("pylock.toml", [])
        + config_and_lock_files.get("requirements.txt", [])
        + config_and_lock_files.get("uv.lock", [])
    )
    dependency_file_to_config_map: dict[Path, Configuration] = {}
    default_config = Configuration()
    for dependency_file in dependency_file_paths:
        current_dir = dependency_file.parent
        while True:
            found_config = path_config_map.get(current_dir)
            if found_config is not None or current_dir == root_dir:
                break
            current_dir = current_dir.parent

        if found_config is None:
            found_config = default_config
        dependency_file_to_config_map[dependency_file] = found_config
    return dependency_file_to_config_map


async def get_dependency_file_to_config_map(
    root_dir: Path,
) -> dict[Path, Configuration]:
    """Map dependency files under ``root_dir`` to configurations.

    Args:
        root_dir: Project root to scan.

    Returns:
        dict[Path, Configuration]: Dependency file to nearest configuration map.
    """
    root_dir = await root_dir.resolve()
    config_and_lock_files = await _find_files(
        root_dir,
        (
            "pyproject.toml",
            "uv-secure.toml",
            ".uv-secure.toml",
            "pylock.toml",
            "requirements.txt",
            "uv.lock",
        ),
    )

    return await _fetch_dependency_files(root_dir, config_and_lock_files)


async def get_dependency_files_to_config_map(
    file_paths: Sequence[Path],
) -> dict[Path, Configuration]:
    """Map specific dependency files to configurations.

    Args:
        file_paths: Dependency files to process.

    Returns:
        dict[Path, Configuration]: Dependency file to nearest configuration map.
    """
    resolved_paths = await _resolve_paths(file_paths)
    root_dir = _get_root_dir(resolved_paths)
    config_and_lock_files = await _find_files(
        root_dir, ["pyproject.toml", "uv-secure.toml", ".uv-secure.toml"]
    )
    config_and_lock_files["pylock.toml"] = [
        path for path in resolved_paths if path.name == "pylock.toml"
    ]
    config_and_lock_files["requirements.txt"] = [
        path for path in resolved_paths if path.name == "requirements.txt"
    ]
    config_and_lock_files["uv.lock"] = [
        path for path in resolved_paths if path.name == "uv.lock"
    ]

    return await _fetch_dependency_files(root_dir, config_and_lock_files)
