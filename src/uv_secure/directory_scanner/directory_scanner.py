from collections.abc import Iterable, Sequence

from anyio import Path
from asyncer import create_task_group

from uv_secure.configuration import config_file_factory, Configuration


async def _search_file(directory: Path, filename: str) -> list[Path]:
    return [file_path async for file_path in directory.glob(f"**/{filename}")]


async def _find_files(
    directory: Path, filenames: Iterable[str]
) -> dict[str, list[Path]]:
    async with create_task_group() as tg:
        tasks = {
            filename: tg.soonify(_search_file)(directory, filename)
            for filename in filenames
        }

    return {filename: task.value for filename, task in tasks.items()}


async def _resolve_paths(file_paths: Sequence[Path]) -> list[Path]:
    async with create_task_group() as tg:
        tasks = [tg.soonify(path.resolve)() for path in file_paths]
    return [task.value for task in tasks]


def _get_root_dir(file_paths: Sequence[Path]) -> Path:
    if len(file_paths) == 1:
        return file_paths[0].parent

    split_paths = [list(rp.parts) for rp in file_paths]
    min_length = min(len(parts) for parts in split_paths)
    common_prefix_len = 0

    for part_idx in range(min_length):  # pragma: no cover (min_length is always > 0)
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

    async with create_task_group() as tg:
        config_futures = [
            tg.soonify(config_file_factory)(path) for path in config_file_paths
        ]
    configs = [future.value for future in config_futures]
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
    """Get map of requirements.txt, pylock.toml, and uv.lock files to configurations

    Using provided dependency files or root directory discover the files and also
    find and map the nearest parent configuration for each dependency file.

    Args:
        root_dir: Root directory

    Returns:
        A dictionary mapping dependency files to their nearest Configuration
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
    """Get map of requirements.txt, pylock.toml, and uv.lock files to configurations

    Using provided dependency files or root directory discover the files and also
    find and map the nearest parent configuration for each dependency file.

    Args:
        file_paths: A list of dependency files

    Returns:
        A dictionary mapping dependency files to their nearest Configuration
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
