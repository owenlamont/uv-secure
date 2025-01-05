from collections.abc import Iterable
from typing import Union

from anyio import Path
from asyncer import create_task_group

from uv_secure.configuration import config_file_factory, Configuration


async def search_file(directory: Path, filename: str) -> list[Path]:
    return [file_path async for file_path in directory.glob(f"**/{filename}")]


async def find_files(
    directory: Path, filenames: Iterable[str]
) -> dict[str, list[Path]]:
    async with create_task_group() as tg:
        tasks = {
            filename: tg.soonify(search_file)(directory, filename)
            for filename in filenames
        }

    return {filename: task.value for filename, task in tasks.items()}


async def _get_root_dir(file_paths: Iterable[Path]) -> Path:
    async with create_task_group() as tg:
        tasks = [tg.soonify(path.resolve)() for path in file_paths]

    resolved_paths = [task.value for task in tasks]
    if len(resolved_paths) == 1:
        return resolved_paths[0].parent

    # --- Split resolved paths into parts ---
    split_paths = [list(rp.parts) for rp in resolved_paths]

    # Find the minimum length of these parts to avoid index errors
    min_length = min(len(parts) for parts in split_paths)
    common_prefix_len = 0

    # Compare each path segment across all paths
    for i in range(min_length):
        segment_set = {parts[i] for parts in split_paths}
        if len(segment_set) == 1:
            # All paths have the same segment at index i
            common_prefix_len += 1
        else:
            # A mismatch occurred
            break

    # Rebuild the common directory from the shared prefix
    # (Using the first path's parts up to common_prefix_len)
    common_parts = split_paths[0][:common_prefix_len]
    return Path(*common_parts)


async def get_lock_to_config_map(
    file_paths: Union[Path, list[Path]],
) -> dict[Path, Configuration]:
    if type(file_paths) is Path:
        root_dir = file_paths
        config_and_lock_files = await find_files(
            root_dir, ["pyproject.toml", "uv-secure.toml", ".uv-secure.toml", "uv.lock"]
        )
    else:
        root_dir = await _get_root_dir(file_paths)
        config_and_lock_files = await find_files(
            root_dir, ["pyproject.toml", "uv-secure.toml", ".uv-secure.toml"]
        )
        config_and_lock_files["uv.lock"] = file_paths

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
        p.parent: c for p, c in zip(config_file_paths, configs) if c is not None
    }

    lock_file_paths = config_and_lock_files.get("uv.lock", [])
    lock_to_config_map: dict[Path, Configuration] = {}
    default_config = Configuration()
    for lock_file in lock_file_paths:
        current_dir = lock_file.parent
        while True:
            found_config = path_config_map.get(current_dir)
            if found_config is not None or current_dir == root_dir:
                break
            current_dir = current_dir.parent

        if found_config is None:
            found_config = default_config
        lock_to_config_map[lock_file] = found_config
    return lock_to_config_map