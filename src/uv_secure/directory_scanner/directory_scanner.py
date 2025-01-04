from collections.abc import Iterable

from anyio import Path
from asyncer import create_task_group

from uv_secure.configuration import Configuration


async def find_files(directory: Path) -> dict[str, Iterable[Path]]:
    filenames = ["pyproject.toml", "uv-secure.toml", ".uv-secure.toml", "uv.lock"]

    async def search_file(filename: str) -> Iterable[Path]:
        return [file_path async for file_path in directory.glob(f"**/{filename}")]

    async with create_task_group() as tg:
        tasks = {filename: tg.soonify(search_file)(filename) for filename in filenames}

    return {filename: task.value for filename, task in tasks.items()}


async def get_config_lock_file_pairs(
    root_dir: Path,
) -> dict[Configuration, Iterable[Path]]:
    _ = await find_files(root_dir)
    return {Configuration(): []}
