import asyncio

from anyio import Path as APath
from httpx import AsyncClient

from uv_secure.caching.cache_manager import CacheManager
from uv_secure.configuration import Configuration
from uv_secure.dependency_checker.osv import enrich_vulnerability_severity_data
from uv_secure.dependency_checker.package_processing import (
    build_ignore_packages,
    process_package_metadata,
)
from uv_secure.output_models import FileResultOutput
from uv_secure.package_info import (
    download_package_indexes,
    download_packages,
    PackageIndex,
    PackageInfo,
    parse_pylock_toml_file,
    parse_requirements_txt_file,
    parse_uv_lock_file,
    ParseResult,
)


async def _parse_dependency_file(dependency_file_path: APath) -> ParseResult:
    if dependency_file_path.name == "uv.lock":
        return await parse_uv_lock_file(dependency_file_path)
    if dependency_file_path.name == "requirements.txt":
        return await parse_requirements_txt_file(dependency_file_path)
    return await parse_pylock_toml_file(dependency_file_path)


async def check_dependencies(
    dependency_file_path: APath,
    config: Configuration,
    http_client: AsyncClient,
    cache_manager: CacheManager | None,
    used_ignore_vulnerabilities: set[str] | None = None,
    matched_ignore_packages: set[str] | None = None,
    used_ignore_packages: set[str] | None = None,
) -> FileResultOutput:
    """Check dependencies for vulnerabilities and build structured output.

    Returns:
        FileResultOutput: Structured dependency results for the input file.
    """
    file_path_str = dependency_file_path.as_posix()
    used_ignore_tracker = (
        used_ignore_vulnerabilities
        if used_ignore_vulnerabilities is not None
        else set()
    )
    used_ignore_packages_tracker = (
        used_ignore_packages if used_ignore_packages is not None else set()
    )
    matched_ignore_packages_tracker = (
        matched_ignore_packages if matched_ignore_packages is not None else set()
    )

    if not await dependency_file_path.exists():
        return FileResultOutput(
            file_path=file_path_str,
            error=f"File {dependency_file_path} does not exist.",
        )

    try:
        parse_result = await _parse_dependency_file(dependency_file_path)
    except Exception as exc:  # pragma: no cover - defensive, surfaced to user
        return FileResultOutput(
            file_path=file_path_str,
            error=f"Failed to parse {dependency_file_path}: {exc}",
        )

    dependencies = parse_result.dependencies
    ignored_count = parse_result.ignored_count
    if len(dependencies) == 0:
        return FileResultOutput(
            file_path=file_path_str, dependencies=[], ignored_count=ignored_count
        )

    package_infos_task = asyncio.create_task(
        download_packages(dependencies, http_client, cache_manager)
    )
    package_indexes_task = asyncio.create_task(
        download_package_indexes(dependencies, http_client, cache_manager)
    )
    package_infos, package_indexes = await asyncio.gather(
        package_infos_task, package_indexes_task
    )
    await enrich_vulnerability_severity_data(package_infos, http_client, cache_manager)

    package_metadata: list[
        tuple[PackageInfo | BaseException, PackageIndex | BaseException]
    ] = list(zip(package_infos, package_indexes, strict=True))

    ignore_packages = build_ignore_packages(config)
    dependency_outputs = []
    for idx, (package_info, package_index) in enumerate(package_metadata):
        result = process_package_metadata(
            package_info,
            package_index,
            dependencies[idx].name,
            config,
            ignore_packages,
            used_ignore_tracker,
            matched_ignore_packages_tracker,
            used_ignore_packages_tracker,
        )
        if isinstance(result, str):
            return FileResultOutput(file_path=file_path_str, error=result)
        if result is not None:
            dependency_outputs.append(result)

    return FileResultOutput(
        file_path=file_path_str,
        dependencies=dependency_outputs,
        ignored_count=ignored_count,
    )
