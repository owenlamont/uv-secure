from pathlib import Path
from textwrap import dedent

import pytest


@pytest.fixture
def temp_uv_lock_file(tmp_path: Path) -> Path:
    """Fixture to create a temporary uv.lock file with a single dependency."""
    uv_lock_path = tmp_path / "uv.lock"
    uv_lock_data = """
        [[package]]
        name = "example-package"
        version = "1.0.0"
        source = { registry = "https://pypi.org/simple" }
    """
    uv_lock_path.write_text(dedent(uv_lock_data).strip())
    return uv_lock_path
