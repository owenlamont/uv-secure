from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any


def total_bytes(root: Path) -> int:
    """Return cumulative size of all Python files under root."""

    return sum(path.stat().st_size for path in root.rglob("*.py"))


def compute_ratio(repo_root: Path) -> dict[str, Any]:
    """Compute tests/src byte ratio for the repo rooted at repo_root.

    Returns:
        dict[str, Any]: Mapping with src_bytes, test_bytes, and ratio keys.
    """

    src_bytes = total_bytes(repo_root / "src")
    test_bytes = total_bytes(repo_root / "tests")
    ratio = test_bytes / src_bytes if src_bytes else 0.0
    return {"src_bytes": src_bytes, "test_bytes": test_bytes, "ratio": ratio}


def main() -> None:
    """CLI entrypoint."""

    parser = argparse.ArgumentParser(description="Compute tests/src size ratio.")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    result = compute_ratio(repo_root)
    if args.format == "json":
        import json

        print(json.dumps(result))
    else:
        print(
            f"tests/src ratio: {result['ratio']:.3f} "
            f"(tests={result['test_bytes']} bytes, src={result['src_bytes']} bytes)"
        )


if __name__ == "__main__":
    main()
