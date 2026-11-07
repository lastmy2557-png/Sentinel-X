"""
SHA-256 File Inventory for Sentinel-X Anti-REA / Release Protection (Sections 5.1 & 5.2).
Computes deterministic SHA-256 digests and sizes for all release files while preventing
symlink traversal and excluding transient runtime directories.
"""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from sentinel_x.core.exceptions import ReleaseProtectionError, SecurityBoundaryError

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "logs",
}

DEFAULT_EXCLUDED_PATTERNS: List[str] = [
    "*.pyc",
    "*.pyo",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    "*.sqlite3-wal",
    "*.sqlite3-shm",
    "release_manifest*.json",
]


@dataclass(frozen=True)
class FileInventoryEntry:
    """Single file record in a SHA-256 Release Inventory."""

    relative_path: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


def compute_file_sha256(file_path: Path) -> str:
    """Compute hex-encoded SHA-256 digest of a file in chunks."""
    if file_path.is_symlink():
        raise SecurityBoundaryError(f"Refusing to hash symlink: {file_path}")
    hasher = hashlib.sha256()
    try:
        with file_path.open("rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as exc:
        raise ReleaseProtectionError(f"Failed to read file for hashing '{file_path}': {exc}") from exc
    return hasher.hexdigest()


def build_file_inventory(
    root_dir: Path | str,
    excluded_dirs: Optional[Set[str]] = None,
    excluded_patterns: Optional[Iterable[str]] = None,
) -> List[FileInventoryEntry]:
    """
    Walk root_dir deterministically and build a sorted SHA-256 inventory of all release files.
    """
    root = Path(root_dir).resolve()
    if not root.is_dir():
        raise ReleaseProtectionError(f"Release root directory does not exist: {root_dir}")

    skip_dirs = excluded_dirs if excluded_dirs is not None else DEFAULT_EXCLUDED_DIRS
    skip_patterns = list(
        excluded_patterns if excluded_patterns is not None else DEFAULT_EXCLUDED_PATTERNS
    )

    entries: List[FileInventoryEntry] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in skip_dirs for part in rel_parts):
            continue
        # Skip runtime database directory if present
        rel_posix = path.relative_to(root).as_posix()
        if rel_posix.startswith(("data/runtime/", "data/local/", "secrets/", "credentials/")):
            continue
        if path.is_dir():
            continue
        if any(fnmatch.fnmatch(path.name, pat) or fnmatch.fnmatch(rel_posix, pat) for pat in skip_patterns):
            continue

        digest = compute_file_sha256(path)
        size_bytes = path.stat().st_size
        entries.append(
            FileInventoryEntry(
                relative_path=rel_posix,
                sha256=digest,
                size_bytes=size_bytes,
            )
        )

    entries.sort(key=lambda e: e.relative_path)
    return entries
