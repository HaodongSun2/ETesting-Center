from __future__ import annotations

import hashlib
from pathlib import Path


def file_hashes(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def sample_bytes(path: Path, limit: int = 4 * 1024 * 1024) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)
