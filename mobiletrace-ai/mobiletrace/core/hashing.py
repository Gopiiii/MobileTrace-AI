"""Cryptographic SHA-256 hashing and verification helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable


CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_file(path: Path, on_bytes: Callable[[int], None] | None = None) -> tuple[str, int]:
    """Compute SHA-256 hex digest and byte count by streaming the file."""
    digest = hashlib.sha256()
    total_bytes = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            total_bytes += len(chunk)
            if on_bytes is not None:
                on_bytes(len(chunk))
    return digest.hexdigest(), total_bytes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def verify_file_sha256(path: Path, expected_sha256: str) -> tuple[bool, str | None, int]:
    """Re-hash a file on disk and verify it matches expected_sha256."""
    if not path.is_file():
        return False, None, 0
    actual, size_bytes = sha256_file(path)
    return actual.lower() == expected_sha256.lower(), actual, size_bytes
