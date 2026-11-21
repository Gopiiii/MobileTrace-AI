"""Input validation, safe filenames, and path confinement utilities."""

from __future__ import annotations

import re
from pathlib import Path

WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *{f"COM{i}" for i in range(1, 10)},
    *{f"LPT{i}" for i in range(1, 10)},
}

_UNSAFE_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(name: str, fallback: str = "file") -> str:
    """Sanitize a single filename component safely for Windows & POSIX."""
    cleaned = _UNSAFE_CHARS_RE.sub("_", name).strip().rstrip(".")
    if not cleaned or cleaned in {".", ".."}:
        cleaned = fallback
    stem = cleaned.split(".")[0].upper()
    if stem in WINDOWS_RESERVED_NAMES:
        cleaned = f"_{cleaned}"
    return cleaned[:240]


def sanitize_relative_path(raw_path: str) -> Path:
    """Convert an arbitrary remote/archive relative path into a safe confined Path."""
    normalized = raw_path.replace("\\", "/").strip("/")
    parts = []
    for part in normalized.split("/"):
        if not part or part in {".", ".."}:
            continue
        parts.append(sanitize_filename(part, fallback="item"))
    if not parts:
        return Path("unnamed_item")
    return Path(*parts)


def resolve_confined_path(base_dir: Path, relative_or_name: str | Path) -> Path:
    """Resolve a path strictly inside base_dir, raising ValueError on traversal."""
    base_resolved = base_dir.resolve()
    rel_path = sanitize_relative_path(str(relative_or_name)) if isinstance(relative_or_name, str) else relative_or_name
    candidate = (base_resolved / rel_path).resolve()
    try:
        candidate.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"Path escapes base directory: {relative_or_name}") from exc
    if candidate == base_resolved:
        raise ValueError("Resolved path must point inside base directory, not root itself")
    return candidate


def validate_adb_remote_path(remote_path: str) -> str:
    """Validate an Android remote path before passing to adb arguments."""
    cleaned = remote_path.strip()
    if not cleaned.startswith("/"):
        raise ValueError("Remote Android path must be absolute (start with '/').")
    if "\x00" in cleaned or "\n" in cleaned or "\r" in cleaned:
        raise ValueError("Remote path contains prohibited control characters.")
    if any(seg == ".." for seg in cleaned.split("/")):
        raise ValueError("Remote path must not contain '..' segments.")
    return cleaned
