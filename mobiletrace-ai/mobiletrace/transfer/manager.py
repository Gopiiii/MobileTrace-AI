"""Real byte-accurate forensic data transfer manager with SHA-256 verification and manifests."""

from __future__ import annotations

import hashlib
import json
import shutil
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from mobiletrace.core.hashing import CHUNK_SIZE, sha256_file
from mobiletrace.core.validation import resolve_confined_path, sanitize_filename
from mobiletrace.db.repository import ForensicRepository


@dataclass
class TransferProgress:
    files_done: int
    total_files: int
    bytes_done: int
    total_bytes: int
    current_file: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _unique_destination(dest_path: Path) -> Path:
    stem = dest_path.stem
    suffix = dest_path.suffix
    parent = dest_path.parent
    counter = 1
    while True:
        candidate = parent / f"{stem}_copy{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


class TransferManager:
    """Copies acquired evidence files cleanly while preserving sources and verifying SHA-256."""

    def execute_transfer(
        self,
        *,
        repo: ForensicRepository,
        case_id: str,
        source_paths: list[Path],
        destination_dir: Path,
        source_root: Path | None = None,
        conflict_policy: str = "rename",
        actor: str = "examiner",
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[TransferProgress], None] | None = None,
    ) -> dict[str, Any]:
        if conflict_policy not in {"skip", "rename", "overwrite"}:
            raise ValueError("conflict_policy must be 'skip', 'rename', or 'overwrite'")

        dest_root = Path(destination_dir).resolve()
        dest_root.mkdir(parents=True, exist_ok=True)

        # Expand directories cleanly while validating source existence
        resolved_files: list[tuple[Path, Path]] = []
        for raw_src in source_paths:
            src = Path(raw_src).resolve()
            if not src.exists():
                raise FileNotFoundError(f"Source path does not exist: {src}")
            if src.is_dir():
                for child in sorted(src.rglob("*")):
                    if child.is_file():
                        rel = child.relative_to(src)
                        resolved_files.append((child, rel))
            elif src.is_file():
                if source_root:
                    try:
                        rel = src.relative_to(Path(source_root).resolve())
                    except ValueError:
                        rel = Path(sanitize_filename(src.name))
                else:
                    rel = Path(sanitize_filename(src.name))
                resolved_files.append((src, rel))

        total_bytes_planned = sum(src.stat().st_size for src, _ in resolved_files)
        usage = shutil.disk_usage(dest_root)
        if usage.free < total_bytes_planned:
            raise OSError(
                f"Insufficient destination disk space: required {total_bytes_planned} bytes, "
                f"available {usage.free} bytes at {dest_root}"
            )

        manifest = repo.create_transfer_manifest(
            case_id=case_id,
            source_root=str(source_root or (resolved_files[0][0].parent if resolved_files else dest_root)),
            destination_root=str(dest_root),
            conflict_policy=conflict_policy,
            actor=actor,
        )
        manifest_id = manifest["manifest_id"]

        bytes_done = 0
        succeeded = 0
        failed = 0
        skipped = 0
        manifest_entries: list[dict[str, Any]] = []
        cancelled = False

        for idx, (src_file, rel_path) in enumerate(resolved_files, start=1):
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break

            try:
                target_path = resolve_confined_path(dest_root, rel_path)
            except ValueError as exc:
                failed += 1
                rec = repo.record_transferred_file(
                    manifest_id=manifest_id,
                    case_id=case_id,
                    source_path=str(src_file),
                    destination_path="",
                    byte_size=0,
                    source_sha256="",
                    destination_sha256="",
                    verified=False,
                    status="failed",
                    error_message=str(exc),
                )
                manifest_entries.append(rec)
                continue

            # Ensure source != destination to preserve source evidence
            if src_file.resolve() == target_path.resolve():
                failed += 1
                rec = repo.record_transferred_file(
                    manifest_id=manifest_id,
                    case_id=case_id,
                    source_path=str(src_file),
                    destination_path=str(target_path),
                    byte_size=0,
                    source_sha256="",
                    destination_sha256="",
                    verified=False,
                    status="failed",
                    error_message="Destination path resolves to source file; source preservation forbids in-place overwrite.",
                )
                manifest_entries.append(rec)
                continue

            if target_path.exists():
                if conflict_policy == "skip":
                    skipped += 1
                    rec = repo.record_transferred_file(
                        manifest_id=manifest_id,
                        case_id=case_id,
                        source_path=str(src_file),
                        destination_path=str(target_path),
                        byte_size=src_file.stat().st_size,
                        source_sha256="",
                        destination_sha256="",
                        verified=False,
                        status="skipped",
                        error_message="Destination file already exists (conflict_policy=skip).",
                    )
                    manifest_entries.append(rec)
                    continue
                elif conflict_policy == "rename":
                    target_path = _unique_destination(target_path)

            target_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = target_path.with_name(f".{target_path.name}.partial")

            try:
                src_digest = hashlib.sha256()
                copied_bytes = 0
                with src_file.open("rb") as f_in, temp_path.open("wb") as f_out:
                    while True:
                        if cancel_event is not None and cancel_event.is_set():
                            cancelled = True
                            break
                        chunk = f_in.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f_out.write(chunk)
                        src_digest.update(chunk)
                        copied_bytes += len(chunk)
                        bytes_done += len(chunk)
                        if on_progress is not None:
                            on_progress(
                                TransferProgress(
                                    files_done=idx - 1,
                                    total_files=len(resolved_files),
                                    bytes_done=bytes_done,
                                    total_bytes=total_bytes_planned,
                                    current_file=str(src_file.name),
                                )
                            )
                if cancelled:
                    temp_path.unlink(missing_ok=True)
                    break

                shutil.copystat(src_file, temp_path)
                temp_path.replace(target_path)

                src_hex = src_digest.hexdigest()
                dst_hex, dst_bytes = sha256_file(target_path)
                verified = src_hex == dst_hex and dst_bytes == copied_bytes
                if not verified:
                    failed += 1
                    rec = repo.record_transferred_file(
                        manifest_id=manifest_id,
                        case_id=case_id,
                        source_path=str(src_file),
                        destination_path=str(target_path),
                        byte_size=dst_bytes,
                        source_sha256=src_hex,
                        destination_sha256=dst_hex,
                        verified=False,
                        status="failed",
                        error_message="Post-copy SHA-256 verification failed.",
                    )
                else:
                    succeeded += 1
                    rec = repo.record_transferred_file(
                        manifest_id=manifest_id,
                        case_id=case_id,
                        source_path=str(src_file),
                        destination_path=str(target_path),
                        byte_size=dst_bytes,
                        source_sha256=src_hex,
                        destination_sha256=dst_hex,
                        verified=True,
                        status="verified",
                        error_message="",
                    )
                manifest_entries.append(rec)
            except Exception as exc:
                temp_path.unlink(missing_ok=True)
                failed += 1
                rec = repo.record_transferred_file(
                    manifest_id=manifest_id,
                    case_id=case_id,
                    source_path=str(src_file),
                    destination_path=str(target_path),
                    byte_size=0,
                    source_sha256="",
                    destination_sha256="",
                    verified=False,
                    status="failed",
                    error_message=str(exc),
                )
                manifest_entries.append(rec)

            if on_progress is not None:
                on_progress(
                    TransferProgress(
                        files_done=idx,
                        total_files=len(resolved_files),
                        bytes_done=bytes_done,
                        total_bytes=total_bytes_planned,
                        current_file=str(src_file.name),
                    )
                )

        if cancelled:
            final_status = "cancelled"
        elif failed > 0 and succeeded > 0:
            final_status = "completed_with_errors"
        elif failed > 0 and succeeded == 0:
            final_status = "failed"
        else:
            final_status = "completed"

        manifest_file = dest_root / f"transfer_manifest_{manifest_id}.json"
        manifest_payload = {
            "manifest_id": manifest_id,
            "case_id": case_id,
            "status": final_status,
            "conflict_policy": conflict_policy,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_files": len(resolved_files),
            "succeeded_files": succeeded,
            "failed_files": failed,
            "skipped_files": skipped,
            "total_bytes_copied": bytes_done,
            "files": manifest_entries,
        }
        manifest_file.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")
        manifest_sha, _ = sha256_file(manifest_file)

        final_record = repo.finalize_transfer_manifest(
            manifest_id=manifest_id,
            status=final_status,
            total_files=len(resolved_files),
            succeeded_files=succeeded,
            failed_files=failed,
            skipped_files=skipped,
            total_bytes=bytes_done,
            manifest_path=str(manifest_file),
            manifest_sha256=manifest_sha,
            actor=actor,
        )
        return {"manifest": final_record, "files": manifest_entries, "manifest_json_path": str(manifest_file)}
