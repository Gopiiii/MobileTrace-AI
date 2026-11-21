"""Built-in forensic artifact parsers for real iOS backups and acquired Android/local directories."""

from __future__ import annotations

import json
import mimetypes
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mobiletrace.analysis.exif_parser import extract_jpeg_exif
from mobiletrace.core.hashing import sha256_file
from mobiletrace.core.validation import resolve_confined_path
from mobiletrace.db.repository import ForensicRepository


APPLE_EPOCH = datetime(2001, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
PARSER_VERSION = "1.0.0"


def convert_apple_timestamp(raw_value: Any) -> tuple[str, str, str, str]:
    """Convert Apple CoreData/Cocoa timestamps (seconds or nanoseconds since 2001-01-01 UTC)."""
    if raw_value is None or raw_value == "" or raw_value == 0:
        return "", "unknown", "", ""
    try:
        num = float(raw_value)
    except (TypeError, ValueError):
        return str(raw_value), "unknown", "", "Non-numeric timestamp; preserved verbatim."
    if abs(num) > 1e14:  # nanoseconds since 2001-01-01
        seconds = num / 1_000_000_000.0
        unit = "nanoseconds_since_2001_01_01_utc"
    else:
        seconds = num
        unit = "seconds_since_2001_01_01_utc"
    dt = APPLE_EPOCH + timedelta(seconds=seconds)
    return str(raw_value), unit, dt.isoformat(), f"Converted Apple CoreData epoch ({unit}) to UTC ISO-8601."


def convert_unix_timestamp(raw_value: Any) -> tuple[str, str, str, str]:
    if raw_value is None or raw_value == "" or raw_value == 0:
        return "", "unknown", "", ""
    try:
        num = float(raw_value)
    except (TypeError, ValueError):
        return str(raw_value), "unknown", "", "Non-numeric timestamp; preserved verbatim."
    if abs(num) > 1e12:
        seconds = num / 1000.0
        unit = "unix_epoch_ms_utc"
    else:
        seconds = num
        unit = "unix_epoch_s_utc"
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    return str(raw_value), unit, dt.isoformat(), f"Converted {unit} to UTC ISO-8601."


def _locate_ios_backup_file(backup_dir: Path, file_id: str) -> Path | None:
    nested = backup_dir / file_id[:2] / file_id
    if nested.is_file():
        return nested
    flat = backup_dir / file_id
    if flat.is_file():
        return flat
    return None


def parse_ios_backup_artifacts(
    *,
    repo: ForensicRepository,
    case_id: str,
    device_id: str,
    session_id: str | None,
    backup_dir: Path,
    actor: str = "analyzer",
) -> dict[str, Any]:
    """Parse genuine iOS backup SQLite databases and media from Manifest.db without altering originals."""
    backup_dir = Path(backup_dir).resolve()
    manifest_db = backup_dir / "Manifest.db"
    if not manifest_db.is_file():
        raise FileNotFoundError(f"Manifest.db not found in {backup_dir}")

    counts = {"sms_messages": 0, "contacts": 0, "calls": 0, "safari_history": 0, "media_files": 0, "errors": []}
    conn = sqlite3.connect(f"file:{manifest_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT fileID, domain, relativePath, flags FROM Files WHERE flags = 1"
        ).fetchall()
    finally:
        conn.close()

    by_rel: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        entry = dict(r)
        by_rel.setdefault(entry["relativePath"], []).append(entry)

    # 1. SMS / iMessage (Library/SMS/sms.db)
    for item in by_rel.get("Library/SMS/sms.db", []):
        src_file = _locate_ios_backup_file(backup_dir, item["fileID"])
        if not src_file:
            continue
        sha_val, size_b = sha256_file(src_file)
        try:
            sconn = sqlite3.connect(f"file:{src_file}?mode=ro", uri=True)
            sconn.row_factory = sqlite3.Row
            msgs = sconn.execute(
                """
                SELECT m.ROWID, m.text, m.date, m.is_from_me, m.service, h.id AS handle_id
                FROM message m
                LEFT JOIN handle h ON h.ROWID = m.handle_id
                ORDER BY m.date ASC
                LIMIT 2000
                """
            ).fetchall()
            sconn.close()
            for m in msgs:
                orig_ts, orig_tz, norm_utc, justif = convert_apple_timestamp(m["date"])
                direction = "outgoing" if m["is_from_me"] else "incoming"
                peer = m["handle_id"] or "unknown"
                repo.add_artifact(
                    case_id=case_id,
                    device_id=device_id,
                    session_id=session_id,
                    artifact_type="sms_message",
                    title=f"{m['service'] or 'SMS'} ({direction}) — {peer}",
                    summary=(m["text"] or "")[:240],
                    original_source_path=f"{item['domain']}/{item['relativePath']}#ROWID={m['ROWID']}",
                    stored_copy_path=str(src_file),
                    original_timestamp=orig_ts,
                    original_timezone=orig_tz,
                    normalized_timestamp_utc=norm_utc,
                    normalization_justification=justif,
                    acquisition_method="ios_backup_manifest_db",
                    parser_name="mobiletrace_ios_sms",
                    parser_version=PARSER_VERSION,
                    sha256=sha_val,
                    byte_size=size_b,
                    provenance={"fileID": item["fileID"], "rowid": m["ROWID"]},
                    content={
                        "service": m["service"],
                        "direction": direction,
                        "peer": peer,
                        "text": m["text"] or "",
                    },
                    timeline_event_type="message",
                    timeline_confidence="verified_epoch" if norm_utc else "unverified",
                    actor=actor,
                )
                counts["sms_messages"] += 1
        except Exception as exc:
            counts["errors"].append(f"sms.db parse error: {exc}")

    # 2. Contacts (Library/AddressBook/AddressBook.sqlitedb)
    for item in by_rel.get("Library/AddressBook/AddressBook.sqlitedb", []):
        src_file = _locate_ios_backup_file(backup_dir, item["fileID"])
        if not src_file:
            continue
        sha_val, size_b = sha256_file(src_file)
        try:
            cconn = sqlite3.connect(f"file:{src_file}?mode=ro", uri=True)
            cconn.row_factory = sqlite3.Row
            persons = cconn.execute(
                """
                SELECT p.ROWID, p.First, p.Last, p.Organization,
                       GROUP_CONCAT(mv.value, '; ') AS values_list
                FROM ABPerson p
                LEFT JOIN ABMultiValue mv ON mv.record_id = p.ROWID
                GROUP BY p.ROWID
                LIMIT 2000
                """
            ).fetchall()
            cconn.close()
            for p in persons:
                full_name = " ".join(filter(None, [p["First"], p["Last"]])).strip() or p["Organization"] or f"Contact #{p['ROWID']}"
                repo.add_artifact(
                    case_id=case_id,
                    device_id=device_id,
                    session_id=session_id,
                    artifact_type="contact",
                    title=full_name,
                    summary=p["values_list"] or p["Organization"] or "",
                    original_source_path=f"{item['domain']}/{item['relativePath']}#ROWID={p['ROWID']}",
                    stored_copy_path=str(src_file),
                    acquisition_method="ios_backup_manifest_db",
                    parser_name="mobiletrace_ios_contacts",
                    parser_version=PARSER_VERSION,
                    sha256=sha_val,
                    byte_size=size_b,
                    provenance={"fileID": item["fileID"], "rowid": p["ROWID"]},
                    content={
                        "first": p["First"],
                        "last": p["Last"],
                        "organization": p["Organization"],
                        "identifiers": p["values_list"],
                    },
                    actor=actor,
                )
                counts["contacts"] += 1
        except Exception as exc:
            counts["errors"].append(f"AddressBook.sqlitedb parse error: {exc}")

    # 3. Call History (Library/CallHistoryDB/CallHistory.storedata or call_history.db)
    for rel_key in ("Library/CallHistoryDB/CallHistory.storedata", "Library/CallHistory/call_history.db"):
        for item in by_rel.get(rel_key, []):
            src_file = _locate_ios_backup_file(backup_dir, item["fileID"])
            if not src_file:
                continue
            sha_val, size_b = sha256_file(src_file)
            try:
                hconn = sqlite3.connect(f"file:{src_file}?mode=ro", uri=True)
                hconn.row_factory = sqlite3.Row
                tables = {r[0] for r in hconn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                if "ZCALLRECORD" in tables:
                    calls = hconn.execute(
                        "SELECT Z_PK, ZADDRESS, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED FROM ZCALLRECORD ORDER BY ZDATE ASC LIMIT 2000"
                    ).fetchall()
                    for c in calls:
                        orig_ts, orig_tz, norm_utc, justif = convert_apple_timestamp(c["ZDATE"])
                        direction = "outgoing" if c["ZORIGINATED"] else "incoming"
                        repo.add_artifact(
                            case_id=case_id,
                            device_id=device_id,
                            session_id=session_id,
                            artifact_type="call_log",
                            title=f"Call ({direction}) — {c['ZADDRESS'] or 'unknown'}",
                            summary=f"Duration {round(float(c['ZDURATION'] or 0), 1)}s, answered={bool(c['ZANSWERED'])}",
                            original_source_path=f"{item['domain']}/{item['relativePath']}#Z_PK={c['Z_PK']}",
                            stored_copy_path=str(src_file),
                            original_timestamp=orig_ts,
                            original_timezone=orig_tz,
                            normalized_timestamp_utc=norm_utc,
                            normalization_justification=justif,
                            acquisition_method="ios_backup_manifest_db",
                            parser_name="mobiletrace_ios_calls",
                            parser_version=PARSER_VERSION,
                            sha256=sha_val,
                            byte_size=size_b,
                            provenance={"fileID": item["fileID"], "z_pk": c["Z_PK"]},
                            content={
                                "address": c["ZADDRESS"],
                                "duration_seconds": c["ZDURATION"],
                                "direction": direction,
                                "answered": bool(c["ZANSWERED"]),
                            },
                            timeline_event_type="call",
                            timeline_confidence="verified_epoch" if norm_utc else "unverified",
                            actor=actor,
                        )
                        counts["calls"] += 1
                elif "call" in tables:
                    calls = hconn.execute(
                        "SELECT ROWID, address, date, duration, flags FROM call ORDER BY date ASC LIMIT 2000"
                    ).fetchall()
                    for c in calls:
                        orig_ts, orig_tz, norm_utc, justif = convert_unix_timestamp(c["date"])
                        repo.add_artifact(
                            case_id=case_id,
                            device_id=device_id,
                            session_id=session_id,
                            artifact_type="call_log",
                            title=f"Call — {c['address'] or 'unknown'}",
                            summary=f"Duration {c['duration']}s",
                            original_source_path=f"{item['domain']}/{item['relativePath']}#ROWID={c['ROWID']}",
                            stored_copy_path=str(src_file),
                            original_timestamp=orig_ts,
                            original_timezone=orig_tz,
                            normalized_timestamp_utc=norm_utc,
                            normalization_justification=justif,
                            acquisition_method="ios_backup_manifest_db",
                            parser_name="mobiletrace_ios_calls",
                            parser_version=PARSER_VERSION,
                            sha256=sha_val,
                            byte_size=size_b,
                            provenance={"fileID": item["fileID"], "rowid": c["ROWID"]},
                            content={"address": c["address"], "duration_seconds": c["duration"], "flags": c["flags"]},
                            timeline_event_type="call",
                            timeline_confidence="verified_epoch" if norm_utc else "unverified",
                            actor=actor,
                        )
                        counts["calls"] += 1
                hconn.close()
            except Exception as exc:
                counts["errors"].append(f"{rel_key} parse error: {exc}")

    # 4. Safari History (Library/Safari/History.db)
    for item in by_rel.get("Library/Safari/History.db", []):
        src_file = _locate_ios_backup_file(backup_dir, item["fileID"])
        if not src_file:
            continue
        sha_val, size_b = sha256_file(src_file)
        try:
            bconn = sqlite3.connect(f"file:{src_file}?mode=ro", uri=True)
            bconn.row_factory = sqlite3.Row
            visits = bconn.execute(
                """
                SELECT v.id, i.url, v.title, v.visit_time
                FROM history_visits v
                JOIN history_items i ON i.id = v.history_item
                ORDER BY v.visit_time ASC
                LIMIT 2000
                """
            ).fetchall()
            bconn.close()
            for v in visits:
                orig_ts, orig_tz, norm_utc, justif = convert_apple_timestamp(v["visit_time"])
                repo.add_artifact(
                    case_id=case_id,
                    device_id=device_id,
                    session_id=session_id,
                    artifact_type="browser_history",
                    title=v["title"] or v["url"],
                    summary=v["url"],
                    original_source_path=f"{item['domain']}/{item['relativePath']}#visit_id={v['id']}",
                    stored_copy_path=str(src_file),
                    original_timestamp=orig_ts,
                    original_timezone=orig_tz,
                    normalized_timestamp_utc=norm_utc,
                    normalization_justification=justif,
                    acquisition_method="ios_backup_manifest_db",
                    parser_name="mobiletrace_ios_safari",
                    parser_version=PARSER_VERSION,
                    sha256=sha_val,
                    byte_size=size_b,
                    provenance={"fileID": item["fileID"], "visit_id": v["id"]},
                    content={"url": v["url"], "title": v["title"] or ""},
                    timeline_event_type="web_visit",
                    timeline_confidence="verified_epoch" if norm_utc else "unverified",
                    actor=actor,
                )
                counts["safari_history"] += 1
        except Exception as exc:
            counts["errors"].append(f"Safari History.db parse error: {exc}")

    # 5. Media / CameraRoll files (EXIF & Hash)
    for r in rows:
        rel = r["relativePath"]
        if rel.lower().endswith((".jpg", ".jpeg", ".png", ".heic", ".mov", ".mp4")):
            src_file = _locate_ios_backup_file(backup_dir, r["fileID"])
            if not src_file:
                continue
            sha_val, size_b = sha256_file(src_file)
            exif = extract_jpeg_exif(src_file) if rel.lower().endswith((".jpg", ".jpeg")) else {}
            orig_ts = exif.get("DateTimeOriginal") or exif.get("DateTime") or ""
            offset = exif.get("OffsetTimeOriginal") or exif.get("OffsetTime") or ""
            norm_utc, justif = _parse_exif_datetime(orig_ts, offset)
            repo.add_artifact(
                case_id=case_id,
                device_id=device_id,
                session_id=session_id,
                artifact_type="media_file",
                title=Path(rel).name,
                summary=f"iOS backup media ({size_b} bytes)" + (f" · {exif.get('Model')}" if exif.get("Model") else ""),
                original_source_path=f"{r['domain']}/{rel}",
                stored_copy_path=str(src_file),
                original_timestamp=orig_ts,
                original_timezone=offset or ("exif_local_unspecified" if orig_ts else "unknown"),
                normalized_timestamp_utc=norm_utc,
                normalization_justification=justif,
                acquisition_method="ios_backup_manifest_db",
                parser_name="mobiletrace_media_exif",
                parser_version=PARSER_VERSION,
                sha256=sha_val,
                byte_size=size_b,
                provenance={"fileID": r["fileID"], "domain": r["domain"]},
                content={"exif": exif},
                timeline_event_type="media_capture" if orig_ts else None,
                timeline_confidence="exif_with_offset" if norm_utc else "exif_no_tz",
                actor=actor,
            )
            counts["media_files"] += 1

    return counts


def ingest_local_directory(
    *,
    repo: ForensicRepository,
    case_id: str,
    device_id: str,
    source_dir: Path,
    evidence_copy_dir: Path,
    platform: str = "android",
    acquisition_method: str = "local_evidence_ingest",
    actor: str = "examiner",
) -> dict[str, Any]:
    """Copy real local/exported files into evidence workspace, hash SHA-256, and extract genuine metadata."""
    source_dir = Path(source_dir).resolve()
    if not source_dir.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")
    evidence_copy_dir.mkdir(parents=True, exist_ok=True)

    limitations = [
        "Local directory / exported evidence ingestion; scope is limited to files present in the supplied source directory.",
        "Original source directory is preserved untouched; SHA-256 hashes are verified on workspace copies.",
    ]
    session = repo.create_acquisition_session(
        case_id=case_id,
        device_id=device_id,
        acquisition_method=acquisition_method,
        scope_classification="exported_directory_ingest",
        source_location=str(source_dir),
        output_directory=str(evidence_copy_dir),
        limitations=limitations,
        actor=actor,
    )

    files_copied = 0
    bytes_copied = 0
    errors: list[str] = []

    for src_path in sorted(source_dir.rglob("*")):
        if not src_path.is_file():
            continue
        rel = src_path.relative_to(source_dir)
        dest_path = resolve_confined_path(evidence_copy_dir, rel)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            src_hash, _ = sha256_file(src_path)
            shutil.copy2(src_path, dest_path)
            dst_hash, size_b = sha256_file(dest_path)
            if src_hash != dst_hash:
                errors.append(f"Hash mismatch on copy for {rel}: src={src_hash}, dst={dst_hash}")
                continue
        except Exception as exc:
            errors.append(f"Failed copying {rel}: {exc}")
            continue

        files_copied += 1
        bytes_copied += size_b
        mime, _ = mimetypes.guess_type(str(dest_path))
        exif = extract_jpeg_exif(dest_path) if dest_path.suffix.lower() in {".jpg", ".jpeg"} else {}

        mtime_utc = datetime.fromtimestamp(src_path.stat().st_mtime, tz=timezone.utc).isoformat()
        orig_ts = exif.get("DateTimeOriginal") or exif.get("DateTime") or mtime_utc
        offset = exif.get("OffsetTimeOriginal") or exif.get("OffsetTime") or ("UTC" if not exif else "")
        norm_utc, justif = (
            _parse_exif_datetime(orig_ts, offset)
            if exif.get("DateTimeOriginal") or exif.get("DateTime")
            else (mtime_utc, "Filesystem mtime converted from POSIX epoch to UTC.")
        )

        extra_content: dict[str, Any] = {"mime_type": mime or "application/octet-stream", "platform": platform}
        if exif:
            extra_content["exif"] = exif
        elif dest_path.suffix.lower() == ".json" and size_b <= 256_000:
            try:
                extra_content["json_preview"] = json.loads(dest_path.read_text(encoding="utf-8", errors="replace"))
            except Exception as exc:
                errors.append(f"JSON parse warning ({rel}): {exc}")

        repo.add_artifact(
            case_id=case_id,
            device_id=device_id,
            session_id=session["session_id"],
            artifact_type="media_file" if (mime or "").startswith("image/") else "acquired_file",
            title=dest_path.name,
            summary=f"{mime or 'file'} ({size_b} bytes)" + (f" · EXIF {exif.get('Model')}" if exif.get("Model") else ""),
            original_source_path=str(src_path),
            stored_copy_path=str(dest_path),
            original_timestamp=orig_ts,
            original_timezone=offset or ("exif_local_unspecified" if exif else "UTC"),
            normalized_timestamp_utc=norm_utc,
            normalization_justification=justif,
            acquisition_method=acquisition_method,
            parser_name="mobiletrace_directory_ingestor",
            parser_version=PARSER_VERSION,
            sha256=dst_hash,
            byte_size=size_b,
            provenance={"relative_path": str(rel).replace("\\", "/")},
            content=extra_content,
            timeline_event_type="media_capture" if exif else "file_mtime",
            timeline_confidence="verified_epoch" if norm_utc else "exif_no_tz",
            actor=actor,
        )

    status = "completed" if not errors else ("completed_with_errors" if files_copied > 0 else "failed")
    final_session = repo.finalize_acquisition_session(
        session_id=session["session_id"],
        status=status,
        files_copied=files_copied,
        bytes_copied=bytes_copied,
        errors=errors,
        limitations=limitations,
        actor=actor,
    )
    return {"session": final_session, "files_ingested": files_copied, "bytes_ingested": bytes_copied, "errors": errors}


def _parse_exif_datetime(raw_dt: str, offset: str) -> tuple[str, str]:
    if not raw_dt:
        return "", ""
    try:
        naive = datetime.strptime(raw_dt.strip(), "%Y:%m:%d %H:%M:%S")
    except ValueError:
        return "", "EXIF timestamp did not match YYYY:MM:DD HH:MM:SS; preserved verbatim."
    if offset and len(offset) in (5, 6) and offset[0] in ("+", "-"):
        clean = offset.replace(":", "")
        sign = 1 if clean[0] == "+" else -1
        hours = int(clean[1:3])
        mins = int(clean[3:5])
        tz = timezone(timedelta(hours=sign * hours, minutes=sign * mins))
        return naive.replace(tzinfo=tz).astimezone(timezone.utc).isoformat(), f"EXIF OffsetTime {offset} applied to normalize to UTC."
    return "", "EXIF DateTimeOriginal lacks timezone offset; preserved verbatim without speculative UTC conversion."
