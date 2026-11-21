"""Persistent SQLite forensic repository with foreign keys, transactions, and hash-chained audit logs."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from mobiletrace.core.hashing import sha256_json
from mobiletrace.db.migrations import apply_migrations


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class ForensicRepository:
    """Thread-safe SQLite repository enforcing foreign keys, transactions, and append-only audit logs."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path).resolve()
        apply_migrations(self.db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _row_to_dict(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return dict(row)

    # ---------------- Audit Log (Append-Only Hash Chain) ----------------

    def _append_audit_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        case_id: str,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        last_row = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = last_row["event_hash"] if last_row else "0" * 64
        event_id = _new_id("aud")
        created_at = _utc_iso()
        details_json = json.dumps(details or {}, sort_keys=True, default=str)
        event_hash = sha256_json(
            {
                "event_id": event_id,
                "case_id": case_id,
                "actor": actor,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "details_json": details_json,
                "prev_event_hash": prev_hash,
                "created_at": created_at,
            }
        )
        conn.execute(
            """
            INSERT INTO audit_events (
                event_id, case_id, actor, action, target_type, target_id,
                details_json, prev_event_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                case_id,
                actor,
                action,
                target_type,
                target_id,
                details_json,
                prev_hash,
                event_hash,
                created_at,
            ),
        )
        return {
            "event_id": event_id,
            "case_id": case_id,
            "actor": actor,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "details": details or {},
            "prev_event_hash": prev_hash,
            "event_hash": event_hash,
            "created_at": created_at,
        }

    def append_audit_event(
        self,
        *,
        case_id: str,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as conn:
            return self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=actor,
                action=action,
                target_type=target_type,
                target_id=target_id,
                details=details,
            )

    def list_audit_events(self, case_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            if case_id:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE case_id = ? ORDER BY seq DESC LIMIT ?",
                    (case_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def verify_audit_chain(self) -> dict[str, Any]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
            expected_prev = "0" * 64
            broken: list[dict[str, Any]] = []
            for row in rows:
                r = dict(row)
                if r["prev_event_hash"] != expected_prev:
                    broken.append({"seq": r["seq"], "event_id": r["event_id"], "reason": "prev_event_hash mismatch"})
                recomputed = sha256_json(
                    {
                        "event_id": r["event_id"],
                        "case_id": r["case_id"],
                        "actor": r["actor"],
                        "action": r["action"],
                        "target_type": r["target_type"],
                        "target_id": r["target_id"],
                        "details_json": r["details_json"],
                        "prev_event_hash": r["prev_event_hash"],
                        "created_at": r["created_at"],
                    }
                )
                if r["event_hash"] != recomputed:
                    broken.append({"seq": r["seq"], "event_id": r["event_id"], "reason": "event_hash mismatch"})
                expected_prev = r["event_hash"]
            return {"valid": len(broken) == 0, "total_events": len(rows), "broken_links": broken}
        finally:
            conn.close()

    # ---------------- Cases ----------------

    def create_case(
        self,
        *,
        case_number: str,
        title: str,
        examiner: str,
        agency: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        case_number_clean = case_number.strip()
        title_clean = title.strip()
        examiner_clean = examiner.strip()
        if not case_number_clean or not title_clean or not examiner_clean:
            raise ValueError("case_number, title, and examiner are required.")
        case_id = _new_id("case")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO cases (case_id, case_number, title, examiner, agency, status, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?)
                """,
                (case_id, case_number_clean, title_clean, examiner_clean, agency.strip(), notes.strip(), now, now),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=examiner_clean,
                action="case.created",
                target_type="case",
                target_id=case_id,
                details={"case_number": case_number_clean, "title": title_clean},
            )
        return self.get_case(case_id)  # type: ignore[return-value]

    def list_cases(self) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT c.*,
                    (SELECT COUNT(*) FROM devices d WHERE d.case_id = c.case_id) AS device_count,
                    (SELECT COUNT(*) FROM artifacts a WHERE a.case_id = c.case_id) AS artifact_count,
                    (SELECT COUNT(*) FROM acquisition_sessions s WHERE s.case_id = c.case_id) AS session_count
                FROM cases c
                ORDER BY c.updated_at DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            return self._row_to_dict(row)
        finally:
            conn.close()

    def update_case_status(self, case_id: str, status: str, actor: str) -> dict[str, Any]:
        if status not in {"open", "in_review", "closed", "archived"}:
            raise ValueError(f"Unsupported case status: {status}")
        now = _utc_iso()
        with self.transaction() as conn:
            cur = conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                (status, now, case_id),
            )
            if cur.rowcount == 0:
                raise KeyError(f"Case not found: {case_id}")
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=actor,
                action="case.status_updated",
                target_type="case",
                target_id=case_id,
                details={"status": status},
            )
        return self.get_case(case_id)  # type: ignore[return-value]

    # ---------------- Devices & Authorizations ----------------

    def register_device(
        self,
        *,
        case_id: str,
        platform: str,
        serial_or_udid: str,
        manufacturer: str = "",
        model: str = "",
        os_version: str = "",
        build_or_sdk: str = "",
        connection_state: str = "unknown",
        metadata: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> dict[str, Any]:
        if not self.get_case(case_id):
            raise KeyError(f"Case not found: {case_id}")
        conn = self._connect()
        try:
            existing = conn.execute(
                "SELECT * FROM devices WHERE case_id = ? AND serial_or_udid = ?",
                (case_id, serial_or_udid),
            ).fetchone()
        finally:
            conn.close()

        meta_json = json.dumps(metadata or {}, sort_keys=True, default=str)
        if existing:
            device_id = existing["device_id"]
            with self.transaction() as conn:
                conn.execute(
                    """
                    UPDATE devices
                    SET platform = ?, manufacturer = ?, model = ?, os_version = ?,
                        build_or_sdk = ?, connection_state = ?, metadata_json = ?
                    WHERE device_id = ?
                    """,
                    (platform, manufacturer, model, os_version, build_or_sdk, connection_state, meta_json, device_id),
                )
                self._append_audit_in_tx(
                    conn,
                    case_id=case_id,
                    actor=actor,
                    action="device.updated",
                    target_type="device",
                    target_id=device_id,
                    details={"serial_or_udid": serial_or_udid, "connection_state": connection_state},
                )
        else:
            device_id = _new_id("dev")
            now = _utc_iso()
            with self.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO devices (
                        device_id, case_id, platform, serial_or_udid, manufacturer,
                        model, os_version, build_or_sdk, connection_state, metadata_json, first_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        device_id,
                        case_id,
                        platform,
                        serial_or_udid,
                        manufacturer,
                        model,
                        os_version,
                        build_or_sdk,
                        connection_state,
                        meta_json,
                        now,
                    ),
                )
                self._append_audit_in_tx(
                    conn,
                    case_id=case_id,
                    actor=actor,
                    action="device.registered",
                    target_type="device",
                    target_id=device_id,
                    details={"platform": platform, "serial_or_udid": serial_or_udid, "model": model},
                )
        return self.get_device(device_id)  # type: ignore[return-value]

    def get_device(self, device_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            return self._row_to_dict(row)
        finally:
            conn.close()

    def list_devices(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM devices WHERE case_id = ? ORDER BY first_seen_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def record_authorization(
        self,
        *,
        case_id: str,
        device_id: str,
        authority_type: str,
        reference_number: str,
        authorized_by: str,
        scope_description: str,
    ) -> dict[str, Any]:
        if not authority_type.strip() or not authorized_by.strip() or not scope_description.strip():
            raise ValueError("authority_type, authorized_by, and scope_description are required.")
        auth_id = _new_id("auth")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO authorization_records (
                    auth_id, case_id, device_id, authority_type, reference_number,
                    authorized_by, scope_description, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (auth_id, case_id, device_id, authority_type.strip(), reference_number.strip(), authorized_by.strip(), scope_description.strip(), now),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=authorized_by.strip(),
                action="authorization.recorded",
                target_type="authorization",
                target_id=auth_id,
                details={"device_id": device_id, "authority_type": authority_type, "reference_number": reference_number},
            )
        conn = self._connect()
        try:
            return dict(conn.execute("SELECT * FROM authorization_records WHERE auth_id = ?", (auth_id,)).fetchone())
        finally:
            conn.close()

    def list_authorizations(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM authorization_records WHERE case_id = ? ORDER BY verified_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ---------------- Acquisition Sessions ----------------

    def create_acquisition_session(
        self,
        *,
        case_id: str,
        device_id: str,
        acquisition_method: str,
        scope_classification: str,
        source_location: str = "",
        output_directory: str = "",
        limitations: list[str] | None = None,
        actor: str = "examiner",
    ) -> dict[str, Any]:
        session_id = _new_id("acq")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO acquisition_sessions (
                    session_id, case_id, device_id, acquisition_method, scope_classification,
                    source_location, output_directory, status, files_copied, bytes_copied,
                    errors_json, limitations_json, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 0, 0, '[]', ?, ?, '')
                """,
                (
                    session_id,
                    case_id,
                    device_id,
                    acquisition_method,
                    scope_classification,
                    source_location,
                    output_directory,
                    json.dumps(limitations or []),
                    now,
                ),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=actor,
                action="acquisition.started",
                target_type="acquisition_session",
                target_id=session_id,
                details={"acquisition_method": acquisition_method, "scope_classification": scope_classification},
            )
        return self.get_acquisition_session(session_id)  # type: ignore[return-value]

    def finalize_acquisition_session(
        self,
        *,
        session_id: str,
        status: str,
        files_copied: int,
        bytes_copied: int,
        errors: list[str],
        limitations: list[str],
        actor: str = "examiner",
    ) -> dict[str, Any]:
        now = _utc_iso()
        session = self.get_acquisition_session(session_id)
        if not session:
            raise KeyError(f"Acquisition session not found: {session_id}")
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE acquisition_sessions
                SET status = ?, files_copied = ?, bytes_copied = ?,
                    errors_json = ?, limitations_json = ?, finished_at = ?
                WHERE session_id = ?
                """,
                (status, files_copied, bytes_copied, json.dumps(errors), json.dumps(limitations), now, session_id),
            )
            self._append_audit_in_tx(
                conn,
                case_id=session["case_id"],
                actor=actor,
                action="acquisition.finished",
                target_type="acquisition_session",
                target_id=session_id,
                details={"status": status, "files_copied": files_copied, "bytes_copied": bytes_copied, "error_count": len(errors)},
            )
        return self.get_acquisition_session(session_id)  # type: ignore[return-value]

    def get_acquisition_session(self, session_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM acquisition_sessions WHERE session_id = ?", (session_id,)).fetchone()
            return self._row_to_dict(row)
        finally:
            conn.close()

    def list_acquisition_sessions(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM acquisition_sessions WHERE case_id = ? ORDER BY started_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ---------------- Artifacts & Timeline ----------------

    def add_artifact(
        self,
        *,
        case_id: str,
        device_id: str,
        session_id: str | None,
        artifact_type: str,
        title: str,
        summary: str = "",
        original_source_path: str,
        stored_copy_path: str = "",
        original_timestamp: str = "",
        original_timezone: str = "unknown",
        normalized_timestamp_utc: str = "",
        normalization_justification: str = "",
        acquisition_method: str,
        parser_name: str,
        parser_version: str,
        sha256: str = "",
        byte_size: int = 0,
        extraction_errors: str = "",
        parsing_errors: str = "",
        provenance: dict[str, Any] | None = None,
        content: dict[str, Any] | None = None,
        timeline_event_type: str | None = None,
        timeline_confidence: str = "unverified",
        actor: str = "parser",
    ) -> dict[str, Any]:
        artifact_id = _new_id("art")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, case_id, device_id, session_id, artifact_type, title, summary,
                    original_source_path, stored_copy_path, original_timestamp, original_timezone,
                    normalized_timestamp_utc, normalization_justification, acquisition_method,
                    parser_name, parser_version, sha256, byte_size, extraction_errors,
                    parsing_errors, provenance_json, content_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    case_id,
                    device_id,
                    session_id,
                    artifact_type,
                    title,
                    summary,
                    original_source_path,
                    stored_copy_path,
                    original_timestamp,
                    original_timezone,
                    normalized_timestamp_utc,
                    normalization_justification,
                    acquisition_method,
                    parser_name,
                    parser_version,
                    sha256,
                    byte_size,
                    extraction_errors,
                    parsing_errors,
                    json.dumps(provenance or {}, sort_keys=True, default=str),
                    json.dumps(content or {}, sort_keys=True, default=str),
                    now,
                ),
            )
            if original_timestamp or normalized_timestamp_utc:
                event_id = _new_id("evt")
                conn.execute(
                    """
                    INSERT INTO timeline_events (
                        event_id, case_id, device_id, artifact_id, event_type, description,
                        original_timestamp, original_timezone, normalized_utc, timestamp_confidence, source_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        case_id,
                        device_id,
                        artifact_id,
                        timeline_event_type or artifact_type,
                        f"{title}: {summary}".strip(": "),
                        original_timestamp,
                        original_timezone,
                        normalized_timestamp_utc,
                        timeline_confidence,
                        original_source_path,
                    ),
                )
        return self.get_artifact(artifact_id)  # type: ignore[return-value]

    def get_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)).fetchone()
            return self._row_to_dict(row)
        finally:
            conn.close()

    def search_artifacts(
        self,
        case_id: str,
        *,
        query: str = "",
        artifact_type: str = "",
        device_id: str = "",
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            clauses = ["case_id = ?"]
            params: list[Any] = [case_id]
            if artifact_type:
                clauses.append("artifact_type = ?")
                params.append(artifact_type)
            if device_id:
                clauses.append("device_id = ?")
                params.append(device_id)
            if query.strip():
                like = f"%{query.strip()}%"
                clauses.append(
                    "(title LIKE ? OR summary LIKE ? OR original_source_path LIKE ? OR content_json LIKE ? OR sha256 LIKE ?)"
                )
                params.extend([like, like, like, like, like])
            params.append(limit)
            sql = f"SELECT * FROM artifacts WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT ?"
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def list_timeline_events(
        self,
        case_id: str,
        *,
        device_id: str = "",
        query: str = "",
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            clauses = ["t.case_id = ?"]
            params: list[Any] = [case_id]
            if device_id:
                clauses.append("t.device_id = ?")
                params.append(device_id)
            if query.strip():
                like = f"%{query.strip()}%"
                clauses.append("(t.description LIKE ? OR t.event_type LIKE ? OR t.source_path LIKE ?)")
                params.extend([like, like, like])
            params.append(limit)
            sql = f"""
                SELECT t.*, d.model AS device_model, d.platform AS device_platform
                FROM timeline_events t
                JOIN devices d ON d.device_id = t.device_id
                WHERE {' AND '.join(clauses)}
                ORDER BY CASE WHEN t.normalized_utc = '' THEN 1 ELSE 0 END, t.normalized_utc ASC, t.original_timestamp ASC
                LIMIT ?
            """
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ---------------- Transfers ----------------

    def create_transfer_manifest(
        self,
        *,
        case_id: str,
        source_root: str,
        destination_root: str,
        conflict_policy: str,
        actor: str = "examiner",
    ) -> dict[str, Any]:
        manifest_id = _new_id("xfer")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO transfer_manifests (
                    manifest_id, case_id, source_root, destination_root, conflict_policy,
                    status, total_files, succeeded_files, failed_files, skipped_files,
                    total_bytes, manifest_path, manifest_sha256, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, 'running', 0, 0, 0, 0, 0, '', '', ?, '')
                """,
                (manifest_id, case_id, source_root, destination_root, conflict_policy, now),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=actor,
                action="transfer.started",
                target_type="transfer_manifest",
                target_id=manifest_id,
                details={"destination_root": destination_root, "conflict_policy": conflict_policy},
            )
        return self.get_transfer_manifest(manifest_id)  # type: ignore[return-value]

    def record_transferred_file(
        self,
        *,
        manifest_id: str,
        case_id: str,
        source_path: str,
        destination_path: str,
        byte_size: int,
        source_sha256: str,
        destination_sha256: str,
        verified: bool,
        status: str,
        error_message: str = "",
    ) -> dict[str, Any]:
        file_id = _new_id("tf")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO transferred_files (
                    file_id, manifest_id, case_id, source_path, destination_path,
                    byte_size, source_sha256, destination_sha256, verified, status, error_message, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    manifest_id,
                    case_id,
                    source_path,
                    destination_path,
                    byte_size,
                    source_sha256,
                    destination_sha256,
                    1 if verified else 0,
                    status,
                    error_message,
                    now,
                ),
            )
        conn = self._connect()
        try:
            return dict(conn.execute("SELECT * FROM transferred_files WHERE file_id = ?", (file_id,)).fetchone())
        finally:
            conn.close()

    def finalize_transfer_manifest(
        self,
        *,
        manifest_id: str,
        status: str,
        total_files: int,
        succeeded_files: int,
        failed_files: int,
        skipped_files: int,
        total_bytes: int,
        manifest_path: str,
        manifest_sha256: str,
        actor: str = "examiner",
    ) -> dict[str, Any]:
        manifest = self.get_transfer_manifest(manifest_id)
        if not manifest:
            raise KeyError(f"Transfer manifest not found: {manifest_id}")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE transfer_manifests
                SET status = ?, total_files = ?, succeeded_files = ?, failed_files = ?,
                    skipped_files = ?, total_bytes = ?, manifest_path = ?, manifest_sha256 = ?, finished_at = ?
                WHERE manifest_id = ?
                """,
                (
                    status,
                    total_files,
                    succeeded_files,
                    failed_files,
                    skipped_files,
                    total_bytes,
                    manifest_path,
                    manifest_sha256,
                    now,
                    manifest_id,
                ),
            )
            self._append_audit_in_tx(
                conn,
                case_id=manifest["case_id"],
                actor=actor,
                action="transfer.finished",
                target_type="transfer_manifest",
                target_id=manifest_id,
                details={
                    "status": status,
                    "succeeded_files": succeeded_files,
                    "failed_files": failed_files,
                    "skipped_files": skipped_files,
                    "total_bytes": total_bytes,
                },
            )
        return self.get_transfer_manifest(manifest_id)  # type: ignore[return-value]

    def get_transfer_manifest(self, manifest_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM transfer_manifests WHERE manifest_id = ?", (manifest_id,)).fetchone()
            return self._row_to_dict(row)
        finally:
            conn.close()

    def list_transfer_manifests(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM transfer_manifests WHERE case_id = ? ORDER BY started_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def list_transferred_files(self, manifest_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM transferred_files WHERE manifest_id = ? ORDER BY created_at ASC",
                (manifest_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ---------------- Findings, Notes, AI Analyses, Reports ----------------

    def add_finding(
        self,
        *,
        case_id: str,
        title: str,
        category: str,
        severity: str,
        description: str,
        linked_artifact_ids: list[str],
        created_by: str,
    ) -> dict[str, Any]:
        if not title.strip() or not description.strip():
            raise ValueError("Finding title and description are required.")
        finding_id = _new_id("find")
        now = _utc_iso()
        with self.transaction() as conn:
            # Verify linked artifact IDs belong to this case
            if linked_artifact_ids:
                placeholders = ",".join("?" for _ in linked_artifact_ids)
                found = conn.execute(
                    f"SELECT artifact_id FROM artifacts WHERE case_id = ? AND artifact_id IN ({placeholders})",
                    [case_id, *linked_artifact_ids],
                ).fetchall()
                valid_ids = {r["artifact_id"] for r in found}
                missing = [aid for aid in linked_artifact_ids if aid not in valid_ids]
                if missing:
                    raise ValueError(f"Invalid artifact IDs for case {case_id}: {missing}")
            conn.execute(
                """
                INSERT INTO investigation_findings (
                    finding_id, case_id, title, category, severity, description,
                    linked_artifact_ids_json, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    case_id,
                    title.strip(),
                    category.strip(),
                    severity.strip(),
                    description.strip(),
                    json.dumps(linked_artifact_ids),
                    created_by.strip(),
                    now,
                ),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=created_by.strip(),
                action="finding.created",
                target_type="finding",
                target_id=finding_id,
                details={"title": title.strip(), "linked_count": len(linked_artifact_ids)},
            )
        conn = self._connect()
        try:
            return dict(conn.execute("SELECT * FROM investigation_findings WHERE finding_id = ?", (finding_id,)).fetchone())
        finally:
            conn.close()

    def list_findings(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM investigation_findings WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def add_note(
        self,
        *,
        case_id: str,
        author: str,
        body: str,
        artifact_id: str | None = None,
    ) -> dict[str, Any]:
        if not body.strip() or not author.strip():
            raise ValueError("Author and body are required for analyst notes.")
        note_id = _new_id("note")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO analyst_notes (note_id, case_id, artifact_id, author, body, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (note_id, case_id, artifact_id, author.strip(), body.strip(), now),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=author.strip(),
                action="note.created",
                target_type="note",
                target_id=note_id,
                details={"artifact_id": artifact_id},
            )
        conn = self._connect()
        try:
            return dict(conn.execute("SELECT * FROM analyst_notes WHERE note_id = ?", (note_id,)).fetchone())
        finally:
            conn.close()

    def list_notes(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM analyst_notes WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def save_ai_analysis(
        self,
        *,
        case_id: str,
        model_name: str,
        analyst_approved: bool,
        pii_redacted: bool,
        prompt_question: str,
        selected_artifact_ids: list[str],
        verified_artifact_ids: list[str],
        rejected_artifact_ids: list[str],
        response_payload: dict[str, Any],
        actor: str = "examiner",
    ) -> dict[str, Any]:
        analysis_id = _new_id("ai")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO ai_analyses (
                    analysis_id, case_id, model_name, analyst_approved, pii_redacted,
                    prompt_question, selected_artifact_ids_json, verified_artifact_ids_json,
                    rejected_artifact_ids_json, response_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    case_id,
                    model_name,
                    1 if analyst_approved else 0,
                    1 if pii_redacted else 0,
                    prompt_question,
                    json.dumps(selected_artifact_ids),
                    json.dumps(verified_artifact_ids),
                    json.dumps(rejected_artifact_ids),
                    json.dumps(response_payload, sort_keys=True, default=str),
                    now,
                ),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=actor,
                action="ai_analysis.recorded",
                target_type="ai_analysis",
                target_id=analysis_id,
                details={
                    "model_name": model_name,
                    "analyst_approved": analyst_approved,
                    "pii_redacted": pii_redacted,
                    "selected_count": len(selected_artifact_ids),
                    "verified_cited": len(verified_artifact_ids),
                    "rejected_cited": len(rejected_artifact_ids),
                },
            )
        conn = self._connect()
        try:
            return dict(conn.execute("SELECT * FROM ai_analyses WHERE analysis_id = ?", (analysis_id,)).fetchone())
        finally:
            conn.close()

    def list_ai_analyses(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM ai_analyses WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def record_report(
        self,
        *,
        case_id: str,
        report_format: str,
        output_path: str,
        sha256: str,
        generated_by: str,
    ) -> dict[str, Any]:
        report_id = _new_id("rpt")
        now = _utc_iso()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO report_records (report_id, case_id, report_format, output_path, sha256, generated_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (report_id, case_id, report_format, output_path, sha256, generated_by, now),
            )
            self._append_audit_in_tx(
                conn,
                case_id=case_id,
                actor=generated_by,
                action="report.generated",
                target_type="report",
                target_id=report_id,
                details={"report_format": report_format, "sha256": sha256, "output_path": output_path},
            )
        conn = self._connect()
        try:
            return dict(conn.execute("SELECT * FROM report_records WHERE report_id = ?", (report_id,)).fetchone())
        finally:
            conn.close()

    def list_reports(self, case_id: str) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM report_records WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
