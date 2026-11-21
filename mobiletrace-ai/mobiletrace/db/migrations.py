"""Transactional SQLite schema migrations and safe database backup engine."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


MIGRATIONS: list[tuple[str, str]] = [
    (
        "0001_initial_schema",
        """
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            case_number TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            examiner TEXT NOT NULL,
            agency TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            platform TEXT NOT NULL,
            serial_or_udid TEXT NOT NULL,
            manufacturer TEXT NOT NULL DEFAULT '',
            model TEXT NOT NULL DEFAULT '',
            os_version TEXT NOT NULL DEFAULT '',
            build_or_sdk TEXT NOT NULL DEFAULT '',
            connection_state TEXT NOT NULL DEFAULT 'unknown',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            first_seen_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_devices_case_id ON devices(case_id);
        CREATE INDEX IF NOT EXISTS ix_devices_serial_udid ON devices(serial_or_udid);

        CREATE TABLE IF NOT EXISTS authorization_records (
            auth_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            authority_type TEXT NOT NULL,
            reference_number TEXT NOT NULL DEFAULT '',
            authorized_by TEXT NOT NULL,
            scope_description TEXT NOT NULL,
            verified_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_auth_case_device ON authorization_records(case_id, device_id);

        CREATE TABLE IF NOT EXISTS acquisition_sessions (
            session_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            acquisition_method TEXT NOT NULL,
            scope_classification TEXT NOT NULL,
            source_location TEXT NOT NULL DEFAULT '',
            output_directory TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            files_copied INTEGER NOT NULL DEFAULT 0,
            bytes_copied INTEGER NOT NULL DEFAULT 0,
            errors_json TEXT NOT NULL DEFAULT '[]',
            limitations_json TEXT NOT NULL DEFAULT '[]',
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS ix_acq_case_id ON acquisition_sessions(case_id);

        CREATE TABLE IF NOT EXISTS transfer_manifests (
            manifest_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            source_root TEXT NOT NULL,
            destination_root TEXT NOT NULL,
            conflict_policy TEXT NOT NULL,
            status TEXT NOT NULL,
            total_files INTEGER NOT NULL DEFAULT 0,
            succeeded_files INTEGER NOT NULL DEFAULT 0,
            failed_files INTEGER NOT NULL DEFAULT 0,
            skipped_files INTEGER NOT NULL DEFAULT 0,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            manifest_path TEXT NOT NULL DEFAULT '',
            manifest_sha256 TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS ix_transfer_case_id ON transfer_manifests(case_id);

        CREATE TABLE IF NOT EXISTS transferred_files (
            file_id TEXT PRIMARY KEY,
            manifest_id TEXT NOT NULL REFERENCES transfer_manifests(manifest_id) ON DELETE CASCADE,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            source_path TEXT NOT NULL,
            destination_path TEXT NOT NULL,
            byte_size INTEGER NOT NULL DEFAULT 0,
            source_sha256 TEXT NOT NULL DEFAULT '',
            destination_sha256 TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            error_message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_tfile_manifest_id ON transferred_files(manifest_id);
        CREATE INDEX IF NOT EXISTS ix_tfile_case_id ON transferred_files(case_id);

        CREATE TABLE IF NOT EXISTS artifacts (
            artifact_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            session_id TEXT REFERENCES acquisition_sessions(session_id) ON DELETE SET NULL,
            artifact_type TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '',
            original_source_path TEXT NOT NULL,
            stored_copy_path TEXT NOT NULL DEFAULT '',
            original_timestamp TEXT NOT NULL DEFAULT '',
            original_timezone TEXT NOT NULL DEFAULT 'unknown',
            normalized_timestamp_utc TEXT NOT NULL DEFAULT '',
            normalization_justification TEXT NOT NULL DEFAULT '',
            acquisition_method TEXT NOT NULL,
            parser_name TEXT NOT NULL,
            parser_version TEXT NOT NULL,
            sha256 TEXT NOT NULL DEFAULT '',
            byte_size INTEGER NOT NULL DEFAULT 0,
            extraction_errors TEXT NOT NULL DEFAULT '',
            parsing_errors TEXT NOT NULL DEFAULT '',
            provenance_json TEXT NOT NULL DEFAULT '{}',
            content_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_artifacts_case_id ON artifacts(case_id);
        CREATE INDEX IF NOT EXISTS ix_artifacts_device_id ON artifacts(device_id);
        CREATE INDEX IF NOT EXISTS ix_artifacts_type ON artifacts(artifact_type);
        CREATE INDEX IF NOT EXISTS ix_artifacts_sha256 ON artifacts(sha256);

        CREATE TABLE IF NOT EXISTS timeline_events (
            event_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
            artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            original_timestamp TEXT NOT NULL,
            original_timezone TEXT NOT NULL,
            normalized_utc TEXT NOT NULL DEFAULT '',
            timestamp_confidence TEXT NOT NULL DEFAULT 'unverified',
            source_path TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS ix_timeline_case_utc ON timeline_events(case_id, normalized_utc);
        CREATE INDEX IF NOT EXISTS ix_timeline_device ON timeline_events(device_id);

        CREATE TABLE IF NOT EXISTS investigation_findings (
            finding_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'informational',
            description TEXT NOT NULL,
            linked_artifact_ids_json TEXT NOT NULL DEFAULT '[]',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_findings_case_id ON investigation_findings(case_id);

        CREATE TABLE IF NOT EXISTS analyst_notes (
            note_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            artifact_id TEXT REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_notes_case_id ON analyst_notes(case_id);

        CREATE TABLE IF NOT EXISTS ai_analyses (
            analysis_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            model_name TEXT NOT NULL,
            analyst_approved INTEGER NOT NULL,
            pii_redacted INTEGER NOT NULL,
            prompt_question TEXT NOT NULL,
            selected_artifact_ids_json TEXT NOT NULL,
            verified_artifact_ids_json TEXT NOT NULL,
            rejected_artifact_ids_json TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_ai_case_id ON ai_analyses(case_id);

        CREATE TABLE IF NOT EXISTS report_records (
            report_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
            report_format TEXT NOT NULL,
            output_path TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            generated_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_reports_case_id ON report_records(case_id);

        CREATE TABLE IF NOT EXISTS audit_events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            case_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            details_json TEXT NOT NULL DEFAULT '{}',
            prev_event_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_audit_case_seq ON audit_events(case_id, seq);
        """,
    ),
]


def apply_migrations(db_path: Path) -> list[str]:
    """Apply pending SQLite schema migrations inside explicit transactions."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    applied: list[str] = []
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    try:
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            );
            """
        )
        existing = {row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
        for version, ddl in MIGRATIONS:
            if version in existing:
                continue
            with conn:
                conn.executescript(ddl)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, datetime.now(timezone.utc).isoformat()),
                )
            applied.append(version)
    finally:
        conn.close()
    return applied


def backup_database(db_path: Path, backup_path: Path) -> Path:
    """Create a consistent online backup using SQLite's native backup API."""
    if not db_path.is_file():
        raise FileNotFoundError(f"Database file does not exist: {db_path}")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(db_path), timeout=30.0)
    dst = sqlite3.connect(str(backup_path), timeout=30.0)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    return backup_path
