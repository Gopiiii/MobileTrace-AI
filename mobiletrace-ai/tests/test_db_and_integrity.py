"""Tests for SQLite persistence, foreign keys, backups, audit hash chain, and integrity checks."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from mobiletrace.core.hashing import sha256_file
from mobiletrace.db.migrations import apply_migrations, backup_database
from mobiletrace.db.repository import ForensicRepository
from mobiletrace.reporting.integrity import verify_case_integrity


class TestDatabaseAndIntegrity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "test.db"
        self.repo = ForensicRepository(self.db_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_migrations_and_foreign_keys(self) -> None:
        applied_again = apply_migrations(self.db_path)
        self.assertEqual(applied_again, [])

        # Foreign key must reject device referencing nonexistent case
        with self.assertRaises(sqlite3.IntegrityError):
            with self.repo.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO devices (
                        device_id, case_id, platform, serial_or_udid, first_seen_at
                    ) VALUES ('dev_bad', 'case_missing', 'android', '1234', '2026-01-01T00:00:00Z')
                    """
                )

    def test_case_persistence_backup_and_tamper_detection(self) -> None:
        case = self.repo.create_case(
            case_number="MT-TEST-001",
            title="Integrity Verification Case",
            examiner="Examiner Jane",
            agency="Forensic Lab",
        )
        dev = self.repo.register_device(
            case_id=case["case_id"],
            platform="android",
            serial_or_udid="FA891234",
            manufacturer="Google",
            model="Pixel 8",
            os_version="15",
            connection_state="device",
        )
        sample_file = self.root / "evidence.bin"
        sample_file.write_bytes(b"GENUINE_FORENSIC_PAYLOAD_123456")
        digest, size_b = sha256_file(sample_file)

        self.repo.add_artifact(
            case_id=case["case_id"],
            device_id=dev["device_id"],
            session_id=None,
            artifact_type="acquired_file",
            title="evidence.bin",
            original_source_path="/sdcard/Documents/evidence.bin",
            stored_copy_path=str(sample_file),
            acquisition_method="adb_accessible_pull",
            parser_name="test",
            parser_version="1.0.0",
            sha256=digest,
            byte_size=size_b,
        )

        # Verify intact state
        manifest_path = self.root / "manifest.json"
        res_ok = verify_case_integrity(self.repo, case["case_id"], manifest_output_path=manifest_path)
        self.assertTrue(res_ok["overall_intact"])
        self.assertEqual(res_ok["summary"]["verified_files"], 1)
        self.assertTrue(res_ok["audit_chain"]["valid"])
        self.assertTrue(manifest_path.is_file())

        # Backup database safely
        bkp = backup_database(self.db_path, self.root / "backup.db")
        self.assertTrue(bkp.is_file())
        bkp_repo = ForensicRepository(bkp)
        self.assertEqual(len(bkp_repo.list_cases()), 1)

        # Tamper with file on disk and verify mismatch is caught
        sample_file.write_bytes(b"TAMPERED_PAYLOAD")
        res_bad = verify_case_integrity(self.repo, case["case_id"])
        self.assertFalse(res_bad["overall_intact"])
        self.assertEqual(res_bad["summary"]["hash_mismatches"], 1)


if __name__ == "__main__":
    unittest.main()
