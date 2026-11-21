"""Tests for ADB output parsing, iOS Manifest.db parsing, EXIF parsing, and cross-device correlation."""

from __future__ import annotations

import plistlib
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from mobiletrace.acquisition.android_adb import (
    parse_adb_devices_output,
    parse_getprop_output,
    parse_ls_la_output,
)
from mobiletrace.acquisition.ios_backup import iOSBackupClient
from mobiletrace.analysis.correlation import compare_devices_timeline
from mobiletrace.analysis.exif_parser import extract_jpeg_exif
from mobiletrace.analysis.native_parsers import parse_ios_backup_artifacts
from mobiletrace.core.validation import validate_adb_remote_path
from mobiletrace.db.repository import ForensicRepository


def _build_minimal_exif_jpeg(dest: Path) -> None:
    """Create a valid minimal JPEG with an APP1 EXIF TIFF header containing Make, Model, and DateTimeOriginal."""
    # Little-endian TIFF header: II, 42, offset 8
    tiff = bytearray()
    tiff.extend(b"II")
    tiff.extend(struct.pack("<HI", 42, 8))

    make_bytes = b"Canon\x00"
    model_bytes = b"TestCam\x00"
    dt_bytes = b"2026:11:19 14:22:10\x00"
    off_bytes = b"+00:00\x00"

    # IFD0: 4 entries (Make, Model, DateTimeOriginal, OffsetTimeOriginal)
    # Offset after IFD0 = 8 + 2 + 4*12 + 4 = 62
    data_start = 62
    make_off = data_start
    model_off = make_off + len(make_bytes)
    dt_off = model_off + len(model_bytes)
    off_off = dt_off + len(dt_bytes)

    tiff.extend(struct.pack("<H", 4))
    tiff.extend(struct.pack("<HHII", 0x010F, 2, len(make_bytes), make_off))
    tiff.extend(struct.pack("<HHII", 0x0110, 2, len(model_bytes), model_off))
    tiff.extend(struct.pack("<HHII", 0x9003, 2, len(dt_bytes), dt_off))
    tiff.extend(struct.pack("<HHII", 0x9011, 2, len(off_bytes), off_off))
    tiff.extend(struct.pack("<I", 0))  # next IFD
    tiff.extend(make_bytes + model_bytes + dt_bytes + off_bytes)

    app1_payload = b"Exif\x00\x00" + bytes(tiff)
    app1_seg = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    jpeg = b"\xff\xd8" + app1_seg + b"\xff\xd9"
    dest.write_bytes(jpeg)


class TestParsersAndADB(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = ForensicRepository(self.root / "forensics.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_adb_parsers_and_validation(self) -> None:
        raw_devices = (
            "List of devices attached\n"
            "R5CR90ABCDE            device usb:1-2 product:oriole model:Pixel_6 device:oriole transport_id:4\n"
            "9B011FFAZ00222         unauthorized usb:1-3 transport_id:5\n"
        )
        parsed = parse_adb_devices_output(raw_devices)
        self.assertEqual(len(parsed), 2)
        self.assertTrue(parsed[0].authorized)
        self.assertEqual(parsed[0].model, "Pixel 6")
        self.assertFalse(parsed[1].authorized)
        self.assertEqual(parsed[1].state, "unauthorized")

        props = parse_getprop_output("[ro.product.manufacturer]: [Google]\n[ro.build.version.release]: [14]\n")
        self.assertEqual(props["ro.product.manufacturer"], "Google")
        self.assertEqual(props["ro.build.version.release"], "14")

        ls_out = (
            "total 16\n"
            "drwxrwx--x 2 root sdcard_rw 4096 2026-11-18 10:15 Camera\n"
            "-rw-rw---- 1 root sdcard_rw 12345 2026-11-18 10:16 IMG_001.jpg\n"
        )
        entries = parse_ls_la_output(ls_out, "/sdcard/DCIM")
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0].is_dir)
        self.assertEqual(entries[1].size_bytes, 12345)

        with self.assertRaises(ValueError):
            validate_adb_remote_path("/sdcard/../etc/passwd")

    def test_jpeg_exif_parser(self) -> None:
        jpg = self.root / "photo.jpg"
        _build_minimal_exif_jpeg(jpg)
        exif = extract_jpeg_exif(jpg)
        self.assertEqual(exif.get("Make"), "Canon")
        self.assertEqual(exif.get("Model"), "TestCam")
        self.assertEqual(exif.get("DateTimeOriginal"), "2026:11:19 14:22:10")
        self.assertEqual(exif.get("OffsetTimeOriginal"), "+00:00")

    def test_ios_backup_fixture_and_cross_device_correlation(self) -> None:
        bdir = self.root / "ios_backup"
        bdir.mkdir()

        with (bdir / "Info.plist").open("wb") as f:
            plistlib.dump(
                {
                    "Unique Identifier": "00008120-TESTUDID",
                    "Device Name": "Custodian iPhone",
                    "Product Type": "iPhone15,2",
                    "Product Version": "18.1",
                    "Build Version": "22B83",
                    "Serial Number": "C02TESTSERIAL",
                },
                f,
            )
        with (bdir / "Manifest.plist").open("wb") as f:
            plistlib.dump(
                {
                    "IsEncrypted": False,
                    "Applications": {"com.apple.MobileSMS": {"CFBundleIdentifier": "com.apple.MobileSMS"}},
                },
                f,
            )
        with (bdir / "Status.plist").open("wb") as f:
            plistlib.dump({"BackupState": "new", "SnapshotState": "finished"}, f)

        # Create real sms.db file inside Apple hashed subfolder
        sms_file_id = "3d0d7e5fb2ce288813306e4d4636395e047a3d28"
        sms_dir = bdir / sms_file_id[:2]
        sms_dir.mkdir()
        sms_path = sms_dir / sms_file_id
        sconn = sqlite3.connect(str(sms_path))
        sconn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
        sconn.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, text TEXT, date INTEGER, is_from_me INTEGER, service TEXT, handle_id INTEGER)")
        sconn.execute("INSERT INTO handle (ROWID, id) VALUES (1, '+15550109999')")
        # Apple timestamp: 785337600 seconds after 2001-01-01 = 2025-11-20T13:20:00+00:00
        sconn.execute("INSERT INTO message (ROWID, text, date, is_from_me, service, handle_id) VALUES (1, 'Meet at gate 4', 785337600, 0, 'iMessage', 1)")
        sconn.commit()
        sconn.close()

        # Manifest.db
        mconn = sqlite3.connect(str(bdir / "Manifest.db"))
        mconn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        mconn.execute(
            "INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?, ?, ?, 1, X'')",
            (sms_file_id, "HomeDomain", "Library/SMS/sms.db"),
        )
        mconn.commit()
        mconn.close()

        case = self.repo.create_case(case_number="MT-IOS-01", title="iOS Backup Test", examiner="Examiner A")
        ios_client = iOSBackupClient()
        imported = ios_client.import_local_backup(repo=self.repo, case_id=case["case_id"], backup_dir=bdir)
        counts = parse_ios_backup_artifacts(
            repo=self.repo,
            case_id=case["case_id"],
            device_id=imported["device"]["device_id"],
            session_id=imported["session"]["session_id"],
            backup_dir=bdir,
        )
        self.assertEqual(counts["sms_messages"], 1)

        # Register second device with a proximate timestamp and check correlation caveat
        dev2 = self.repo.register_device(
            case_id=case["case_id"],
            platform="android",
            serial_or_udid="ANDROID-2",
            model="Pixel 9",
        )
        self.repo.add_artifact(
            case_id=case["case_id"],
            device_id=dev2["device_id"],
            session_id=None,
            artifact_type="acquired_file",
            title="note.txt",
            original_source_path="/sdcard/Documents/note.txt",
            original_timestamp="2025-11-20T13:21:00+00:00",
            original_timezone="UTC",
            normalized_timestamp_utc="2025-11-20T13:21:00+00:00",
            acquisition_method="adb_accessible_pull",
            parser_name="test",
            parser_version="1.0.0",
        )
        corr = compare_devices_timeline(self.repo, case["case_id"], window_seconds=120)
        self.assertEqual(len(corr["proximate_pairs"]), 1)
        self.assertIn("do NOT by themselves prove", corr["caveat"])


if __name__ == "__main__":
    unittest.main()
