"""Tests for TransferManager, HTML/PDF reports, PII redaction, and AI citation validation."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from mobiletrace.ai.gemini_investigator import build_minimized_evidence_bundle, validate_ai_citations
from mobiletrace.ai.redact_pii import redact_text
from mobiletrace.core.validation import resolve_confined_path, sanitize_filename
from mobiletrace.db.repository import ForensicRepository
from mobiletrace.reporting.report_generator import generate_html_report, generate_pdf_report
from mobiletrace.transfer.manager import TransferManager


class TestTransferAndReports(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = ForensicRepository(self.root / "mt.db")
        self.case = self.repo.create_case(
            case_number="MT-XFER-01",
            title="Transfer & Report Case",
            examiner="Examiner B",
        )
        self.dev = self.repo.register_device(
            case_id=self.case["case_id"],
            platform="android",
            serial_or_udid="SER123",
            model="Galaxy S24",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_path_validation_and_transfer_manager(self) -> None:
        self.assertEqual(sanitize_filename("CON"), "_CON")
        with self.assertRaises(ValueError):
            resolve_confined_path(self.root / "dest", Path("../escape.txt"))

        src_dir = self.root / "src"
        src_dir.mkdir()
        (src_dir / "alpha.txt").write_bytes(b"ALPHA_BYTES_123456")
        (src_dir / "sub").mkdir()
        (src_dir / "sub" / "beta.bin").write_bytes(b"BETA_BYTES_ABCDEF")

        dst_dir = self.root / "dst"
        mgr = TransferManager()
        res1 = mgr.execute_transfer(
            repo=self.repo,
            case_id=self.case["case_id"],
            source_paths=[src_dir],
            destination_dir=dst_dir,
            source_root=src_dir,
            conflict_policy="rename",
        )
        self.assertEqual(res1["manifest"]["status"], "completed")
        self.assertEqual(res1["manifest"]["succeeded_files"], 2)
        self.assertTrue(Path(res1["manifest_json_path"]).is_file())

        # Second transfer with rename conflict policy creates _copy1 without overwriting
        res2 = mgr.execute_transfer(
            repo=self.repo,
            case_id=self.case["case_id"],
            source_paths=[src_dir],
            destination_dir=dst_dir,
            source_root=src_dir,
            conflict_policy="rename",
        )
        self.assertEqual(res2["manifest"]["succeeded_files"], 2)
        self.assertTrue((dst_dir / "alpha_copy1.txt").is_file())

        # Cancellation before start returns cancelled cleanly
        ev = threading.Event()
        ev.set()
        res_cancel = mgr.execute_transfer(
            repo=self.repo,
            case_id=self.case["case_id"],
            source_paths=[src_dir],
            destination_dir=self.root / "dst_cancel",
            source_root=src_dir,
            cancel_event=ev,
        )
        self.assertEqual(res_cancel["manifest"]["status"], "cancelled")

    def test_pii_redaction_and_citation_validation(self) -> None:
        redacted, counts = redact_text("Contact alice@example.com or +1-555-234-5678 from 192.168.1.44")
        self.assertNotIn("alice@example.com", redacted)
        self.assertNotIn("192.168.1.44", redacted)
        self.assertEqual(counts["emails"], 1)
        self.assertEqual(counts["ips"], 1)

        art = self.repo.add_artifact(
            case_id=self.case["case_id"],
            device_id=self.dev["device_id"],
            session_id=None,
            artifact_type="sms_message",
            title="Message from alice@example.com",
            summary="Call +1-555-234-5678",
            original_source_path="/data/sms.db#1",
            acquisition_method="adb_backup",
            parser_name="test",
            parser_version="1.0",
        )
        bundle = build_minimized_evidence_bundle(self.repo, self.case["case_id"], [art["artifact_id"]], redact_pii=True)
        self.assertIn("[REDACTED_EMAIL]", json.dumps(bundle))

        # AI response with one real ID and one hallucinated ID
        ai_payload = {
            "verified_observations": [
                {"statement": "Message logged", "artifact_ids": [art["artifact_id"], "art_fake_999999"]}
            ]
        }
        val = validate_ai_citations(self.repo, self.case["case_id"], ai_payload)
        self.assertEqual(val["verified_artifact_ids"], [art["artifact_id"]])
        self.assertEqual(val["rejected_artifact_ids"], ["art_fake_999999"])
        self.assertEqual(val["validated_payload"]["verified_observations"][0]["artifact_ids"], [art["artifact_id"]])

    def test_html_and_pdf_report_generation(self) -> None:
        html_out = self.root / "reports" / "case.html"
        pdf_out = self.root / "reports" / "case.pdf"
        hres = generate_html_report(repo=self.repo, case_id=self.case["case_id"], output_path=html_out)
        pres = generate_pdf_report(repo=self.repo, case_id=self.case["case_id"], output_path=pdf_out)

        self.assertTrue(html_out.is_file())
        self.assertIn("MobileTrace AI", html_out.read_text(encoding="utf-8"))
        self.assertTrue(pdf_out.is_file())
        self.assertTrue(pdf_out.read_bytes().startswith(b"%PDF-"))
        self.assertEqual(len(hres["sha256"]), 64)
        self.assertEqual(len(pres["sha256"]), 64)

    def test_grounding_metadata_extraction(self) -> None:
        from mobiletrace.ai.gemini_investigator import extract_grounding_metadata

        candidate = {
            "grounding_metadata": {
                "web_search_queries": ["iOS 18 forensic backup sqlite CVE-2025", "  "],
                "grounding_chunks": [
                    {"web": {"uri": "https://nvd.nist.gov/vuln/detail/CVE-2025-1000", "title": "NIST NVD"}},
                    {"web": {"uri": "https://nvd.nist.gov/vuln/detail/CVE-2025-1000", "title": "Duplicate"}},
                    {"web": {"uri": "javascript:alert(1)", "title": "Bad Scheme"}},
                ],
            }
        }
        extracted = extract_grounding_metadata(candidate)
        self.assertEqual(extracted["queries"], ["iOS 18 forensic backup sqlite CVE-2025"])
        self.assertEqual(len(extracted["sources"]), 1)
        self.assertEqual(extracted["sources"][0]["title"], "NIST NVD")


if __name__ == "__main__":
    unittest.main()
