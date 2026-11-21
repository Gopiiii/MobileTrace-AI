"""Tests for external forensic tool integrations (ALEAPP, iLEAPP, MVT), CLI handlers, and Alembic schema parity."""

from __future__ import annotations

import ast
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from mobiletrace import cli
from mobiletrace.analysis.tools_integration import run_leapp_tool, run_mvt_check
from mobiletrace.db.repository import ForensicRepository


class TestToolsAndCLI(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "mobiletrace.db"
        self.repo = ForensicRepository(self.db_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_run_leapp_and_mvt_subprocess_ingestion(self) -> None:
        case = self.repo.create_case(case_number="MT-TOOL-01", title="External Tools", examiner="Examiner X")
        dev = self.repo.register_device(case_id=case["case_id"], platform="android", serial_or_udid="SER-1")

        # Create real executable Python script acting as ALEAPP CLI
        leapp_script = self.root / "fake_aleapp.py"
        leapp_script.write_text(
            f"#!{sys.executable}\n"
            "import argparse, pathlib\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('-t', required=True)\n"
            "p.add_argument('-i', required=True)\n"
            "p.add_argument('-o', required=True)\n"
            "args = p.parse_args()\n"
            "out = pathlib.Path(args.o) / 'TSV Exports'\n"
            "out.mkdir(parents=True, exist_ok=True)\n"
            "(out / 'Installed_Apps.tsv').write_text('Timestamp\\tPackage\\tVersion\\n2026-11-20 10:00:00\\tcom.example.app\\t1.2.3\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        os.chmod(leapp_script, os.stat(leapp_script).st_mode | stat.S_IXUSR)

        in_dir = self.root / "fs_in"
        in_dir.mkdir()
        leapp_out = self.root / "leapp_out"

        res_leapp = run_leapp_tool(
            tool_key="aleapp",
            binary_path=str(leapp_script),
            input_type="fs",
            input_path=in_dir,
            output_dir=leapp_out,
            repo=self.repo,
            case_id=case["case_id"],
            device_id=dev["device_id"],
        )
        self.assertTrue(res_leapp["success"])
        self.assertEqual(res_leapp["tsv_files_found"], 1)
        self.assertEqual(res_leapp["artifacts_ingested"], 1)

        # Create real executable Python script acting as MVT CLI
        mvt_script = self.root / "fake_mvt.py"
        mvt_script.write_text(
            f"#!{sys.executable}\n"
            "import json, pathlib, sys\n"
            "out_idx = sys.argv.index('--output')\n"
            "out = pathlib.Path(sys.argv[out_idx + 1])\n"
            "out.mkdir(parents=True, exist_ok=True)\n"
            "(out / 'safari_history.json').write_text(json.dumps([{'timestamp': '2026-11-20T10:05:00Z', 'domain': 'example.org'}]), encoding='utf-8')\n",
            encoding="utf-8",
        )
        os.chmod(mvt_script, os.stat(mvt_script).st_mode | stat.S_IXUSR)

        mvt_out = self.root / "mvt_out"
        res_mvt = run_mvt_check(
            tool_key="mvt_ios",
            binary_path=str(mvt_script),
            subcommand="check-backup",
            target_path_or_none=in_dir,
            output_dir=mvt_out,
            iocs_path=None,
            repo=self.repo,
            case_id=case["case_id"],
            device_id=dev["device_id"],
        )
        self.assertTrue(res_mvt["success"])
        self.assertEqual(res_mvt["json_files_found"], 1)
        self.assertEqual(res_mvt["artifacts_ingested"], 1)

        arts = self.repo.search_artifacts(case["case_id"])
        types = {a["artifact_type"] for a in arts}
        self.assertIn("aleapp_installed_apps", types)
        self.assertIn("mvt_ios_safari_history", types)

    def test_cli_validation_and_error_honesty(self) -> None:
        old_db = os.environ.get("MOBILETRACE_DB_PATH")
        old_ws = os.environ.get("MOBILETRACE_WORKSPACE_DIR")
        os.environ["MOBILETRACE_DB_PATH"] = str(self.root / "cli.db")
        os.environ["MOBILETRACE_WORKSPACE_DIR"] = str(self.root / "ws")
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli.main(
                    [
                        "case-create",
                        "--case-number",
                        "MT-CLI-1",
                        "--title",
                        "CLI Test",
                        "--examiner",
                        "Examiner",
                    ]
                )
            self.assertEqual(rc, 0)
            case_id = json.loads(buf.getvalue())["case_id"]

            # run-external-tool must reject empty --input-path cleanly
            buf_err = io.StringIO()
            with redirect_stdout(buf_err):
                rc_err = cli.main(
                    [
                        "run-external-tool",
                        "--case-id",
                        case_id,
                        "--device-id",
                        "dev_none",
                        "--tool",
                        "aleapp",
                        "--input-path",
                        "",
                    ]
                )
            self.assertEqual(rc_err, 1)
            self.assertIn("--input-path is required", json.loads(buf_err.getvalue())["error"])

            # ios-live-backup without idevicebackup2 must return exit code 1 with honest error
            buf_ios = io.StringIO()
            with redirect_stdout(buf_ios):
                rc_ios = cli.main(["ios-live-backup", "--case-id", case_id, "--udid", "TESTUDID"])
            if rc_ios != 0:
                self.assertIn("error", json.loads(buf_ios.getvalue()))
        finally:
            if old_db is None:
                os.environ.pop("MOBILETRACE_DB_PATH", None)
            else:
                os.environ["MOBILETRACE_DB_PATH"] = old_db
            if old_ws is None:
                os.environ.pop("MOBILETRACE_WORKSPACE_DIR", None)
            else:
                os.environ["MOBILETRACE_WORKSPACE_DIR"] = old_ws

    def test_alembic_initial_migration_has_all_13_tables(self) -> None:
        mig_file = Path(__file__).resolve().parent.parent / "alembic" / "versions" / "0001_initial_schema.py"
        tree = ast.parse(mig_file.read_text(encoding="utf-8"))
        created_tables: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "create_table"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                created_tables.add(str(node.args[0].value))
        expected = {
            "cases",
            "devices",
            "authorization_records",
            "acquisition_sessions",
            "transfer_manifests",
            "transferred_files",
            "artifacts",
            "timeline_events",
            "investigation_findings",
            "analyst_notes",
            "ai_analyses",
            "report_records",
            "audit_events",
        }
        self.assertEqual(created_tables, expected)


if __name__ == "__main__":
    unittest.main()
