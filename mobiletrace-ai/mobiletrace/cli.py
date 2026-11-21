"""JSON CLI bridge for MobileTrace AI Python forensic core."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mobiletrace.acquisition.android_adb import AndroidADBClient
from mobiletrace.acquisition.ios_backup import iOSBackupClient
from mobiletrace.ai.gemini_investigator import (
    build_minimized_evidence_bundle,
    run_gemini_investigation,
    validate_ai_citations,
)
from mobiletrace.analysis.correlation import compare_devices_timeline
from mobiletrace.analysis.native_parsers import ingest_local_directory, parse_ios_backup_artifacts
from mobiletrace.analysis.tools_integration import inspect_forensic_tools, run_leapp_tool, run_mvt_check
from mobiletrace.config import load_config
from mobiletrace.db.migrations import backup_database
from mobiletrace.db.repository import ForensicRepository
from mobiletrace.reporting.integrity import verify_case_integrity
from mobiletrace.reporting.report_generator import generate_html_report, generate_pdf_report
from mobiletrace.transfer.manager import TransferManager


def _emit(payload: Any, exit_code: int = 0) -> int:
    print(json.dumps(payload, indent=2, default=str))
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mobiletrace-cli", description="MobileTrace AI Forensic CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("diagnostics")

    p_case_create = sub.add_parser("case-create")
    p_case_create.add_argument("--case-number", required=True)
    p_case_create.add_argument("--title", required=True)
    p_case_create.add_argument("--examiner", required=True)
    p_case_create.add_argument("--agency", default="")
    p_case_create.add_argument("--notes", default="")

    sub.add_parser("case-list")

    p_case_get = sub.add_parser("case-get")
    p_case_get.add_argument("--case-id", required=True)

    p_adb_ls = sub.add_parser("adb-ls")
    p_adb_ls.add_argument("--serial", required=True)
    p_adb_ls.add_argument("--path", required=True)

    p_adb_pull = sub.add_parser("adb-acquire")
    p_adb_pull.add_argument("--case-id", required=True)
    p_adb_pull.add_argument("--serial", required=True)
    p_adb_pull.add_argument("--remote-roots", nargs="+", required=True)
    p_adb_pull.add_argument("--actor", default="examiner")

    p_adb_bkp = sub.add_parser("adb-backup")
    p_adb_bkp.add_argument("--case-id", required=True)
    p_adb_bkp.add_argument("--serial", required=True)
    p_adb_bkp.add_argument("--include-shared", action="store_true")
    p_adb_bkp.add_argument("--include-apks", action="store_true")
    p_adb_bkp.add_argument("--actor", default="examiner")

    p_ios_live = sub.add_parser("ios-live-backup")
    p_ios_live.add_argument("--case-id", required=True)
    p_ios_live.add_argument("--udid", required=True)
    p_ios_live.add_argument("--actor", default="examiner")

    p_ios_import = sub.add_parser("ios-import-backup")
    p_ios_import.add_argument("--case-id", required=True)
    p_ios_import.add_argument("--backup-dir", required=True)
    p_ios_import.add_argument("--password", default="")
    p_ios_import.add_argument("--actor", default="examiner")

    p_ingest_dir = sub.add_parser("ingest-directory")
    p_ingest_dir.add_argument("--case-id", required=True)
    p_ingest_dir.add_argument("--source-dir", required=True)
    p_ingest_dir.add_argument("--platform", default="android")
    p_ingest_dir.add_argument("--device-label", default="Local Evidence Folder")
    p_ingest_dir.add_argument("--serial", default="")
    p_ingest_dir.add_argument("--actor", default="examiner")

    p_auth = sub.add_parser("auth-record")
    p_auth.add_argument("--case-id", required=True)
    p_auth.add_argument("--device-id", required=True)
    p_auth.add_argument("--authority-type", required=True)
    p_auth.add_argument("--reference-number", default="")
    p_auth.add_argument("--authorized-by", required=True)
    p_auth.add_argument("--scope-description", required=True)

    p_artifacts = sub.add_parser("artifact-search")
    p_artifacts.add_argument("--case-id", required=True)
    p_artifacts.add_argument("--query", default="")
    p_artifacts.add_argument("--artifact-type", default="")
    p_artifacts.add_argument("--device-id", default="")

    p_timeline = sub.add_parser("timeline")
    p_timeline.add_argument("--case-id", required=True)
    p_timeline.add_argument("--device-id", default="")
    p_timeline.add_argument("--query", default="")

    p_compare = sub.add_parser("compare-devices")
    p_compare.add_argument("--case-id", required=True)
    p_compare.add_argument("--window-seconds", type=int, default=300)

    p_transfer = sub.add_parser("transfer-run")
    p_transfer.add_argument("--case-id", required=True)
    p_transfer.add_argument("--sources", nargs="+", required=True)
    p_transfer.add_argument("--destination", required=True)
    p_transfer.add_argument("--conflict-policy", default="rename", choices=["skip", "rename", "overwrite"])
    p_transfer.add_argument("--actor", default="examiner")

    p_verify = sub.add_parser("verify-integrity")
    p_verify.add_argument("--case-id", required=True)
    p_verify.add_argument("--actor", default="examiner")

    p_finding = sub.add_parser("finding-add")
    p_finding.add_argument("--case-id", required=True)
    p_finding.add_argument("--title", required=True)
    p_finding.add_argument("--category", required=True)
    p_finding.add_argument("--severity", default="informational")
    p_finding.add_argument("--description", required=True)
    p_finding.add_argument("--artifact-ids", nargs="*", default=[])
    p_finding.add_argument("--actor", default="examiner")

    p_note = sub.add_parser("note-add")
    p_note.add_argument("--case-id", required=True)
    p_note.add_argument("--author", required=True)
    p_note.add_argument("--body", required=True)
    p_note.add_argument("--artifact-id", default="")

    p_report = sub.add_parser("report-generate")
    p_report.add_argument("--case-id", required=True)
    p_report.add_argument("--format", required=True, choices=["html", "pdf"])
    p_report.add_argument("--actor", default="examiner")

    p_bundle = sub.add_parser("ai-prepare-bundle")
    p_bundle.add_argument("--case-id", required=True)
    p_bundle.add_argument("--artifact-ids", nargs="+", required=True)
    p_bundle.add_argument("--redact-pii", action="store_true")

    p_ai_save = sub.add_parser("ai-validate-and-save")
    p_ai_save.add_argument("--case-id", required=True)
    p_ai_save.add_argument("--model-name", required=True)
    p_ai_save.add_argument("--question", required=True)
    p_ai_save.add_argument("--analyst-approved", action="store_true")
    p_ai_save.add_argument("--pii-redacted", action="store_true")
    p_ai_save.add_argument("--selected-ids", nargs="+", required=True)
    p_ai_save.add_argument("--response-json-stdin", action="store_true")
    p_ai_save.add_argument("--actor", default="examiner")

    p_ai_run = sub.add_parser("ai-investigate")
    p_ai_run.add_argument("--case-id", required=True)
    p_ai_run.add_argument("--artifact-ids", nargs="+", required=True)
    p_ai_run.add_argument("--question", required=True)
    p_ai_run.add_argument("--analyst-approved", action="store_true")
    p_ai_run.add_argument("--no-redact", action="store_true")
    p_ai_run.add_argument("--use-search-grounding", action="store_true")
    p_ai_run.add_argument("--actor", default="examiner")

    p_tool = sub.add_parser("run-external-tool")
    p_tool.add_argument("--case-id", required=True)
    p_tool.add_argument("--device-id", required=True)
    p_tool.add_argument("--tool", required=True, choices=["aleapp", "ileapp", "mvt_ios", "mvt_android"])
    p_tool.add_argument("--input-path", default="")
    p_tool.add_argument("--input-type", default="fs")
    p_tool.add_argument("--subcommand", default="check-backup")
    p_tool.add_argument("--actor", default="examiner")

    sub.add_parser("db-backup")

    args = parser.parse_args(argv)
    cfg = load_config()
    repo = ForensicRepository(cfg.db_path)

    try:
        if args.command == "diagnostics":
            adb_client = AndroidADBClient(cfg.adb_path)
            ios_client = iOSBackupClient(cfg.idevice_dir)
            return _emit(
                {
                    "host_os": cfg.host_os,
                    "db_path": str(cfg.db_path),
                    "workspace_dir": str(cfg.workspace_dir),
                    "gemini_configured": cfg.gemini_configured,
                    "gemini_model": cfg.gemini_model,
                    "redact_pii_default": cfg.redact_pii,
                    "android": adb_client.list_devices(),
                    "ios": ios_client.detect_devices(),
                    "ios_tooling": ios_client.check_tooling(),
                    "forensic_tools": inspect_forensic_tools(cfg),
                }
            )

        if args.command == "case-create":
            return _emit(
                repo.create_case(
                    case_number=args.case_number,
                    title=args.title,
                    examiner=args.examiner,
                    agency=args.agency,
                    notes=args.notes,
                )
            )

        if args.command == "case-list":
            return _emit({"cases": repo.list_cases()})

        if args.command == "case-get":
            case = repo.get_case(args.case_id)
            if not case:
                return _emit({"error": f"Case not found: {args.case_id}"}, 1)
            return _emit(
                {
                    "case": case,
                    "devices": repo.list_devices(args.case_id),
                    "authorizations": repo.list_authorizations(args.case_id),
                    "sessions": repo.list_acquisition_sessions(args.case_id),
                    "transfers": [
                        {**m, "files": repo.list_transferred_files(m["manifest_id"])}
                        for m in repo.list_transfer_manifests(args.case_id)
                    ],
                    "artifacts": repo.search_artifacts(args.case_id, limit=500),
                    "timeline": repo.list_timeline_events(args.case_id, limit=500),
                    "findings": repo.list_findings(args.case_id),
                    "notes": repo.list_notes(args.case_id),
                    "ai_analyses": repo.list_ai_analyses(args.case_id),
                    "reports": repo.list_reports(args.case_id),
                    "audit_events": repo.list_audit_events(args.case_id, limit=200),
                }
            )

        if args.command == "adb-ls":
            adb = AndroidADBClient(cfg.adb_path)
            return _emit(adb.list_directory(args.serial, args.path))

        if args.command == "adb-acquire":
            adb = AndroidADBClient(cfg.adb_path)
            devices_info = adb.list_devices()
            match = next((d for d in devices_info["devices"] if d["serial"] == args.serial), None)
            if not match:
                return _emit({"error": f"Device {args.serial} not connected."}, 1)
            device = repo.register_device(
                case_id=args.case_id,
                platform="android",
                serial_or_udid=args.serial,
                manufacturer=match.get("manufacturer", ""),
                model=match.get("model", ""),
                os_version=match.get("os_version", ""),
                build_or_sdk=match.get("sdk_version", ""),
                connection_state=match.get("state", "unknown"),
                metadata=match.get("properties", {}),
                actor=args.actor,
            )
            out_dir = cfg.workspace_dir / "acquisitions" / args.case_id / f"android_{args.serial}"
            session = adb.acquire_accessible_files(
                repo=repo,
                case_id=args.case_id,
                device_id=device["device_id"],
                serial=args.serial,
                remote_roots=args.remote_roots,
                output_dir=out_dir,
                actor=args.actor,
            )
            return _emit({"device": device, "session": session})

        if args.command == "adb-backup":
            adb = AndroidADBClient(cfg.adb_path)
            devices_info = adb.list_devices()
            match = next((d for d in devices_info["devices"] if d["serial"] == args.serial), None)
            if not match:
                return _emit({"error": f"Android device {args.serial} is not connected."}, 1)
            device = repo.register_device(
                case_id=args.case_id,
                platform="android",
                serial_or_udid=args.serial,
                manufacturer=match.get("manufacturer", ""),
                model=match.get("model", ""),
                os_version=match.get("os_version", ""),
                build_or_sdk=match.get("sdk_version", ""),
                connection_state=match.get("state", "unknown"),
                metadata=match.get("properties", {}),
                actor=args.actor,
            )
            ab_path = cfg.workspace_dir / "acquisitions" / args.case_id / f"adb_backup_{args.serial}.ab"
            bkp_res = adb.create_adb_backup(
                serial=args.serial,
                dest_ab_path=ab_path,
                include_shared=args.include_shared,
                include_apks=args.include_apks,
            )
            repo.append_audit_event(
                case_id=args.case_id,
                actor=args.actor,
                action="acquisition.adb_backup",
                target_type="device",
                target_id=device["device_id"],
                details=bkp_res,
            )
            return _emit({"device": device, "backup": bkp_res})

        if args.command == "ios-live-backup":
            ios = iOSBackupClient(cfg.idevice_dir)
            bkp_root = cfg.workspace_dir / "acquisitions" / args.case_id / f"ios_live_{args.udid}"
            live_res = ios.create_local_backup(udid=args.udid, backup_root=bkp_root)
            repo.append_audit_event(
                case_id=args.case_id,
                actor=args.actor,
                action="acquisition.ios_live_backup",
                target_type="case",
                target_id=args.case_id,
                details={"udid": args.udid, "success": live_res["success"]},
            )
            return _emit(live_res)

        if args.command == "ios-import-backup":
            ios = iOSBackupClient(cfg.idevice_dir)
            dec_dir = cfg.workspace_dir / "analysis" / args.case_id / "ios_decrypted"
            imported = ios.import_local_backup(
                repo=repo,
                case_id=args.case_id,
                backup_dir=Path(args.backup_dir),
                backup_password=args.password or None,
                decrypted_output_dir=dec_dir,
                actor=args.actor,
            )
            working_dir = Path(imported["working_dir"])
            parsed_counts = {}
            if (working_dir / "Manifest.db").is_file():
                parsed_counts = parse_ios_backup_artifacts(
                    repo=repo,
                    case_id=args.case_id,
                    device_id=imported["device"]["device_id"],
                    session_id=imported["session"]["session_id"],
                    backup_dir=working_dir,
                    actor=args.actor,
                )
            return _emit({**imported, "parsed_artifacts": parsed_counts})

        if args.command == "ingest-directory":
            serial_val = args.serial.strip() or f"local-{Path(args.source_dir).name}"
            device = repo.register_device(
                case_id=args.case_id,
                platform=args.platform,
                serial_or_udid=serial_val,
                manufacturer="Host/Exported",
                model=args.device_label,
                os_version="",
                connection_state="local_directory",
                actor=args.actor,
            )
            copy_dir = cfg.workspace_dir / "acquisitions" / args.case_id / device["device_id"]
            res = ingest_local_directory(
                repo=repo,
                case_id=args.case_id,
                device_id=device["device_id"],
                source_dir=Path(args.source_dir),
                evidence_copy_dir=copy_dir,
                platform=args.platform,
                actor=args.actor,
            )
            return _emit({"device": device, **res})

        if args.command == "auth-record":
            return _emit(
                repo.record_authorization(
                    case_id=args.case_id,
                    device_id=args.device_id,
                    authority_type=args.authority_type,
                    reference_number=args.reference_number,
                    authorized_by=args.authorized_by,
                    scope_description=args.scope_description,
                )
            )

        if args.command == "artifact-search":
            return _emit(
                {
                    "artifacts": repo.search_artifacts(
                        args.case_id,
                        query=args.query,
                        artifact_type=args.artifact_type,
                        device_id=args.device_id,
                    )
                }
            )

        if args.command == "timeline":
            return _emit(
                {
                    "events": repo.list_timeline_events(
                        args.case_id, device_id=args.device_id, query=args.query
                    )
                }
            )

        if args.command == "compare-devices":
            return _emit(compare_devices_timeline(repo, args.case_id, window_seconds=args.window_seconds))

        if args.command == "transfer-run":
            mgr = TransferManager()
            src_paths = [Path(p) for p in args.sources]
            return _emit(
                mgr.execute_transfer(
                    repo=repo,
                    case_id=args.case_id,
                    source_paths=src_paths,
                    destination_dir=Path(args.destination),
                    conflict_policy=args.conflict_policy,
                    actor=args.actor,
                )
            )

        if args.command == "verify-integrity":
            manifest_path = cfg.workspace_dir / "reports" / f"integrity_{args.case_id}.json"
            return _emit(
                verify_case_integrity(repo, args.case_id, manifest_output_path=manifest_path, actor=args.actor)
            )

        if args.command == "finding-add":
            return _emit(
                repo.add_finding(
                    case_id=args.case_id,
                    title=args.title,
                    category=args.category,
                    severity=args.severity,
                    description=args.description,
                    linked_artifact_ids=args.artifact_ids,
                    created_by=args.actor,
                )
            )

        if args.command == "note-add":
            return _emit(
                repo.add_note(
                    case_id=args.case_id,
                    author=args.author,
                    body=args.body,
                    artifact_id=args.artifact_id or None,
                )
            )

        if args.command == "report-generate":
            ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            out_dir = cfg.workspace_dir / "reports" / args.case_id
            if args.format == "html":
                return _emit(
                    generate_html_report(
                        repo=repo,
                        case_id=args.case_id,
                        output_path=out_dir / f"report_{args.case_id}_{ts_slug}.html",
                        generated_by=args.actor,
                    )
                )
            return _emit(
                generate_pdf_report(
                    repo=repo,
                    case_id=args.case_id,
                    output_path=out_dir / f"report_{args.case_id}_{ts_slug}.pdf",
                    generated_by=args.actor,
                )
            )

        if args.command == "ai-prepare-bundle":
            return _emit(
                build_minimized_evidence_bundle(
                    repo,
                    args.case_id,
                    args.artifact_ids,
                    redact_pii=args.redact_pii,
                )
            )

        if args.command == "ai-validate-and-save":
            raw = sys.stdin.read() if args.response_json_stdin else "{}"
            payload = json.loads(raw)
            validation = validate_ai_citations(repo, args.case_id, payload)
            saved = repo.save_ai_analysis(
                case_id=args.case_id,
                model_name=args.model_name,
                analyst_approved=args.analyst_approved,
                pii_redacted=args.pii_redacted,
                prompt_question=args.question,
                selected_artifact_ids=args.selected_ids,
                verified_artifact_ids=validation["verified_artifact_ids"],
                rejected_artifact_ids=validation["rejected_artifact_ids"],
                response_payload=validation["validated_payload"],
                actor=args.actor,
            )
            return _emit(
                {
                    "analysis": saved,
                    "verified_artifact_ids": validation["verified_artifact_ids"],
                    "rejected_artifact_ids": validation["rejected_artifact_ids"],
                    "result": validation["validated_payload"],
                }
            )

        if args.command == "ai-investigate":
            return _emit(
                run_gemini_investigation(
                    repo=repo,
                    case_id=args.case_id,
                    artifact_ids=args.artifact_ids,
                    question=args.question,
                    analyst_approved=args.analyst_approved,
                    redact_pii=not args.no_redact,
                    use_search_grounding=args.use_search_grounding,
                    model_name=cfg.gemini_model,
                    actor=args.actor,
                )
            )

        if args.command == "run-external-tool":
            out_dir = cfg.workspace_dir / "analysis" / args.case_id / args.tool
            if args.tool in {"aleapp", "ileapp"}:
                if not args.input_path.strip():
                    return _emit({"error": f"--input-path is required for {args.tool.upper()}."}, 1)
                bin_path = cfg.aleapp_path if args.tool == "aleapp" else cfg.ileapp_path
                return _emit(
                    run_leapp_tool(
                        tool_key=args.tool,
                        binary_path=bin_path,
                        input_type=args.input_type,
                        input_path=Path(args.input_path),
                        output_dir=out_dir,
                        repo=repo,
                        case_id=args.case_id,
                        device_id=args.device_id,
                        actor=args.actor,
                    )
                )
            if args.subcommand != "check-adb" and not args.input_path.strip():
                return _emit({"error": f"--input-path is required for {args.tool} {args.subcommand}."}, 1)
            bin_path = cfg.mvt_ios_path if args.tool == "mvt_ios" else cfg.mvt_android_path
            return _emit(
                run_mvt_check(
                    tool_key=args.tool,
                    binary_path=bin_path,
                    subcommand=args.subcommand,
                    target_path_or_none=Path(args.input_path) if args.input_path.strip() else None,
                    output_dir=out_dir,
                    iocs_path=None,
                    repo=repo,
                    case_id=args.case_id,
                    device_id=args.device_id,
                    actor=args.actor,
                )
            )

        if args.command == "db-backup":
            ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            dst = cfg.workspace_dir / "backups" / f"mobiletrace_backup_{ts_slug}.db"
            backup_database(cfg.db_path, dst)
            return _emit({"backup_path": str(dst)})

    except Exception as exc:
        return _emit({"error": str(exc)}, 1)

    return _emit({"error": "Unknown command"}, 1)


if __name__ == "__main__":
    raise SystemExit(main())
