"""Genuine external forensic tool integrations: ALEAPP, iLEAPP, and MVT."""

from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path
from typing import Any

from mobiletrace.config import WorkstationConfig
from mobiletrace.core.hashing import sha256_file
from mobiletrace.db.repository import ForensicRepository


TOOL_CATALOG = {
    "aleapp": {
        "name": "ALEAPP",
        "license": "MIT",
        "supported_inputs": ["fs (extracted filesystem folder)", "tar", "zip", "adb (only if extracted)"],
        "platform_notes": "Python 3 CLI/GUI (abrignoni/ALEAPP). Requires ALEAPP installed on PATH or MOBILETRACE_ALEAPP_PATH.",
    },
    "ileapp": {
        "name": "iLEAPP",
        "license": "MIT",
        "supported_inputs": ["itunes (iOS local backup folder)", "fs", "tar", "zip"],
        "platform_notes": "Python 3 CLI/GUI (abrignoni/iLEAPP). Requires iLEAPP installed on PATH or MOBILETRACE_ILEAPP_PATH.",
    },
    "mvt_ios": {
        "name": "MVT (mvt-ios)",
        "license": "MVT License (Amnesty Tech)",
        "supported_inputs": ["check-backup (unencrypted/decrypted iOS backup)", "check-iocs"],
        "platform_notes": "Mobile Verification Toolkit for iOS spyware/IOC triage. Requires mvt-ios installed.",
    },
    "mvt_android": {
        "name": "MVT (mvt-android)",
        "license": "MVT License (Amnesty Tech)",
        "supported_inputs": ["check-adb (authorized ADB device)", "check-backup", "check-bugreport"],
        "platform_notes": "Mobile Verification Toolkit for Android spyware/IOC triage. Requires mvt-android installed.",
    },
}


def _probe_version(binary: str | None) -> tuple[bool, str]:
    if not binary:
        return False, ""
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10.0, shell=False)
        out = (proc.stdout + "\n" + proc.stderr).strip()
        first = out.splitlines()[0] if out else "detected"
        return proc.returncode == 0 or bool(out), first
    except Exception as exc:
        return False, str(exc)


def inspect_forensic_tools(cfg: WorkstationConfig) -> dict[str, Any]:
    """Return real detection status, versions, licenses, and limitations for ALEAPP, iLEAPP, and MVT."""
    mapping = {
        "aleapp": cfg.aleapp_path,
        "ileapp": cfg.ileapp_path,
        "mvt_ios": cfg.mvt_ios_path,
        "mvt_android": cfg.mvt_android_path,
    }
    report: dict[str, Any] = {}
    for key, meta in TOOL_CATALOG.items():
        path = mapping[key]
        ok, ver = _probe_version(path)
        report[key] = {
            **meta,
            "installed": ok,
            "binary_path": path,
            "version": ver if ok else None,
        }
    return report


def run_leapp_tool(
    *,
    tool_key: str,
    binary_path: str | None,
    input_type: str,
    input_path: Path,
    output_dir: Path,
    repo: ForensicRepository,
    case_id: str,
    device_id: str,
    actor: str = "examiner",
) -> dict[str, Any]:
    """Run real ALEAPP or iLEAPP subprocess against acquired evidence and ingest TSV exports."""
    if tool_key not in {"aleapp", "ileapp"}:
        raise ValueError("tool_key must be 'aleapp' or 'ileapp'")
    if not binary_path:
        raise FileNotFoundError(
            f"{tool_key.upper()} is not installed on this workstation. Install it or set MOBILETRACE_{tool_key.upper()}_PATH."
        )
    if not input_path.exists():
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [binary_path, "-t", input_type, "-i", str(input_path), "-o", str(output_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600.0, shell=False)

    ingested = 0
    tsv_files = list(output_dir.rglob("*.tsv"))
    for tsv_path in tsv_files:
        sha_val, size_b = sha256_file(tsv_path)
        with tsv_path.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f, delimiter="\t")
            for idx, row in enumerate(reader):
                if idx >= 500:
                    break
                ts_candidate = row.get("Timestamp") or row.get("Date") or row.get("Start Time") or ""
                repo.add_artifact(
                    case_id=case_id,
                    device_id=device_id,
                    session_id=None,
                    artifact_type=f"{tool_key}_{tsv_path.stem.lower()}",
                    title=f"{tsv_path.stem} #{idx + 1}",
                    summary=" | ".join(f"{k}: {v}" for k, v in list(row.items())[:4] if v),
                    original_source_path=str(tsv_path),
                    stored_copy_path=str(tsv_path),
                    original_timestamp=str(ts_candidate),
                    original_timezone="tool_export_unspecified",
                    normalized_timestamp_utc="",
                    normalization_justification=f"Exported by {tool_key.upper()}; timezone depends on underlying plugin.",
                    acquisition_method=f"{tool_key}_{input_type}",
                    parser_name=tool_key,
                    parser_version="external_cli",
                    sha256=sha_val,
                    byte_size=size_b,
                    content=dict(row),
                    actor=actor,
                )
                ingested += 1

    repo.append_audit_event(
        case_id=case_id,
        actor=actor,
        action=f"tool.{tool_key}.executed",
        target_type="device",
        target_id=device_id,
        details={"returncode": proc.returncode, "tsv_files": len(tsv_files), "ingested": ingested},
    )
    return {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "output_dir": str(output_dir),
        "tsv_files_found": len(tsv_files),
        "artifacts_ingested": ingested,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }


def run_mvt_check(
    *,
    tool_key: str,
    binary_path: str | None,
    subcommand: str,
    target_path_or_none: Path | None,
    output_dir: Path,
    iocs_path: Path | None,
    repo: ForensicRepository,
    case_id: str,
    device_id: str,
    actor: str = "examiner",
) -> dict[str, Any]:
    """Run real mvt-ios or mvt-android subprocess and ingest JSON module outputs."""
    if not binary_path:
        raise FileNotFoundError(
            f"{tool_key} is not installed on this workstation. Install MVT (`pip install mvt`) to run IOC checks."
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [binary_path, subcommand, "--output", str(output_dir)]
    if iocs_path:
        cmd.extend(["--iocs", str(iocs_path)])
    if target_path_or_none is not None:
        cmd.append(str(target_path_or_none))

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600.0, shell=False)
    ingested = 0
    json_files = list(output_dir.rglob("*.json"))
    for jf in json_files:
        sha_val, size_b = sha256_file(jf)
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        records = data if isinstance(data, list) else [data]
        for idx, rec in enumerate(records[:500]):
            if not isinstance(rec, dict):
                continue
            repo.add_artifact(
                case_id=case_id,
                device_id=device_id,
                session_id=None,
                artifact_type=f"{tool_key}_{jf.stem}",
                title=f"MVT {jf.stem} #{idx + 1}",
                summary=str(rec.get("matched_indicator") or rec.get("domain") or rec.get("bundle_id") or "")[:240],
                original_source_path=str(jf),
                stored_copy_path=str(jf),
                original_timestamp=str(rec.get("timestamp", "")),
                original_timezone="mvt_utc_if_iso",
                normalized_timestamp_utc="",
                normalization_justification="Imported from MVT JSON module output.",
                acquisition_method=f"{tool_key}_{subcommand}",
                parser_name=tool_key,
                parser_version="external_cli",
                sha256=sha_val,
                byte_size=size_b,
                content=rec,
                actor=actor,
            )
            ingested += 1

    repo.append_audit_event(
        case_id=case_id,
        actor=actor,
        action=f"tool.{tool_key}.executed",
        target_type="device",
        target_id=device_id,
        details={"subcommand": subcommand, "returncode": proc.returncode, "ingested": ingested},
    )
    return {
        "success": proc.returncode == 0,
        "returncode": proc.returncode,
        "output_dir": str(output_dir),
        "json_files_found": len(json_files),
        "artifacts_ingested": ingested,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
    }
