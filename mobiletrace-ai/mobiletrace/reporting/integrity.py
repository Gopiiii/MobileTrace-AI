"""Repeatable SHA-256 integrity verification and manifest export for forensic cases."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mobiletrace.core.hashing import sha256_file, verify_file_sha256
from mobiletrace.db.repository import ForensicRepository


def verify_case_integrity(
    repo: ForensicRepository,
    case_id: str,
    *,
    manifest_output_path: Path | None = None,
    actor: str = "examiner",
) -> dict[str, Any]:
    """Re-hash every stored artifact and transferred file on disk and verify audit chain continuity."""
    case = repo.get_case(case_id)
    if not case:
        raise KeyError(f"Case not found: {case_id}")

    artifacts = repo.search_artifacts(case_id, limit=10000)
    artifact_checks: list[dict[str, Any]] = []
    verified_count = 0
    mismatch_count = 0
    missing_count = 0
    unhashed_count = 0

    for art in artifacts:
        expected = art.get("sha256", "")
        copy_path = art.get("stored_copy_path", "")
        if not expected or not copy_path:
            unhashed_count += 1
            artifact_checks.append(
                {
                    "artifact_id": art["artifact_id"],
                    "title": art["title"],
                    "status": "metadata_only_no_file_hash",
                    "expected_sha256": expected,
                    "actual_sha256": None,
                    "path": copy_path,
                }
            )
            continue
        p = Path(copy_path)
        if not p.is_file():
            missing_count += 1
            artifact_checks.append(
                {
                    "artifact_id": art["artifact_id"],
                    "title": art["title"],
                    "status": "missing_file",
                    "expected_sha256": expected,
                    "actual_sha256": None,
                    "path": copy_path,
                }
            )
            continue
        ok, actual, size_b = verify_file_sha256(p, expected)
        if ok:
            verified_count += 1
            status = "verified"
        else:
            mismatch_count += 1
            status = "hash_mismatch"
        artifact_checks.append(
            {
                "artifact_id": art["artifact_id"],
                "title": art["title"],
                "status": status,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "byte_size": size_b,
                "path": copy_path,
            }
        )

    audit_check = repo.verify_audit_chain()
    overall_intact = (mismatch_count == 0 and missing_count == 0 and audit_check["valid"])

    result = {
        "case_id": case_id,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "overall_intact": overall_intact,
        "summary": {
            "total_artifacts": len(artifacts),
            "verified_files": verified_count,
            "hash_mismatches": mismatch_count,
            "missing_files": missing_count,
            "metadata_only_artifacts": unhashed_count,
        },
        "audit_chain": audit_check,
        "artifacts": artifact_checks,
    }

    if manifest_output_path is not None:
        manifest_output_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        manifest_sha, _ = sha256_file(manifest_output_path)
        result["manifest_path"] = str(manifest_output_path)
        result["manifest_sha256"] = manifest_sha

    repo.append_audit_event(
        case_id=case_id,
        actor=actor,
        action="integrity.verified",
        target_type="case",
        target_id=case_id,
        details={
            "overall_intact": overall_intact,
            "verified_files": verified_count,
            "hash_mismatches": mismatch_count,
            "missing_files": missing_count,
            "audit_chain_valid": audit_check["valid"],
        },
    )
    return result
