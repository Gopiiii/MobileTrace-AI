"""Monochrome forensic HTML and PDF report generator."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mobiletrace.core.hashing import sha256_file
from mobiletrace.db.repository import ForensicRepository
from mobiletrace.reporting.integrity import verify_case_integrity


def _esc(val: Any) -> str:
    return html.escape(str(val if val is not None else ""))


def _collect_report_context(repo: ForensicRepository, case_id: str) -> dict[str, Any]:
    case = repo.get_case(case_id)
    if not case:
        raise KeyError(f"Case not found: {case_id}")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "devices": repo.list_devices(case_id),
        "authorizations": repo.list_authorizations(case_id),
        "sessions": repo.list_acquisition_sessions(case_id),
        "artifacts": repo.search_artifacts(case_id, limit=1000),
        "timeline": repo.list_timeline_events(case_id, limit=1000),
        "findings": repo.list_findings(case_id),
        "notes": repo.list_notes(case_id),
        "ai_analyses": repo.list_ai_analyses(case_id),
        "integrity": verify_case_integrity(repo, case_id, actor="report_generator"),
    }


def generate_html_report(
    *,
    repo: ForensicRepository,
    case_id: str,
    output_path: Path,
    generated_by: str = "examiner",
) -> dict[str, Any]:
    """Generate a strictly monochrome, print-ready HTML forensic report."""
    ctx = _collect_report_context(repo, case_id)
    c = ctx["case"]

    devices_rows = "".join(
        f"<tr><td>{_esc(d['device_id'])}</td><td>{_esc(d['platform'])}</td><td>{_esc(d['manufacturer'])} {_esc(d['model'])}</td>"
        f"<td>{_esc(d['os_version'])}</td><td class='mono'>{_esc(d['serial_or_udid'])}</td><td>{_esc(d['connection_state'])}</td></tr>"
        for d in ctx["devices"]
    ) or "<tr><td colspan='6'>No devices registered.</td></tr>"

    session_rows = "".join(
        f"<tr><td>{_esc(s['session_id'])}</td><td>{_esc(s['acquisition_method'])}</td><td>{_esc(s['scope_classification'])}</td>"
        f"<td>{_esc(s['status'])}</td><td class='mono'>{s['files_copied']} / {s['bytes_copied']} B</td>"
        f"<td>{_esc('; '.join(json.loads(s['limitations_json'] or '[]')))}</td></tr>"
        for s in ctx["sessions"]
    ) or "<tr><td colspan='6'>No acquisition sessions recorded.</td></tr>"

    artifact_rows = "".join(
        f"<tr><td class='mono'>{_esc(a['artifact_id'])}</td><td>{_esc(a['artifact_type'])}</td>"
        f"<td>{_esc(a['title'])}</td><td class='mono'>{_esc(a['original_source_path'])}</td>"
        f"<td class='mono'>{_esc(a['normalized_timestamp_utc'] or a['original_timestamp'] or '—')}</td>"
        f"<td class='mono'>{_esc(a['sha256'][:16] + '...' if a['sha256'] else '—')}</td></tr>"
        for a in ctx["artifacts"]
    ) or "<tr><td colspan='6'>No artifacts recorded.</td></tr>"

    finding_blocks = "".join(
        f"<div class='block'><h3>{_esc(f['title'])} ({_esc(f['severity'])})</h3>"
        f"<p>{_esc(f['description'])}</p>"
        f"<p class='meta'>Category: {_esc(f['category'])} · Linked Artifacts: {_esc(f['linked_artifact_ids_json'])} · Author: {_esc(f['created_by'])}</p></div>"
        for f in ctx["findings"]
    ) or "<p>No formal investigator findings recorded.</p>"

    ai_blocks = ""
    for ai in ctx["ai_analyses"]:
        payload = json.loads(ai["response_json"] or "{}")
        ai_blocks += (
            f"<div class='block'>"
            f"<h3>AI Analysis {_esc(ai['analysis_id'])} · Model: {_esc(ai['model_name'])}</h3>"
            f"<p class='meta'>Analyst Approved: {bool(ai['analyst_approved'])} · PII Redacted: {bool(ai['pii_redacted'])} · "
            f"Verified Cited IDs: {_esc(ai['verified_artifact_ids_json'])} · Rejected IDs: {_esc(ai['rejected_artifact_ids_json'])}</p>"
            f"<p><strong>Question:</strong> {_esc(ai['prompt_question'])}</p>"
            f"<pre class='mono'>{_esc(json.dumps(payload, indent=2))}</pre>"
            f"</div>"
        )
    if not ai_blocks:
        ai_blocks = "<p>No AI-assisted analyses were run for this case.</p>"

    integ = ctx["integrity"]["summary"]
    audit_valid = ctx["integrity"]["audit_chain"]["valid"]

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>MobileTrace AI Forensic Report — {_esc(c['case_number'])}</title>
<style>
  body {{ font-family: 'Public Sans', Arial, sans-serif; color: #111111; background: #ffffff; margin: 40px auto; max-width: 1080px; line-height: 1.5; }}
  h1, h2, h3 {{ font-family: 'Plus Jakarta Sans', Arial, sans-serif; color: #000000; margin-top: 28px; }}
  h1 {{ font-size: 26px; border-bottom: 2px solid #000000; padding-bottom: 10px; }}
  h2 {{ font-size: 16px; text-transform: uppercase; letter-spacing: 0.04em; border-bottom: 1px solid #d4d4d4; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0 24px; font-size: 12px; }}
  th, td {{ border: 1px solid #d4d4d4; padding: 7px 9px; text-align: left; vertical-align: top; word-break: break-word; }}
  th {{ background: #f5f5f5; font-weight: 600; }}
  .mono {{ font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; }}
  .meta {{ color: #525252; font-size: 12px; }}
  .block {{ border: 1px solid #d4d4d4; padding: 14px; margin: 12px 0; background: #fafafa; }}
  .warning {{ border: 1px solid #171717; padding: 12px 14px; background: #f5f5f5; margin: 14px 0; font-size: 13px; }}
  pre {{ white-space: pre-wrap; background: #ffffff; border: 1px solid #e5e5e5; padding: 10px; }}
</style>
</head>
<body>
  <h1>MobileTrace AI — Digital Forensics Examination Report</h1>
  <p class="meta">Case Number: <strong>{_esc(c['case_number'])}</strong> · Case ID: <span class="mono">{_esc(c['case_id'])}</span> · Examiner: {_esc(c['examiner'])} · Agency: {_esc(c['agency'] or 'N/A')} · Generated UTC: <span class="mono">{_esc(ctx['generated_at'])}</span></p>
  <p><strong>Case Title:</strong> {_esc(c['title'])} &nbsp;|&nbsp; <strong>Status:</strong> {_esc(c['status'])}</p>

  <h2>1. Evidence Integrity Summary</h2>
  <div class="block">
    <p>Verified Files on Disk: <strong>{integ['verified_files']}</strong> · Hash Mismatches: <strong>{integ['hash_mismatches']}</strong> · Missing Files: <strong>{integ['missing_files']}</strong> · Append-Only Audit Chain Valid: <strong>{audit_valid}</strong></p>
  </div>

  <h2>2. Registered Devices</h2>
  <table>
    <thead><tr><th>Device ID</th><th>Platform</th><th>Model</th><th>OS Version</th><th>Serial / UDID</th><th>State</th></tr></thead>
    <tbody>{devices_rows}</tbody>
  </table>

  <h2>3. Acquisition Sessions &amp; Scope Limitations</h2>
  <table>
    <thead><tr><th>Session ID</th><th>Method</th><th>Scope Classification</th><th>Status</th><th>Files / Bytes</th><th>Recorded Limitations</th></tr></thead>
    <tbody>{session_rows}</tbody>
  </table>

  <h2>4. Verified Forensic Artifacts (SHA-256 &amp; Provenance)</h2>
  <table>
    <thead><tr><th>Artifact ID</th><th>Type</th><th>Title</th><th>Original Source Path</th><th>Timestamp</th><th>SHA-256</th></tr></thead>
    <tbody>{artifact_rows}</tbody>
  </table>

  <h2>5. Examiner Findings (Evidence-Linked)</h2>
  {finding_blocks}

  <h2>6. AI-Assisted Interpretations &amp; Uncertainty (Requires Examiner Verification)</h2>
  <div class="warning">
    <strong>Forensic Disclosure:</strong> The items below were generated by an AI model over minimized, analyst-approved evidence excerpts. All cited artifact IDs have been checked against the SQLite evidence store, but AI interpretations are NOT verified forensic facts. Missing artifacts do not prove non-occurrence, and matching timestamps do not prove causation.
  </div>
  {ai_blocks}
</body>
</html>"""

    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_doc, encoding="utf-8")
    digest, _ = sha256_file(output_path)
    rec = repo.record_report(
        case_id=case_id,
        report_format="html",
        output_path=str(output_path),
        sha256=digest,
        generated_by=generated_by,
    )
    return {"report": rec, "sha256": digest, "output_path": str(output_path)}


def generate_pdf_report(
    *,
    repo: ForensicRepository,
    case_id: str,
    output_path: Path,
    generated_by: str = "examiner",
) -> dict[str, Any]:
    """Generate a monochrome forensic PDF report using ReportLab when installed, or built-in PDF 1.4 writer."""
    ctx = _collect_report_context(repo, case_id)
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = _build_pdf_lines(ctx)
    try:
        from reportlab.lib.pagesizes import LETTER  # type: ignore
        from reportlab.pdfgen import canvas  # type: ignore

        c = canvas.Canvas(str(output_path), pagesize=LETTER)
        width, height = LETTER
        y = height - 48
        c.setFont("Courier", 9)
        for line in lines:
            if y < 48:
                c.showPage()
                c.setFont("Courier", 9)
                y = height - 48
            c.drawString(42, y, line[:102])
            y -= 13
        c.save()
    except ImportError:
        _write_minimal_pdf(output_path, lines)

    digest, _ = sha256_file(output_path)
    rec = repo.record_report(
        case_id=case_id,
        report_format="pdf",
        output_path=str(output_path),
        sha256=digest,
        generated_by=generated_by,
    )
    return {"report": rec, "sha256": digest, "output_path": str(output_path)}


def _build_pdf_lines(ctx: dict[str, Any]) -> list[str]:
    c = ctx["case"]
    integ = ctx["integrity"]["summary"]
    lines = [
        "MOBILETRACE AI - DIGITAL FORENSICS EXAMINATION REPORT",
        "=" * 78,
        f"Case Number: {c['case_number']}   Case ID: {c['case_id']}",
        f"Title:       {c['title']}",
        f"Examiner:    {c['examiner']}   Agency: {c['agency'] or 'N/A'}   Status: {c['status']}",
        f"Generated:   {ctx['generated_at']}",
        "",
        "1. EVIDENCE INTEGRITY SUMMARY",
        f"   Verified Files: {integ['verified_files']} | Hash Mismatches: {integ['hash_mismatches']} | Missing: {integ['missing_files']}",
        f"   Audit Chain Valid: {ctx['integrity']['audit_chain']['valid']}",
        "",
        "2. REGISTERED DEVICES",
    ]
    for d in ctx["devices"]:
        lines.append(f"   - [{d['platform']}] {d['manufacturer']} {d['model']} (OS {d['os_version']}) | ID: {d['serial_or_udid']} | State: {d['connection_state']}")
    if not ctx["devices"]:
        lines.append("   (None registered)")
    lines.append("")
    lines.append("3. ACQUISITION SESSIONS & LIMITATIONS")
    for s in ctx["sessions"]:
        lines.append(f"   - {s['session_id']} | {s['acquisition_method']} | {s['scope_classification']} | {s['status']} | {s['files_copied']} files / {s['bytes_copied']} B")
        for lim in json.loads(s["limitations_json"] or "[]"):
            lines.append(f"     Limitation: {lim[:90]}")
    lines.append("")
    lines.append("4. VERIFIED ARTIFACTS (SAMPLE / FULL MANIFEST IN HTML/JSON)")
    for a in ctx["artifacts"][:120]:
        ts = a["normalized_timestamp_utc"] or a["original_timestamp"] or "no-ts"
        lines.append(f"   - {a['artifact_id']} | {a['artifact_type']} | {a['title'][:34]} | {ts[:22]} | sha256={a['sha256'][:16]}")
    lines.append("")
    lines.append("5. EXAMINER FINDINGS")
    for f in ctx["findings"]:
        lines.append(f"   - [{f['severity']}] {f['title']} (Artifacts: {f['linked_artifact_ids_json']})")
        lines.append(f"     {f['description'][:95]}")
    lines.append("")
    lines.append("6. AI-ASSISTED INTERPRETATIONS (NOT VERIFIED FACT)")
    for ai in ctx["ai_analyses"]:
        lines.append(f"   - {ai['analysis_id']} ({ai['model_name']}) | Approved={bool(ai['analyst_approved'])} | Redacted={bool(ai['pii_redacted'])}")
        lines.append(f"     Verified Cited IDs: {ai['verified_artifact_ids_json']}")
    return lines


def _write_minimal_pdf(output_path: Path, lines: list[str]) -> None:
    """Standards-compliant pure-Python multi-page PDF 1.4 writer (Helvetica/Courier monochrome)."""
    lines_per_page = 52
    pages_lines = [lines[i : i + lines_per_page] for i in range(0, max(1, len(lines)), lines_per_page)]

    def _pdf_escape(text: str) -> str:
        ascii_safe = text.encode("latin-1", errors="replace").decode("latin-1")
        return ascii_safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    objects: list[bytes] = []
    # 1: Catalog, 2: Pages, 3: Font Courier
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_obj_nums: list[int] = []
    font_obj_num = 3
    next_obj_num = 4
    page_entries: list[tuple[int, int, bytes]] = []
    for chunk in pages_lines:
        page_num = next_obj_num
        content_num = next_obj_num + 1
        next_obj_num += 2
        page_obj_nums.append(page_num)

        stream_cmds = ["BT", "/F1 9 Tf", "42 748 Td", "13 TL"]
        for idx, ln in enumerate(chunk):
            escaped = _pdf_escape(ln[:98])
            if idx == 0:
                stream_cmds.append(f"({escaped}) Tj")
            else:
                stream_cmds.append(f"T* ({escaped}) Tj")
        stream_cmds.append("ET")
        stream_bytes = "\n".join(stream_cmds).encode("latin-1")
        page_entries.append((page_num, content_num, stream_bytes))

    kids_str = " ".join(f"{n} 0 R" for n in page_obj_nums)
    objects.append(f"<< /Type /Pages /Kids [ {kids_str} ] /Count {len(page_obj_nums)} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

    for page_num, content_num, stream_bytes in page_entries:
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_obj_num} 0 R >> >> /Contents {content_num} 0 R >>".encode("ascii")
        )
        objects.append(
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii") + stream_bytes + b"\nendstream"
        )

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = [0]
    for idx, obj_body in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode("ascii"))
        out.extend(obj_body)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    output_path.write_bytes(bytes(out))
