"""Gemini AI forensic investigator with analyst approval gate, PII minimization, and DB citation validation."""

from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlparse

from mobiletrace.ai.redact_pii import redact_payload
from mobiletrace.db.repository import ForensicRepository


MAX_ARTIFACTS_PER_CLOUD_CALL = 40

FORENSIC_SYSTEM_INSTRUCTION = """You are assisting a certified mobile digital forensics examiner.
Rules you MUST obey:
1. Only cite artifact_id values that appear verbatim in the supplied artifacts array. Never invent or guess artifact_ids.
2. Strictly separate VERIFIED OBSERVATIONS (direct facts present in the supplied artifact records) from AI INTERPRETATIONS, COMPETING HYPOTHESES, and UNCERTAINTY.
3. Never treat missing data as proof an event did not occur.
4. Never treat matching or proximate timestamps alone as proof of a causal relationship.
5. Respond ONLY with valid JSON matching the requested schema."""


def build_minimized_evidence_bundle(
    repo: ForensicRepository,
    case_id: str,
    artifact_ids: list[str],
    *,
    redact_pii: bool = True,
) -> dict[str, Any]:
    """Build a minimized, optionally PII-redacted evidence payload for selected artifacts only."""
    case = repo.get_case(case_id)
    if not case:
        raise KeyError(f"Case not found: {case_id}")
    if not artifact_ids:
        raise ValueError("Select at least one artifact for targeted analysis; full-backup uploads are prohibited.")
    if len(artifact_ids) > MAX_ARTIFACTS_PER_CLOUD_CALL:
        raise ValueError(
            f"Targeted analysis is capped at {MAX_ARTIFACTS_PER_CLOUD_CALL} selected artifacts per request to minimize data exposure."
        )

    devices = {d["device_id"]: d for d in repo.list_devices(case_id)}
    selected_records: list[dict[str, Any]] = []
    missing_ids: list[str] = []

    for aid in artifact_ids:
        art = repo.get_artifact(aid)
        if not art or art["case_id"] != case_id:
            missing_ids.append(aid)
            continue
        dev = devices.get(art["device_id"], {})
        selected_records.append(
            {
                "artifact_id": art["artifact_id"],
                "device_id": art["device_id"],
                "device_label": f"{dev.get('platform', '')} {dev.get('model', '')}".strip(),
                "artifact_type": art["artifact_type"],
                "title": art["title"],
                "summary": art["summary"][:400],
                "original_source_path": art["original_source_path"],
                "original_timestamp": art["original_timestamp"],
                "original_timezone": art["original_timezone"],
                "normalized_timestamp_utc": art["normalized_timestamp_utc"],
                "acquisition_method": art["acquisition_method"],
                "sha256": art["sha256"],
                "extraction_errors": art["extraction_errors"],
                "parsing_errors": art["parsing_errors"],
            }
        )

    if missing_ids:
        raise ValueError(f"Requested artifact IDs not found in case {case_id}: {missing_ids}")

    redaction_counts = {"emails": 0, "phones": 0, "ips": 0, "ssns": 0, "imeis": 0, "tokens": 0}
    payload_records = selected_records
    if redact_pii:
        payload_records, redaction_counts = redact_payload(selected_records, redaction_counts)

    return {
        "case_summary": {
            "case_id": case["case_id"],
            "case_number": case["case_number"],
            "title": case["title"],
        },
        "pii_redacted": redact_pii,
        "redaction_counts": redaction_counts,
        "artifact_count": len(payload_records),
        "artifacts": payload_records,
    }


def validate_ai_citations(
    repo: ForensicRepository,
    case_id: str,
    ai_response: dict[str, Any],
) -> dict[str, Any]:
    """Validate every artifact_id cited by Gemini against actual SQLite records for the case."""
    valid_map = {a["artifact_id"] for a in repo.search_artifacts(case_id, limit=5000)}
    verified_cited: set[str] = set()
    rejected_cited: set[str] = set()

    def _filter_id_list(ids: Any) -> tuple[list[str], list[str]]:
        if not isinstance(ids, list):
            return [], []
        ok: list[str] = []
        bad: list[str] = []
        for raw_id in ids:
            sid = str(raw_id).strip()
            if sid in valid_map:
                ok.append(sid)
                verified_cited.add(sid)
            elif sid:
                bad.append(sid)
                rejected_cited.add(sid)
        return ok, bad

    cleaned = dict(ai_response)
    for section in ("verified_observations", "contradictions", "cross_device_correlations"):
        items = cleaned.get(section)
        if isinstance(items, list):
            updated_items = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                ok_ids, bad_ids = _filter_id_list(item.get("artifact_ids", []))
                new_item = dict(item)
                new_item["artifact_ids"] = ok_ids
                if bad_ids:
                    new_item["rejected_unverified_ids"] = bad_ids
                    new_item["citation_warning"] = (
                        f"Removed {len(bad_ids)} AI-cited artifact ID(s) not present in case database."
                    )
                updated_items.append(new_item)
            cleaned[section] = updated_items

    return {
        "validated_payload": cleaned,
        "verified_artifact_ids": sorted(verified_cited),
        "rejected_artifact_ids": sorted(rejected_cited),
    }


def extract_grounding_metadata(candidate: Any) -> dict[str, Any]:
    """Extract sanitized web URLs and search queries from Gemini grounding_metadata."""
    if candidate is None:
        return {"sources": [], "queries": []}
    gm = candidate.get("grounding_metadata") if isinstance(candidate, dict) else getattr(candidate, "grounding_metadata", None)
    if gm is None and isinstance(candidate, dict):
        gm = candidate.get("groundingMetadata")
    if gm is None:
        return {"sources": [], "queries": []}

    raw_chunks = (
        gm.get("grounding_chunks", gm.get("groundingChunks", []))
        if isinstance(gm, dict)
        else getattr(gm, "grounding_chunks", None) or []
    )
    raw_queries = (
        gm.get("web_search_queries", gm.get("webSearchQueries", []))
        if isinstance(gm, dict)
        else getattr(gm, "web_search_queries", None) or []
    )

    sources: list[dict[str, str]] = []
    seen: set[str] = set()
    for ch in raw_chunks:
        web = ch.get("web") if isinstance(ch, dict) else getattr(ch, "web", None)
        if web is None:
            continue
        uri = (web.get("uri") if isinstance(web, dict) else getattr(web, "uri", "")) or ""
        title = (web.get("title") if isinstance(web, dict) else getattr(web, "title", "")) or ""
        uri = str(uri).strip()
        title = str(title).strip()
        parsed_url = urlparse(uri)
        if parsed_url.scheme not in {"http", "https"} or uri in seen:
            continue
        seen.add(uri)
        sources.append({"title": title or uri, "uri": uri})

    queries = [str(q).strip() for q in raw_queries if isinstance(q, str) and q.strip()]
    return {"sources": sources, "queries": queries}


def _parse_ai_json_output(raw_text: str) -> dict[str, Any]:
    trimmed = (raw_text or "").strip()
    if not trimmed:
        return {}
    try:
        obj = json.loads(trimmed)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", trimmed, flags=re.IGNORECASE)
    if fence:
        try:
            obj = json.loads(fence.group(1).strip())
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
    start = trimmed.find("{")
    end = trimmed.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(trimmed[start : end + 1])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
    return {
        "verified_observations": [],
        "contradictions": [],
        "competing_hypotheses": [],
        "missing_evidence_gaps": [],
        "cross_device_correlations": [],
        "suggested_next_steps": [],
        "report_draft_summary": trimmed,
        "uncertainty_and_limitations": "Model returned grounded narrative prose instead of JSON; verify claims and external URLs manually.",
    }


def run_gemini_investigation(
    *,
    repo: ForensicRepository,
    case_id: str,
    artifact_ids: list[str],
    question: str,
    analyst_approved: bool,
    redact_pii: bool = True,
    use_search_grounding: bool = False,
    model_name: str = "gemini-4-hydrogen",
    actor: str = "examiner",
) -> dict[str, Any]:
    """Execute targeted Gemini forensic analysis only after explicit analyst approval."""
    if not analyst_approved:
        raise PermissionError(
            "Explicit analyst approval is required before sending minimized evidence summaries to Gemini cloud."
        )
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key or api_key == "MY_GEMINI_API_KEY":
        raise RuntimeError(
            "GEMINI_API_KEY is not configured. Offline acquisition, hashing, parsing, timelines, and reports remain available."
        )

    bundle = build_minimized_evidence_bundle(repo, case_id, artifact_ids, redact_pii=redact_pii)

    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise RuntimeError("google-genai Python SDK is not installed. Run `pip install google-genai`.") from exc

    prompt = (
        f"Examiner Question: {question.strip()}\n\n"
        "Return ONLY a valid JSON object with keys:\n"
        "- verified_observations: list of {statement, artifact_ids}\n"
        "- contradictions: list of {description, artifact_ids}\n"
        "- competing_hypotheses: list of {hypothesis, supporting_points, refuting_points}\n"
        "- missing_evidence_gaps: list of strings\n"
        "- cross_device_correlations: list of {observation, artifact_ids, caveat}\n"
        "- suggested_next_steps: list of strings\n"
        "- relevant_cves_and_best_practices: list of {reference, relevance_to_case, verification_needed}\n"
        "- report_draft_summary: string\n"
        "- uncertainty_and_limitations: string\n\n"
        f"Minimized Evidence Bundle:\n{json.dumps(bundle, indent=2)}"
    )

    client = genai.Client(api_key=api_key)
    config_kwargs: dict[str, Any] = {
        "system_instruction": FORENSIC_SYSTEM_INSTRUCTION,
    }
    if use_search_grounding:
        config_kwargs["tools"] = [types.Tool(google_search=types.GoogleSearch())]
    else:
        config_kwargs["response_mime_type"] = "application/json"

    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(**config_kwargs),
    )

    raw_text = (response.text or "{}").strip()
    parsed = _parse_ai_json_output(raw_text)
    candidates = getattr(response, "candidates", None) or []
    grounding = extract_grounding_metadata(candidates[0] if candidates else None)
    parsed["search_grounding_used"] = bool(use_search_grounding)
    parsed["web_search_queries"] = grounding["queries"]
    parsed["grounding_sources"] = grounding["sources"]

    validation = validate_ai_citations(repo, case_id, parsed)

    saved = repo.save_ai_analysis(
        case_id=case_id,
        model_name=model_name,
        analyst_approved=analyst_approved,
        pii_redacted=redact_pii,
        prompt_question=question.strip(),
        selected_artifact_ids=artifact_ids,
        verified_artifact_ids=validation["verified_artifact_ids"],
        rejected_artifact_ids=validation["rejected_artifact_ids"],
        response_payload=validation["validated_payload"],
        actor=actor,
    )
    return {
        "analysis": saved,
        "bundle_redaction_counts": bundle["redaction_counts"],
        "verified_artifact_ids": validation["verified_artifact_ids"],
        "rejected_artifact_ids": validation["rejected_artifact_ids"],
        "grounding_sources": grounding["sources"],
        "web_search_queries": grounding["queries"],
        "result": validation["validated_payload"],
    }
