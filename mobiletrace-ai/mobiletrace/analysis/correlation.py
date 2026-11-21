"""Cross-device timeline correlation with strict forensic evidentiary caveats."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from mobiletrace.db.repository import ForensicRepository


FORENSIC_CORRELATION_CAVEAT = (
    "Evidentiary Rule: Matching or proximate timestamps across devices do NOT by themselves prove "
    "a relationship, causal link, or shared actor. Absence of an artifact on a device does NOT prove "
    "an event did not occur."
)


def compare_devices_timeline(
    repo: ForensicRepository,
    case_id: str,
    window_seconds: int = 300,
) -> dict[str, Any]:
    """Compare verified UTC timeline events across distinct devices in the same case."""
    events = repo.list_timeline_events(case_id, limit=2000)
    parsed: list[tuple[datetime, dict[str, Any]]] = []
    unnormalized_count = 0

    for evt in events:
        norm = evt.get("normalized_utc", "")
        if not norm:
            unnormalized_count += 1
            continue
        try:
            dt = datetime.fromisoformat(norm.replace("Z", "+00:00"))
            parsed.append((dt, evt))
        except ValueError:
            unnormalized_count += 1

    parsed.sort(key=lambda item: item[0])
    matches: list[dict[str, Any]] = []
    for i in range(len(parsed)):
        dt_a, evt_a = parsed[i]
        for j in range(i + 1, len(parsed)):
            dt_b, evt_b = parsed[j]
            delta = (dt_b - dt_a).total_seconds()
            if delta > window_seconds:
                break
            if evt_a["device_id"] == evt_b["device_id"]:
                continue
            matches.append(
                {
                    "delta_seconds": round(delta, 3),
                    "device_a_id": evt_a["device_id"],
                    "device_a_label": f"{evt_a.get('device_platform', '')} {evt_a.get('device_model', '')}".strip(),
                    "artifact_a_id": evt_a["artifact_id"],
                    "event_a_description": evt_a["description"],
                    "event_a_utc": evt_a["normalized_utc"],
                    "device_b_id": evt_b["device_id"],
                    "device_b_label": f"{evt_b.get('device_platform', '')} {evt_b.get('device_model', '')}".strip(),
                    "artifact_b_id": evt_b["artifact_id"],
                    "event_b_description": evt_b["description"],
                    "event_b_utc": evt_b["normalized_utc"],
                    "forensic_note": "Temporal proximity only; requires independent corroboration.",
                }
            )
            if len(matches) >= 200:
                break
        if len(matches) >= 200:
            break

    return {
        "case_id": case_id,
        "window_seconds": window_seconds,
        "normalized_events_evaluated": len(parsed),
        "unnormalized_events_excluded": unnormalized_count,
        "proximate_pairs": matches,
        "caveat": FORENSIC_CORRELATION_CAVEAT,
    }
