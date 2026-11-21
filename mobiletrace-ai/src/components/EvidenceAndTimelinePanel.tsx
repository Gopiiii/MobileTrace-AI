import React, { useMemo, useState } from "react";
import { CaseDetailResponse, ForensicArtifact } from "../types/forensics";
import { formatBytes } from "../utils/forensicValidation";

interface Props {
  mode: "evidence" | "timeline";
  activeCaseId: string | null;
  caseDetail: CaseDetailResponse | null;
  onRefreshCase: () => Promise<void>;
}

export function EvidenceAndTimelinePanel({ mode, activeCaseId, caseDetail, onRefreshCase }: Props) {
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [selectedArtifact, setSelectedArtifact] = useState<ForensicArtifact | null>(null);

  const [findingTitle, setFindingTitle] = useState("");
  const [findingCategory, setFindingCategory] = useState("device_activity");
  const [findingSeverity, setFindingSeverity] = useState("informational");
  const [findingDesc, setFindingDesc] = useState("");
  const [noteBody, setNoteBody] = useState("");

  const [windowSeconds, setWindowSeconds] = useState(300);
  const [compareResult, setCompareResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const artifacts = caseDetail?.artifacts || [];
  const filteredArtifacts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return artifacts.filter((a) => {
      if (typeFilter && a.artifact_type !== typeFilter) return false;
      if (!q) return true;
      return (
        a.title.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.original_source_path.toLowerCase().includes(q) ||
        a.sha256.toLowerCase().includes(q) ||
        a.artifact_id.toLowerCase().includes(q)
      );
    });
  }, [artifacts, searchQuery, typeFilter]);

  const artifactTypes = useMemo(
    () => Array.from(new Set(artifacts.map((a) => a.artifact_type))).sort(),
    [artifacts]
  );

  async function handleAddFinding(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) return;
    setError(null);
    if (!findingTitle.trim() || !findingDesc.trim()) {
      setError("Finding title and description are required.");
      return;
    }
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/findings`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: findingTitle,
          category: findingCategory,
          severity: findingSeverity,
          description: findingDesc,
          artifactIds: selectedArtifact ? [selectedArtifact.artifact_id] : [],
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Failed to save finding.");
      setFindingTitle("");
      setFindingDesc("");
      await onRefreshCase();
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function handleAddNote(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId || !noteBody.trim()) return;
    setError(null);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/notes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          body: noteBody,
          artifactId: selectedArtifact?.artifact_id || "",
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Failed to add note.");
      setNoteBody("");
      await onRefreshCase();
    } catch (err: any) {
      setError(err.message);
    }
  }

  async function handleCompareDevices() {
    if (!activeCaseId) return;
    setError(null);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/compare?window=${windowSeconds}`);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Comparison failed.");
      setCompareResult(data);
    } catch (err: any) {
      setError(err.message);
    }
  }

  if (mode === "evidence") {
    return (
      <div className="space-y-8">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
              Evidence Explorer &amp; Findings
            </h2>
            <p className="mt-1 text-sm text-neutral-600">
              Search indexed artifacts, inspect original source paths and SHA-256 digests, and link formal findings to verified IDs.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              aria-label="Search artifacts"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search title, path, SHA-256..."
              className="border border-neutral-300 px-3 py-2 text-xs w-60"
            />
            <select
              aria-label="Filter artifact type"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="border border-neutral-300 px-3 py-2 text-xs bg-white"
            >
              <option value="">All Artifact Types</option>
              {artifactTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <section className="lg:col-span-7 border border-neutral-200 bg-white overflow-x-auto">
            {filteredArtifacts.length === 0 ? (
              <div className="p-8 text-sm text-neutral-600">
                No artifacts match the current filter. Acquire device files or import a backup in Acquisition Wizard.
              </div>
            ) : (
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                    <th className="py-2.5 px-3">ID</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Title</th>
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3 text-right">Size</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredArtifacts.map((a) => {
                    const active = selectedArtifact?.artifact_id === a.artifact_id;
                    return (
                      <tr
                        key={a.artifact_id}
                        onClick={() => setSelectedArtifact(a)}
                        className={`border-b border-neutral-100 cursor-pointer ${
                          active ? "bg-neutral-100" : "hover:bg-neutral-50"
                        }`}
                      >
                        <td className="py-2 px-3 font-mono">{a.artifact_id}</td>
                        <td className="py-2 px-3">{a.artifact_type}</td>
                        <td className="py-2 px-3 font-medium text-neutral-950">{a.title}</td>
                        <td className="py-2 px-3 font-mono whitespace-nowrap">
                          {a.normalized_timestamp_utc
                            ? `${a.normalized_timestamp_utc.slice(0, 19).replace("T", " ")}Z`
                            : a.original_timestamp || "—"}
                        </td>
                        <td className="py-2 px-3 text-right font-mono tabular-nums">{formatBytes(a.byte_size)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </section>

          <section className="lg:col-span-5 border border-neutral-200 bg-white p-5 space-y-4">
            <h3 className="text-base font-semibold text-neutral-950">Artifact Provenance Inspector</h3>
            {!selectedArtifact ? (
              <p className="text-xs text-neutral-600">
                Select any artifact row on the left to inspect its SHA-256 digest, parser version, timestamp provenance, and attach findings.
              </p>
            ) : (
              <div className="space-y-3 text-xs">
                <div className="font-mono text-neutral-950 break-all">
                  <strong>ID:</strong> {selectedArtifact.artifact_id}
                </div>
                <div className="break-all">
                  <strong>Source Path:</strong> {selectedArtifact.original_source_path}
                </div>
                <div className="font-mono break-all">
                  <strong>SHA-256:</strong> {selectedArtifact.sha256 || "None (metadata row)"}
                </div>
                <div>
                  <strong>Original Timestamp:</strong> {selectedArtifact.original_timestamp || "—"} ({selectedArtifact.original_timezone})
                </div>
                <div>
                  <strong>Normalized UTC:</strong> {selectedArtifact.normalized_timestamp_utc || "Unconverted"}
                </div>
                {selectedArtifact.normalization_justification && (
                  <div className="text-neutral-600">{selectedArtifact.normalization_justification}</div>
                )}
                <div>
                  <strong>Parser:</strong> {selectedArtifact.parser_name} v{selectedArtifact.parser_version} · {selectedArtifact.acquisition_method}
                </div>
                <pre className="border border-neutral-200 bg-neutral-50 p-3 max-h-40 overflow-auto text-[11px]">
                  {JSON.stringify(JSON.parse(selectedArtifact.content_json || "{}"), null, 2)}
                </pre>
              </div>
            )}

            <hr className="border-neutral-200" />
            <form onSubmit={handleAddFinding} className="space-y-2.5">
              <h4 className="text-sm font-semibold text-neutral-950">
                Record Evidence-Linked Finding
              </h4>
              <input
                value={findingTitle}
                onChange={(e) => setFindingTitle(e.target.value)}
                placeholder="Finding title"
                className="w-full border border-neutral-300 px-3 py-1.5 text-xs"
              />
              <div className="grid grid-cols-2 gap-2">
                <input
                  value={findingCategory}
                  onChange={(e) => setFindingCategory(e.target.value)}
                  placeholder="Category"
                  className="border border-neutral-300 px-3 py-1.5 text-xs"
                />
                <select
                  value={findingSeverity}
                  onChange={(e) => setFindingSeverity(e.target.value)}
                  className="border border-neutral-300 px-3 py-1.5 text-xs bg-white"
                >
                  <option value="informational">Informational</option>
                  <option value="notable">Notable</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <textarea
                rows={2}
                value={findingDesc}
                onChange={(e) => setFindingDesc(e.target.value)}
                placeholder="Examiner finding statement"
                className="w-full border border-neutral-300 px-3 py-1.5 text-xs"
              />
              <button
                type="submit"
                disabled={!activeCaseId}
                className="bg-neutral-950 text-white px-3 py-1.5 text-xs font-medium hover:bg-neutral-800 cursor-pointer"
              >
                Save Finding {selectedArtifact ? `(Links ${selectedArtifact.artifact_id})` : ""}
              </button>
            </form>

            <form onSubmit={handleAddNote} className="space-y-2 pt-2 border-t border-neutral-200">
              <input
                value={noteBody}
                onChange={(e) => setNoteBody(e.target.value)}
                placeholder="Add analyst note..."
                className="w-full border border-neutral-300 px-3 py-1.5 text-xs"
              />
              <button
                type="submit"
                disabled={!activeCaseId}
                className="border border-neutral-300 px-3 py-1.5 text-xs font-medium hover:bg-neutral-100 cursor-pointer"
              >
                Save Analyst Note
              </button>
            </form>
          </section>
        </div>
      </div>
    );
  }

  const events = caseDetail?.timeline || [];
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Timeline &amp; Cross-Device Comparison
          </h2>
          <p className="mt-1 text-sm text-neutral-600">
            Chronological artifact events preserving original timezones alongside justified UTC conversions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="corr-window" className="text-xs text-neutral-700">
            Window (sec):
          </label>
          <input
            id="corr-window"
            type="number"
            min={10}
            max={86400}
            value={windowSeconds}
            onChange={(e) => setWindowSeconds(Number(e.target.value) || 300)}
            className="w-24 border border-neutral-300 px-2.5 py-1.5 text-xs font-mono tabular-nums"
          />
          <button
            type="button"
            disabled={!activeCaseId}
            onClick={handleCompareDevices}
            className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 cursor-pointer"
          >
            Compare Devices
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}

      {compareResult && (
        <section className="border border-neutral-900 bg-neutral-50 p-5 space-y-3">
          <div className="text-xs font-semibold text-neutral-950">Cross-Device Proximity Analysis</div>
          <p className="text-xs text-neutral-700">{compareResult.caveat}</p>
          <div className="text-xs font-mono text-neutral-600">
            Evaluated: {compareResult.normalized_events_evaluated} · Unnormalized Excluded:{" "}
            {compareResult.unnormalized_events_excluded} · Proximate Pairs: {compareResult.proximate_pairs.length}
          </div>
          {compareResult.proximate_pairs.length > 0 && (
            <div className="overflow-x-auto bg-white border border-neutral-200">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-neutral-200 bg-neutral-50">
                    <th className="py-2 px-3">Delta (s)</th>
                    <th className="py-2 px-3">Device A Event</th>
                    <th className="py-2 px-3">Device B Event</th>
                  </tr>
                </thead>
                <tbody>
                  {compareResult.proximate_pairs.map((p: any, idx: number) => (
                    <tr key={idx} className="border-b border-neutral-100">
                      <td className="py-2 px-3 font-mono tabular-nums">{p.delta_seconds}s</td>
                      <td className="py-2 px-3">
                        <div className="font-medium">{p.device_a_label}</div>
                        <div className="text-neutral-600">{p.event_a_description}</div>
                        <div className="font-mono text-[11px] text-neutral-500">{p.event_a_utc}</div>
                      </td>
                      <td className="py-2 px-3">
                        <div className="font-medium">{p.device_b_label}</div>
                        <div className="text-neutral-600">{p.event_b_description}</div>
                        <div className="font-mono text-[11px] text-neutral-500">{p.event_b_utc}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <section className="border border-neutral-200 bg-white overflow-x-auto">
        {events.length === 0 ? (
          <div className="p-8 text-sm text-neutral-600">No timeline events recorded for this case yet.</div>
        ) : (
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                <th className="py-2.5 px-4">UTC Normalized</th>
                <th className="py-2.5 px-4">Original Timestamp</th>
                <th className="py-2.5 px-4">Device</th>
                <th className="py-2.5 px-4">Type</th>
                <th className="py-2.5 px-4">Description</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev.event_id} className="border-b border-neutral-100">
                  <td className="py-2 px-4 font-mono whitespace-nowrap">{ev.normalized_utc || "unconverted"}</td>
                  <td className="py-2 px-4 font-mono text-neutral-600">
                    {ev.original_timestamp} ({ev.original_timezone})
                  </td>
                  <td className="py-2 px-4">{`${ev.device_platform || ""} ${ev.device_model || ""}`.trim()}</td>
                  <td className="py-2 px-4">{ev.event_type}</td>
                  <td className="py-2 px-4 text-neutral-900">{ev.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
