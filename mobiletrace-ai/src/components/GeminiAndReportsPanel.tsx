import React, { useEffect, useMemo, useState } from "react";
import { CaseDetailResponse, DiagnosticsResponse } from "../types/forensics";
import { isSafeHttpUrl, previewPiiRedaction } from "../utils/forensicValidation";

interface Props {
  mode: "gemini" | "reports" | "settings";
  activeCaseId: string | null;
  caseDetail: CaseDetailResponse | null;
  diagnostics: DiagnosticsResponse | null;
  onRefreshCase: () => Promise<void>;
}

export function GeminiAndReportsPanel({ mode, activeCaseId, caseDetail, diagnostics, onRefreshCase }: Props) {
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [question, setQuestion] = useState("");
  const [redactPii, setRedactPii] = useState(true);
  const [useSearchGrounding, setUseSearchGrounding] = useState(true);
  const [analystApproved, setAnalystApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [aiResult, setAiResult] = useState<any>(null);
  const [backupMsg, setBackupMsg] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    setBackupMsg(null);
  }, [mode]);

  const artifacts = caseDetail?.artifacts || [];

  const redactionPreview = useMemo(() => {
    const selectedText = artifacts
      .filter((a) => selectedIds.includes(a.artifact_id))
      .map((a) => `${a.title} ${a.summary}`)
      .join(" | ");
    return previewPiiRedaction(selectedText);
  }, [artifacts, selectedIds]);

  function toggleId(id: string) {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  async function handleRunGemini(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) return;
    setError(null);
    if (!analystApproved) {
      setError("Explicit analyst approval checkbox must be checked before cloud analysis.");
      return;
    }
    if (selectedIds.length === 0 || !question.trim()) {
      setError("Select at least one artifact and enter an investigative question.");
      return;
    }
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/ai-investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          artifactIds: selectedIds,
          question,
          analystApproved,
          redactPii,
          useSearchGrounding,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Gemini investigation failed.");
      setAiResult(data);
      await onRefreshCase();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleGenerateReport(format: "html" | "pdf") {
    if (!activeCaseId) return;
    setError(null);
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Report generation failed.");
      await onRefreshCase();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDatabaseBackup() {
    setError(null);
    setBackupMsg(null);
    try {
      const resp = await fetch("/api/database/backup", { method: "POST" });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Database backup failed.");
      setBackupMsg(`Consistent SQLite backup created: ${data.backup_path}`);
    } catch (err: any) {
      setError(err.message);
    }
  }

  if (mode === "gemini") {
    return (
      <div className="space-y-8">
        <div className="border-b border-neutral-200 pb-5">
          <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Gemini Investigation Panel
          </h2>
          <p className="mt-1 text-sm text-neutral-600">
            Submit minimized, PII-redacted summaries of explicitly selected artifacts only after analyst approval. Optional Google Search grounding fetches updated mobile forensic best practices and CVE databases; every cited artifact ID is validated against SQLite.
          </p>
        </div>

        {error && (
          <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <section className="lg:col-span-5 border border-neutral-200 bg-white">
            <div className="px-5 py-3.5 border-b border-neutral-200 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-neutral-950">Select Artifacts (Max 40)</h3>
              <span className="text-xs font-mono tabular-nums text-neutral-500">
                {selectedIds.length} selected
              </span>
            </div>
            {artifacts.length === 0 ? (
              <div className="p-6 text-xs text-neutral-600">No artifacts in active case yet.</div>
            ) : (
              <div className="max-h-80 overflow-y-auto divide-y divide-neutral-100">
                {artifacts.slice(0, 100).map((a) => (
                  <label key={a.artifact_id} className="flex items-start gap-3 px-4 py-2.5 text-xs hover:bg-neutral-50 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedIds.includes(a.artifact_id)}
                      onChange={() => toggleId(a.artifact_id)}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="font-medium text-neutral-950 truncate">{a.title}</div>
                      <div className="font-mono text-[11px] text-neutral-500">
                        {a.artifact_id} · {a.artifact_type}
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            )}
          </section>

          <form onSubmit={handleRunGemini} className="lg:col-span-7 border border-neutral-200 bg-white p-6 space-y-4">
            <div>
              <label htmlFor="gemini-question" className="block text-xs font-medium text-neutral-700 mb-1">
                Investigative Question *
              </label>
              <textarea
                id="gemini-question"
                rows={3}
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Identify contradictions, competing hypotheses, relevant OS/app CVEs, updated forensic best practices, and suggested next investigative steps."
                className="w-full border border-neutral-300 px-3 py-2 text-sm"
              />
            </div>

            <div className="space-y-2.5 border border-neutral-200 bg-neutral-50 p-4 text-xs">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={redactPii}
                  onChange={(e) => setRedactPii(e.target.checked)}
                />
                <span>
                  Minimize &amp; Redact PII (emails, phone numbers, IPs, IMEIs, tokens) before cloud submission.
                  {redactPii && selectedIds.length > 0 && (
                    <span className="block font-mono text-neutral-600 mt-1">
                      Preview redactions detected in selected titles/summaries: {redactionPreview.count}
                    </span>
                  )}
                </span>
              </label>
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useSearchGrounding}
                  onChange={(e) => setUseSearchGrounding(e.target.checked)}
                />
                <span>
                  Enable Google Search Grounding (fetch updated mobile forensic best practices, artifact documentation, and CVE advisories via Google Search).
                </span>
              </label>
              <label className="flex items-start gap-2.5 cursor-pointer font-medium text-neutral-950">
                <input
                  type="checkbox"
                  checked={analystApproved}
                  onChange={(e) => setAnalystApproved(e.target.checked)}
                />
                <span>
                  Explicit Analyst Approval: I approve transmitting minimized summaries of the {selectedIds.length} selected artifact(s) to Gemini ({diagnostics?.gemini_model || "gemini-4-hydrogen"}).
                </span>
              </label>
            </div>

            <button
              type="submit"
              disabled={busy || !activeCaseId}
              className="bg-neutral-950 text-white px-4 py-2.5 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
            >
              {busy ? "Analyzing Minimized Bundle..." : "Run Targeted Gemini Analysis"}
            </button>

            {!diagnostics?.gemini_configured && (
              <p className="text-xs text-neutral-600">
                Cloud status: GEMINI_API_KEY is not configured in server environment secrets. All offline forensic modules remain fully operational.
              </p>
            )}
          </form>
        </div>

        {(aiResult || (caseDetail?.ai_analyses?.length ?? 0) > 0) && (
          <section className="border border-neutral-200 bg-white p-6 space-y-4">
            <h3 className="text-base font-semibold text-neutral-950">
              AI Analysis History (Verified Case Citations vs Search Grounding &amp; AI Interpretations)
            </h3>
            {(aiResult ? [aiResult.analysis] : caseDetail?.ai_analyses || []).map((item: any) => {
              let parsedPayload: Record<string, any> = {};
              try {
                parsedPayload = JSON.parse(item.response_json || "{}");
              } catch {
                parsedPayload = {};
              }
              const groundingSources: Array<{ title: string; uri: string }> = Array.isArray(
                parsedPayload.grounding_sources
              )
                ? parsedPayload.grounding_sources.filter((s: any) => s?.uri && isSafeHttpUrl(s.uri))
                : [];
              const searchQueries: string[] = Array.isArray(parsedPayload.web_search_queries)
                ? parsedPayload.web_search_queries
                : [];

              return (
                <div key={item.analysis_id} className="border border-neutral-200 p-4 space-y-3 text-xs">
                  <div className="font-mono text-neutral-700">
                    {item.analysis_id} · Model: {item.model_name} · Search Grounding:{" "}
                    {parsedPayload.search_grounding_used ? "Enabled" : "Disabled"} · Verified IDs:{" "}
                    {item.verified_artifact_ids_json} · Rejected IDs: {item.rejected_artifact_ids_json}
                  </div>
                  <div className="font-medium text-neutral-950">Question: {item.prompt_question}</div>

                  {(searchQueries.length > 0 || groundingSources.length > 0) && (
                    <div className="border border-neutral-300 bg-neutral-50 p-3 space-y-2">
                      <div className="font-semibold text-neutral-950">
                        External Web Grounding Sources (Google Search — Independently Verify Before Citing as Fact)
                      </div>
                      {searchQueries.length > 0 && (
                        <div className="font-mono text-[11px] text-neutral-600">
                          Queries: {searchQueries.join(" | ")}
                        </div>
                      )}
                      {groundingSources.length > 0 && (
                        <ul className="list-disc pl-5 space-y-1">
                          {groundingSources.map((src) => (
                            <li key={src.uri}>
                              <a
                                href={src.uri}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="underline text-neutral-950 hover:text-neutral-700"
                              >
                                {src.title}
                              </a>
                              <span className="ml-2 font-mono text-[11px] text-neutral-500">{src.uri}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}

                  <pre className="bg-neutral-50 border border-neutral-200 p-3 overflow-auto max-h-80 text-[11px]">
                    {JSON.stringify(parsedPayload, null, 2)}
                  </pre>
                </div>
              );
            })}
          </section>
        )}
      </div>
    );
  }

  if (mode === "reports") {
    return (
      <div className="space-y-8">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
              Audit Log &amp; Forensic Report Export
            </h2>
            <p className="mt-1 text-sm text-neutral-600">
              Generate SHA-256 verified HTML and PDF reports separating verified forensic artifacts from AI interpretations.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy || !activeCaseId}
              onClick={() => handleGenerateReport("html")}
              className="border border-neutral-300 bg-white px-4 py-2 text-xs font-medium hover:bg-neutral-100 cursor-pointer"
            >
              Generate HTML Report
            </button>
            <button
              type="button"
              disabled={busy || !activeCaseId}
              onClick={() => handleGenerateReport("pdf")}
              className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 cursor-pointer"
            >
              Generate PDF Report
            </button>
          </div>
        </div>

        {error && (
          <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
            {error}
          </div>
        )}

        <section className="border border-neutral-200 bg-white">
          <div className="px-6 py-4 border-b border-neutral-200">
            <h3 className="text-base font-semibold text-neutral-950">Generated Reports</h3>
          </div>
          {!caseDetail || caseDetail.reports.length === 0 ? (
            <div className="p-6 text-sm text-neutral-600">No HTML or PDF reports generated for this case yet.</div>
          ) : (
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                  <th className="py-2.5 px-4">Report ID</th>
                  <th className="py-2.5 px-4">Format</th>
                  <th className="py-2.5 px-4">SHA-256</th>
                  <th className="py-2.5 px-4">Created UTC</th>
                  <th className="py-2.5 px-4 text-right">Download</th>
                </tr>
              </thead>
              <tbody>
                {caseDetail.reports.map((r) => (
                  <tr key={r.report_id} className="border-b border-neutral-100">
                    <td className="py-2.5 px-4 font-mono">{r.report_id}</td>
                    <td className="py-2.5 px-4 uppercase font-medium">{r.report_format}</td>
                    <td className="py-2.5 px-4 font-mono">{r.sha256}</td>
                    <td className="py-2.5 px-4 font-mono">{r.created_at}</td>
                    <td className="py-2.5 px-4 text-right">
                      <a
                        href={`/api/cases/${caseDetail.case.case_id}/reports/${r.report_id}/download`}
                        className="underline font-medium text-neutral-950"
                      >
                        Download {r.report_format.toUpperCase()}
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section className="border border-neutral-200 bg-white">
          <div className="px-6 py-4 border-b border-neutral-200">
            <h3 className="text-base font-semibold text-neutral-950">Append-Only Hash-Chained Audit Log</h3>
          </div>
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                  <th className="py-2 px-4">Seq</th>
                  <th className="py-2 px-4">UTC Timestamp</th>
                  <th className="py-2 px-4">Actor</th>
                  <th className="py-2 px-4">Action</th>
                  <th className="py-2 px-4">Target</th>
                  <th className="py-2 px-4">Event Hash</th>
                </tr>
              </thead>
              <tbody>
                {(caseDetail?.audit_events || []).map((ev) => (
                  <tr key={ev.event_id} className="border-b border-neutral-100">
                    <td className="py-2 px-4 font-mono tabular-nums">{ev.seq}</td>
                    <td className="py-2 px-4 font-mono">{ev.created_at}</td>
                    <td className="py-2 px-4">{ev.actor}</td>
                    <td className="py-2 px-4 font-medium">{ev.action}</td>
                    <td className="py-2 px-4 font-mono">{ev.target_id}</td>
                    <td className="py-2 px-4 font-mono">{ev.event_hash.slice(0, 20)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Settings &amp; Workstation Configuration
          </h2>
          <p className="mt-1 text-sm text-neutral-600">
            Environment configuration, binary paths, and consistent SQLite online backup maintenance.
          </p>
        </div>
        <button
          type="button"
          onClick={handleDatabaseBackup}
          className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 cursor-pointer"
        >
          Create SQLite Online Backup
        </button>
      </div>

      {error && (
        <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}
      {backupMsg && (
        <div className="border border-neutral-400 bg-neutral-50 px-4 py-3 text-xs font-mono text-neutral-950">
          {backupMsg}
        </div>
      )}

      {diagnostics && (
        <div className="border border-neutral-200 bg-white p-6 space-y-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-neutral-500">Host Operating System</div>
              <div className="font-mono text-neutral-950 mt-0.5">{diagnostics.host_os}</div>
            </div>
            <div>
              <div className="text-neutral-500">Gemini Cloud API Status (Environment Secret)</div>
              <div className="font-mono text-neutral-950 mt-0.5">
                {diagnostics.gemini_configured ? `Configured (${diagnostics.gemini_model})` : "Not configured (offline mode active)"}
              </div>
            </div>
            <div>
              <div className="text-neutral-500">SQLite Database Path</div>
              <div className="font-mono text-neutral-950 mt-0.5 break-all">{diagnostics.db_path}</div>
            </div>
            <div>
              <div className="text-neutral-500">Evidence Workspace Directory</div>
              <div className="font-mono text-neutral-950 mt-0.5 break-all">{diagnostics.workspace_dir}</div>
            </div>
          </div>
          <p className="text-neutral-600 pt-2 border-t border-neutral-200">
            Desktop PySide6 Launch (Windows): <span className="font-mono">.\.venv\Scripts\python.exe -m mobiletrace</span>
          </p>
        </div>
      )}
    </div>
  );
}
