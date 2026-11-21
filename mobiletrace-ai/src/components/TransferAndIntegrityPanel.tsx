import React, { useState } from "react";
import { CaseDetailResponse } from "../types/forensics";
import { formatBytes, isSafeSubdirectoryName } from "../utils/forensicValidation";

interface Props {
  mode: "transfer" | "integrity";
  activeCaseId: string | null;
  caseDetail: CaseDetailResponse | null;
  onRefreshCase: () => Promise<void>;
}

export function TransferAndIntegrityPanel({ mode, activeCaseId, caseDetail, onRefreshCase }: Props) {
  const [destSubdir, setDestSubdir] = useState("verified_export_01");
  const [conflictPolicy, setConflictPolicy] = useState<"rename" | "skip" | "overwrite">("rename");
  const [selectedArtifactIds, setSelectedArtifactIds] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [transferResult, setTransferResult] = useState<any>(null);
  const [integrityResult, setIntegrityResult] = useState<any>(null);

  const fileBackedArtifacts = (caseDetail?.artifacts || []).filter((a) => Boolean(a.stored_copy_path));

  function toggleArtifact(id: string) {
    setSelectedArtifactIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  async function handleStartTransfer(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) return;
    setError(null);
    if (!isSafeSubdirectoryName(destSubdir)) {
      setError("Destination folder name must contain only letters, numbers, '.', '-', or '_' (no path traversal).");
      return;
    }
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          artifactIds: selectedArtifactIds,
          destinationSubdir: destSubdir.trim(),
          conflictPolicy,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Transfer failed.");
      setTransferResult(data);
      await onRefreshCase();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyIntegrity() {
    if (!activeCaseId) return;
    setError(null);
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/verify-integrity`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actor: "examiner" }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Verification failed.");
      setIntegrityResult(data);
      await onRefreshCase();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (mode === "transfer") {
    return (
      <div className="space-y-8">
        <div className="border-b border-neutral-200 pb-5">
          <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Transfer Manager
          </h2>
          <p className="mt-1 text-sm text-neutral-600">
            Copy acquired evidence files with destination space checks, conflict handling, source preservation, and post-copy SHA-256 manifest verification.
          </p>
        </div>

        {error && (
          <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <form onSubmit={handleStartTransfer} className="lg:col-span-5 border border-neutral-200 bg-white p-6 space-y-4">
            <h3 className="text-base font-semibold text-neutral-950">Configure Verified Copy</h3>
            <div>
              <label htmlFor="xfer-dest" className="block text-xs font-medium text-neutral-700 mb-1">
                Destination Subfolder (under case transfers/)
              </label>
              <input
                id="xfer-dest"
                value={destSubdir}
                onChange={(e) => setDestSubdir(e.target.value)}
                className="w-full border border-neutral-300 px-3 py-2 text-sm font-mono"
              />
            </div>
            <div>
              <label htmlFor="xfer-policy" className="block text-xs font-medium text-neutral-700 mb-1">
                Conflict Policy
              </label>
              <select
                id="xfer-policy"
                value={conflictPolicy}
                onChange={(e) => setConflictPolicy(e.target.value as any)}
                className="w-full border border-neutral-300 px-3 py-2 text-sm bg-white"
              >
                <option value="rename">Rename with _copyN suffix</option>
                <option value="skip">Skip existing files</option>
                <option value="overwrite">Overwrite destination copy</option>
              </select>
            </div>
            <p className="text-xs text-neutral-600">
              {selectedArtifactIds.length > 0
                ? `${selectedArtifactIds.length} specific file(s) selected`
                : `All ${fileBackedArtifacts.length} file-backed case artifacts will be transferred.`}
            </p>
            <button
              type="submit"
              disabled={busy || !activeCaseId || fileBackedArtifacts.length === 0}
              className="w-full bg-neutral-950 text-white px-4 py-2.5 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
            >
              {busy ? "Copying & Verifying SHA-256..." : "Execute Verified Transfer"}
            </button>
          </form>

          <section className="lg:col-span-7 border border-neutral-200 bg-white">
            <div className="px-6 py-4 border-b border-neutral-200 flex items-center justify-between">
              <h3 className="text-base font-semibold text-neutral-950">Source Evidence Files</h3>
              <span className="text-xs text-neutral-500 font-mono tabular-nums">
                {fileBackedArtifacts.length} available
              </span>
            </div>
            {fileBackedArtifacts.length === 0 ? (
              <div className="p-6 text-sm text-neutral-600">
                No file-backed artifacts acquired in this case yet.
              </div>
            ) : (
              <div className="max-h-80 overflow-y-auto divide-y divide-neutral-100">
                {fileBackedArtifacts.map((a) => (
                  <label key={a.artifact_id} className="flex items-center gap-3 px-4 py-2.5 text-xs hover:bg-neutral-50 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedArtifactIds.includes(a.artifact_id)}
                      onChange={() => toggleArtifact(a.artifact_id)}
                    />
                    <span className="font-medium text-neutral-950 flex-1 truncate">{a.title}</span>
                    <span className="font-mono text-neutral-500">{formatBytes(a.byte_size)}</span>
                    <span className="font-mono text-neutral-500">{a.sha256.slice(0, 12)}</span>
                  </label>
                ))}
              </div>
            )}
          </section>
        </div>

        {transferResult && (
          <section className="border border-neutral-200 bg-white p-6 space-y-3">
            <h3 className="text-base font-semibold text-neutral-950">Latest Transfer Manifest Result</h3>
            <div className="flex flex-wrap gap-6 text-xs font-mono tabular-nums text-neutral-700">
              <span>Status: {transferResult.manifest.status}</span>
              <span>Succeeded: {transferResult.manifest.succeeded_files}</span>
              <span>Failed: {transferResult.manifest.failed_files}</span>
              <span>Skipped: {transferResult.manifest.skipped_files}</span>
              <span>Bytes: {formatBytes(transferResult.manifest.total_bytes)}</span>
            </div>
            <p className="text-xs font-mono text-neutral-600 break-all">
              Manifest SHA-256: {transferResult.manifest.manifest_sha256}
            </p>
          </section>
        )}

        {caseDetail && caseDetail.transfers.length > 0 && (
          <section className="border border-neutral-200 bg-white">
            <div className="px-6 py-4 border-b border-neutral-200">
              <h3 className="text-base font-semibold text-neutral-950">Transfer Manifest History</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                    <th className="py-2.5 px-4">Manifest ID</th>
                    <th className="py-2.5 px-4">Status</th>
                    <th className="py-2.5 px-4">Policy</th>
                    <th className="py-2.5 px-4 text-right">Files (OK/Fail/Skip)</th>
                    <th className="py-2.5 px-4 text-right">Bytes</th>
                    <th className="py-2.5 px-4">Manifest SHA-256</th>
                  </tr>
                </thead>
                <tbody>
                  {caseDetail.transfers.map((t) => (
                    <tr key={t.manifest_id} className="border-b border-neutral-100">
                      <td className="py-2.5 px-4 font-mono">{t.manifest_id}</td>
                      <td className="py-2.5 px-4 font-medium">{t.status}</td>
                      <td className="py-2.5 px-4">{t.conflict_policy}</td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums">
                        {t.succeeded_files} / {t.failed_files} / {t.skipped_files}
                      </td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums">{formatBytes(t.total_bytes)}</td>
                      <td className="py-2.5 px-4 font-mono">{t.manifest_sha256.slice(0, 20)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Hash Verification &amp; Chain Integrity
          </h2>
          <p className="mt-1 text-sm text-neutral-600">
            Re-compute SHA-256 digests for every stored evidence file on disk and verify the append-only audit log hash chain.
          </p>
        </div>
        <button
          type="button"
          disabled={busy || !activeCaseId}
          onClick={handleVerifyIntegrity}
          className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
        >
          {busy ? "Re-Hashing Files..." : "Run SHA-256 Integrity Verification"}
        </button>
      </div>

      {error && (
        <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}

      {!integrityResult ? (
        <div className="border border-neutral-200 bg-white p-8 text-sm text-neutral-600">
          Click Run SHA-256 Integrity Verification to re-hash every stored copy in this case and validate audit chain continuity.
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="border border-neutral-200 bg-white p-4">
              <div className="text-xs text-neutral-500">Overall Integrity</div>
              <div className="mt-1 text-lg font-semibold text-neutral-950">
                {integrityResult.overall_intact ? "INTACT" : "ALERT"}
              </div>
            </div>
            <div className="border border-neutral-200 bg-white p-4">
              <div className="text-xs text-neutral-500">Verified Files</div>
              <div className="mt-1 text-lg font-semibold font-mono tabular-nums">
                {integrityResult.summary.verified_files}
              </div>
            </div>
            <div className="border border-neutral-200 bg-white p-4">
              <div className="text-xs text-neutral-500">Mismatches / Missing</div>
              <div className="mt-1 text-lg font-semibold font-mono tabular-nums">
                {integrityResult.summary.hash_mismatches} / {integrityResult.summary.missing_files}
              </div>
            </div>
            <div className="border border-neutral-200 bg-white p-4">
              <div className="text-xs text-neutral-500">Audit Chain</div>
              <div className="mt-1 text-lg font-semibold">
                {integrityResult.audit_chain.valid
                  ? `Valid (${integrityResult.audit_chain.total_events})`
                  : "Broken"}
              </div>
            </div>
          </div>

          <section className="border border-neutral-200 bg-white overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                  <th className="py-2.5 px-4">Artifact ID</th>
                  <th className="py-2.5 px-4">Title</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4">Recorded SHA-256</th>
                  <th className="py-2.5 px-4">Disk SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {integrityResult.artifacts.map((row: any) => (
                  <tr key={row.artifact_id} className="border-b border-neutral-100">
                    <td className="py-2.5 px-4 font-mono">{row.artifact_id}</td>
                    <td className="py-2.5 px-4">{row.title}</td>
                    <td className="py-2.5 px-4 font-medium">{row.status}</td>
                    <td className="py-2.5 px-4 font-mono">{row.expected_sha256 ? row.expected_sha256.slice(0, 18) : "—"}</td>
                    <td className="py-2.5 px-4 font-mono">{row.actual_sha256 ? row.actual_sha256.slice(0, 18) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      )}
    </div>
  );
}
