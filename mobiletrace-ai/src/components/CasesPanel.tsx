import React, { useState } from "react";
import { CaseDetailResponse, ForensicCase } from "../types/forensics";
import { formatBytes } from "../utils/forensicValidation";

interface CasesPanelProps {
  cases: ForensicCase[];
  activeCaseId: string | null;
  caseDetail: CaseDetailResponse | null;
  onSelectCase: (caseId: string) => void;
  onCreateCase: (payload: {
    caseNumber: string;
    title: string;
    examiner: string;
    agency: string;
    notes: string;
  }) => Promise<void>;
  onRecordAuth: (payload: {
    deviceId: string;
    authorityType: string;
    referenceNumber: string;
    authorizedBy: string;
    scopeDescription: string;
  }) => Promise<void>;
}

export function CasesPanel({
  cases,
  activeCaseId,
  caseDetail,
  onSelectCase,
  onCreateCase,
  onRecordAuth,
}: CasesPanelProps) {
  const [caseNumber, setCaseNumber] = useState("");
  const [title, setTitle] = useState("");
  const [examiner, setExaminer] = useState("");
  const [agency, setAgency] = useState("");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [authDeviceId, setAuthDeviceId] = useState("");
  const [authorityType, setAuthorityType] = useState("written_consent");
  const [referenceNumber, setReferenceNumber] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [scopeDescription, setScopeDescription] = useState("");

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!caseNumber.trim() || !title.trim() || !examiner.trim()) {
      setError("Case Number, Title, and Examiner are required.");
      return;
    }
    setSubmitting(true);
    try {
      await onCreateCase({ caseNumber, title, examiner, agency, notes });
      setCaseNumber("");
      setTitle("");
      setAgency("");
      setNotes("");
    } catch (err: any) {
      setError(err.message || "Failed to create case.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleAuthSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const targetDevice = authDeviceId || caseDetail?.devices[0]?.device_id || "";
    if (!targetDevice || !authorizedBy.trim() || !scopeDescription.trim()) {
      setError("Select a device and enter Authorized By and Scope Description.");
      return;
    }
    try {
      await onRecordAuth({
        deviceId: targetDevice,
        authorityType,
        referenceNumber,
        authorizedBy,
        scopeDescription,
      });
      setReferenceNumber("");
      setScopeDescription("");
    } catch (err: any) {
      setError(err.message || "Failed to record authorization.");
    }
  }

  const totalBytes =
    caseDetail?.artifacts.reduce((acc, a) => acc + (Number(a.byte_size) || 0), 0) ?? 0;

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Dashboard &amp; Case Management
          </h2>
          <p className="mt-1 text-sm text-neutral-600">
            Persistent SQLite case ledger with foreign-key integrity and append-only audit logging.
          </p>
        </div>
        {caseDetail && (
          <div className="flex items-center gap-6 text-xs text-neutral-600 font-mono tabular-nums">
            <span>Devices: {caseDetail.devices.length}</span>
            <span aria-hidden="true">·</span>
            <span>Sessions: {caseDetail.sessions.length}</span>
            <span aria-hidden="true">·</span>
            <span>Artifacts: {caseDetail.artifacts.length}</span>
            <span aria-hidden="true">·</span>
            <span>Indexed Size: {formatBytes(totalBytes)}</span>
          </div>
        )}
      </div>

      {error && (
        <div role="alert" className="border border-neutral-900 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        <section className="lg:col-span-5 border border-neutral-200 bg-white p-6">
          <h3 className="text-base font-semibold text-neutral-950">Create Forensic Case</h3>
          <form onSubmit={handleCreate} className="mt-4 space-y-4">
            <div>
              <label htmlFor="case-number" className="block text-xs font-medium text-neutral-700 mb-1">
                Case Number *
              </label>
              <input
                id="case-number"
                value={caseNumber}
                onChange={(e) => setCaseNumber(e.target.value)}
                placeholder="MT-2026-001"
                className="w-full border border-neutral-300 px-3 py-2 text-sm text-neutral-950 focus:outline-none focus:border-neutral-950"
              />
            </div>
            <div>
              <label htmlFor="case-title" className="block text-xs font-medium text-neutral-700 mb-1">
                Case Title *
              </label>
              <input
                id="case-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Authorized Custodian Device Examination"
                className="w-full border border-neutral-300 px-3 py-2 text-sm text-neutral-950 focus:outline-none focus:border-neutral-950"
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label htmlFor="case-examiner" className="block text-xs font-medium text-neutral-700 mb-1">
                  Examiner *
                </label>
                <input
                  id="case-examiner"
                  value={examiner}
                  onChange={(e) => setExaminer(e.target.value)}
                  placeholder="Examiner Name"
                  className="w-full border border-neutral-300 px-3 py-2 text-sm text-neutral-950 focus:outline-none focus:border-neutral-950"
                />
              </div>
              <div>
                <label htmlFor="case-agency" className="block text-xs font-medium text-neutral-700 mb-1">
                  Agency / Lab
                </label>
                <input
                  id="case-agency"
                  value={agency}
                  onChange={(e) => setAgency(e.target.value)}
                  placeholder="Digital Forensics Unit"
                  className="w-full border border-neutral-300 px-3 py-2 text-sm text-neutral-950 focus:outline-none focus:border-neutral-950"
                />
              </div>
            </div>
            <div>
              <label htmlFor="case-notes" className="block text-xs font-medium text-neutral-700 mb-1">
                Scope &amp; Notes
              </label>
              <textarea
                id="case-notes"
                rows={2}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Legal authority, device custody details, acquisition constraints"
                className="w-full border border-neutral-300 px-3 py-2 text-sm text-neutral-950 focus:outline-none focus:border-neutral-950"
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full bg-neutral-950 text-white px-4 py-2.5 text-sm font-medium hover:bg-neutral-800 disabled:bg-neutral-400 transition-colors cursor-pointer"
            >
              {submitting ? "Creating Case..." : "Create Case"}
            </button>
          </form>
        </section>

        <section className="lg:col-span-7 border border-neutral-200 bg-white">
          <div className="px-6 py-4 border-b border-neutral-200 flex items-center justify-between">
            <h3 className="text-base font-semibold text-neutral-950">Saved Cases</h3>
            <span className="text-xs text-neutral-500 font-mono tabular-nums">{cases.length} total</span>
          </div>
          {cases.length === 0 ? (
            <div className="p-8 text-sm text-neutral-600">
              No cases exist in SQLite yet. Create a case to register devices, record legal authorization, and acquire real artifacts.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-neutral-200 bg-neutral-50 text-xs text-neutral-600">
                    <th className="py-2.5 px-4 font-medium">Case Number</th>
                    <th className="py-2.5 px-4 font-medium">Title</th>
                    <th className="py-2.5 px-4 font-medium">Examiner</th>
                    <th className="py-2.5 px-4 font-medium text-right">Devices</th>
                    <th className="py-2.5 px-4 font-medium text-right">Artifacts</th>
                    <th className="py-2.5 px-4 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {cases.map((c) => {
                    const isActive = c.case_id === activeCaseId;
                    return (
                      <tr
                        key={c.case_id}
                        className={`border-b border-neutral-100 ${isActive ? "bg-neutral-100" : "hover:bg-neutral-50"}`}
                      >
                        <td className="py-2.5 px-4 font-mono text-xs text-neutral-950 whitespace-nowrap">
                          {c.case_number}
                        </td>
                        <td className="py-2.5 px-4 text-neutral-900 font-medium">{c.title}</td>
                        <td className="py-2.5 px-4 text-neutral-600">{c.examiner}</td>
                        <td className="py-2.5 px-4 text-right font-mono tabular-nums">{c.device_count ?? 0}</td>
                        <td className="py-2.5 px-4 text-right font-mono tabular-nums">{c.artifact_count ?? 0}</td>
                        <td className="py-2.5 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => onSelectCase(c.case_id)}
                            className={`px-3 py-1 text-xs font-medium border whitespace-nowrap cursor-pointer ${
                              isActive
                                ? "bg-neutral-950 text-white border-neutral-950"
                                : "bg-white text-neutral-900 border-neutral-300 hover:bg-neutral-100"
                            }`}
                          >
                            {isActive ? "Selected" : "Open Case"}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {caseDetail && (
        <section className="border border-neutral-200 bg-white p-6">
          <h3 className="text-base font-semibold text-neutral-950">Device Authorization Records</h3>
          <p className="mt-1 text-xs text-neutral-600">
            Document custodian consent, warrant, or corporate authorization prior to device acquisition.
          </p>
          {caseDetail.devices.length === 0 ? (
            <p className="mt-4 text-sm text-neutral-600">
              No devices registered to this case yet. Connect a device or ingest an evidence folder in Acquisition.
            </p>
          ) : (
            <div className="mt-4 grid grid-cols-1 lg:grid-cols-12 gap-6">
              <form onSubmit={handleAuthSubmit} className="lg:col-span-5 space-y-3">
                <div>
                  <label htmlFor="auth-device" className="block text-xs font-medium text-neutral-700 mb-1">
                    Target Device
                  </label>
                  <select
                    id="auth-device"
                    value={authDeviceId || caseDetail.devices[0]?.device_id || ""}
                    onChange={(e) => setAuthDeviceId(e.target.value)}
                    className="w-full border border-neutral-300 px-3 py-2 text-sm bg-white"
                  >
                    {caseDetail.devices.map((d) => (
                      <option key={d.device_id} value={d.device_id}>
                        {d.platform} · {d.model || d.serial_or_udid}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="auth-type" className="block text-xs font-medium text-neutral-700 mb-1">
                      Authority Type
                    </label>
                    <select
                      id="auth-type"
                      value={authorityType}
                      onChange={(e) => setAuthorityType(e.target.value)}
                      className="w-full border border-neutral-300 px-3 py-2 text-sm bg-white"
                    >
                      <option value="written_consent">Written Consent</option>
                      <option value="search_warrant">Search Warrant</option>
                      <option value="corporate_policy">Corporate Authority</option>
                      <option value="court_order">Court Order</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="auth-ref" className="block text-xs font-medium text-neutral-700 mb-1">
                      Reference Number
                    </label>
                    <input
                      id="auth-ref"
                      value={referenceNumber}
                      onChange={(e) => setReferenceNumber(e.target.value)}
                      placeholder="CONSENT-2026-14"
                      className="w-full border border-neutral-300 px-3 py-2 text-sm"
                    />
                  </div>
                </div>
                <div>
                  <label htmlFor="auth-by" className="block text-xs font-medium text-neutral-700 mb-1">
                    Authorized By *
                  </label>
                  <input
                    id="auth-by"
                    value={authorizedBy}
                    onChange={(e) => setAuthorizedBy(e.target.value)}
                    placeholder="Custodian / Issuing Authority"
                    className="w-full border border-neutral-300 px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label htmlFor="auth-scope" className="block text-xs font-medium text-neutral-700 mb-1">
                    Permitted Scope *
                  </label>
                  <input
                    id="auth-scope"
                    value={scopeDescription}
                    onChange={(e) => setScopeDescription(e.target.value)}
                    placeholder="DCIM media and Documents folder"
                    className="w-full border border-neutral-300 px-3 py-2 text-sm"
                  />
                </div>
                <button
                  type="submit"
                  className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 cursor-pointer"
                >
                  Record Authorization
                </button>
              </form>

              <div className="lg:col-span-7 overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                      <th className="py-2 px-3">Authority</th>
                      <th className="py-2 px-3">Reference</th>
                      <th className="py-2 px-3">Authorized By</th>
                      <th className="py-2 px-3">Scope</th>
                    </tr>
                  </thead>
                  <tbody>
                    {caseDetail.authorizations.map((a) => (
                      <tr key={a.auth_id} className="border-b border-neutral-100">
                        <td className="py-2 px-3 font-medium">{a.authority_type}</td>
                        <td className="py-2 px-3 font-mono">{a.reference_number || "—"}</td>
                        <td className="py-2 px-3">{a.authorized_by}</td>
                        <td className="py-2 px-3 text-neutral-600">{a.scope_description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
