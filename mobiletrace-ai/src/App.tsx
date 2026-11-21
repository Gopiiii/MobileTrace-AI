/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useState } from "react";
import { CasesPanel } from "./components/CasesPanel";
import { DevicesAndAcquisitionPanel } from "./components/DevicesAndAcquisitionPanel";
import { EvidenceAndTimelinePanel } from "./components/EvidenceAndTimelinePanel";
import { GeminiAndReportsPanel } from "./components/GeminiAndReportsPanel";
import { TransferAndIntegrityPanel } from "./components/TransferAndIntegrityPanel";
import { CaseDetailResponse, DiagnosticsResponse, ForensicCase } from "./types/forensics";

type NavSection =
  | "dashboard"
  | "devices"
  | "acquisition"
  | "transfer"
  | "evidence"
  | "timeline"
  | "integrity"
  | "gemini"
  | "reports"
  | "settings";

const NAV_ITEMS: Array<{ key: NavSection; label: string }> = [
  { key: "dashboard", label: "Dashboard & Cases" },
  { key: "devices", label: "Devices & Capabilities" },
  { key: "acquisition", label: "Acquisition Wizard" },
  { key: "transfer", label: "Transfer Manager" },
  { key: "evidence", label: "Evidence Explorer" },
  { key: "timeline", label: "Timeline & Comparison" },
  { key: "integrity", label: "Hash Verification" },
  { key: "gemini", label: "Gemini Investigation" },
  { key: "reports", label: "Audit Log & Reports" },
  { key: "settings", label: "Settings & Backup" },
];

export default function App() {
  const [section, setSection] = useState<NavSection>("dashboard");
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<CaseDetailResponse | null>(null);
  const [diagnostics, setDiagnostics] = useState<DiagnosticsResponse | null>(null);

  const loadCases = useCallback(async () => {
    const resp = await fetch("/api/cases");
    if (!resp.ok) return;
    const data = await resp.json();
    const list: ForensicCase[] = data.cases || [];
    setCases(list);
    setActiveCaseId((prev) => {
      if (prev && list.some((c) => c.case_id === prev)) return prev;
      return list[0]?.case_id || null;
    });
  }, []);

  const loadCaseDetail = useCallback(async (caseId: string | null) => {
    if (!caseId) {
      setCaseDetail(null);
      return;
    }
    const resp = await fetch(`/api/cases/${caseId}`);
    if (!resp.ok) return;
    const data: CaseDetailResponse = await resp.json();
    setCaseDetail(data);
  }, []);

  const loadDiagnostics = useCallback(async () => {
    const resp = await fetch("/api/diagnostics");
    if (!resp.ok) return;
    const data: DiagnosticsResponse = await resp.json();
    setDiagnostics(data);
  }, []);

  useEffect(() => {
    loadCases();
    loadDiagnostics();
  }, [loadCases, loadDiagnostics]);

  useEffect(() => {
    loadCaseDetail(activeCaseId);
  }, [activeCaseId, loadCaseDetail]);

  async function handleCreateCase(payload: {
    caseNumber: string;
    title: string;
    examiner: string;
    agency: string;
    notes: string;
  }) {
    const resp = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Failed to create case.");
    await loadCases();
    setActiveCaseId(data.case_id);
  }

  async function handleRecordAuth(payload: {
    deviceId: string;
    authorityType: string;
    referenceNumber: string;
    authorizedBy: string;
    scopeDescription: string;
  }) {
    if (!activeCaseId) return;
    const resp = await fetch(`/api/cases/${activeCaseId}/authorizations`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Failed to record authorization.");
    await loadCaseDetail(activeCaseId);
  }

  const refreshActive = async () => {
    await Promise.all([loadCases(), loadCaseDetail(activeCaseId)]);
  };

  return (
    <div className="min-h-screen bg-white text-neutral-950 flex flex-col">
      {/* Top Bar Contract: 3 clean zones */}
      <header className="h-14 border-b border-neutral-200 px-6 flex items-center justify-between gap-8 bg-white shrink-0">
        <a href="#top" onClick={(e) => { e.preventDefault(); setSection("dashboard"); }} className="text-lg font-bold tracking-tight text-neutral-950 whitespace-nowrap shrink-0">
          MobileTrace AI
        </a>

        <nav className="hidden xl:flex items-center gap-6 text-xs font-medium text-neutral-600">
          <button type="button" onClick={() => setSection("dashboard")} className="hover:text-neutral-950 whitespace-nowrap shrink-0 cursor-pointer">
            Cases
          </button>
          <button type="button" onClick={() => setSection("devices")} className="hover:text-neutral-950 whitespace-nowrap shrink-0 cursor-pointer">
            Devices
          </button>
          <button type="button" onClick={() => setSection("acquisition")} className="hover:text-neutral-950 whitespace-nowrap shrink-0 cursor-pointer">
            Acquisition
          </button>
          <button type="button" onClick={() => setSection("evidence")} className="hover:text-neutral-950 whitespace-nowrap shrink-0 cursor-pointer">
            Evidence
          </button>
          <button type="button" onClick={() => setSection("reports")} className="hover:text-neutral-950 whitespace-nowrap shrink-0 cursor-pointer">
            Reports
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => {
              loadCases();
              loadCaseDetail(activeCaseId);
              loadDiagnostics();
            }}
            className="bg-neutral-950 text-white px-4 py-1.5 text-xs font-medium hover:bg-neutral-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Refresh Workspace
          </button>
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Sidebar */}
        <aside className="w-60 border-r border-neutral-200 bg-neutral-50 p-4 flex flex-col gap-1 shrink-0">
          <div className="px-2 pb-3 mb-2 border-b border-neutral-200 text-xs text-neutral-600">
            {caseDetail ? (
              <div>
                <div className="font-mono text-neutral-950 font-semibold truncate">{caseDetail.case.case_number}</div>
                <div className="truncate">{caseDetail.case.title}</div>
              </div>
            ) : (
              <span>No active case selected</span>
            )}
          </div>

          {NAV_ITEMS.map((item) => {
            const active = section === item.key;
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => setSection(item.key)}
                className={`text-left px-3 py-2 text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                  active
                    ? "bg-neutral-950 text-white"
                    : "text-neutral-700 hover:bg-neutral-200/60 hover:text-neutral-950"
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </aside>

        {/* Main Workspace */}
        <main className="flex-1 p-8 overflow-y-auto bg-white">
          <div className="max-w-6xl mx-auto">
            {section === "dashboard" && (
              <CasesPanel
                cases={cases}
                activeCaseId={activeCaseId}
                caseDetail={caseDetail}
                onSelectCase={(id) => setActiveCaseId(id)}
                onCreateCase={handleCreateCase}
                onRecordAuth={handleRecordAuth}
              />
            )}
            {(section === "devices" || section === "acquisition") && (
              <DevicesAndAcquisitionPanel
                mode={section}
                activeCaseId={activeCaseId}
                caseDetail={caseDetail}
                diagnostics={diagnostics}
                onRefreshDiagnostics={loadDiagnostics}
                onRefreshCase={refreshActive}
              />
            )}
            {(section === "transfer" || section === "integrity") && (
              <TransferAndIntegrityPanel
                mode={section}
                activeCaseId={activeCaseId}
                caseDetail={caseDetail}
                onRefreshCase={refreshActive}
              />
            )}
            {(section === "evidence" || section === "timeline") && (
              <EvidenceAndTimelinePanel
                mode={section}
                activeCaseId={activeCaseId}
                caseDetail={caseDetail}
                onRefreshCase={refreshActive}
              />
            )}
            {(section === "gemini" || section === "reports" || section === "settings") && (
              <GeminiAndReportsPanel
                mode={section}
                activeCaseId={activeCaseId}
                caseDetail={caseDetail}
                diagnostics={diagnostics}
                onRefreshCase={refreshActive}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
