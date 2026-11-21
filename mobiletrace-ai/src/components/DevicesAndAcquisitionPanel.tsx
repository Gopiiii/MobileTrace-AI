import React, { useEffect, useState } from "react";
import { CaseDetailResponse, DiagnosticsResponse } from "../types/forensics";
import { formatBytes } from "../utils/forensicValidation";

interface Props {
  mode: "devices" | "acquisition";
  activeCaseId: string | null;
  caseDetail: CaseDetailResponse | null;
  diagnostics: DiagnosticsResponse | null;
  onRefreshDiagnostics: () => Promise<void>;
  onRefreshCase: () => Promise<void>;
}

export function DevicesAndAcquisitionPanel({
  mode,
  activeCaseId,
  caseDetail,
  diagnostics,
  onRefreshDiagnostics,
  onRefreshCase,
}: Props) {
  const [adbSerial, setAdbSerial] = useState("");
  const [adbPath, setAdbPath] = useState("/sdcard/DCIM");
  const [adbLsResult, setAdbLsResult] = useState<any>(null);
  const [adbRoots, setAdbRoots] = useState("/sdcard/DCIM,/sdcard/Documents,/sdcard/Download");
  const [adbIncludeShared, setAdbIncludeShared] = useState(true);

  const [iosUdid, setIosUdid] = useState("");

  const [uploadMode, setUploadMode] = useState<"directory" | "ios_backup">("directory");
  const [uploadPlatform, setUploadPlatform] = useState<"android" | "ios" | "other">("android");
  const [deviceLabel, setDeviceLabel] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);

  const [extTool, setExtTool] = useState<"aleapp" | "ileapp" | "mvt_ios" | "mvt_android">("aleapp");
  const [extSessionId, setExtSessionId] = useState("");
  const [extMode, setExtMode] = useState("fs");

  const [busy, setBusy] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    setErrorMsg(null);
    setStatusMsg(null);
  }, [mode]);

  async function handleAdbList() {
    setErrorMsg(null);
    setStatusMsg(null);
    if (!adbSerial.trim()) {
      setErrorMsg("Enter a connected authorized Android serial.");
      return;
    }
    setBusy(true);
    try {
      const resp = await fetch(
        `/api/android/${encodeURIComponent(adbSerial.trim())}/ls?path=${encodeURIComponent(adbPath)}`
      );
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "ADB directory listing failed.");
      setAdbLsResult(data);
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleAdbAcquire(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) {
      setErrorMsg("Select or create an active case first.");
      return;
    }
    setErrorMsg(null);
    setStatusMsg(null);
    const roots = adbRoots
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!adbSerial.trim() || roots.length === 0) {
      setErrorMsg("Provide a connected Android serial and at least one remote path.");
      return;
    }
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/acquire/adb`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ serial: adbSerial.trim(), remoteRoots: roots }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "ADB acquisition failed.");
      setStatusMsg(
        `ADB acquisition ${data.session.status}: ${data.session.files_copied} files (${formatBytes(
          data.session.bytes_copied
        )}) verified.`
      );
      await onRefreshCase();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleAdbBackup() {
    if (!activeCaseId) {
      setErrorMsg("Select or create an active case first.");
      return;
    }
    if (!adbSerial.trim()) {
      setErrorMsg("Provide a connected Android serial for ADB backup.");
      return;
    }
    setErrorMsg(null);
    setStatusMsg(null);
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/acquire/adb-backup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ serial: adbSerial.trim(), includeShared: adbIncludeShared }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "ADB backup failed.");
      setStatusMsg(
        data.backup?.success
          ? `ADB backup created (${formatBytes(data.backup.byte_size)}) SHA-256: ${data.backup.sha256}`
          : `ADB backup exited without archive (${data.backup?.limitation || "user cancelled or restricted on OS"}).`
      );
      await onRefreshCase();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleIosLiveBackup(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) {
      setErrorMsg("Select or create an active case first.");
      return;
    }
    if (!iosUdid.trim()) {
      setErrorMsg("Provide a connected, trusted iPhone UDID.");
      return;
    }
    setErrorMsg(null);
    setStatusMsg(null);
    setBusy(true);
    try {
      const resp = await fetch(`/api/cases/${activeCaseId}/acquire/ios-live-backup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ udid: iosUdid.trim() }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Live iOS backup failed.");
      setStatusMsg(
        data.success
          ? `iOS live backup completed at ${data.backup_root}.`
          : `iOS live backup reported an error: ${data.stderr || data.stdout}`
      );
      await onRefreshCase();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleFileIngest(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) {
      setErrorMsg("Select or create an active case first.");
      return;
    }
    if (selectedFiles.length === 0) {
      setErrorMsg("Select real evidence files or an iOS backup folder first.");
      return;
    }
    setErrorMsg(null);
    setStatusMsg(null);
    setBusy(true);
    try {
      const form = new FormData();
      form.append("mode", uploadMode);
      form.append("platform", uploadMode === "ios_backup" ? "ios" : uploadPlatform);
      form.append("deviceLabel", deviceLabel.trim() || "Acquired Evidence Package");
      if (backupPassword) form.append("backupPassword", backupPassword);

      for (const file of selectedFiles) {
        form.append("files", file);
        const rel = (file as any).webkitRelativePath || file.name;
        form.append("relativePaths", rel);
      }

      const resp = await fetch(`/api/cases/${activeCaseId}/ingest/upload`, {
        method: "POST",
        body: form,
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "Evidence ingestion failed.");

      if (uploadMode === "ios_backup") {
        setStatusMsg(
          `iOS backup imported (${data.session.status}). Parsed: ${JSON.stringify(data.parsed_artifacts || {})}`
        );
      } else {
        setStatusMsg(
          `Ingested ${data.files_ingested} files (${formatBytes(data.bytes_ingested)}) with SHA-256 verification.`
        );
      }
      setSelectedFiles([]);
      await onRefreshCase();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleRunExternalTool(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCaseId) {
      setErrorMsg("Select or create an active case first.");
      return;
    }
    setErrorMsg(null);
    setStatusMsg(null);
    setBusy(true);
    try {
      const isLeapp = extTool === "aleapp" || extTool === "ileapp";
      const resp = await fetch(`/api/cases/${activeCaseId}/tools/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool: extTool,
          sessionId: extSessionId || undefined,
          inputType: isLeapp ? extMode : "fs",
          subcommand: isLeapp ? "check-backup" : extMode,
        }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || "External forensic tool execution failed.");
      setStatusMsg(
        `${extTool.toUpperCase()} completed (exit ${data.returncode}): ${data.artifacts_ingested} artifact(s) ingested.`
      );
      await onRefreshCase();
    } catch (err: any) {
      setErrorMsg(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (mode === "devices") {
    return (
      <div className="space-y-8">
        <div className="flex flex-wrap items-end justify-between gap-4 border-b border-neutral-200 pb-5">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
              Real Device Connection &amp; Capability Status
            </h2>
            <p className="mt-1 text-sm text-neutral-600">
              Live hardware and forensic CLI detection on this host. Missing drivers or tools are reported verbatim.
            </p>
          </div>
          <button
            type="button"
            onClick={() => onRefreshDiagnostics()}
            className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 whitespace-nowrap shrink-0 cursor-pointer"
          >
            Probe Host Hardware &amp; Tools
          </button>
        </div>

        {!diagnostics ? (
          <p className="text-sm text-neutral-600">Probing host capabilities...</p>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <section className="border border-neutral-200 bg-white p-6 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-semibold text-neutral-950">Android (Official ADB)</h3>
                  <span className="text-xs font-mono text-neutral-700">
                    {diagnostics.android.adb_available ? "ADB Available" : "ADB Not Installed"}
                  </span>
                </div>
                {diagnostics.android.error && (
                  <p className="text-xs text-neutral-700 border border-neutral-300 bg-neutral-50 p-3">
                    {diagnostics.android.error}
                  </p>
                )}
                {diagnostics.android.devices.length === 0 ? (
                  <p className="text-sm text-neutral-600">
                    No Android devices detected via USB ADB on {diagnostics.host_os}.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {diagnostics.android.devices.map((d) => (
                      <div key={d.serial} className="border border-neutral-200 p-3 text-xs space-y-1">
                        <div className="font-semibold text-neutral-950">
                          {d.manufacturer} {d.model || "Android Device"} · <span className="font-mono">{d.serial}</span>
                        </div>
                        <div className="text-neutral-600">
                          State: {d.state} · OS: {d.os_version || "unknown"} · SDK: {d.sdk_version || "unknown"}
                        </div>
                        {d.status_note && <div className="text-neutral-700">{d.status_note}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </section>

              <section className="border border-neutral-200 bg-white p-6 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-base font-semibold text-neutral-950">iPhone / iOS (libimobiledevice)</h3>
                  <span className="text-xs font-mono text-neutral-700">
                    {diagnostics.ios_tooling.libimobiledevice_available ? "Tooling Ready" : "USB Tools Missing"}
                  </span>
                </div>
                <p className="text-xs text-neutral-700 border border-neutral-300 bg-neutral-50 p-3">
                  {diagnostics.ios_tooling.guidance}
                </p>
                {diagnostics.ios.devices.length === 0 ? (
                  <p className="text-sm text-neutral-600">
                    No live USB iOS devices detected. Local iTunes/Finder backup folder import remains supported.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {diagnostics.ios.devices.map((d) => (
                      <div key={d.udid} className="border border-neutral-200 p-3 text-xs space-y-1">
                        <div className="font-semibold text-neutral-950">
                          {d.device_name || d.product_type} · <span className="font-mono">{d.udid}</span>
                        </div>
                        <div className="text-neutral-600">
                          State: {d.connection_state} · iOS {d.product_version || "unknown"}
                        </div>
                        {d.status_note && <div className="text-neutral-700">{d.status_note}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>

            <section className="border border-neutral-200 bg-white p-6 space-y-2">
              <h3 className="text-base font-semibold text-neutral-950">
                Authorized Custodian &amp; Windows Environment Requirements
              </h3>
              <ul className="list-disc pl-5 text-xs text-neutral-700 space-y-1">
                <li>
                  <strong>Android</strong>: Custodian unlocks device, enables USB Debugging, and approves the workstation RSA fingerprint. Accessible shared storage is distinguished from full-filesystem acquisition.
                </li>
                <li>
                  <strong>iPhone / iOS</strong>: Custodian unlocks iPhone, taps &ldquo;Trust This Computer&rdquo;, enters passcode, and provides encrypted backup password if configured. Windows live USB acquisition requires Apple Mobile Device Support + libimobiledevice or pymobiledevice3.
                </li>
                <li>
                  <strong>Security Boundaries</strong>: MobileTrace AI never bypasses passcodes, activation locks, OS encryption, or app sandboxes.
                </li>
              </ul>
            </section>

            <section className="border border-neutral-200 bg-white">
              <div className="px-6 py-4 border-b border-neutral-200">
                <h3 className="text-base font-semibold text-neutral-950">
                  External Forensic Parser Integrations (ALEAPP, iLEAPP, MVT)
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                      <th className="py-2.5 px-4">Tool</th>
                      <th className="py-2.5 px-4">License</th>
                      <th className="py-2.5 px-4">Status</th>
                      <th className="py-2.5 px-4">Supported Inputs</th>
                      <th className="py-2.5 px-4">Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(diagnostics.forensic_tools).map(([key, tool]) => (
                      <tr key={key} className="border-b border-neutral-100">
                        <td className="py-2.5 px-4 font-semibold text-neutral-950">{tool.name}</td>
                        <td className="py-2.5 px-4 font-mono">{tool.license}</td>
                        <td className="py-2.5 px-4 font-mono">
                          {tool.installed ? `Installed (${tool.version || "ready"})` : "Not installed on host"}
                        </td>
                        <td className="py-2.5 px-4 text-neutral-600">{tool.supported_inputs.join(", ")}</td>
                        <td className="py-2.5 px-4 text-neutral-600">{tool.platform_notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}
      </div>
    );
  }

  const selectedToolMeta = diagnostics?.forensic_tools?.[extTool];
  const sessionsList = caseDetail?.sessions || [];

  return (
    <div className="space-y-8">
      <div className="border-b border-neutral-200 pb-5">
        <h2 className="text-2xl font-semibold tracking-tight text-neutral-950">
          Acquisition Wizard
        </h2>
        <p className="mt-1 text-sm text-neutral-600">
          Acquire genuinely accessible Android files via ADB, run user-authorized iOS/Android backups, or ingest real evidence packages with SHA-256 verification.
        </p>
      </div>

      {!activeCaseId && (
        <div className="border border-neutral-900 bg-neutral-50 p-4 text-sm text-neutral-900">
          Select or create a case in Dashboard &amp; Cases before starting an acquisition.
        </div>
      )}

      {errorMsg && (
        <div role="alert" className="border border-neutral-950 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {errorMsg}
        </div>
      )}
      {statusMsg && (
        <div className="border border-neutral-400 bg-neutral-50 px-4 py-3 text-sm text-neutral-950">
          {statusMsg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <section className="border border-neutral-200 bg-white p-6 space-y-4">
          <h3 className="text-base font-semibold text-neutral-950">
            1. Android ADB Accessible-File Acquisition &amp; Backup
          </h3>
          <p className="text-xs text-neutral-600">
            Scope: Accessible shared storage only (/sdcard/*). Does not bypass lock screens or extract protected /data/data sandboxes.
          </p>
          <form onSubmit={handleAdbAcquire} className="space-y-3">
            <div>
              <label htmlFor="adb-serial" className="block text-xs font-medium text-neutral-700 mb-1">
                Authorized Device Serial
              </label>
              <input
                id="adb-serial"
                value={adbSerial}
                onChange={(e) => setAdbSerial(e.target.value)}
                placeholder="e.g., R5CR90ABCDE"
                className="w-full border border-neutral-300 px-3 py-2 text-sm font-mono"
              />
            </div>
            <div className="flex gap-2">
              <input
                aria-label="Remote directory to inspect"
                value={adbPath}
                onChange={(e) => setAdbPath(e.target.value)}
                className="flex-1 border border-neutral-300 px-3 py-2 text-sm font-mono"
              />
              <button
                type="button"
                disabled={busy}
                onClick={handleAdbList}
                className="border border-neutral-300 bg-white px-3 py-2 text-xs font-medium hover:bg-neutral-100 cursor-pointer"
              >
                List Remote Dir
              </button>
            </div>
            {adbLsResult && (
              <pre className="border border-neutral-200 bg-neutral-50 p-3 text-xs max-h-40 overflow-auto">
                {JSON.stringify(adbLsResult, null, 2)}
              </pre>
            )}
            <div>
              <label htmlFor="adb-roots" className="block text-xs font-medium text-neutral-700 mb-1">
                Remote Paths to Pull (comma-separated)
              </label>
              <input
                id="adb-roots"
                value={adbRoots}
                onChange={(e) => setAdbRoots(e.target.value)}
                className="w-full border border-neutral-300 px-3 py-2 text-sm font-mono"
              />
            </div>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                type="submit"
                disabled={busy || !activeCaseId || !diagnostics?.android.adb_available}
                className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
              >
                {diagnostics?.android.adb_available
                  ? "Acquire Accessible Files via ADB"
                  : "ADB Unavailable on Host"}
              </button>
              <button
                type="button"
                disabled={busy || !activeCaseId || !diagnostics?.android.adb_available}
                onClick={handleAdbBackup}
                className="border border-neutral-300 bg-white px-3 py-2 text-xs font-medium hover:bg-neutral-100 disabled:text-neutral-400 cursor-pointer"
              >
                Authorized ADB Backup (.ab)
              </button>
            </div>
            <label className="flex items-center gap-2 text-xs text-neutral-600">
              <input
                type="checkbox"
                checked={adbIncludeShared}
                onChange={(e) => setAdbIncludeShared(e.target.checked)}
              />
              Include shared storage in ADB backup (deprecated on Android 12+; requires device-side custodian tap)
            </label>
          </form>
        </section>

        <section className="border border-neutral-200 bg-white p-6 space-y-4">
          <h3 className="text-base font-semibold text-neutral-950">
            2. Real Local Backup / Evidence File Ingestion
          </h3>
          <p className="text-xs text-neutral-600">
            Upload real acquired files, photos (JPEG EXIF), or an Apple iOS backup set (Info.plist, Manifest.plist, Manifest.db, hashed files) for SHA-256 hashing and parsing.
          </p>

          <div className="flex gap-1 p-1 bg-neutral-100 border border-neutral-200 w-fit">
            <button
              type="button"
              onClick={() => setUploadMode("directory")}
              className={`px-3 py-1.5 text-xs font-medium cursor-pointer ${
                uploadMode === "directory" ? "bg-white text-neutral-950 border border-neutral-300" : "text-neutral-600"
              }`}
            >
              Acquired Files / Media
            </button>
            <button
              type="button"
              onClick={() => setUploadMode("ios_backup")}
              className={`px-3 py-1.5 text-xs font-medium cursor-pointer ${
                uploadMode === "ios_backup" ? "bg-white text-neutral-950 border border-neutral-300" : "text-neutral-600"
              }`}
            >
              iOS Backup Package
            </button>
          </div>

          <form onSubmit={handleFileIngest} className="space-y-3">
            {uploadMode === "directory" ? (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="ingest-platform" className="block text-xs font-medium text-neutral-700 mb-1">
                    Source Platform
                  </label>
                  <select
                    id="ingest-platform"
                    value={uploadPlatform}
                    onChange={(e) => setUploadPlatform(e.target.value as any)}
                    className="w-full border border-neutral-300 px-3 py-2 text-sm bg-white"
                  >
                    <option value="android">Android</option>
                    <option value="ios">iOS</option>
                    <option value="other">Other</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="ingest-label" className="block text-xs font-medium text-neutral-700 mb-1">
                    Device / Export Label
                  </label>
                  <input
                    id="ingest-label"
                    value={deviceLabel}
                    onChange={(e) => setDeviceLabel(e.target.value)}
                    placeholder="Pixel 8 Custodian Export"
                    className="w-full border border-neutral-300 px-3 py-2 text-sm"
                  />
                </div>
              </div>
            ) : (
              <div>
                <label htmlFor="ios-pwd" className="block text-xs font-medium text-neutral-700 mb-1">
                  Encrypted Backup Password (only if IsEncrypted=true)
                </label>
                <input
                  id="ios-pwd"
                  type="password"
                  value={backupPassword}
                  onChange={(e) => setBackupPassword(e.target.value)}
                  placeholder="Leave blank for unencrypted iOS backup"
                  className="w-full border border-neutral-300 px-3 py-2 text-sm"
                />
              </div>
            )}

            <div>
              <label htmlFor="evidence-file-input" className="block text-xs font-medium text-neutral-700 mb-1">
                Select Evidence Files *
              </label>
              <input
                id="evidence-file-input"
                type="file"
                multiple
                onChange={(e) => setSelectedFiles(Array.from(e.target.files || []))}
                className="w-full border border-neutral-300 px-3 py-2 text-xs bg-neutral-50"
              />
              <p className="mt-1 text-xs text-neutral-500 font-mono tabular-nums">
                {selectedFiles.length} file(s) selected
              </p>
            </div>

            <button
              type="submit"
              disabled={busy || !activeCaseId}
              className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
            >
              {busy ? "Processing & Hashing..." : "Ingest & Verify SHA-256"}
            </button>
          </form>
        </section>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <section className="border border-neutral-200 bg-white p-6 space-y-4">
          <h3 className="text-base font-semibold text-neutral-950">
            3. iPhone Live USB Backup &amp; Custodian Trust Procedure
          </h3>
          <ol className="list-decimal pl-5 text-xs text-neutral-700 space-y-1">
            <li>Connect authorized iPhone over USB and unlock the device screen.</li>
            <li>Custodian taps &ldquo;Trust This Computer&rdquo; and confirms the device passcode.</li>
            <li>Ensure Apple Mobile Device Support + libimobiledevice (idevicebackup2) are present on Windows.</li>
          </ol>
          <form onSubmit={handleIosLiveBackup} className="space-y-3">
            <div>
              <label htmlFor="ios-live-udid" className="block text-xs font-medium text-neutral-700 mb-1">
                Connected iOS UDID
              </label>
              <input
                id="ios-live-udid"
                value={iosUdid}
                onChange={(e) => setIosUdid(e.target.value)}
                placeholder="UDID from Devices & Capabilities"
                className="w-full border border-neutral-300 px-3 py-2 text-sm font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={busy || !activeCaseId || !diagnostics?.ios_tooling.binaries?.idevicebackup2}
              className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
            >
              {diagnostics?.ios_tooling.binaries?.idevicebackup2
                ? "Run Live USB Backup (idevicebackup2)"
                : "idevicebackup2 Unavailable on Host"}
            </button>
          </form>
        </section>

        <section className="border border-neutral-200 bg-white p-6 space-y-4">
          <h3 className="text-base font-semibold text-neutral-950">
            4. External Forensic Tools Runner (ALEAPP / iLEAPP / MVT)
          </h3>
          <p className="text-xs text-neutral-600">
            Executes genuine ALEAPP, iLEAPP, or Mobile Verification Toolkit CLI binaries against an acquired case session directory and ingests TSV/JSON records.
          </p>
          <form onSubmit={handleRunExternalTool} className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="ext-tool-select" className="block text-xs font-medium text-neutral-700 mb-1">
                  Forensic Tool
                </label>
                <select
                  id="ext-tool-select"
                  value={extTool}
                  onChange={(e) => {
                    const v = e.target.value as any;
                    setExtTool(v);
                    setExtMode(v === "ileapp" ? "itunes" : v === "aleapp" ? "fs" : "check-backup");
                  }}
                  className="w-full border border-neutral-300 px-3 py-2 text-sm bg-white"
                >
                  <option value="aleapp">ALEAPP (Android)</option>
                  <option value="ileapp">iLEAPP (iOS)</option>
                  <option value="mvt_ios">MVT (mvt-ios)</option>
                  <option value="mvt_android">MVT (mvt-android)</option>
                </select>
              </div>
              <div>
                <label htmlFor="ext-mode-input" className="block text-xs font-medium text-neutral-700 mb-1">
                  Input Mode / Subcommand
                </label>
                <input
                  id="ext-mode-input"
                  value={extMode}
                  onChange={(e) => setExtMode(e.target.value)}
                  className="w-full border border-neutral-300 px-3 py-2 text-sm font-mono"
                />
              </div>
            </div>

            <div>
              <label htmlFor="ext-session-select" className="block text-xs font-medium text-neutral-700 mb-1">
                Target Case Acquisition Session
              </label>
              <select
                id="ext-session-select"
                value={extSessionId}
                onChange={(e) => setExtSessionId(e.target.value)}
                className="w-full border border-neutral-300 px-3 py-2 text-sm bg-white"
              >
                <option value="">Select recorded session directory...</option>
                {sessionsList.map((s) => (
                  <option key={s.session_id} value={s.session_id}>
                    {s.session_id} · {s.acquisition_method} ({s.files_copied} files)
                  </option>
                ))}
              </select>
            </div>

            <button
              type="submit"
              disabled={busy || !activeCaseId || !selectedToolMeta?.installed}
              className="bg-neutral-950 text-white px-4 py-2 text-xs font-medium hover:bg-neutral-800 disabled:bg-neutral-400 cursor-pointer"
            >
              {selectedToolMeta?.installed
                ? `Run ${selectedToolMeta.name} & Ingest`
                : `${selectedToolMeta?.name || extTool} Not Installed on Host`}
            </button>
          </form>
        </section>
      </div>

      {caseDetail && caseDetail.sessions.length > 0 && (
        <section className="border border-neutral-200 bg-white">
          <div className="px-6 py-4 border-b border-neutral-200">
            <h3 className="text-base font-semibold text-neutral-950">Recorded Acquisition Sessions</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-neutral-200 bg-neutral-50 text-neutral-600">
                  <th className="py-2.5 px-4">Session ID</th>
                  <th className="py-2.5 px-4">Method</th>
                  <th className="py-2.5 px-4">Scope Classification</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Files / Bytes</th>
                  <th className="py-2.5 px-4">Limitations</th>
                </tr>
              </thead>
              <tbody>
                {caseDetail.sessions.map((s) => {
                  const lims: string[] = JSON.parse(s.limitations_json || "[]");
                  return (
                    <tr key={s.session_id} className="border-b border-neutral-100">
                      <td className="py-2.5 px-4 font-mono">{s.session_id}</td>
                      <td className="py-2.5 px-4">{s.acquisition_method}</td>
                      <td className="py-2.5 px-4 font-mono">{s.scope_classification}</td>
                      <td className="py-2.5 px-4 font-medium">{s.status}</td>
                      <td className="py-2.5 px-4 text-right font-mono tabular-nums">
                        {s.files_copied} / {formatBytes(s.bytes_copied)}
                      </td>
                      <td className="py-2.5 px-4 text-neutral-600">{lims.join(" ")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
