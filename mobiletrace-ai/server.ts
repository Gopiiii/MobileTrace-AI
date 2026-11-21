import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";
import express from "express";
import fs from "fs";
import multer from "multer";
import path from "path";
import { execFile, spawn } from "child_process";
import { promisify } from "util";
import { createServer as createViteServer } from "vite";
import { extractGroundingSources, parseGroundedAiJson } from "./src/utils/forensicValidation";

dotenv.config();

const execFileAsync = promisify(execFile);
const PORT = Number.parseInt(process.env.PORT || "3000", 10) || 3000;
const HOST = (process.env.MOBILETRACE_HOST || "0.0.0.0").trim() || "0.0.0.0";
const IS_PROD = process.env.NODE_ENV === "production" || process.argv.includes("--prod");
const ROOT_DIR = process.cwd();
const rawWorkspaceEnv = (process.env.MOBILETRACE_WORKSPACE_DIR || "").trim();
const isWinDriveOnPosix = process.platform !== "win32" && /^[A-Za-z]:[\\/]/.test(rawWorkspaceEnv);
const WORKSPACE_DIR = path.resolve(
  rawWorkspaceEnv && !isWinDriveOnPosix ? rawWorkspaceEnv : path.join(ROOT_DIR, "data", "workspace")
);
const UPLOAD_STAGE_DIR = path.join(WORKSPACE_DIR, "uploads");

fs.mkdirSync(WORKSPACE_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_STAGE_DIR, { recursive: true });

function sanitizeSegment(seg: string): string {
  const cleaned = seg.replace(/[<>:"/\\|?*\x00-\x1f]/g, "_").trim();
  if (!cleaned || cleaned === "." || cleaned === "..") {
    return "item";
  }
  return cleaned.slice(0, 180);
}

function confinePath(baseDir: string, relPath: string): string {
  const baseResolved = path.resolve(baseDir);
  const parts = relPath
    .replace(/\\/g, "/")
    .split("/")
    .filter((p) => p && p !== "." && p !== "..")
    .map(sanitizeSegment);
  const candidate = path.resolve(baseResolved, ...(parts.length > 0 ? parts : ["file"]));
  if (!candidate.startsWith(baseResolved + path.sep)) {
    throw new Error(`Path escapes allowed workspace directory: ${relPath}`);
  }
  return candidate;
}

function resolvePythonBinary(): string {
  const override = (process.env.MOBILETRACE_PYTHON_PATH || "").trim();
  if (override && fs.existsSync(override)) {
    return override;
  }
  const venvCandidates =
    process.platform === "win32"
      ? [path.join(ROOT_DIR, ".venv", "Scripts", "python.exe")]
      : [path.join(ROOT_DIR, ".venv", "bin", "python"), path.join(ROOT_DIR, ".venv", "bin", "python3")];
  for (const cand of venvCandidates) {
    if (fs.existsSync(cand)) {
      return cand;
    }
  }
  return process.platform === "win32" ? "python" : "python3";
}

async function runCli(args: string[], stdinJson?: unknown): Promise<any> {
  const pythonBin = resolvePythonBinary();
  if (stdinJson !== undefined) {
    return await new Promise((resolve, reject) => {
      const child = spawn(pythonBin, ["-m", "mobiletrace.cli", ...args], {
        cwd: ROOT_DIR,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d.toString()));
      child.stderr.on("data", (d) => (stderr += d.toString()));
      child.on("error", reject);
      child.on("close", (code) => {
        try {
          const parsed = JSON.parse(stdout || "{}");
          if (code !== 0) {
            reject(new Error(parsed.error || stderr || `CLI exited with code ${code}`));
            return;
          }
          resolve(parsed);
        } catch {
          reject(new Error(stderr || stdout || `CLI exited with code ${code}`));
        }
      });
      child.stdin.write(JSON.stringify(stdinJson));
      child.stdin.end();
    });
  }

  try {
    const { stdout } = await execFileAsync(pythonBin, ["-m", "mobiletrace.cli", ...args], {
      cwd: ROOT_DIR,
      env: process.env,
      maxBuffer: 16 * 1024 * 1024,
    });
    return JSON.parse(stdout || "{}");
  } catch (err: any) {
    // The Python CLI reports failures as {"error": "..."} on stdout (non-zero exit). Surface that message.
    let cliMessage = "";
    try {
      const parsed = JSON.parse(String(err?.stdout || ""));
      cliMessage = parsed?.error ? String(parsed.error) : "";
    } catch {
      /* stdout was not JSON; fall back to stderr / generic message below */
    }
    throw new Error(cliMessage || String(err?.stderr || "").trim() || err?.message || "Forensic CLI execution failed");
  }
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024, files: 100 },
});

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "4mb" }));

  // 1. Host diagnostics & real hardware/tooling probe
  app.get("/api/diagnostics", async (_req, res) => {
    try {
      const data = await runCli(["diagnostics"]);
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 2. Cases
  app.get("/api/cases", async (_req, res) => {
    try {
      const data = await runCli(["case-list"]);
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post("/api/cases", async (req, res) => {
    try {
      const { caseNumber, title, examiner, agency = "", notes = "" } = req.body ?? {};
      if (!caseNumber || !title || !examiner) {
        res.status(400).json({ error: "caseNumber, title, and examiner are required." });
        return;
      }
      const data = await runCli([
        "case-create",
        "--case-number",
        String(caseNumber),
        "--title",
        String(title),
        "--examiner",
        String(examiner),
        "--agency",
        String(agency),
        "--notes",
        String(notes),
      ]);
      res.status(201).json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/cases/:caseId", async (req, res) => {
    try {
      const data = await runCli(["case-get", "--case-id", req.params.caseId]);
      res.json(data);
    } catch (err: any) {
      res.status(404).json({ error: err.message });
    }
  });

  // 3. Authorization record
  app.post("/api/cases/:caseId/authorizations", async (req, res) => {
    try {
      const { deviceId, authorityType, referenceNumber = "", authorizedBy, scopeDescription } = req.body ?? {};
      if (!deviceId || !authorityType || !authorizedBy || !scopeDescription) {
        res.status(400).json({ error: "deviceId, authorityType, authorizedBy, and scopeDescription are required." });
        return;
      }
      const data = await runCli([
        "auth-record",
        "--case-id",
        req.params.caseId,
        "--device-id",
        String(deviceId),
        "--authority-type",
        String(authorityType),
        "--reference-number",
        String(referenceNumber),
        "--authorized-by",
        String(authorizedBy),
        "--scope-description",
        String(scopeDescription),
      ]);
      res.status(201).json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 4. Android ADB directory listing & acquisition
  app.get("/api/android/:serial/ls", async (req, res) => {
    try {
      const remotePath = String(req.query.path || "/sdcard");
      const data = await runCli(["adb-ls", "--serial", req.params.serial, "--path", remotePath]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/cases/:caseId/acquire/adb", async (req, res) => {
    try {
      const { serial, remoteRoots, actor = "examiner" } = req.body ?? {};
      if (!serial || !Array.isArray(remoteRoots) || remoteRoots.length === 0) {
        res.status(400).json({ error: "serial and non-empty remoteRoots array are required." });
        return;
      }
      const data = await runCli([
        "adb-acquire",
        "--case-id",
        req.params.caseId,
        "--serial",
        String(serial),
        "--remote-roots",
        ...remoteRoots.map(String),
        "--actor",
        String(actor),
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/cases/:caseId/acquire/adb-backup", async (req, res) => {
    try {
      const { serial, includeShared = true, includeApks = false, actor = "examiner" } = req.body ?? {};
      if (!serial) {
        res.status(400).json({ error: "Authorized Android device serial is required." });
        return;
      }
      const args = [
        "adb-backup",
        "--case-id",
        req.params.caseId,
        "--serial",
        String(serial),
        "--actor",
        String(actor),
      ];
      if (includeShared) args.push("--include-shared");
      if (includeApks) args.push("--include-apks");
      const data = await runCli(args);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/cases/:caseId/acquire/ios-live-backup", async (req, res) => {
    try {
      const { udid, actor = "examiner" } = req.body ?? {};
      if (!udid) {
        res.status(400).json({ error: "Connected trusted iOS device UDID is required." });
        return;
      }
      const data = await runCli([
        "ios-live-backup",
        "--case-id",
        req.params.caseId,
        "--udid",
        String(udid),
        "--actor",
        String(actor),
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/cases/:caseId/tools/run", async (req, res) => {
    try {
      const {
        tool,
        deviceId = "",
        sessionId = "",
        workspaceSubpath = "",
        inputType = "fs",
        subcommand = "check-backup",
        actor = "examiner",
      } = req.body ?? {};
      if (!["aleapp", "ileapp", "mvt_ios", "mvt_android"].includes(String(tool))) {
        res.status(400).json({ error: "tool must be one of aleapp, ileapp, mvt_ios, mvt_android." });
        return;
      }
      const caseData = await runCli(["case-get", "--case-id", req.params.caseId]);
      let effectiveDeviceId = String(deviceId || "");
      let resolvedInputPath = "";

      if (sessionId) {
        const sess = (caseData.sessions || []).find((s: any) => s.session_id === sessionId);
        if (!sess) {
          res.status(404).json({ error: `Acquisition session not found: ${sessionId}` });
          return;
        }
        effectiveDeviceId = effectiveDeviceId || sess.device_id;
        const candidate = path.resolve(sess.output_directory || "");
        if (!candidate.startsWith(WORKSPACE_DIR + path.sep)) {
          res.status(403).json({ error: "Session directory is outside the confined workstation workspace." });
          return;
        }
        resolvedInputPath = candidate;
      } else if (workspaceSubpath) {
        resolvedInputPath = confinePath(WORKSPACE_DIR, String(workspaceSubpath));
      }

      if (!effectiveDeviceId) {
        const firstDev = (caseData.devices || [])[0];
        if (!firstDev) {
          res.status(400).json({ error: "Acquire or ingest a device in this case before running external tools." });
          return;
        }
        effectiveDeviceId = firstDev.device_id;
      }

      const args = [
        "run-external-tool",
        "--case-id",
        req.params.caseId,
        "--device-id",
        effectiveDeviceId,
        "--tool",
        String(tool),
        "--input-type",
        String(inputType || "fs"),
        "--subcommand",
        String(subcommand || "check-backup"),
        "--actor",
        String(actor),
      ];
      if (resolvedInputPath) {
        args.push("--input-path", resolvedInputPath);
      }
      const data = await runCli(args);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 5. Real Evidence File / Backup Upload & Ingest (multipart -> confined staging dir -> Python ingest/iOS parser)
  app.post("/api/cases/:caseId/ingest/upload", upload.array("files", 100), async (req, res) => {
    try {
      const uploaded = (req.files as Express.Multer.File[]) || [];
      if (uploaded.length === 0) {
        res.status(400).json({ error: "Select at least one real file or backup folder to ingest." });
        return;
      }
      const mode = String(req.body?.mode || "directory");
      const platform = String(req.body?.platform || (mode === "ios_backup" ? "ios" : "android"));
      const deviceLabel = String(req.body?.deviceLabel || "Uploaded Evidence Set");
      const backupPassword = String(req.body?.backupPassword || "");
      const actor = String(req.body?.actor || "examiner");

      const batchId = `batch_${Date.now()}`;
      const batchDir = path.join(UPLOAD_STAGE_DIR, sanitizeSegment(req.params.caseId), batchId);
      fs.mkdirSync(batchDir, { recursive: true });

      const relPathsRaw: string[] = Array.isArray(req.body?.relativePaths)
        ? req.body.relativePaths.map(String)
        : req.body?.relativePaths
          ? [String(req.body.relativePaths)]
          : [];

      for (let i = 0; i < uploaded.length; i++) {
        const f = uploaded[i];
        const rel = relPathsRaw[i] || f.originalname;
        // Strip top-level folder prefix if webkitRelativePath was sent for iOS backup root
        const target = confinePath(batchDir, rel);
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, f.buffer);
      }

      // Detect if an iOS backup root sits one level inside batchDir (from folder picker)
      let effectiveDir = batchDir;
      const children = fs.readdirSync(batchDir);
      if (children.length === 1) {
        const sub = path.join(batchDir, children[0]);
        if (fs.statSync(sub).isDirectory() && fs.existsSync(path.join(sub, "Manifest.plist"))) {
          effectiveDir = sub;
        }
      }

      if (mode === "ios_backup" || fs.existsSync(path.join(effectiveDir, "Manifest.plist"))) {
        const cliArgs = [
          "ios-import-backup",
          "--case-id",
          req.params.caseId,
          "--backup-dir",
          effectiveDir,
          "--actor",
          actor,
        ];
        if (backupPassword) {
          cliArgs.push("--password", backupPassword);
        }
        const data = await runCli(cliArgs);
        res.json(data);
        return;
      }

      const data = await runCli([
        "ingest-directory",
        "--case-id",
        req.params.caseId,
        "--source-dir",
        effectiveDir,
        "--platform",
        platform,
        "--device-label",
        deviceLabel,
        "--actor",
        actor,
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 6. Transfer Manager (confined within workspace destinations)
  app.post("/api/cases/:caseId/transfer", async (req, res) => {
    try {
      const { artifactIds = [], destinationSubdir = "export_bundle", conflictPolicy = "rename", actor = "examiner" } =
        req.body ?? {};
      const caseData = await runCli(["case-get", "--case-id", req.params.caseId]);
      const artifacts: any[] = caseData.artifacts || [];
      const selected =
        Array.isArray(artifactIds) && artifactIds.length > 0
          ? artifacts.filter((a) => artifactIds.includes(a.artifact_id))
          : artifacts;

      const sourcePaths = Array.from(
        new Set(selected.map((a) => a.stored_copy_path).filter((p: string) => p && fs.existsSync(p)))
      );
      if (sourcePaths.length === 0) {
        res.status(400).json({ error: "No stored artifact files are available on disk to transfer for this case." });
        return;
      }

      const destDir = confinePath(path.join(WORKSPACE_DIR, "transfers", sanitizeSegment(req.params.caseId)), destinationSubdir);
      const data = await runCli([
        "transfer-run",
        "--case-id",
        req.params.caseId,
        "--sources",
        ...sourcePaths,
        "--destination",
        destDir,
        "--conflict-policy",
        String(conflictPolicy),
        "--actor",
        String(actor),
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 7. Evidence search, timeline, cross-device correlation
  app.get("/api/cases/:caseId/artifacts", async (req, res) => {
    try {
      const data = await runCli([
        "artifact-search",
        "--case-id",
        req.params.caseId,
        "--query",
        String(req.query.q || ""),
        "--artifact-type",
        String(req.query.type || ""),
        "--device-id",
        String(req.query.deviceId || ""),
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/cases/:caseId/timeline", async (req, res) => {
    try {
      const data = await runCli([
        "timeline",
        "--case-id",
        req.params.caseId,
        "--device-id",
        String(req.query.deviceId || ""),
        "--query",
        String(req.query.q || ""),
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/cases/:caseId/compare", async (req, res) => {
    try {
      const windowSeconds = Math.max(10, Math.min(86400, Number(req.query.window || 300)));
      const data = await runCli([
        "compare-devices",
        "--case-id",
        req.params.caseId,
        "--window-seconds",
        String(windowSeconds),
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 8. Integrity verification & DB backup
  app.post("/api/cases/:caseId/verify-integrity", async (req, res) => {
    try {
      const actor = String(req.body?.actor || "examiner");
      const data = await runCli(["verify-integrity", "--case-id", req.params.caseId, "--actor", actor]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/database/backup", async (_req, res) => {
    try {
      const data = await runCli(["db-backup"]);
      res.json(data);
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // 9. Findings & Notes
  app.post("/api/cases/:caseId/findings", async (req, res) => {
    try {
      const { title, category, severity = "informational", description, artifactIds = [], actor = "examiner" } =
        req.body ?? {};
      if (!title || !category || !description) {
        res.status(400).json({ error: "title, category, and description are required." });
        return;
      }
      const args = [
        "finding-add",
        "--case-id",
        req.params.caseId,
        "--title",
        String(title),
        "--category",
        String(category),
        "--severity",
        String(severity),
        "--description",
        String(description),
        "--actor",
        String(actor),
      ];
      if (Array.isArray(artifactIds) && artifactIds.length > 0) {
        args.push("--artifact-ids", ...artifactIds.map(String));
      }
      const data = await runCli(args);
      res.status(201).json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.post("/api/cases/:caseId/notes", async (req, res) => {
    try {
      const { author = "examiner", body, artifactId = "" } = req.body ?? {};
      if (!body) {
        res.status(400).json({ error: "Note body is required." });
        return;
      }
      const data = await runCli([
        "note-add",
        "--case-id",
        req.params.caseId,
        "--author",
        String(author),
        "--body",
        String(body),
        "--artifact-id",
        String(artifactId),
      ]);
      res.status(201).json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // 10. Gemini AI Investigation (server-side @google/genai + Search Grounding + Python DB validation)
  app.post("/api/cases/:caseId/ai-investigate", async (req, res) => {
    try {
      const {
        artifactIds,
        question,
        analystApproved,
        redactPii = true,
        useSearchGrounding = true,
        actor = "examiner",
      } = req.body ?? {};
      if (!analystApproved) {
        res.status(403).json({
          error: "Explicit analyst approval is required before sending minimized artifact summaries to Gemini.",
        });
        return;
      }
      if (!Array.isArray(artifactIds) || artifactIds.length === 0 || !question) {
        res.status(400).json({ error: "Select at least one artifact and provide an investigative question." });
        return;
      }

      const apiKey = (process.env.GEMINI_API_KEY || "").trim();
      if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
        res.status(503).json({
          error:
            "GEMINI_API_KEY is not configured in environment secrets. Local acquisition, hashing, parsing, timelines, and PDF/HTML reports continue to work offline.",
        });
        return;
      }

      const bundleArgs = [
        "ai-prepare-bundle",
        "--case-id",
        req.params.caseId,
        "--artifact-ids",
        ...artifactIds.map(String),
      ];
      if (redactPii) {
        bundleArgs.push("--redact-pii");
      }
      const bundle = await runCli(bundleArgs);

      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            "User-Agent": "aistudio-build",
          },
        },
      });
      const rawModelEnv = (process.env.MOBILETRACE_GEMINI_MODEL || "").trim();
      const modelName = /^gemini-[a-z0-9.-]+$/i.test(rawModelEnv) ? rawModelEnv : "gemini-4-hydrogen";

      const systemInstruction =
        "You are assisting a certified mobile digital forensics examiner. " +
        "Only cite artifact_id values present verbatim in the supplied artifacts array. " +
        "Strictly separate verified forensic observations from AI interpretations, competing hypotheses, and uncertainty. " +
        "Never treat missing data as proof an event did not happen, and never treat matching timestamps alone as proof of a relationship. " +
        (useSearchGrounding
          ? "When Google Search grounding is enabled, retrieve up-to-date mobile forensic best practices, OS artifact behavior, and CVE advisories relevant to the artifacts, and return ONLY a single valid JSON object with keys: verified_observations, contradictions, competing_hypotheses, missing_evidence_gaps, cross_device_correlations, suggested_next_steps, relevant_cves_and_best_practices, report_draft_summary, uncertainty_and_limitations."
          : "");

      const contents =
        `Examiner Question: ${String(question).trim()}\n\n` +
        (useSearchGrounding
          ? "Output JSON keys: verified_observations ([{statement, artifact_ids}]), contradictions ([{description, artifact_ids}]), competing_hypotheses ([{hypothesis, supporting_points, refuting_points}]), missing_evidence_gaps ([string]), cross_device_correlations ([{observation, artifact_ids, caveat}]), suggested_next_steps ([string]), relevant_cves_and_best_practices ([{reference, relevance_to_case, verification_needed}]), report_draft_summary (string), uncertainty_and_limitations (string).\n\n"
          : "") +
        `Minimized Evidence Bundle:\n${JSON.stringify(bundle, null, 2)}`;

      const config: Record<string, any> = useSearchGrounding
        ? {
            systemInstruction,
            tools: [{ googleSearch: {} }],
          }
        : {
            systemInstruction,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                verified_observations: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      statement: { type: Type.STRING },
                      artifact_ids: { type: Type.ARRAY, items: { type: Type.STRING } },
                    },
                  },
                },
                contradictions: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      description: { type: Type.STRING },
                      artifact_ids: { type: Type.ARRAY, items: { type: Type.STRING } },
                    },
                  },
                },
                competing_hypotheses: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      hypothesis: { type: Type.STRING },
                      supporting_points: { type: Type.ARRAY, items: { type: Type.STRING } },
                      refuting_points: { type: Type.ARRAY, items: { type: Type.STRING } },
                    },
                  },
                },
                missing_evidence_gaps: { type: Type.ARRAY, items: { type: Type.STRING } },
                cross_device_correlations: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      observation: { type: Type.STRING },
                      artifact_ids: { type: Type.ARRAY, items: { type: Type.STRING } },
                      caveat: { type: Type.STRING },
                    },
                  },
                },
                suggested_next_steps: { type: Type.ARRAY, items: { type: Type.STRING } },
                relevant_cves_and_best_practices: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      reference: { type: Type.STRING },
                      relevance_to_case: { type: Type.STRING },
                      verification_needed: { type: Type.STRING },
                    },
                  },
                },
                report_draft_summary: { type: Type.STRING },
                uncertainty_and_limitations: { type: Type.STRING },
              },
            },
          };

      const response = await ai.models.generateContent({
        model: modelName,
        contents,
        config,
      });

      const parsedResponse = parseGroundedAiJson(response.text ?? "{}");
      const grounding = extractGroundingSources(response.candidates?.[0]?.groundingMetadata);
      parsedResponse.search_grounding_used = Boolean(useSearchGrounding);
      parsedResponse.web_search_queries = grounding.queries;
      parsedResponse.grounding_sources = grounding.sources;

      const saveArgs = [
        "ai-validate-and-save",
        "--case-id",
        req.params.caseId,
        "--model-name",
        modelName,
        "--question",
        String(question),
        "--analyst-approved",
        "--selected-ids",
        ...artifactIds.map(String),
        "--response-json-stdin",
        "--actor",
        String(actor),
      ];
      if (redactPii) {
        saveArgs.push("--pii-redacted");
      }
      const saved = await runCli(saveArgs, parsedResponse);
      res.json({
        ...saved,
        bundle_redaction_counts: bundle.redaction_counts,
        grounding_sources: grounding.sources,
        web_search_queries: grounding.queries,
      });
    } catch (err: any) {
      let statusCode = typeof err?.status === "number" ? err.status : 500;
      let cleanMessage = String(err?.message || "Gemini forensic analysis failed.");
      try {
        const parsed = JSON.parse(cleanMessage);
        if (parsed?.error) {
          if (typeof parsed.error.code === "number") {
            statusCode = parsed.error.code;
          }
          if (parsed.error.message) {
            cleanMessage =
              parsed.error.status === "RESOURCE_EXHAUSTED" || statusCode === 429
                ? "Gemini API quota exceeded (429 RESOURCE_EXHAUSTED). Check your Gemini API billing/quota or retry shortly; all offline forensic tools remain available."
                : `${parsed.error.status ? `${parsed.error.status}: ` : ""}${parsed.error.message}`;
          }
        }
      } catch {
        // Non-JSON error message; keep cleanMessage as-is
      }
      if (statusCode < 400 || statusCode > 599) statusCode = 502;
      res.status(statusCode).json({ error: cleanMessage });
    }
  });

  // 11. Reports (Generate & Safe Download)
  app.post("/api/cases/:caseId/reports", async (req, res) => {
    try {
      const format = req.body?.format === "pdf" ? "pdf" : "html";
      const actor = String(req.body?.actor || "examiner");
      const data = await runCli([
        "report-generate",
        "--case-id",
        req.params.caseId,
        "--format",
        format,
        "--actor",
        actor,
      ]);
      res.json(data);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.get("/api/cases/:caseId/reports/:reportId/download", async (req, res) => {
    try {
      const caseData = await runCli(["case-get", "--case-id", req.params.caseId]);
      const match = (caseData.reports || []).find((r: any) => r.report_id === req.params.reportId);
      if (!match) {
        res.status(404).json({ error: "Report not found." });
        return;
      }
      const reportsBase = path.resolve(WORKSPACE_DIR, "reports");
      const resolvedFile = path.resolve(match.output_path);
      if (!resolvedFile.startsWith(reportsBase + path.sep) || !fs.existsSync(resolvedFile)) {
        res.status(404).json({ error: "Report file unavailable on disk." });
        return;
      }
      res.download(resolvedFile, path.basename(resolvedFile));
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  // Vite middleware for dev / static serving in production
  const distDir = path.resolve(ROOT_DIR, "dist");
  const hasBuild = fs.existsSync(path.join(distDir, "index.html"));
  if (IS_PROD && !hasBuild) {
    console.warn("[MobileTrace] No dist/ build found (run `npm run build` first). Falling back to the Vite dev server.");
  }
  if (!IS_PROD || !hasBuild) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  }

  // Initialize SQLite schema & WAL once before accepting concurrent HTTP requests
  await runCli(["case-list"]);

  const httpServer = app.listen(PORT, HOST, () => {
    console.log(`MobileTrace AI workstation listening on http://localhost:${PORT}`);
  });
  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(`Port ${PORT} is already in use. Close the other process or start with a different port (e.g. PORT=3001).`);
    } else {
      console.error("HTTP server error:", err);
    }
    process.exit(1);
  });
}

startServer().catch((err) => {
  console.error("Failed to start MobileTrace AI server:", err);
  process.exit(1);
});
