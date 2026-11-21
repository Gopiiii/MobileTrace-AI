#!/usr/bin/env node
/**
 * MobileTrace AI — one-command launcher.
 *
 *   node run.mjs              Start the web console (installs everything first if needed)
 *   node run.mjs desktop      Start the PySide6 desktop app
 *   node run.mjs setup        Only install / repair dependencies
 *   node run.mjs test         Run Python + TypeScript tests and the type check
 *   node run.mjs doctor       Print what is installed / missing, change nothing
 *
 * Options:  --no-open (don't open the browser)   --port 3001   --localhost-only
 */
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import http from "node:http";

const ROOT = import.meta.dirname;
const IS_WIN = process.platform === "win32";
const args = process.argv.slice(2);
const positional = args.filter((a, i) => !a.startsWith("--") && args[i - 1] !== "--port");
const mode = positional[0] || "web";
const flag = (name) => args.includes(`--${name}`);
const opt = (name) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const PORT = Number.parseInt(opt("port") || process.env.PORT || "3000", 10) || 3000;
const VENV_DIR = path.join(ROOT, ".venv");
const VENV_PY = IS_WIN ? path.join(VENV_DIR, "Scripts", "python.exe") : path.join(VENV_DIR, "bin", "python");

const c = (code, s) => (process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const info = (m) => console.log(c(36, "[MobileTrace] ") + m);
const ok = (m) => console.log(c(32, "[MobileTrace] ") + m);
const warn = (m) => console.log(c(33, "[MobileTrace] ") + m);
const fail = (m) => {
  console.error(c(31, "[MobileTrace] ERROR: ") + m);
  process.exit(1);
};

/** Run a command to completion with live output. Returns the exit status. */
function run(cmd, cmdArgs, options = {}) {
  const r = spawnSync(cmd, cmdArgs, { cwd: ROOT, stdio: "inherit", shell: options.shell ?? false, env: process.env });
  return r.status ?? 1;
}
/** Run quietly, capture output. */
function probe(cmd, cmdArgs) {
  try {
    const r = spawnSync(cmd, cmdArgs, { cwd: ROOT, encoding: "utf8", timeout: 60_000 });
    return { status: r.status ?? 1, out: `${r.stdout || ""}${r.stderr || ""}`.trim() };
  } catch {
    return { status: 1, out: "" };
  }
}
const npmRun = (npmArgs) => run(IS_WIN ? "npm.cmd" : "npm", npmArgs, { shell: IS_WIN });

// ---------------------------------------------------------------- checks ----
function checkNode() {
  const [maj, min] = process.versions.node.split(".").map(Number);
  if (maj < 20 || (maj === 20 && min < 11)) {
    fail(`Node.js ${process.versions.node} is too old. Install Node 20.11+ (22 LTS recommended) from https://nodejs.org`);
  }
}

function findSystemPython() {
  const candidates = IS_WIN ? [["py", "-3"], ["python"], ["python3"]] : [["python3"], ["python"]];
  for (const [cmd, ...pre] of candidates) {
    const r = probe(cmd, [...pre, "-c", "import sys;print('%d.%d'%sys.version_info[:2])"]);
    if (r.status !== 0) continue;
    const [maj, min] = r.out.split(".").map(Number);
    if (maj > 3 || (maj === 3 && min >= 11)) return { cmd, pre };
  }
  return null;
}

function ensureEnvFile() {
  const envPath = path.join(ROOT, ".env");
  if (!fs.existsSync(envPath) && fs.existsSync(path.join(ROOT, ".env.example"))) {
    fs.copyFileSync(path.join(ROOT, ".env.example"), envPath);
    ok("Created .env from .env.example (add your GEMINI_API_KEY there if you want AI features).");
  }
}

function ensureNodeModules() {
  const marker = path.join(ROOT, "node_modules", ".package-lock.json");
  const tsx = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
  if (fs.existsSync(marker) && fs.existsSync(tsx)) return;
  info("Installing Node dependencies (npm install) ...");
  if (npmRun(["install"]) !== 0) {
    warn("npm install failed — retrying with --legacy-peer-deps ...");
    if (npmRun(["install", "--legacy-peer-deps"]) !== 0) fail("npm install failed. Check your internet connection and the messages above.");
  }
}

function readRequirements(file, { skipPySide = false } = {}) {
  return fs
    .readFileSync(path.join(ROOT, file), "utf8")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith("-"))
    .filter((l) => !(skipPySide && /^pyside6/i.test(l)));
}

function pythonModulesOk(modules) {
  const code = modules.map((m) => `import ${m}`).join(";");
  return probe(VENV_PY, ["-c", code]).status === 0;
}

function ensurePython({ needDesktop }) {
  if (!fs.existsSync(VENV_PY)) {
    const sys = findSystemPython();
    if (!sys) fail("Python 3.11+ not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH') and run again.");
    info("Creating Python virtual environment (.venv) ...");
    if (run(sys.cmd, [...sys.pre, "-m", "venv", VENV_DIR]) !== 0 || !fs.existsSync(VENV_PY)) {
      fail("Could not create the virtual environment. On Debian/Ubuntu run: sudo apt install python3-venv");
    }
    run(VENV_PY, ["-m", "pip", "install", "--upgrade", "pip", "-q"]);
  }

  const coreMods = ["sqlalchemy", "alembic", "reportlab", "dotenv", "google.genai"];
  const needed = needDesktop ? [...coreMods, "PySide6"] : coreMods;
  if (!pythonModulesOk(needed)) {
    const reqs = readRequirements("requirements.txt", { skipPySide: !needDesktop });
    info(`Installing Python dependencies (${reqs.length} packages${needDesktop ? ", incl. PySide6 — large download" : ""}) ...`);
    if (run(VENV_PY, ["-m", "pip", "install", ...reqs]) !== 0) fail("pip install failed. Check your internet connection and the messages above.");
  }

  // Optional iOS helpers: try once, never block startup.
  const triedMarker = path.join(VENV_DIR, ".ios-optional-tried");
  if (!fs.existsSync(triedMarker) && fs.existsSync(path.join(ROOT, "requirements-ios.txt"))) {
    info("Installing optional iOS helper packages (safe to fail) ...");
    const st = run(VENV_PY, ["-m", "pip", "install", ...readRequirements("requirements-ios.txt")]);
    if (st !== 0) warn("Optional iOS packages were not installed. Everything else works; encrypted-backup decryption will be unavailable.");
    fs.writeFileSync(triedMarker, new Date().toISOString());
  }
}

function setup({ needDesktop = false } = {}) {
  checkNode();
  ensureEnvFile();
  ensureNodeModules();
  ensurePython({ needDesktop });
}

// -------------------------------------------------------------- web mode ----
function httpGetJson(port, route) {
  return new Promise((resolve) => {
    const req = http.get({ host: "127.0.0.1", port, path: route, timeout: 4000 }, (res) => {
      let body = "";
      res.on("data", (d) => (body += d));
      res.on("end", () => {
        try {
          resolve({ status: res.statusCode, json: JSON.parse(body) });
        } catch {
          resolve({ status: res.statusCode, json: null });
        }
      });
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });
}

const portInUse = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port });
    s.once("connect", () => (s.destroy(), resolve(true)));
    s.once("error", () => resolve(false));
  });

function openBrowser(url) {
  if (flag("no-open")) return;
  try {
    if (IS_WIN) spawn("cmd", ["/c", "start", "", url], { detached: true, stdio: "ignore" }).unref();
    else if (process.platform === "darwin") spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
    else spawn("xdg-open", [url], { detached: true, stdio: "ignore" }).on("error", () => {}).unref();
  } catch {
    /* the URL is printed anyway */
  }
}

async function runWeb() {
  setup({ needDesktop: false });
  const url = `http://localhost:${PORT}`;

  if (await portInUse(PORT)) {
    const probeRes = await httpGetJson(PORT, "/api/cases");
    if (probeRes?.json && "cases" in probeRes.json) {
      ok(`MobileTrace AI is already running at ${url}`);
      openBrowser(url);
      return;
    }
    fail(`Port ${PORT} is used by another program. Close it or run:  node run.mjs --port ${PORT + 1}`);
  }

  info("Starting web console ...");
  const tsxCli = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");
  const env = { ...process.env, PORT: String(PORT) };
  if (flag("localhost-only")) env.MOBILETRACE_HOST = "127.0.0.1";
  const child = spawn(process.execPath, [tsxCli, "server.ts"], { cwd: ROOT, stdio: "inherit", env });

  let up = false;
  const waiter = setInterval(async () => {
    if (up) return;
    const res = await httpGetJson(PORT, "/api/cases");
    if (res && res.status === 200) {
      up = true;
      clearInterval(waiter);
      ok(`Ready ->  ${url}   (press Ctrl+C to stop)`);
      openBrowser(url);
    }
  }, 700);
  setTimeout(() => {
    if (!up) warn("Server is taking longer than expected — check the messages above.");
  }, 45_000);

  const stop = () => child.kill();
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  child.on("exit", (code) => {
    clearInterval(waiter);
    process.exit(code ?? 0);
  });
}

// ---------------------------------------------------------- other modes -----
function runDesktop() {
  setup({ needDesktop: true });
  info("Starting desktop app ...");
  const st = run(VENV_PY, ["-m", "mobiletrace"]);
  process.exit(st);
}

function runTests() {
  setup({ needDesktop: false });
  let failed = 0;
  info("Python tests ...");
  failed += run(VENV_PY, ["-m", "unittest", "discover", "-s", "tests"]) === 0 ? 0 : 1;
  info("TypeScript tests ...");
  failed += npmRun(["test"]) === 0 ? 0 : 1;
  info("TypeScript type check ...");
  failed += npmRun(["run", "lint"]) === 0 ? 0 : 1;
  failed ? fail(`${failed} check group(s) failed.`) : ok("All checks passed.");
}

function runDoctor() {
  const sys = findSystemPython();
  const row = (label, good, detail = "") => console.log(`${good ? c(32, " OK ") : c(31, "MISS")}  ${label}${detail ? "  — " + detail : ""}`);
  row("Node.js 20.11+", Number(process.versions.node.split(".")[0]) >= 20, process.versions.node);
  row("Python 3.11+", !!sys, sys ? [sys.cmd, ...sys.pre].join(" ") : "install from python.org");
  row("node_modules", fs.existsSync(path.join(ROOT, "node_modules", "tsx")));
  row(".venv", fs.existsSync(VENV_PY));
  if (fs.existsSync(VENV_PY)) {
    row("Python core packages", pythonModulesOk(["sqlalchemy", "alembic", "reportlab", "dotenv", "google.genai"]));
    row("PySide6 (desktop app)", pythonModulesOk(["PySide6"]), "only needed for `desktop`");
    row("pymobiledevice3 (optional)", pythonModulesOk(["pymobiledevice3"]));
    row("iphone-backup-decrypt (optional)", pythonModulesOk(["iphone_backup_decrypt"]));
  }
  row(".env file", fs.existsSync(path.join(ROOT, ".env")));
  const adbOk = probe(IS_WIN ? "where" : "which", ["adb"]).status === 0 || fs.existsSync(path.join(ROOT, "tools", "platform-tools", IS_WIN ? "adb.exe" : "adb"));
  row("adb (Android Platform-Tools)", adbOk, adbOk ? "" : "Windows: scripts\\download_platform_tools.ps1");
}

switch (mode) {
  case "web":
    await runWeb();
    break;
  case "desktop":
    runDesktop();
    break;
  case "setup":
    setup({ needDesktop: true });
    ok("Setup complete. Start with:  node run.mjs   (web)   or   node run.mjs desktop");
    break;
  case "test":
    runTests();
    break;
  case "doctor":
    runDoctor();
    break;
  default:
    console.log("Usage: node run.mjs [web|desktop|setup|test|doctor] [--no-open] [--port N] [--localhost-only]");
    process.exit(mode === "help" ? 0 : 1);
}
