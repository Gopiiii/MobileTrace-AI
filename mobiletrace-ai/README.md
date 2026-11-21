# MobileTrace AI — Real-Device Mobile Forensics Workstation

MobileTrace AI is a forensic examination workstation designed for authorized Android and iOS device acquisition, cryptographic SHA-256 verification, unified artifact indexing, timeline analysis, cross-device comparison, and evidence-backed reporting.

## Architecture & Scope Honesty

MobileTrace AI enforces strict forensic integrity:
- **No simulated devices or synthetic extractions.** Every device check, ADB pull, iOS backup inspection, and file transfer operates against real interfaces and reports actual limitations.
- **Android (ADB)**: Uses official Android SDK Platform-Tools (`adb`) to detect connection/authorization state (`device`, `unauthorized`, `offline`), query `getprop`, list permitted paths, pull accessible shared-storage files, and support user-confirmed `adb backup` (subject to Android 12+ OS restrictions). Protected `/data/data/*` app sandboxes and deleted blocks are never claimed as accessible without supported privileges.
- **iPhone / iOS**: Uses `libimobiledevice` (`idevice_id`, `ideviceinfo`, `idevicepair`, `idevicebackup2`) / `pymobiledevice3` for live device trust/backup workflows, plus direct read-only inspection & parsing of Apple MobileSync / iTunes / Finder backups (`Info.plist`, `Manifest.plist`, `Status.plist`, `Manifest.db`, `sms.db`, `AddressBook.sqlitedb`, `CallHistory.storedata`, `History.db`, and JPEG EXIF). Encrypted backups require authorized credentials (`iphone-backup-decrypt` / `pymobiledevice3`). Activation locks and passcodes are never bypassed.
- **Forensic Tooling Integrations**: Integrates real subprocess execution and output ingestion for **ALEAPP** (MIT), **iLEAPP** (MIT), and **MVT** (`mvt-ios` / `mvt-android`, MVT License) when installed on the workstation.
- **Database Persistence**: SQLite with SQLAlchemy 2.0 ORM definitions, Alembic migrations, foreign keys (`PRAGMA foreign_keys = ON`), WAL mode, transactions, and hash-chained append-only `audit_events`.
- **Gemini AI Investigation**: Optional cloud-assisted analysis via official Google Gen AI SDK (`google-genai` / `@google/genai`). Requires explicit analyst approval, enforces PII redaction/minimization, never uploads full backups, and validates every AI-cited `artifact_id` against SQLite. Core acquisition, hashing, parsing, timelines, and PDF/HTML reports work completely offline without an API key.

## Quick Start (recommended)

The launcher installs everything it needs on first run (npm packages, Python virtual environment, `.env`) and then starts the app.

| Platform | Web console (browser) | Desktop app (PySide6) |
| --- | --- | --- |
| Windows | double-click `run.bat` | `run.bat desktop` |
| Linux / macOS | `./run.sh` | `./run.sh desktop` |
| Any | `node run.mjs` | `node run.mjs desktop` |

Other commands: `node run.mjs doctor` (shows what is installed / missing), `node run.mjs setup` (install only), `node run.mjs test` (all tests + type check).
Options: `--port 3001`, `--no-open` (don't open the browser), `--localhost-only` (reachable only from this PC).

Requirements: **Node.js 20.11+** and **Python 3.11+** on `PATH`.

## Windows Manual Setup (PySide6)

```powershell
.\scripts\install_windows.bat
.\scripts\download_platform_tools.ps1
.\.venv\Scripts\python.exe -m mobiletrace
```

### Windows iOS Requirements
Live USB iPhone acquisition on Windows requires:
1. **Apple Mobile Device Support** (installed via Apple Devices app from Microsoft Store or Apple iTunes).
2. **`libimobiledevice` Windows binaries** on `PATH` or configured via `MOBILETRACE_IDEVICE_DIR`.
3. Device unlocked and **Trust This Computer** confirmed by the custodian.

Importing existing local iTunes / Finder / `idevicebackup2` backup folders works directly without live USB drivers.
`pymobiledevice3` / `iphone-backup-decrypt` (see `requirements-ios.txt`) are optional and only needed for encrypted-backup decryption.

## Web Companion Console (Local Workstation Server)

Node/Express + Vite console backed directly by the Python `mobiletrace` forensic engine and SQLite database.
`node run.mjs` is the easiest way to start it; manually:

```bash
npm install
npm run dev          # development (Vite middleware)
npm run build && npm start   # production build served by the same server
```

Environment: `PORT` (default 3000) and `MOBILETRACE_HOST` (default `0.0.0.0`; use `127.0.0.1` for local-only access).

## Running Tests

```bash
# Python forensic core unit & integration tests
python3 -m unittest discover -s tests -v

# TypeScript UI validation tests + type check
npm test
npm run lint
```
