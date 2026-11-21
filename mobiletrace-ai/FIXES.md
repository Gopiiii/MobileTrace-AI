# What was fixed

1. **`npm install` failed (ERESOLVE)** – `esbuild ^0.25` conflicted with Vite 8 (needs ^0.27/^0.28). Bumped to `^0.28.0`; project name set to `mobiletrace-ai`.
2. **`npm start` crashed** (`ERR_MODULE_NOT_FOUND`) – now runs through `tsx` in production mode (`--prod`), serving `dist/` if built.
3. **CLI error messages were swallowed** – the UI always showed "Command failed: …". Real messages (e.g. "adb not found", "Case not found") now reach the UI.
4. **Vite watched `.venv` / `data/`** – thousands of files, `ENOSPC` watcher spam / high CPU. Now ignored.
5. **Paths depended on the launch folder** – `.env`, `data/mobiletrace.db`, workspace and `tools/platform-tools/adb` were looked up in the current directory (desktop app launched from elsewhere = missing `.env`, a second empty database). Now anchored to the project root.
6. **Windows scripts** – `install_windows.ps1` / `download_platform_tools.ps1` now work from any folder, find Python via `py -3`, treat the optional iOS packages as non-fatal, and the `.bat` pauses so errors stay visible.
7. **Optional iOS packages split out** – `requirements-ios.txt` (pymobiledevice3, iphone-backup-decrypt) so a failure there no longer breaks the whole install. `pytest` moved to `requirements-dev.txt`.
8. **Misleading iOS diagnostics text** ("iOS tooling detected" while libimobiledevice was missing) – now accurate.
9. **Test fixed** – PDF header assertion was hard-coded to `%PDF-1.4`; reportlab writes `1.3`.
10. **Minor** – `PORT` / `MOBILETRACE_HOST` env support, clear "port already in use" message, Vite `__dirname` warning removed, cross-platform `npm run clean`, `npm test` script.

# New: one-command launcher

`run.bat` (Windows double-click) · `./run.sh` · `node run.mjs [web|desktop|setup|test|doctor]`
