"""Configuration and external binary/tool discovery for MobileTrace AI."""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path


def _find_project_root() -> Path:
    """Folder that holds pyproject.toml / .env / data/ (independent of the launch directory)."""
    root = Path(__file__).resolve().parent.parent
    return root if (root / "pyproject.toml").is_file() else Path.cwd().resolve()


PROJECT_ROOT = _find_project_root()


def _load_dotenv_if_present() -> None:
    env_path = PROJECT_ROOT / ".env"
    if not env_path.is_file():
        env_path = Path(os.getcwd()) / ".env"
    if not env_path.is_file():
        return
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass


@dataclass
class WorkstationConfig:
    db_path: Path
    workspace_dir: Path
    adb_path: str | None = None
    idevice_dir: Path | None = None
    aleapp_path: str | None = None
    ileapp_path: str | None = None
    mvt_ios_path: str | None = None
    mvt_android_path: str | None = None
    gemini_model: str = "gemini-4-hydrogen"
    redact_pii: bool = True
    host_os: str = field(default_factory=platform.system)

    @property
    def gemini_configured(self) -> bool:
        key = os.environ.get("GEMINI_API_KEY", "").strip()
        return bool(key and key != "MY_GEMINI_API_KEY")

    def ensure_directories(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        for sub in ("acquisitions", "transfers", "reports", "backups", "analysis"):
            (self.workspace_dir / sub).mkdir(parents=True, exist_ok=True)


def _find_adb(explicit: str | None) -> str | None:
    if explicit and Path(explicit).is_file():
        return str(Path(explicit).resolve())
    candidates: list[Path] = []
    if platform.system() == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", "")
        candidates.extend(
            [
                PROJECT_ROOT / "platform-tools" / "adb.exe",
                PROJECT_ROOT / "tools" / "platform-tools" / "adb.exe",
                Path.cwd() / "platform-tools" / "adb.exe",
                Path.cwd() / "tools" / "platform-tools" / "adb.exe",
                Path(local_app) / "Android" / "Sdk" / "platform-tools" / "adb.exe" if local_app else Path("__none__"),
                Path("C:/platform-tools/adb.exe"),
            ]
        )
    else:
        candidates.extend(
            [
                PROJECT_ROOT / "platform-tools" / "adb",
                PROJECT_ROOT / "tools" / "platform-tools" / "adb",
                Path.cwd() / "platform-tools" / "adb",
                Path.cwd() / "tools" / "platform-tools" / "adb",
            ]
        )
    for cand in candidates:
        if cand.is_file():
            return str(cand.resolve())
    return shutil.which("adb")


def _is_usable_path_env(raw: str) -> bool:
    val = raw.strip()
    if not val:
        return False
    # Ignore Windows drive-letter paths (e.g. D:\Download\MobileTrace) when running on Linux/macOS
    if platform.system() != "Windows" and len(val) >= 3 and val[0].isalpha() and val[1] == ":" and val[2] in ("\\", "/"):
        return False
    return True


def _find_tool(env_var: str, names: list[str]) -> str | None:
    explicit = os.environ.get(env_var, "").strip()
    if _is_usable_path_env(explicit) and Path(explicit).exists():
        return str(Path(explicit).resolve())
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _resolve_user_path(raw: str, default_rel: str) -> Path:
    """Resolve a configured path; relative paths are anchored at the project root, not the cwd."""
    candidate = Path(raw.strip()) if _is_usable_path_env(raw) else Path(default_rel)
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


def _resolve_gemini_model(raw: str) -> str:
    val = raw.strip()
    if val and "/" not in val and "\\" not in val and val.lower().startswith("gemini-"):
        return val
    return "gemini-4-hydrogen"


def load_config() -> WorkstationConfig:
    _load_dotenv_if_present()
    raw_db = os.environ.get("MOBILETRACE_DB_PATH", "").strip()
    db_path = _resolve_user_path(raw_db, "data/mobiletrace.db")
    if db_path.is_dir() or not db_path.suffix:
        db_path = db_path / "mobiletrace.db"

    raw_ws = os.environ.get("MOBILETRACE_WORKSPACE_DIR", "").strip()
    workspace_dir = _resolve_user_path(raw_ws, "data/workspace")

    idevice_dir_raw = os.environ.get("MOBILETRACE_IDEVICE_DIR", "").strip()
    idevice_dir = _resolve_user_path(idevice_dir_raw, ".") if _is_usable_path_env(idevice_dir_raw) else None

    raw_adb = os.environ.get("MOBILETRACE_ADB_PATH", "").strip()
    adb_override = raw_adb if _is_usable_path_env(raw_adb) else None

    cfg = WorkstationConfig(
        db_path=db_path,
        workspace_dir=workspace_dir,
        adb_path=_find_adb(adb_override),
        idevice_dir=idevice_dir,
        aleapp_path=_find_tool("MOBILETRACE_ALEAPP_PATH", ["aleapp", "aleapp.py"]),
        ileapp_path=_find_tool("MOBILETRACE_ILEAPP_PATH", ["ileapp", "ileapp.py"]),
        mvt_ios_path=_find_tool("MOBILETRACE_MVT_IOS_PATH", ["mvt-ios"]),
        mvt_android_path=_find_tool("MOBILETRACE_MVT_ANDROID_PATH", ["mvt-android"]),
        gemini_model=_resolve_gemini_model(os.environ.get("MOBILETRACE_GEMINI_MODEL", "")),
        redact_pii=os.environ.get("MOBILETRACE_REDACT_PII", "true").strip().lower() not in {"0", "false", "no"},
    )
    cfg.ensure_directories()
    return cfg
