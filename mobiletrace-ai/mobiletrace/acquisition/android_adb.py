"""Real Android acquisition using official Android SDK Platform-Tools (ADB)."""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from mobiletrace.core.hashing import sha256_file
from mobiletrace.core.validation import resolve_confined_path, validate_adb_remote_path
from mobiletrace.db.repository import ForensicRepository


ADB_LIMITATIONS_DEFAULT = [
    "Accessible-file collection via official ADB only; not a full-filesystem or physical extraction.",
    "Protected application private sandboxes (/data/data/*) and deleted/unallocated blocks are inaccessible on unrooted production Android devices.",
    "Device must remain unlocked with USB Debugging authorized by the device owner/custodian.",
]

_GETPROP_RE = re.compile(r"^\[([^\]]+)\]:\s*\[(.*)\]$")
_LS_LINE_RE = re.compile(
    r"^([bcdlps-][rwxstST-]{9})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+(.+)$"
)


@dataclass
class ADBDeviceInfo:
    serial: str
    state: str
    authorized: bool
    product: str = ""
    model: str = ""
    device: str = ""
    transport_id: str = ""
    manufacturer: str = ""
    os_version: str = ""
    sdk_version: str = ""
    fingerprint: str = ""
    security_patch: str = ""
    status_note: str = ""
    properties: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ADBDirectoryEntry:
    name: str
    remote_path: str
    is_dir: bool
    is_symlink: bool
    permissions: str
    size_bytes: int
    mtime: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_adb_devices_output(stdout: str) -> list[ADBDeviceInfo]:
    devices: list[ADBDeviceInfo] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("List of devices attached") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial = parts[0]
        state = parts[1]
        kv: dict[str, str] = {}
        for token in parts[2:]:
            if ":" in token:
                k, v = token.split(":", 1)
                kv[k] = v
        authorized = state == "device"
        note = ""
        if state == "unauthorized":
            note = "USB debugging RSA authorization prompt has not been accepted on the Android device."
        elif state == "offline":
            note = "Device is offline; reconnect USB cable or restart ADB server."
        elif state == "no permissions":
            note = "Insufficient OS USB permissions (udev rules on Linux or ADB USB driver on Windows)."
        devices.append(
            ADBDeviceInfo(
                serial=serial,
                state=state,
                authorized=authorized,
                product=kv.get("product", ""),
                model=kv.get("model", "").replace("_", " "),
                device=kv.get("device", ""),
                transport_id=kv.get("transport_id", ""),
                status_note=note,
            )
        )
    return devices


def parse_getprop_output(stdout: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in stdout.splitlines():
        m = _GETPROP_RE.match(line.strip())
        if m:
            props[m.group(1)] = m.group(2)
    return props


def parse_ls_la_output(stdout: str, parent_remote_path: str) -> list[ADBDirectoryEntry]:
    entries: list[ADBDirectoryEntry] = []
    base = parent_remote_path.rstrip("/") or "/"
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("total "):
            continue
        m = _LS_LINE_RE.match(line)
        if not m:
            continue
        perms, _owner, _group, size_str, mtime, raw_name = m.groups()
        is_symlink = perms.startswith("l")
        name = raw_name.split(" -> ", 1)[0] if is_symlink else raw_name
        if name in {".", ".."}:
            continue
        is_dir = perms.startswith("d")
        remote_path = f"{base}/{name}" if base != "/" else f"/{name}"
        entries.append(
            ADBDirectoryEntry(
                name=name,
                remote_path=remote_path,
                is_dir=is_dir,
                is_symlink=is_symlink,
                permissions=perms,
                size_bytes=int(size_str),
                mtime=mtime,
            )
        )
    return entries


class AndroidADBClient:
    """Official Android SDK Platform-Tools (adb) wrapper with strict authorization & path checks."""

    def __init__(self, adb_path: str | None) -> None:
        self.adb_path = adb_path

    def _run(self, args: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
        if not self.adb_path:
            raise FileNotFoundError(
                "Android Platform-Tools (adb) not found. Install via scripts/download_platform_tools.ps1 or set MOBILETRACE_ADB_PATH."
            )
        return subprocess.run(
            [self.adb_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )

    def check_availability(self) -> dict[str, Any]:
        if not self.adb_path:
            return {
                "available": False,
                "adb_path": None,
                "version": None,
                "guidance": "Android SDK Platform-Tools (adb) is not installed on this workstation. Run scripts/download_platform_tools.ps1 on Windows or install android-tools-adb.",
            }
        try:
            proc = self._run(["version"], timeout=10.0)
            first_line = proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""
            return {
                "available": proc.returncode == 0,
                "adb_path": self.adb_path,
                "version": first_line,
                "guidance": "" if proc.returncode == 0 else proc.stderr.strip(),
            }
        except Exception as exc:
            return {
                "available": False,
                "adb_path": self.adb_path,
                "version": None,
                "guidance": f"Failed to execute adb: {exc}",
            }

    def list_devices(self) -> dict[str, Any]:
        avail = self.check_availability()
        if not avail["available"]:
            return {"adb_available": False, "devices": [], "error": avail["guidance"]}
        proc = self._run(["devices", "-l"], timeout=15.0)
        if proc.returncode != 0:
            return {"adb_available": True, "devices": [], "error": proc.stderr.strip() or "adb devices failed"}
        devices = parse_adb_devices_output(proc.stdout)
        for dev in devices:
            if dev.authorized:
                try:
                    prop_proc = self._run(["-s", dev.serial, "shell", "getprop"], timeout=15.0)
                    if prop_proc.returncode == 0:
                        props = parse_getprop_output(prop_proc.stdout)
                        dev.manufacturer = props.get("ro.product.manufacturer", "")
                        dev.model = props.get("ro.product.model", dev.model)
                        dev.os_version = props.get("ro.build.version.release", "")
                        dev.sdk_version = props.get("ro.build.version.sdk", "")
                        dev.fingerprint = props.get("ro.build.fingerprint", "")
                        dev.security_patch = props.get("ro.build.version.security_patch", "")
                        dev.properties = {
                            k: v
                            for k, v in props.items()
                            if k
                            in {
                                "ro.product.manufacturer",
                                "ro.product.model",
                                "ro.product.device",
                                "ro.build.version.release",
                                "ro.build.version.sdk",
                                "ro.build.version.security_patch",
                                "ro.build.fingerprint",
                                "ro.crypto.state",
                                "ro.hardware",
                            }
                        }
                except Exception as exc:
                    dev.status_note = f"Authorized, but getprop failed: {exc}"
        return {"adb_available": True, "devices": [d.to_dict() for d in devices], "error": None}

    def list_directory(self, serial: str, remote_path: str) -> dict[str, Any]:
        safe_remote = validate_adb_remote_path(remote_path)
        quoted = shlex.quote(safe_remote)
        proc = self._run(["-s", serial, "shell", f"ls -la {quoted}"], timeout=20.0)
        if proc.returncode != 0:
            return {
                "remote_path": safe_remote,
                "entries": [],
                "error": proc.stderr.strip() or proc.stdout.strip() or "Directory listing failed",
            }
        entries = parse_ls_la_output(proc.stdout, safe_remote)
        err_lines = [
            ln.strip()
            for ln in (proc.stderr + "\n" + proc.stdout).splitlines()
            if "Permission denied" in ln or "No such file" in ln
        ]
        return {
            "remote_path": safe_remote,
            "entries": [e.to_dict() for e in entries],
            "error": "; ".join(err_lines) if err_lines and not entries else None,
            "warnings": err_lines,
        }

    def _enumerate_remote_files(
        self,
        serial: str,
        remote_roots: list[str],
        max_depth: int = 4,
    ) -> tuple[list[ADBDirectoryEntry], list[str]]:
        discovered: list[ADBDirectoryEntry] = []
        errors: list[str] = []
        queue: list[tuple[str, int]] = [(validate_adb_remote_path(r), 0) for r in remote_roots]
        visited: set[str] = set()
        while queue:
            current_path, depth = queue.pop(0)
            if current_path in visited:
                continue
            visited.add(current_path)
            res = self.list_directory(serial, current_path)
            if res.get("error"):
                errors.append(f"{current_path}: {res['error']}")
            for warn in res.get("warnings", []):
                errors.append(f"{current_path}: {warn}")
            for raw_entry in res.get("entries", []):
                entry = ADBDirectoryEntry(**raw_entry)
                if entry.is_dir:
                    if depth < max_depth:
                        queue.append((entry.remote_path, depth + 1))
                elif not entry.is_symlink:
                    discovered.append(entry)
        return discovered, errors

    def acquire_accessible_files(
        self,
        *,
        repo: ForensicRepository,
        case_id: str,
        device_id: str,
        serial: str,
        remote_roots: list[str],
        output_dir: Path,
        actor: str = "examiner",
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, Any]:
        avail = self.check_availability()
        if not avail["available"]:
            raise RuntimeError(avail["guidance"])
        devices_res = self.list_devices()
        target = next((d for d in devices_res["devices"] if d["serial"] == serial), None)
        if not target:
            raise RuntimeError(f"Android device {serial} is not connected.")
        if not target["authorized"]:
            raise RuntimeError(
                f"Android device {serial} is in state '{target['state']}', not authorized ('device'). "
                f"{target.get('status_note', '')}"
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        limitations = list(ADB_LIMITATIONS_DEFAULT)
        session = repo.create_acquisition_session(
            case_id=case_id,
            device_id=device_id,
            acquisition_method="adb_accessible_pull",
            scope_classification="accessible_shared_storage_only",
            source_location=",".join(remote_roots),
            output_directory=str(output_dir),
            limitations=limitations,
            actor=actor,
        )
        session_id = session["session_id"]
        files_copied = 0
        bytes_copied = 0
        errors: list[str] = []

        try:
            entries, enum_errors = self._enumerate_remote_files(serial, remote_roots)
            errors.extend(enum_errors)
            total = len(entries)
            for idx, entry in enumerate(entries, start=1):
                rel = entry.remote_path.lstrip("/")
                dest_path = resolve_confined_path(output_dir, rel)
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                pull_proc = self._run(["-s", serial, "pull", "-a", entry.remote_path, str(dest_path)], timeout=120.0)
                if pull_proc.returncode != 0 or not dest_path.is_file():
                    errors.append(
                        f"Failed to pull {entry.remote_path}: {pull_proc.stderr.strip() or pull_proc.stdout.strip()}"
                    )
                    continue
                digest, actual_bytes = sha256_file(dest_path)
                if entry.size_bytes > 0 and actual_bytes != entry.size_bytes:
                    errors.append(
                        f"Size mismatch for {entry.remote_path}: remote={entry.size_bytes}, local={actual_bytes}"
                    )
                files_copied += 1
                bytes_copied += actual_bytes
                repo.add_artifact(
                    case_id=case_id,
                    device_id=device_id,
                    session_id=session_id,
                    artifact_type="acquired_file",
                    title=entry.name,
                    summary=f"ADB accessible pull ({actual_bytes} bytes)",
                    original_source_path=entry.remote_path,
                    stored_copy_path=str(dest_path),
                    original_timestamp=entry.mtime,
                    original_timezone="device_local_unspecified",
                    normalized_timestamp_utc="",
                    normalization_justification="ADB ls -la mtime has no explicit timezone offset; preserved verbatim.",
                    acquisition_method="adb_accessible_pull",
                    parser_name="android_adb",
                    parser_version="1.0.0",
                    sha256=digest,
                    byte_size=actual_bytes,
                    provenance={
                        "serial": serial,
                        "permissions": entry.permissions,
                        "scope": "accessible_shared_storage_only",
                    },
                    content={"remote_path": entry.remote_path, "local_path": str(dest_path)},
                    timeline_event_type="file_mtime",
                    timeline_confidence="device_local_unverified_tz",
                    actor=actor,
                )
                if on_progress is not None:
                    on_progress(idx, total, entry.remote_path)

            final_status = "completed" if not errors else ("completed_with_errors" if files_copied > 0 else "failed")
            return repo.finalize_acquisition_session(
                session_id=session_id,
                status=final_status,
                files_copied=files_copied,
                bytes_copied=bytes_copied,
                errors=errors,
                limitations=limitations,
                actor=actor,
            )
        except Exception as exc:
            errors.append(str(exc))
            repo.finalize_acquisition_session(
                session_id=session_id,
                status="failed",
                files_copied=files_copied,
                bytes_copied=bytes_copied,
                errors=errors,
                limitations=limitations,
                actor=actor,
            )
            raise

    def create_adb_backup(
        self,
        *,
        serial: str,
        dest_ab_path: Path,
        include_shared: bool = True,
        include_apks: bool = False,
        timeout: float = 300.0,
    ) -> dict[str, Any]:
        """Run user-confirmed `adb backup` (requires device-side owner approval; restricted on Android 12+)."""
        dest_ab_path.parent.mkdir(parents=True, exist_ok=True)
        flags = ["-s", serial, "backup", "-all"]
        flags.append("-shared" if include_shared else "-noshared")
        flags.append("-apk" if include_apks else "-noapk")
        flags.extend(["-f", str(dest_ab_path)])
        proc = self._run(flags, timeout=timeout)
        exists = dest_ab_path.is_file() and dest_ab_path.stat().st_size > 24
        sha256_val, byte_size = sha256_file(dest_ab_path) if dest_ab_path.is_file() else ("", 0)
        return {
            "success": proc.returncode == 0 and exists,
            "output_path": str(dest_ab_path),
            "byte_size": byte_size,
            "sha256": sha256_val,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "limitation": "adb backup is deprecated on Android 12+ and apps with android:allowBackup='false' are excluded by the OS.",
        }
