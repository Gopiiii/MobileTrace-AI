"""Real iPhone / iOS device detection and supported local/encrypted backup workflow."""

from __future__ import annotations

import os
import platform
import plistlib
import shutil
import sqlite3
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mobiletrace.core.hashing import sha256_file
from mobiletrace.db.repository import ForensicRepository


IOS_LIMITATIONS_DEFAULT = [
    "iOS acquisition relies on Apple-supported device pairing and local backup interfaces (libimobiledevice / pymobiledevice3 / Apple MobileSync).",
    "Unrestricted iOS full-filesystem access is not available on non-jailbroken retail devices.",
    "Device passcode, trust prompt, and backup encryption cannot and will not be bypassed.",
]


@dataclass
class iOSDeviceInfo:
    udid: str
    connection_state: str
    paired: bool
    device_name: str = ""
    product_type: str = ""
    product_version: str = ""
    build_version: str = ""
    serial_number: str = ""
    hardware_model: str = ""
    status_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_ideviceinfo_output(stdout: str) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return info


class iOSBackupClient:
    """Real iOS device and backup interface using libimobiledevice / pymobiledevice3 / local backup folders."""

    def __init__(self, idevice_dir: Path | None = None) -> None:
        self.idevice_dir = idevice_dir

    def _find_binary(self, name: str) -> str | None:
        candidates: list[Path] = []
        if self.idevice_dir:
            candidates.append(self.idevice_dir / f"{name}.exe")
            candidates.append(self.idevice_dir / name)
        if platform.system() == "Windows":
            candidates.extend(
                [
                    Path.cwd() / "tools" / "libimobiledevice" / f"{name}.exe",
                    Path("C:/libimobiledevice") / f"{name}.exe",
                ]
            )
        for cand in candidates:
            if cand.is_file():
                return str(cand.resolve())
        return shutil.which(name)

    def check_tooling(self) -> dict[str, Any]:
        tools = {
            "idevice_id": self._find_binary("idevice_id"),
            "ideviceinfo": self._find_binary("ideviceinfo"),
            "idevicepair": self._find_binary("idevicepair"),
            "idevicebackup2": self._find_binary("idevicebackup2"),
        }
        pymobile3 = shutil.which("pymobiledevice3")
        try:
            import pymobiledevice3  # type: ignore # noqa: F401
            pymobile3_mod = True
        except ImportError:
            pymobile3_mod = False
        try:
            import iphone_backup_decrypt  # type: ignore # noqa: F401
            decrypt_mod = True
        except ImportError:
            decrypt_mod = False

        libimobile_ok = bool(tools["idevice_id"] and tools["ideviceinfo"])
        windows_notes: list[str] = []
        if not libimobile_ok:
            if platform.system() == "Windows":
                windows_notes.append(
                    "On Windows, live iOS USB acquisition requires Apple Mobile Device Support (via Apple Devices or iTunes) plus libimobiledevice binaries "
                    "(put them on PATH or set MOBILETRACE_IDEVICE_DIR)."
                )
            else:
                windows_notes.append(
                    "libimobiledevice (idevice_id / ideviceinfo) was not found, so live iOS USB detection is unavailable. "
                    "Install it (e.g. 'apt install libimobiledevice-utils' or 'brew install libimobiledevice') or set MOBILETRACE_IDEVICE_DIR."
                )
            windows_notes.append(
                "Local iTunes/Finder/idevicebackup2 backup folder import & forensic parsing remain available without live USB drivers."
            )

        return {
            "libimobiledevice_available": libimobile_ok,
            "binaries": tools,
            "pymobiledevice3_available": bool(pymobile3 or pymobile3_mod),
            "encrypted_backup_decrypt_available": decrypt_mod or pymobile3_mod,
            "host_os": platform.system(),
            "guidance": " ".join(windows_notes) if windows_notes else "iOS tooling detected.",
        }

    def detect_devices(self) -> dict[str, Any]:
        tooling = self.check_tooling()
        idevice_id = tooling["binaries"]["idevice_id"]
        if not idevice_id:
            return {
                "tooling_available": False,
                "devices": [],
                "guidance": tooling["guidance"],
            }

        proc = subprocess.run([idevice_id, "-l"], capture_output=True, text=True, timeout=15.0, shell=False)
        if proc.returncode != 0:
            return {
                "tooling_available": True,
                "devices": [],
                "error": proc.stderr.strip() or "idevice_id failed (check usbmuxd / Apple Mobile Device Service).",
            }

        udids = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        devices: list[iOSDeviceInfo] = []
        idevicepair = tooling["binaries"]["idevicepair"]
        ideviceinfo = tooling["binaries"]["ideviceinfo"]

        for udid in udids:
            paired = False
            conn_state = "detected"
            note = ""
            if idevicepair:
                p_proc = subprocess.run(
                    [idevicepair, "-u", udid, "validate"],
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    shell=False,
                )
                out_text = (p_proc.stdout + " " + p_proc.stderr).strip()
                if p_proc.returncode == 0 and "SUCCESS" in out_text.upper():
                    paired = True
                    conn_state = "paired_trusted"
                else:
                    conn_state = "untrusted_or_locked"
                    note = (
                        out_text
                        or "Unlock iPhone, tap 'Trust This Computer', and enter device passcode."
                    )
            info_map: dict[str, str] = {}
            if ideviceinfo and paired:
                i_proc = subprocess.run(
                    [ideviceinfo, "-u", udid],
                    capture_output=True,
                    text=True,
                    timeout=15.0,
                    shell=False,
                )
                if i_proc.returncode == 0:
                    info_map = parse_ideviceinfo_output(i_proc.stdout)

            devices.append(
                iOSDeviceInfo(
                    udid=udid,
                    connection_state=conn_state,
                    paired=paired,
                    device_name=info_map.get("DeviceName", ""),
                    product_type=info_map.get("ProductType", ""),
                    product_version=info_map.get("ProductVersion", ""),
                    build_version=info_map.get("BuildVersion", ""),
                    serial_number=info_map.get("SerialNumber", ""),
                    hardware_model=info_map.get("HardwareModel", ""),
                    status_note=note,
                )
            )
        return {"tooling_available": True, "devices": [d.to_dict() for d in devices], "guidance": tooling["guidance"]}

    def create_local_backup(
        self,
        *,
        udid: str,
        backup_root: Path,
        timeout: float = 1800.0,
    ) -> dict[str, Any]:
        tooling = self.check_tooling()
        idevicebackup2 = tooling["binaries"]["idevicebackup2"]
        if not idevicebackup2:
            raise RuntimeError(
                "idevicebackup2 binary not found. Install libimobiledevice or import an existing Apple Devices / iTunes backup directory."
            )
        backup_root.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [idevicebackup2, "-u", udid, "backup", "--full", str(backup_root)],
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "success": proc.returncode == 0,
            "udid": udid,
            "backup_root": str(backup_root),
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }

    def inspect_backup_directory(self, backup_dir: Path) -> dict[str, Any]:
        """Inspect a real iTunes / Finder / idevicebackup2 backup directory without altering source files."""
        backup_dir = backup_dir.resolve()
        if not backup_dir.is_dir():
            raise FileNotFoundError(f"Backup directory does not exist: {backup_dir}")

        info_plist = backup_dir / "Info.plist"
        manifest_plist = backup_dir / "Manifest.plist"
        status_plist = backup_dir / "Status.plist"
        manifest_db = backup_dir / "Manifest.db"

        info_data: dict[str, Any] = {}
        manifest_data: dict[str, Any] = {}
        status_data: dict[str, Any] = {}
        errors: list[str] = []

        if info_plist.is_file():
            try:
                with info_plist.open("rb") as f:
                    info_data = plistlib.load(f)
            except Exception as exc:
                errors.append(f"Failed to parse Info.plist: {exc}")
        else:
            errors.append("Info.plist missing from backup directory.")

        if manifest_plist.is_file():
            try:
                with manifest_plist.open("rb") as f:
                    manifest_data = plistlib.load(f)
            except Exception as exc:
                errors.append(f"Failed to parse Manifest.plist: {exc}")
        else:
            errors.append("Manifest.plist missing from backup directory.")

        if status_plist.is_file():
            try:
                with status_plist.open("rb") as f:
                    status_data = plistlib.load(f)
            except Exception as exc:
                errors.append(f"Failed to parse Status.plist: {exc}")

        is_encrypted = bool(manifest_data.get("IsEncrypted", False))
        lockdown = manifest_data.get("Lockdown", {}) if isinstance(manifest_data.get("Lockdown"), dict) else {}
        apps = manifest_data.get("Applications", {}) if isinstance(manifest_data.get("Applications"), dict) else {}

        file_count = 0
        if manifest_db.is_file() and not is_encrypted:
            try:
                conn = sqlite3.connect(f"file:{manifest_db}?mode=ro", uri=True)
                try:
                    row = conn.execute("SELECT COUNT(*) FROM Files").fetchone()
                    file_count = int(row[0]) if row else 0
                finally:
                    conn.close()
            except Exception as exc:
                errors.append(f"Unable to read Manifest.db: {exc}")

        return {
            "backup_dir": str(backup_dir),
            "valid_structure": manifest_plist.is_file() and (manifest_db.is_file() or is_encrypted),
            "is_encrypted": is_encrypted,
            "udid": info_data.get("Unique Identifier") or lockdown.get("UniqueDeviceID") or backup_dir.name,
            "device_name": info_data.get("Device Name") or lockdown.get("DeviceName", ""),
            "product_type": info_data.get("Product Type") or lockdown.get("ProductType", ""),
            "product_version": info_data.get("Product Version") or lockdown.get("ProductVersion", ""),
            "serial_number": info_data.get("Serial Number") or lockdown.get("SerialNumber", ""),
            "build_version": info_data.get("Build Version") or lockdown.get("BuildVersion", ""),
            "last_backup_date": str(info_data.get("Last Backup Date", "")),
            "backup_state": status_data.get("BackupState", ""),
            "snapshot_state": status_data.get("SnapshotState", ""),
            "installed_app_count": len(apps),
            "manifest_file_count": file_count,
            "errors": errors,
        }

    def import_local_backup(
        self,
        *,
        repo: ForensicRepository,
        case_id: str,
        backup_dir: Path,
        backup_password: str | None = None,
        decrypted_output_dir: Path | None = None,
        actor: str = "examiner",
    ) -> dict[str, Any]:
        """Validate, register, and index an iOS backup into the forensic database without modifying originals."""
        meta = self.inspect_backup_directory(backup_dir)
        limitations = list(IOS_LIMITATIONS_DEFAULT)
        errors = list(meta["errors"])
        working_dir = Path(backup_dir).resolve()
        acq_method = "ios_local_backup_import"

        if meta["is_encrypted"]:
            acq_method = "ios_encrypted_backup_import"
            if not backup_password:
                raise ValueError(
                    "This iOS backup is encrypted (IsEncrypted=true). Supply the authorized backup password to decrypt a working copy; MobileTrace AI never bypasses encryption."
                )
            if not decrypted_output_dir:
                raise ValueError("decrypted_output_dir is required when importing an encrypted iOS backup.")
            try:
                from iphone_backup_decrypt import EncryptedBackup  # type: ignore

                decrypted_output_dir.mkdir(parents=True, exist_ok=True)
                eb = EncryptedBackup(backup_directory=str(working_dir), passphrase=backup_password)
                manifest_out = decrypted_output_dir / "Manifest.db"
                eb.save_manifest_file(str(manifest_out))
                # Extract supported forensic databases into decrypted working Manifest.db fileID layout
                if manifest_out.is_file():
                    mconn = sqlite3.connect(f"file:{manifest_out}?mode=ro", uri=True)
                    try:
                        targets = (
                            "Library/SMS/sms.db",
                            "Library/AddressBook/AddressBook.sqlitedb",
                            "Library/CallHistoryDB/CallHistory.storedata",
                            "Library/CallHistory/call_history.db",
                            "Library/Safari/History.db",
                        )
                        placeholders = ",".join("?" for _ in targets)
                        rows = mconn.execute(
                            f"SELECT fileID, relativePath FROM Files WHERE flags = 1 AND relativePath IN ({placeholders})",
                            targets,
                        ).fetchall()
                        for fid, relp in rows:
                            out_f = decrypted_output_dir / fid[:2] / fid
                            out_f.parent.mkdir(parents=True, exist_ok=True)
                            try:
                                eb.extract_file(relative_path=relp, output_filename=str(out_f))
                            except Exception as ext_exc:
                                errors.append(f"Encrypted extraction warning ({relp}): {ext_exc}")
                    finally:
                        mconn.close()
                # Copy unencrypted metadata plists alongside decrypted working Manifest.db
                for plist_name in ("Info.plist", "Manifest.plist", "Status.plist"):
                    src_plist = working_dir / plist_name
                    if src_plist.is_file():
                        shutil.copy2(src_plist, decrypted_output_dir / plist_name)
                working_dir = decrypted_output_dir.resolve()
                limitations.append("Encrypted backup decrypted into an isolated analysis working copy using authorized credentials; original encrypted backup preserved untouched.")
            except ImportError as exc:
                raise RuntimeError(
                    "Encrypted iOS backup decryption requires 'iphone-backup-decrypt' (or pymobiledevice3) installed in the Python environment."
                ) from exc

        device = repo.register_device(
            case_id=case_id,
            platform="ios",
            serial_or_udid=str(meta["udid"]),
            manufacturer="Apple",
            model=str(meta["product_type"] or meta["device_name"] or "iPhone"),
            os_version=str(meta["product_version"]),
            build_or_sdk=str(meta["build_version"]),
            connection_state="local_backup_imported",
            metadata={
                "device_name": meta["device_name"],
                "serial_number": meta["serial_number"],
                "is_encrypted": meta["is_encrypted"],
                "last_backup_date": meta["last_backup_date"],
            },
            actor=actor,
        )

        session = repo.create_acquisition_session(
            case_id=case_id,
            device_id=device["device_id"],
            acquisition_method=acq_method,
            scope_classification="ios_logical_backup",
            source_location=str(backup_dir),
            output_directory=str(working_dir),
            limitations=limitations,
            actor=actor,
        )

        files_hashed = 0
        bytes_hashed = 0
        for plist_name in ("Info.plist", "Manifest.plist", "Status.plist", "Manifest.db"):
            p = working_dir / plist_name
            if p.is_file():
                digest, size_b = sha256_file(p)
                files_hashed += 1
                bytes_hashed += size_b
                repo.add_artifact(
                    case_id=case_id,
                    device_id=device["device_id"],
                    session_id=session["session_id"],
                    artifact_type="ios_backup_metadata",
                    title=plist_name,
                    summary=f"iOS backup provenance file ({size_b} bytes)",
                    original_source_path=str(Path(backup_dir) / plist_name),
                    stored_copy_path=str(p),
                    original_timestamp=meta["last_backup_date"],
                    original_timezone="backup_plist_timestamp",
                    normalized_timestamp_utc=_normalize_iso_or_empty(meta["last_backup_date"]),
                    normalization_justification="Parsed from Apple Info.plist Last Backup Date if UTC-aware.",
                    acquisition_method=acq_method,
                    parser_name="ios_backup_inspector",
                    parser_version="1.0.0",
                    sha256=digest,
                    byte_size=size_b,
                    provenance={"udid": meta["udid"], "is_encrypted": meta["is_encrypted"]},
                    content={"backup_state": meta["backup_state"], "snapshot_state": meta["snapshot_state"]},
                    timeline_event_type="ios_backup_created" if plist_name == "Info.plist" else None,
                    timeline_confidence="plist_metadata",
                    actor=actor,
                )

        # Register Manifest.plist installed applications if present
        manifest_plist = working_dir / "Manifest.plist"
        if manifest_plist.is_file():
            try:
                with manifest_plist.open("rb") as f:
                    mdata = plistlib.load(f)
                apps = mdata.get("Applications", {})
                if isinstance(apps, dict):
                    for bundle_id, app_meta in apps.items():
                        repo.add_artifact(
                            case_id=case_id,
                            device_id=device["device_id"],
                            session_id=session["session_id"],
                            artifact_type="installed_application",
                            title=str(bundle_id),
                            summary="Installed iOS application recorded in Manifest.plist",
                            original_source_path=f"{backup_dir}/Manifest.plist#Applications/{bundle_id}",
                            stored_copy_path=str(manifest_plist),
                            acquisition_method=acq_method,
                            parser_name="ios_backup_inspector",
                            parser_version="1.0.0",
                            content={"bundle_id": str(bundle_id), "keys": list(app_meta.keys()) if isinstance(app_meta, dict) else []},
                            actor=actor,
                        )
            except Exception as exc:
                errors.append(f"Applications parse warning: {exc}")

        status = "completed" if not errors else "completed_with_errors"
        final_session = repo.finalize_acquisition_session(
            session_id=session["session_id"],
            status=status,
            files_copied=files_hashed,
            bytes_copied=bytes_hashed,
            errors=errors,
            limitations=limitations,
            actor=actor,
        )
        return {
            "device": device,
            "session": final_session,
            "backup_metadata": meta,
            "working_dir": str(working_dir),
        }


def _normalize_iso_or_empty(raw: str) -> str:
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return ""
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        return ""
