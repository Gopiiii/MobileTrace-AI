"""MobileTrace AI PySide6 Desktop Workstation Main Window."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mobiletrace.acquisition.android_adb import AndroidADBClient
from mobiletrace.acquisition.ios_backup import iOSBackupClient
from mobiletrace.ai.gemini_investigator import run_gemini_investigation
from mobiletrace.analysis.correlation import compare_devices_timeline
from mobiletrace.analysis.native_parsers import ingest_local_directory, parse_ios_backup_artifacts
from mobiletrace.analysis.tools_integration import inspect_forensic_tools, run_leapp_tool, run_mvt_check
from mobiletrace.config import WorkstationConfig
from mobiletrace.db.migrations import backup_database
from mobiletrace.db.repository import ForensicRepository
from mobiletrace.reporting.integrity import verify_case_integrity
from mobiletrace.reporting.report_generator import generate_html_report, generate_pdf_report
from mobiletrace.transfer.manager import TransferManager, TransferProgress
from mobiletrace.ui.theme import MONOCHROME_QSS
from mobiletrace.ui.workers import ForensicTaskWorker


NAV_ITEMS = [
    ("dashboard", "Dashboard & Cases"),
    ("devices", "Devices & Capabilities"),
    ("acquisition", "Acquisition Wizard"),
    ("transfer", "Transfer Manager"),
    ("evidence", "Evidence Explorer"),
    ("timeline", "Timeline & Comparison"),
    ("integrity", "Hash Verification"),
    ("gemini", "Gemini Investigation"),
    ("reports", "Audit Log & Reports"),
    ("settings", "Settings & Diagnostics"),
]


class MobileTraceMainWindow(QMainWindow):
    def __init__(self, config: WorkstationConfig, repo: ForensicRepository) -> None:
        super().__init__()
        self.config = config
        self.repo = repo
        self.active_case_id: str | None = None
        self._workers: list[ForensicTaskWorker] = []
        self._transfer_cancel_event: threading.Event | None = None

        self.setWindowTitle("MobileTrace AI — Mobile Digital Forensics Workstation")
        self.resize(1380, 860)
        self.setStyleSheet(MONOCHROME_QSS)

        self._build_ui()
        self._refresh_cases()
        self._refresh_diagnostics()

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(240)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(14, 18, 14, 14)
        sb_layout.setSpacing(6)

        brand = QLabel("MobileTrace AI")
        brand.setObjectName("BrandTitle")
        sb_layout.addWidget(brand)

        sub_label = QLabel("Digital Forensics Workstation")
        sub_label.setObjectName("MutedMeta")
        sb_layout.addWidget(sub_label)
        sb_layout.addSpacing(14)

        self.nav_buttons: dict[str, QPushButton] = {}
        for key, label in NAV_ITEMS:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.clicked.connect(lambda _checked=False, k=key: self._switch_page(k))
            sb_layout.addWidget(btn)
            self.nav_buttons[key] = btn

        sb_layout.addStretch(1)
        root_layout.addWidget(sidebar)

        # Right main area
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        top_bar = QFrame()
        top_bar.setObjectName("TopBar")
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(20, 12, 20, 12)
        self.active_case_banner = QLabel("Active Case: None Selected")
        self.active_case_banner.setStyleSheet("font-weight: 600;")
        top_layout.addWidget(self.active_case_banner)
        top_layout.addStretch(1)
        refresh_btn = QPushButton("Refresh All")
        refresh_btn.clicked.connect(self._refresh_all)
        top_layout.addWidget(refresh_btn)
        right_layout.addWidget(top_bar)

        self.stack = QStackedWidget()
        self.pages: dict[str, QWidget] = {
            "dashboard": self._build_dashboard_page(),
            "devices": self._build_devices_page(),
            "acquisition": self._build_acquisition_page(),
            "transfer": self._build_transfer_page(),
            "evidence": self._build_evidence_page(),
            "timeline": self._build_timeline_page(),
            "integrity": self._build_integrity_page(),
            "gemini": self._build_gemini_page(),
            "reports": self._build_reports_page(),
            "settings": self._build_settings_page(),
        }
        for key, _label in NAV_ITEMS:
            self.stack.addWidget(self.pages[key])
        right_layout.addWidget(self.stack)

        root_layout.addWidget(right)
        self.setCentralWidget(root)
        self._switch_page("dashboard")

    def _switch_page(self, key: str) -> None:
        idx = [k for k, _ in NAV_ITEMS].index(key)
        self.stack.setCurrentIndex(idx)
        for k, btn in self.nav_buttons.items():
            btn.setProperty("active", k == key)
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _require_case(self) -> str | None:
        if not self.active_case_id:
            QMessageBox.warning(self, "No Active Case", "Create or select a case in Dashboard & Cases first.")
            return None
        return self.active_case_id

    def _refresh_all(self) -> None:
        self._refresh_cases()
        self._refresh_diagnostics()
        if self.active_case_id:
            self._load_active_case_data()

    # ---------------- 1. Dashboard & Cases ----------------

    def _build_dashboard_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        heading = QLabel("Case Management & Overview")
        heading.setObjectName("SectionHeading")
        layout.addWidget(heading)

        form_box = QGroupBox("Create New Forensic Case")
        form_layout = QFormLayout(form_box)
        self.case_num_input = QLineEdit()
        self.case_num_input.setPlaceholderText("MT-2026-001")
        self.case_title_input = QLineEdit()
        self.case_title_input.setPlaceholderText("Custodian Device Examination")
        self.case_examiner_input = QLineEdit()
        self.case_examiner_input.setPlaceholderText("Lead Digital Forensics Examiner")
        self.case_agency_input = QLineEdit()
        self.case_agency_input.setPlaceholderText("Lab / Organization")
        create_btn = QPushButton("Create Case")
        create_btn.setObjectName("PrimaryButton")
        create_btn.clicked.connect(self._on_create_case)

        form_layout.addRow("Case Number *", self.case_num_input)
        form_layout.addRow("Case Title *", self.case_title_input)
        form_layout.addRow("Examiner *", self.case_examiner_input)
        form_layout.addRow("Agency", self.case_agency_input)
        form_layout.addRow("", create_btn)
        layout.addWidget(form_box)

        self.cases_table = QTableWidget(0, 6)
        self.cases_table.setHorizontalHeaderLabels(["Case Number", "Title", "Examiner", "Status", "Devices", "Artifacts"])
        self.cases_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.cases_table.itemSelectionChanged.connect(self._on_case_selected)
        layout.addWidget(self.cases_table)
        return page

    def _on_create_case(self) -> None:
        try:
            case = self.repo.create_case(
                case_number=self.case_num_input.text(),
                title=self.case_title_input.text(),
                examiner=self.case_examiner_input.text(),
                agency=self.case_agency_input.text(),
            )
            self.case_num_input.clear()
            self.case_title_input.clear()
            self.active_case_id = case["case_id"]
            self._refresh_cases()
            self._load_active_case_data()
        except Exception as exc:
            QMessageBox.critical(self, "Case Creation Error", str(exc))

    def _refresh_cases(self) -> None:
        cases = self.repo.list_cases()
        self.cases_table.setRowCount(len(cases))
        for row_idx, c in enumerate(cases):
            vals = [c["case_number"], c["title"], c["examiner"], c["status"], str(c["device_count"]), str(c["artifact_count"])]
            for col_idx, val in enumerate(vals):
                item = QTableWidgetItem(val)
                item.setData(Qt.UserRole, c["case_id"])
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.cases_table.setItem(row_idx, col_idx, item)
        self.cases_table.resizeColumnsToContents()

    def _on_case_selected(self) -> None:
        items = self.cases_table.selectedItems()
        if not items:
            return
        self.active_case_id = items[0].data(Qt.UserRole)
        self._load_active_case_data()

    def _load_active_case_data(self) -> None:
        if not self.active_case_id:
            return
        c = self.repo.get_case(self.active_case_id)
        if not c:
            return
        self.active_case_banner.setText(f"Active Case: {c['case_number']} — {c['title']} ({c['case_id']})")
        self._refresh_evidence_table()
        self._refresh_timeline_table()
        self._refresh_audit_and_reports()
        self._refresh_gemini_artifact_list()

    # ---------------- 2. Devices & Capabilities ----------------

    def _build_devices_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        top = QHBoxLayout()
        h = QLabel("Connected Devices & Forensic Tooling Status")
        h.setObjectName("SectionHeading")
        top.addWidget(h)
        top.addStretch(1)
        scan_btn = QPushButton("Scan Connected Devices")
        scan_btn.setObjectName("PrimaryButton")
        scan_btn.clicked.connect(self._refresh_diagnostics)
        top.addWidget(scan_btn)
        layout.addLayout(top)

        self.diagnostics_output = QPlainTextEdit()
        self.diagnostics_output.setReadOnly(True)
        layout.addWidget(self.diagnostics_output)
        return page

    def _refresh_diagnostics(self) -> None:
        adb = AndroidADBClient(self.config.adb_path)
        ios = iOSBackupClient(self.config.idevice_dir)
        tools = inspect_forensic_tools(self.config)
        payload = {
            "android_adb": adb.list_devices(),
            "ios_usb": ios.detect_devices(),
            "ios_tooling": ios.check_tooling(),
            "external_forensic_tools": tools,
        }
        self.diagnostics_output.setPlainText(json.dumps(payload, indent=2))
        self.settings_diag_text.setPlainText(
            json.dumps(
                {
                    "host_os": self.config.host_os,
                    "db_path": str(self.config.db_path),
                    "workspace_dir": str(self.config.workspace_dir),
                    "adb_path": self.config.adb_path,
                    "gemini_api_key_configured": self.config.gemini_configured,
                    "gemini_model": self.config.gemini_model,
                    "external_tools": tools,
                },
                indent=2,
            )
        )

    # ---------------- 3. Acquisition Wizard ----------------

    def _build_acquisition_page(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        h = QLabel("Acquisition Wizard (Android ADB / iOS Backup / External Forensic Tools)")
        h.setObjectName("SectionHeading")
        layout.addWidget(h)

        # 1. Android ADB box
        adb_box = QGroupBox("1. Android Accessible-File Acquisition & Authorized ADB Backup")
        adb_form = QFormLayout(adb_box)
        self.adb_serial_input = QLineEdit()
        self.adb_serial_input.setPlaceholderText("Device serial from Devices & Capabilities")
        self.adb_roots_input = QLineEdit("/sdcard/DCIM,/sdcard/Documents,/sdcard/Download")
        adb_btn_row = QHBoxLayout()
        adb_btn = QPushButton("Acquire Accessible Files via ADB")
        adb_btn.setObjectName("PrimaryButton")
        adb_btn.clicked.connect(self._on_run_adb_acquire)
        adb_bkp_btn = QPushButton("Run User-Authorized ADB Backup (.ab)")
        adb_bkp_btn.clicked.connect(self._on_run_adb_backup)
        adb_btn_row.addWidget(adb_btn)
        adb_btn_row.addWidget(adb_bkp_btn)
        adb_note = QLabel("Note: adb backup requires on-device custodian confirmation and is restricted on Android 12+.")
        adb_note.setObjectName("MutedMeta")
        adb_note.setWordWrap(True)
        adb_form.addRow("Authorized Serial *", self.adb_serial_input)
        adb_form.addRow("Remote Paths (CSV)", self.adb_roots_input)
        adb_form.addRow("", adb_btn_row)
        adb_form.addRow("", adb_note)
        layout.addWidget(adb_box)

        # 2. iOS live & local backup box
        ios_box = QGroupBox("2. iPhone / iOS Live USB Backup & Local Backup Import")
        ios_form = QFormLayout(ios_box)
        ios_trust = QLabel(
            "Custodian Trust Guide: Unlock iPhone, connect USB, tap 'Trust This Computer', and enter device passcode. "
            "Never bypasses passcodes, activation lock, or backup encryption."
        )
        ios_trust.setObjectName("MutedMeta")
        ios_trust.setWordWrap(True)
        live_row = QHBoxLayout()
        self.ios_udid_input = QLineEdit()
        self.ios_udid_input.setPlaceholderText("UDID from Devices & Capabilities")
        live_btn = QPushButton("Run Live USB Backup (idevicebackup2)")
        live_btn.clicked.connect(self._on_run_ios_live_backup)
        live_row.addWidget(self.ios_udid_input)
        live_row.addWidget(live_btn)

        ios_row = QHBoxLayout()
        self.ios_backup_dir_input = QLineEdit()
        ios_browse = QPushButton("Browse...")
        ios_browse.clicked.connect(lambda: self._pick_dir(self.ios_backup_dir_input))
        ios_row.addWidget(self.ios_backup_dir_input)
        ios_row.addWidget(ios_browse)
        self.ios_password_input = QLineEdit()
        self.ios_password_input.setEchoMode(QLineEdit.Password)
        self.ios_password_input.setPlaceholderText("Required only if IsEncrypted=true")
        ios_btn = QPushButton("Import & Parse iOS Backup Folder")
        ios_btn.setObjectName("PrimaryButton")
        ios_btn.clicked.connect(self._on_import_ios_backup)
        ios_form.addRow("Trust Procedure", ios_trust)
        ios_form.addRow("Live USB UDID", live_row)
        ios_form.addRow("Backup Folder *", ios_row)
        ios_form.addRow("Backup Password", self.ios_password_input)
        ios_form.addRow("", ios_btn)
        layout.addWidget(ios_box)

        # 3. Local directory ingest
        dir_box = QGroupBox("3. Ingest Local Exported Folder (EXIF + SHA-256)")
        dir_form = QFormLayout(dir_box)
        dir_row = QHBoxLayout()
        self.local_ingest_input = QLineEdit()
        dir_browse = QPushButton("Browse...")
        dir_browse.clicked.connect(lambda: self._pick_dir(self.local_ingest_input))
        dir_row.addWidget(self.local_ingest_input)
        dir_row.addWidget(dir_browse)
        self.local_platform_combo = QComboBox()
        self.local_platform_combo.addItems(["android", "ios", "other"])
        dir_btn = QPushButton("Ingest Local Directory")
        dir_btn.clicked.connect(self._on_ingest_local_dir)
        dir_form.addRow("Source Folder *", dir_row)
        dir_form.addRow("Platform Label", self.local_platform_combo)
        dir_form.addRow("", dir_btn)
        layout.addWidget(dir_box)

        # 4. External Forensic Tools Runner (ALEAPP / iLEAPP / MVT)
        tool_box = QGroupBox("4. External Forensic Tool Runner (ALEAPP, iLEAPP, MVT)")
        tool_form = QFormLayout(tool_box)
        self.ext_tool_combo = QComboBox()
        self.ext_tool_combo.addItems(["aleapp", "ileapp", "mvt_ios", "mvt_android"])
        self.ext_tool_mode_input = QLineEdit("fs")
        self.ext_tool_mode_input.setPlaceholderText("LEAPP -t (fs/itunes/tar/zip) or MVT subcommand (check-backup/check-adb)")
        tool_path_row = QHBoxLayout()
        self.ext_tool_path_input = QLineEdit()
        self.ext_tool_path_input.setPlaceholderText("Acquired evidence directory or backup folder (blank for mvt_android check-adb)")
        tool_browse = QPushButton("Browse...")
        tool_browse.clicked.connect(lambda: self._pick_dir(self.ext_tool_path_input))
        tool_path_row.addWidget(self.ext_tool_path_input)
        tool_path_row.addWidget(tool_browse)
        tool_run_btn = QPushButton("Execute Forensic Tool & Ingest Artifacts")
        tool_run_btn.clicked.connect(self._on_run_external_tool)
        tool_form.addRow("Forensic Tool", self.ext_tool_combo)
        tool_form.addRow("Mode / Subcommand", self.ext_tool_mode_input)
        tool_form.addRow("Target Folder", tool_path_row)
        tool_form.addRow("", tool_run_btn)
        layout.addWidget(tool_box)

        self.acq_log = QPlainTextEdit()
        self.acq_log.setReadOnly(True)
        self.acq_log.setMinimumHeight(180)
        layout.addWidget(self.acq_log)
        scroll.setWidget(page)
        return scroll

    def _pick_dir(self, target: QLineEdit) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Select Directory")
        if chosen:
            target.setText(chosen)

    def _on_run_adb_acquire(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        serial = self.adb_serial_input.text().strip()
        roots = [r.strip() for r in self.adb_roots_input.text().split(",") if r.strip()]
        if not serial or not roots:
            QMessageBox.warning(self, "Input Required", "Provide an authorized ADB serial and at least one remote path.")
            return

        def task() -> dict[str, Any]:
            adb = AndroidADBClient(self.config.adb_path)
            info = adb.list_devices()
            match = next((d for d in info["devices"] if d["serial"] == serial), None)
            if not match:
                raise RuntimeError(f"Device {serial} not detected.")
            dev = self.repo.register_device(
                case_id=case_id,
                platform="android",
                serial_or_udid=serial,
                manufacturer=match.get("manufacturer", ""),
                model=match.get("model", ""),
                os_version=match.get("os_version", ""),
                build_or_sdk=match.get("sdk_version", ""),
                connection_state=match.get("state", "unknown"),
                metadata=match.get("properties", {}),
            )
            out_dir = self.config.workspace_dir / "acquisitions" / case_id / f"android_{serial}"
            return adb.acquire_accessible_files(
                repo=self.repo,
                case_id=case_id,
                device_id=dev["device_id"],
                serial=serial,
                remote_roots=roots,
                output_dir=out_dir,
            )

        self._run_worker(task, self.acq_log)

    def _on_run_adb_backup(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        serial = self.adb_serial_input.text().strip()
        if not serial:
            QMessageBox.warning(self, "Input Required", "Provide an authorized ADB serial.")
            return

        def task() -> dict[str, Any]:
            adb = AndroidADBClient(self.config.adb_path)
            info = adb.list_devices()
            match = next((d for d in info["devices"] if d["serial"] == serial), None)
            if not match:
                raise RuntimeError(f"Device {serial} not detected.")
            dev = self.repo.register_device(
                case_id=case_id,
                platform="android",
                serial_or_udid=serial,
                manufacturer=match.get("manufacturer", ""),
                model=match.get("model", ""),
                os_version=match.get("os_version", ""),
                build_or_sdk=match.get("sdk_version", ""),
                connection_state=match.get("state", "unknown"),
                metadata=match.get("properties", {}),
            )
            ab_path = self.config.workspace_dir / "acquisitions" / case_id / f"adb_backup_{serial}.ab"
            res = adb.create_adb_backup(serial=serial, dest_ab_path=ab_path, include_shared=True, include_apks=False)
            self.repo.append_audit_event(
                case_id=case_id,
                actor="examiner",
                action="acquisition.adb_backup",
                target_type="device",
                target_id=dev["device_id"],
                details=res,
            )
            return {"device": dev, "backup": res}

        self._run_worker(task, self.acq_log)

    def _on_run_ios_live_backup(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        udid = self.ios_udid_input.text().strip()
        if not udid:
            QMessageBox.warning(self, "Input Required", "Provide a connected trusted iOS device UDID.")
            return

        def task() -> dict[str, Any]:
            ios = iOSBackupClient(self.config.idevice_dir)
            bkp_root = self.config.workspace_dir / "acquisitions" / case_id / f"ios_live_{udid}"
            res = ios.create_local_backup(udid=udid, backup_root=bkp_root)
            self.repo.append_audit_event(
                case_id=case_id,
                actor="examiner",
                action="acquisition.ios_live_backup",
                target_type="case",
                target_id=case_id,
                details={"udid": udid, "success": res["success"]},
            )
            return res

        self._run_worker(task, self.acq_log)

    def _on_import_ios_backup(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        bdir = Path(self.ios_backup_dir_input.text().strip())
        pwd = self.ios_password_input.text() or None

        def task() -> dict[str, Any]:
            ios = iOSBackupClient(self.config.idevice_dir)
            dec_dir = self.config.workspace_dir / "analysis" / case_id / "ios_decrypted"
            imp = ios.import_local_backup(
                repo=self.repo,
                case_id=case_id,
                backup_dir=bdir,
                backup_password=pwd,
                decrypted_output_dir=dec_dir,
            )
            wdir = Path(imp["working_dir"])
            parsed = {}
            if (wdir / "Manifest.db").is_file():
                parsed = parse_ios_backup_artifacts(
                    repo=self.repo,
                    case_id=case_id,
                    device_id=imp["device"]["device_id"],
                    session_id=imp["session"]["session_id"],
                    backup_dir=wdir,
                )
            return {**imp, "parsed_artifacts": parsed}

        self._run_worker(task, self.acq_log)

    def _on_ingest_local_dir(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        sdir = Path(self.local_ingest_input.text().strip())
        plat = self.local_platform_combo.currentText()

        def task() -> dict[str, Any]:
            dev = self.repo.register_device(
                case_id=case_id,
                platform=plat,
                serial_or_udid=f"local-{sdir.name}",
                manufacturer="Host/Exported",
                model=sdir.name,
                connection_state="local_directory",
            )
            copy_dir = self.config.workspace_dir / "acquisitions" / case_id / dev["device_id"]
            return ingest_local_directory(
                repo=self.repo,
                case_id=case_id,
                device_id=dev["device_id"],
                source_dir=sdir,
                evidence_copy_dir=copy_dir,
                platform=plat,
            )

        self._run_worker(task, self.acq_log)

    def _on_run_external_tool(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        tool_key = self.ext_tool_combo.currentText()
        mode_val = self.ext_tool_mode_input.text().strip() or ("fs" if tool_key in {"aleapp", "ileapp"} else "check-backup")
        target_str = self.ext_tool_path_input.text().strip()

        def task() -> dict[str, Any]:
            devices = self.repo.list_devices(case_id)
            if devices:
                dev = devices[0]
            else:
                plat = "ios" if tool_key in {"ileapp", "mvt_ios"} else "android"
                dev = self.repo.register_device(
                    case_id=case_id,
                    platform=plat,
                    serial_or_udid=f"tool-{tool_key}",
                    manufacturer="External Tool Target",
                    model=tool_key.upper(),
                    connection_state="analysis_target",
                )
            out_dir = self.config.workspace_dir / "analysis" / case_id / tool_key
            if tool_key in {"aleapp", "ileapp"}:
                if not target_str:
                    raise ValueError(f"Target folder is required for {tool_key.upper()}.")
                bin_path = self.config.aleapp_path if tool_key == "aleapp" else self.config.ileapp_path
                return run_leapp_tool(
                    tool_key=tool_key,
                    binary_path=bin_path,
                    input_type=mode_val,
                    input_path=Path(target_str),
                    output_dir=out_dir,
                    repo=self.repo,
                    case_id=case_id,
                    device_id=dev["device_id"],
                )
            if mode_val != "check-adb" and not target_str:
                raise ValueError(f"Target folder is required for {tool_key} {mode_val}.")
            bin_path = self.config.mvt_ios_path if tool_key == "mvt_ios" else self.config.mvt_android_path
            return run_mvt_check(
                tool_key=tool_key,
                binary_path=bin_path,
                subcommand=mode_val,
                target_path_or_none=Path(target_str) if target_str else None,
                output_dir=out_dir,
                iocs_path=None,
                repo=self.repo,
                case_id=case_id,
                device_id=dev["device_id"],
            )

        self._run_worker(task, self.acq_log)

    # ---------------- 4. Transfer Manager ----------------

    def _build_transfer_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        h = QLabel("Verified Data Transfer Manager")
        h.setObjectName("SectionHeading")
        layout.addWidget(h)

        form = QFormLayout()
        s_row = QHBoxLayout()
        self.xfer_src_input = QLineEdit()
        s_btn = QPushButton("Browse...")
        s_btn.clicked.connect(lambda: self._pick_dir(self.xfer_src_input))
        s_row.addWidget(self.xfer_src_input)
        s_row.addWidget(s_btn)

        d_row = QHBoxLayout()
        self.xfer_dst_input = QLineEdit()
        d_btn = QPushButton("Browse...")
        d_btn.clicked.connect(lambda: self._pick_dir(self.xfer_dst_input))
        d_row.addWidget(self.xfer_dst_input)
        d_row.addWidget(d_btn)

        self.xfer_policy = QComboBox()
        self.xfer_policy.addItems(["rename", "skip", "overwrite"])

        btn_row = QHBoxLayout()
        start_btn = QPushButton("Start Verified Transfer")
        start_btn.setObjectName("PrimaryButton")
        start_btn.clicked.connect(self._on_start_transfer)
        cancel_btn = QPushButton("Cancel Transfer")
        cancel_btn.clicked.connect(self._on_cancel_transfer)
        btn_row.addWidget(start_btn)
        btn_row.addWidget(cancel_btn)

        form.addRow("Source Folder *", s_row)
        form.addRow("Destination Folder *", d_row)
        form.addRow("Conflict Policy", self.xfer_policy)
        form.addRow("", btn_row)
        layout.addLayout(form)

        self.xfer_progress = QProgressBar()
        self.xfer_status = QLabel("Idle")
        layout.addWidget(self.xfer_progress)
        layout.addWidget(self.xfer_status)

        self.xfer_output = QPlainTextEdit()
        self.xfer_output.setReadOnly(True)
        layout.addWidget(self.xfer_output)
        return page

    def _on_start_transfer(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        src = Path(self.xfer_src_input.text().strip())
        dst = Path(self.xfer_dst_input.text().strip())
        policy = self.xfer_policy.currentText()
        cancel_ev = threading.Event()
        self._transfer_cancel_event = cancel_ev

        def on_prog(p: TransferProgress) -> None:
            worker.progress.emit(p.bytes_done, max(1, p.total_bytes), f"{p.files_done}/{p.total_files}: {p.current_file}")

        def task() -> dict[str, Any]:
            mgr = TransferManager()
            return mgr.execute_transfer(
                repo=self.repo,
                case_id=case_id,
                source_paths=[src],
                destination_dir=dst,
                source_root=src,
                conflict_policy=policy,
                cancel_event=cancel_ev,
                on_progress=on_prog,
            )

        worker = ForensicTaskWorker(task)
        worker.progress.connect(self._on_xfer_progress)
        worker.finished_ok.connect(lambda res: (self.xfer_output.setPlainText(json.dumps(res, indent=2)), self._refresh_all()))
        worker.failed.connect(lambda err: QMessageBox.critical(self, "Transfer Failed", err))
        self._workers.append(worker)
        worker.start()

    def _on_xfer_progress(self, done: int, total: int, label: str) -> None:
        pct = int((done / total) * 100) if total > 0 else 0
        self.xfer_progress.setValue(pct)
        self.xfer_status.setText(f"{label} ({done:,} / {total:,} bytes)")

    def _on_cancel_transfer(self) -> None:
        if self._transfer_cancel_event:
            self._transfer_cancel_event.set()
            self.xfer_status.setText("Cancellation requested...")

    # ---------------- 5. Evidence Explorer ----------------

    def _build_evidence_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        top = QHBoxLayout()
        h = QLabel("Evidence Explorer & Provenance Inspector")
        h.setObjectName("SectionHeading")
        top.addWidget(h)
        top.addStretch(1)
        self.ev_search = QLineEdit()
        self.ev_search.setPlaceholderText("Search artifacts, paths, SHA-256...")
        self.ev_search.returnPressed.connect(self._refresh_evidence_table)
        sbtn = QPushButton("Search")
        sbtn.clicked.connect(self._refresh_evidence_table)
        top.addWidget(self.ev_search)
        top.addWidget(sbtn)
        layout.addLayout(top)

        self._evidence_rows_cache: list[dict[str, Any]] = []
        self.evidence_table = QTableWidget(0, 6)
        self.evidence_table.setHorizontalHeaderLabels(["Artifact ID", "Type", "Title", "Timestamp", "Source Path", "SHA-256"])
        self.evidence_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.evidence_table.itemSelectionChanged.connect(self._on_evidence_selected)
        layout.addWidget(self.evidence_table, 2)

        bottom_row = QHBoxLayout()
        self.evidence_inspector = QPlainTextEdit()
        self.evidence_inspector.setReadOnly(True)
        self.evidence_inspector.setPlaceholderText("Select an artifact row above to inspect full provenance, timestamps, parser, and errors.")
        bottom_row.addWidget(self.evidence_inspector, 1)

        right_forms = QVBoxLayout()
        finding_box = QGroupBox("Record Evidence-Linked Finding")
        f_form = QFormLayout(finding_box)
        self.finding_title_input = QLineEdit()
        self.finding_cat_input = QLineEdit("Timeline Analysis")
        self.finding_sev_combo = QComboBox()
        self.finding_sev_combo.addItems(["informational", "low", "medium", "high"])
        self.finding_desc_input = QLineEdit()
        f_btn = QPushButton("Save Finding")
        f_btn.setObjectName("PrimaryButton")
        f_btn.clicked.connect(self._on_add_finding)
        f_form.addRow("Title *", self.finding_title_input)
        f_form.addRow("Category", self.finding_cat_input)
        f_form.addRow("Severity", self.finding_sev_combo)
        f_form.addRow("Observation *", self.finding_desc_input)
        f_form.addRow("", f_btn)
        right_forms.addWidget(finding_box)

        note_box = QGroupBox("Add Analyst Note")
        n_form = QFormLayout(note_box)
        self.note_author_input = QLineEdit("examiner")
        self.note_body_input = QLineEdit()
        n_btn = QPushButton("Save Note")
        n_btn.clicked.connect(self._on_add_note)
        n_form.addRow("Author", self.note_author_input)
        n_form.addRow("Note *", self.note_body_input)
        n_form.addRow("", n_btn)
        right_forms.addWidget(note_box)

        bottom_row.addLayout(right_forms, 1)
        layout.addLayout(bottom_row, 1)
        return page

    def _refresh_evidence_table(self) -> None:
        if not self.active_case_id:
            return
        rows = self.repo.search_artifacts(self.active_case_id, query=self.ev_search.text())
        self._evidence_rows_cache = rows
        self.evidence_table.setRowCount(len(rows))
        for i, a in enumerate(rows):
            vals = [
                a["artifact_id"],
                a["artifact_type"],
                a["title"],
                a["normalized_timestamp_utc"] or a["original_timestamp"] or "—",
                a["original_source_path"],
                a["sha256"][:20] if a["sha256"] else "—",
            ]
            for j, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setData(Qt.UserRole, i)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.evidence_table.setItem(i, j, item)
        self.evidence_table.resizeColumnsToContents()

    def _selected_artifact(self) -> dict[str, Any] | None:
        items = self.evidence_table.selectedItems()
        if not items:
            return None
        idx = items[0].data(Qt.UserRole)
        if isinstance(idx, int) and 0 <= idx < len(self._evidence_rows_cache):
            return self._evidence_rows_cache[idx]
        return None

    def _on_evidence_selected(self) -> None:
        art = self._selected_artifact()
        if not art:
            return
        self.evidence_inspector.setPlainText(json.dumps(art, indent=2, default=str))

    def _on_add_finding(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        title = self.finding_title_input.text().strip()
        desc = self.finding_desc_input.text().strip()
        if not title or not desc:
            QMessageBox.warning(self, "Input Required", "Finding title and observation description are required.")
            return
        art = self._selected_artifact()
        linked = [art["artifact_id"]] if art else []
        try:
            self.repo.add_finding(
                case_id=case_id,
                title=title,
                category=self.finding_cat_input.text().strip() or "General",
                severity=self.finding_sev_combo.currentText(),
                description=desc,
                linked_artifact_ids=linked,
                created_by="examiner",
            )
            self.finding_title_input.clear()
            self.finding_desc_input.clear()
            self._refresh_all()
        except Exception as exc:
            QMessageBox.critical(self, "Finding Error", str(exc))

    def _on_add_note(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        body = self.note_body_input.text().strip()
        if not body:
            QMessageBox.warning(self, "Input Required", "Note body is required.")
            return
        art = self._selected_artifact()
        try:
            self.repo.add_note(
                case_id=case_id,
                author=self.note_author_input.text().strip() or "examiner",
                body=body,
                artifact_id=art["artifact_id"] if art else None,
            )
            self.note_body_input.clear()
            self._refresh_all()
        except Exception as exc:
            QMessageBox.critical(self, "Note Error", str(exc))

    # ---------------- 6. Timeline & Comparison ----------------

    def _build_timeline_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        top = QHBoxLayout()
        h = QLabel("Chronological Timeline & Cross-Device Comparison")
        h.setObjectName("SectionHeading")
        top.addWidget(h)
        top.addStretch(1)
        self.corr_window = QSpinBox()
        self.corr_window.setRange(10, 86400)
        self.corr_window.setValue(300)
        cmp_btn = QPushButton("Compare Devices (Proximity)")
        cmp_btn.clicked.connect(self._on_compare_devices)
        top.addWidget(QLabel("Window (s):"))
        top.addWidget(self.corr_window)
        top.addWidget(cmp_btn)
        layout.addLayout(top)

        self.timeline_table = QTableWidget(0, 5)
        self.timeline_table.setHorizontalHeaderLabels(["UTC Normalized", "Original Timestamp", "Device", "Event Type", "Description"])
        layout.addWidget(self.timeline_table)

        self.corr_output = QPlainTextEdit()
        self.corr_output.setReadOnly(True)
        self.corr_output.setMaximumHeight(200)
        layout.addWidget(self.corr_output)
        return page

    def _refresh_timeline_table(self) -> None:
        if not self.active_case_id:
            return
        events = self.repo.list_timeline_events(self.active_case_id)
        self.timeline_table.setRowCount(len(events))
        for i, e in enumerate(events):
            vals = [
                e["normalized_utc"] or "unconverted",
                f"{e['original_timestamp']} ({e['original_timezone']})",
                f"{e.get('device_platform', '')} {e.get('device_model', '')}".strip(),
                e["event_type"],
                e["description"],
            ]
            for j, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.timeline_table.setItem(i, j, item)
        self.timeline_table.resizeColumnsToContents()

    def _on_compare_devices(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        res = compare_devices_timeline(self.repo, case_id, window_seconds=self.corr_window.value())
        self.corr_output.setPlainText(json.dumps(res, indent=2))

    # ---------------- 7. Hash Verification ----------------

    def _build_integrity_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        top = QHBoxLayout()
        h = QLabel("SHA-256 Evidence Integrity & Audit Chain Verification")
        h.setObjectName("SectionHeading")
        top.addWidget(h)
        top.addStretch(1)
        vbtn = QPushButton("Verify All Case Files & Audit Chain")
        vbtn.setObjectName("PrimaryButton")
        vbtn.clicked.connect(self._on_verify_integrity)
        top.addWidget(vbtn)
        layout.addLayout(top)

        self.integrity_output = QPlainTextEdit()
        self.integrity_output.setReadOnly(True)
        layout.addWidget(self.integrity_output)
        return page

    def _on_verify_integrity(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        manifest_path = self.config.workspace_dir / "reports" / f"integrity_{case_id}.json"
        res = verify_case_integrity(self.repo, case_id, manifest_output_path=manifest_path)
        self.integrity_output.setPlainText(json.dumps(res, indent=2))
        self._refresh_audit_and_reports()

    # ---------------- 8. Gemini Investigation ----------------

    def _build_gemini_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        h = QLabel("Gemini Forensic Investigation Panel")
        h.setObjectName("SectionHeading")
        layout.addWidget(h)

        self.gemini_artifact_list = QListWidget()
        self.gemini_artifact_list.setMaximumHeight(160)
        layout.addWidget(QLabel("Select Specific Artifacts to Include (Max 40; Full Backups Never Uploaded):"))
        layout.addWidget(self.gemini_artifact_list)

        self.gemini_question = QLineEdit()
        self.gemini_question.setPlaceholderText("e.g., Summarize timeline gaps, contradictions, and next investigative steps")
        layout.addWidget(self.gemini_question)

        self.gemini_redact_cb = QCheckBox("Minimize & Redact PII (emails, phone numbers, IPs, tokens) before cloud request")
        self.gemini_redact_cb.setChecked(True)
        self.gemini_search_cb = QCheckBox("Enable Google Search Grounding (fetch updated mobile forensic best practices & CVE references)")
        self.gemini_search_cb.setChecked(True)
        self.gemini_approve_cb = QCheckBox("Analyst Approval: I explicitly authorize sending these minimized artifact summaries to Gemini")
        layout.addWidget(self.gemini_redact_cb)
        layout.addWidget(self.gemini_search_cb)
        layout.addWidget(self.gemini_approve_cb)

        run_btn = QPushButton("Run Targeted Gemini Investigation")
        run_btn.setObjectName("PrimaryButton")
        run_btn.clicked.connect(self._on_run_gemini)
        layout.addWidget(run_btn)

        self.gemini_output = QPlainTextEdit()
        self.gemini_output.setReadOnly(True)
        layout.addWidget(self.gemini_output)
        return page

    def _refresh_gemini_artifact_list(self) -> None:
        self.gemini_artifact_list.clear()
        if not self.active_case_id:
            return
        for a in self.repo.search_artifacts(self.active_case_id, limit=200):
            item = QListWidgetItem(f"{a['artifact_id']} | {a['artifact_type']} | {a['title']}")
            item.setData(Qt.UserRole, a["artifact_id"])
            item.setCheckState(Qt.Unchecked)
            self.gemini_artifact_list.addItem(item)

    def _on_run_gemini(self) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        selected = [
            self.gemini_artifact_list.item(i).data(Qt.UserRole)
            for i in range(self.gemini_artifact_list.count())
            if self.gemini_artifact_list.item(i).checkState() == Qt.Checked
        ]
        question = self.gemini_question.text().strip()
        if not selected or not question:
            QMessageBox.warning(self, "Selection Required", "Select at least one artifact and enter an investigative question.")
            return
        approved = self.gemini_approve_cb.isChecked()
        redact = self.gemini_redact_cb.isChecked()
        use_search = self.gemini_search_cb.isChecked()

        def task() -> dict[str, Any]:
            return run_gemini_investigation(
                repo=self.repo,
                case_id=case_id,
                artifact_ids=selected,
                question=question,
                analyst_approved=approved,
                redact_pii=redact,
                use_search_grounding=use_search,
                model_name=self.config.gemini_model,
            )

        self._run_worker(task, self.gemini_output)

    # ---------------- 9. Audit Log & Reports ----------------

    def _build_reports_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        top = QHBoxLayout()
        h = QLabel("Append-Only Audit Log & Forensic Report Export")
        h.setObjectName("SectionHeading")
        top.addWidget(h)
        top.addStretch(1)
        html_btn = QPushButton("Export HTML Report")
        html_btn.clicked.connect(lambda: self._on_export_report("html"))
        pdf_btn = QPushButton("Export PDF Report")
        pdf_btn.setObjectName("PrimaryButton")
        pdf_btn.clicked.connect(lambda: self._on_export_report("pdf"))
        top.addWidget(html_btn)
        top.addWidget(pdf_btn)
        layout.addLayout(top)

        self.audit_table = QTableWidget(0, 5)
        self.audit_table.setHorizontalHeaderLabels(["Seq", "UTC Timestamp", "Actor", "Action", "Target / Event Hash"])
        layout.addWidget(self.audit_table)
        return page

    def _refresh_audit_and_reports(self) -> None:
        if not self.active_case_id:
            return
        events = self.repo.list_audit_events(self.active_case_id, limit=200)
        self.audit_table.setRowCount(len(events))
        for i, ev in enumerate(events):
            vals = [str(ev["seq"]), ev["created_at"], ev["actor"], ev["action"], f"{ev['target_id']} · {ev['event_hash'][:16]}"]
            for j, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.audit_table.setItem(i, j, item)
        self.audit_table.resizeColumnsToContents()

    def _on_export_report(self, fmt: str) -> None:
        case_id = self._require_case()
        if not case_id:
            return
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_dir = self.config.workspace_dir / "reports" / case_id
        out_path = out_dir / f"report_{case_id}_{ts}.{fmt}"
        try:
            if fmt == "html":
                res = generate_html_report(repo=self.repo, case_id=case_id, output_path=out_path)
            else:
                res = generate_pdf_report(repo=self.repo, case_id=case_id, output_path=out_path)
            QMessageBox.information(self, "Report Generated", f"Saved: {res['output_path']}\nSHA-256: {res['sha256']}")
            self._refresh_audit_and_reports()
        except Exception as exc:
            QMessageBox.critical(self, "Report Export Failed", str(exc))

    # ---------------- 10. Settings & Diagnostics ----------------

    def _build_settings_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        top = QHBoxLayout()
        h = QLabel("Workstation Configuration & Database Maintenance")
        h.setObjectName("SectionHeading")
        top.addWidget(h)
        top.addStretch(1)
        bkp_btn = QPushButton("Backup SQLite Database")
        bkp_btn.setObjectName("PrimaryButton")
        bkp_btn.clicked.connect(self._on_backup_db)
        top.addWidget(bkp_btn)
        layout.addLayout(top)

        note = QLabel(
            "Environment variables (GEMINI_API_KEY, MOBILETRACE_ADB_PATH, MOBILETRACE_IDEVICE_DIR, "
            "MOBILETRACE_ALEAPP_PATH, MOBILETRACE_ILEAPP_PATH, MOBILETRACE_MVT_IOS_PATH) are loaded from .env / OS environment."
        )
        note.setWordWrap(True)
        note.setObjectName("MutedMeta")
        layout.addWidget(note)

        self.settings_diag_text = QPlainTextEdit()
        self.settings_diag_text.setReadOnly(True)
        layout.addWidget(self.settings_diag_text)
        return page

    def _on_backup_db(self) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        dst = self.config.workspace_dir / "backups" / f"mobiletrace_backup_{ts}.db"
        try:
            backup_database(self.config.db_path, dst)
            QMessageBox.information(self, "Backup Completed", f"SQLite backup created:\n{dst}")
        except Exception as exc:
            QMessageBox.critical(self, "Backup Failed", str(exc))

    def _run_worker(self, fn: Any, output_widget: QPlainTextEdit) -> None:
        output_widget.setPlainText("Running operation...")
        worker = ForensicTaskWorker(fn)
        worker.finished_ok.connect(
            lambda res: (output_widget.setPlainText(json.dumps(res, indent=2, default=str)), self._refresh_all())
        )
        worker.failed.connect(
            lambda err: (output_widget.setPlainText(f"ERROR: {err}"), QMessageBox.critical(self, "Operation Failed", err))
        )
        self._workers.append(worker)
        worker.start()
