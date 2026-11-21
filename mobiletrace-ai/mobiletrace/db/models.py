"""SQLAlchemy 2.0 ORM models for MobileTrace AI persistent forensic database."""

from __future__ import annotations

from datetime import datetime, timezone

try:
    from sqlalchemy import (
        Boolean,
        DateTime,
        ForeignKey,
        Index,
        Integer,
        String,
        Text,
        UniqueConstraint,
    )
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

    SQLALCHEMY_AVAILABLE = True
except ImportError:  # pragma: no cover - bare stdlib fallback
    SQLALCHEMY_AVAILABLE = False
    DeclarativeBase = object  # type: ignore[assignment,misc]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


if SQLALCHEMY_AVAILABLE:

    class Base(DeclarativeBase):
        pass

    class Case(Base):
        __tablename__ = "cases"

        case_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_number: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
        title: Mapped[str] = mapped_column(String(255), nullable=False)
        examiner: Mapped[str] = mapped_column(String(128), nullable=False)
        agency: Mapped[str] = mapped_column(String(128), nullable=False, default="")
        status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
        notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)
        updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

        devices: Mapped[list["Device"]] = relationship(back_populates="case", cascade="all, delete-orphan")
        acquisitions: Mapped[list["AcquisitionSession"]] = relationship(back_populates="case", cascade="all, delete-orphan")
        artifacts: Mapped[list["Artifact"]] = relationship(back_populates="case", cascade="all, delete-orphan")

    class Device(Base):
        __tablename__ = "devices"
        __table_args__ = (
            Index("ix_devices_case_id", "case_id"),
            Index("ix_devices_serial_udid", "serial_or_udid"),
        )

        device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        platform: Mapped[str] = mapped_column(String(32), nullable=False)
        serial_or_udid: Mapped[str] = mapped_column(String(128), nullable=False)
        manufacturer: Mapped[str] = mapped_column(String(128), nullable=False, default="")
        model: Mapped[str] = mapped_column(String(128), nullable=False, default="")
        os_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        build_or_sdk: Mapped[str] = mapped_column(String(128), nullable=False, default="")
        connection_state: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
        metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
        first_seen_at: Mapped[str] = mapped_column(String(64), nullable=False)

        case: Mapped["Case"] = relationship(back_populates="devices")

    class AuthorizationRecord(Base):
        __tablename__ = "authorization_records"
        __table_args__ = (Index("ix_auth_case_device", "case_id", "device_id"),)

        auth_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
        authority_type: Mapped[str] = mapped_column(String(64), nullable=False)
        reference_number: Mapped[str] = mapped_column(String(128), nullable=False, default="")
        authorized_by: Mapped[str] = mapped_column(String(128), nullable=False)
        scope_description: Mapped[str] = mapped_column(Text, nullable=False)
        verified_at: Mapped[str] = mapped_column(String(64), nullable=False)

    class AcquisitionSession(Base):
        __tablename__ = "acquisition_sessions"
        __table_args__ = (Index("ix_acq_case_id", "case_id"),)

        session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
        acquisition_method: Mapped[str] = mapped_column(String(64), nullable=False)
        scope_classification: Mapped[str] = mapped_column(String(64), nullable=False)
        source_location: Mapped[str] = mapped_column(Text, nullable=False, default="")
        output_directory: Mapped[str] = mapped_column(Text, nullable=False, default="")
        status: Mapped[str] = mapped_column(String(32), nullable=False)
        files_copied: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        bytes_copied: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        errors_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
        limitations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
        started_at: Mapped[str] = mapped_column(String(64), nullable=False)
        finished_at: Mapped[str] = mapped_column(String(64), nullable=False, default="")

        case: Mapped["Case"] = relationship(back_populates="acquisitions")

    class TransferManifest(Base):
        __tablename__ = "transfer_manifests"
        __table_args__ = (Index("ix_transfer_case_id", "case_id"),)

        manifest_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        source_root: Mapped[str] = mapped_column(Text, nullable=False)
        destination_root: Mapped[str] = mapped_column(Text, nullable=False)
        conflict_policy: Mapped[str] = mapped_column(String(32), nullable=False)
        status: Mapped[str] = mapped_column(String(32), nullable=False)
        total_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        succeeded_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        failed_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        skipped_files: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        total_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        manifest_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
        manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        started_at: Mapped[str] = mapped_column(String(64), nullable=False)
        finished_at: Mapped[str] = mapped_column(String(64), nullable=False, default="")

    class TransferredFile(Base):
        __tablename__ = "transferred_files"
        __table_args__ = (
            Index("ix_tfile_manifest_id", "manifest_id"),
            Index("ix_tfile_case_id", "case_id"),
        )

        file_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        manifest_id: Mapped[str] = mapped_column(ForeignKey("transfer_manifests.manifest_id", ondelete="CASCADE"), nullable=False)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        source_path: Mapped[str] = mapped_column(Text, nullable=False)
        destination_path: Mapped[str] = mapped_column(Text, nullable=False)
        byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        source_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        destination_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
        status: Mapped[str] = mapped_column(String(32), nullable=False)
        error_message: Mapped[str] = mapped_column(Text, nullable=False, default="")
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    class Artifact(Base):
        __tablename__ = "artifacts"
        __table_args__ = (
            Index("ix_artifacts_case_id", "case_id"),
            Index("ix_artifacts_device_id", "device_id"),
            Index("ix_artifacts_type", "artifact_type"),
            Index("ix_artifacts_sha256", "sha256"),
        )

        artifact_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
        session_id: Mapped[str] = mapped_column(ForeignKey("acquisition_sessions.session_id", ondelete="SET NULL"), nullable=True)
        artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
        title: Mapped[str] = mapped_column(String(255), nullable=False)
        summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
        original_source_path: Mapped[str] = mapped_column(Text, nullable=False)
        stored_copy_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
        original_timestamp: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        original_timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
        normalized_timestamp_utc: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        normalization_justification: Mapped[str] = mapped_column(Text, nullable=False, default="")
        acquisition_method: Mapped[str] = mapped_column(String(64), nullable=False)
        parser_name: Mapped[str] = mapped_column(String(128), nullable=False)
        parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
        sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
        extraction_errors: Mapped[str] = mapped_column(Text, nullable=False, default="")
        parsing_errors: Mapped[str] = mapped_column(Text, nullable=False, default="")
        provenance_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
        content_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)

        case: Mapped["Case"] = relationship(back_populates="artifacts")

    class TimelineEvent(Base):
        __tablename__ = "timeline_events"
        __table_args__ = (
            Index("ix_timeline_case_utc", "case_id", "normalized_utc"),
            Index("ix_timeline_device", "device_id"),
        )

        event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        device_id: Mapped[str] = mapped_column(ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False)
        artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.artifact_id", ondelete="CASCADE"), nullable=False)
        event_type: Mapped[str] = mapped_column(String(64), nullable=False)
        description: Mapped[str] = mapped_column(Text, nullable=False)
        original_timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
        original_timezone: Mapped[str] = mapped_column(String(64), nullable=False)
        normalized_utc: Mapped[str] = mapped_column(String(64), nullable=False, default="")
        timestamp_confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="unverified")
        source_path: Mapped[str] = mapped_column(Text, nullable=False, default="")

    class InvestigationFinding(Base):
        __tablename__ = "investigation_findings"
        __table_args__ = (Index("ix_findings_case_id", "case_id"),)

        finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        title: Mapped[str] = mapped_column(String(255), nullable=False)
        category: Mapped[str] = mapped_column(String(64), nullable=False)
        severity: Mapped[str] = mapped_column(String(32), nullable=False, default="informational")
        description: Mapped[str] = mapped_column(Text, nullable=False)
        linked_artifact_ids_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
        created_by: Mapped[str] = mapped_column(String(128), nullable=False)
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    class AnalystNote(Base):
        __tablename__ = "analyst_notes"
        __table_args__ = (Index("ix_notes_case_id", "case_id"),)

        note_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        artifact_id: Mapped[str] = mapped_column(ForeignKey("artifacts.artifact_id", ondelete="SET NULL"), nullable=True)
        author: Mapped[str] = mapped_column(String(128), nullable=False)
        body: Mapped[str] = mapped_column(Text, nullable=False)
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    class AIAnalysis(Base):
        __tablename__ = "ai_analyses"
        __table_args__ = (Index("ix_ai_case_id", "case_id"),)

        analysis_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        model_name: Mapped[str] = mapped_column(String(64), nullable=False)
        analyst_approved: Mapped[bool] = mapped_column(Boolean, nullable=False)
        pii_redacted: Mapped[bool] = mapped_column(Boolean, nullable=False)
        prompt_question: Mapped[str] = mapped_column(Text, nullable=False)
        selected_artifact_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
        verified_artifact_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
        rejected_artifact_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
        response_json: Mapped[str] = mapped_column(Text, nullable=False)
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    class ReportRecord(Base):
        __tablename__ = "report_records"
        __table_args__ = (Index("ix_reports_case_id", "case_id"),)

        report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
        case_id: Mapped[str] = mapped_column(ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
        report_format: Mapped[str] = mapped_column(String(16), nullable=False)
        output_path: Mapped[str] = mapped_column(Text, nullable=False)
        sha256: Mapped[str] = mapped_column(String(64), nullable=False)
        generated_by: Mapped[str] = mapped_column(String(128), nullable=False)
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    class AuditEvent(Base):
        __tablename__ = "audit_events"
        __table_args__ = (Index("ix_audit_case_seq", "case_id", "seq"),)

        seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
        event_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
        case_id: Mapped[str] = mapped_column(String(64), nullable=False)
        actor: Mapped[str] = mapped_column(String(128), nullable=False)
        action: Mapped[str] = mapped_column(String(128), nullable=False)
        target_type: Mapped[str] = mapped_column(String(64), nullable=False)
        target_id: Mapped[str] = mapped_column(String(64), nullable=False)
        details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
        prev_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
        event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
        created_at: Mapped[str] = mapped_column(String(64), nullable=False)
