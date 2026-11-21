"""Initial MobileTrace AI forensic schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-20 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("case_id", sa.String(64), primary_key=True),
        sa.Column("case_number", sa.String(64), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("examiner", sa.String(128), nullable=False),
        sa.Column("agency", sa.String(128), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.String(64), nullable=False),
    )

    op.create_table(
        "devices",
        sa.Column("device_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("serial_or_udid", sa.String(128), nullable=False),
        sa.Column("manufacturer", sa.String(128), nullable=False, server_default=""),
        sa.Column("model", sa.String(128), nullable=False, server_default=""),
        sa.Column("os_version", sa.String(64), nullable=False, server_default=""),
        sa.Column("build_or_sdk", sa.String(128), nullable=False, server_default=""),
        sa.Column("connection_state", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("first_seen_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_devices_case_id", "devices", ["case_id"])
    op.create_index("ix_devices_serial_udid", "devices", ["serial_or_udid"])

    op.create_table(
        "authorization_records",
        sa.Column("auth_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(64), sa.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("authority_type", sa.String(64), nullable=False),
        sa.Column("reference_number", sa.String(128), nullable=False, server_default=""),
        sa.Column("authorized_by", sa.String(128), nullable=False),
        sa.Column("scope_description", sa.Text(), nullable=False),
        sa.Column("verified_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_auth_case_device", "authorization_records", ["case_id", "device_id"])

    op.create_table(
        "acquisition_sessions",
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(64), sa.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("acquisition_method", sa.String(64), nullable=False),
        sa.Column("scope_classification", sa.String(64), nullable=False),
        sa.Column("source_location", sa.Text(), nullable=False, server_default=""),
        sa.Column("output_directory", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("files_copied", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("bytes_copied", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("limitations_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("started_at", sa.String(64), nullable=False),
        sa.Column("finished_at", sa.String(64), nullable=False, server_default=""),
    )
    op.create_index("ix_acq_case_id", "acquisition_sessions", ["case_id"])

    op.create_table(
        "transfer_manifests",
        sa.Column("manifest_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_root", sa.Text(), nullable=False),
        sa.Column("destination_root", sa.Text(), nullable=False),
        sa.Column("conflict_policy", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("total_files", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("succeeded_files", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_files", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_files", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("manifest_path", sa.Text(), nullable=False, server_default=""),
        sa.Column("manifest_sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("started_at", sa.String(64), nullable=False),
        sa.Column("finished_at", sa.String(64), nullable=False, server_default=""),
    )
    op.create_index("ix_transfer_case_id", "transfer_manifests", ["case_id"])

    op.create_table(
        "transferred_files",
        sa.Column("file_id", sa.String(64), primary_key=True),
        sa.Column("manifest_id", sa.String(64), sa.ForeignKey("transfer_manifests.manifest_id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_path", sa.Text(), nullable=False),
        sa.Column("destination_path", sa.Text(), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("destination_sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_tfile_manifest_id", "transferred_files", ["manifest_id"])
    op.create_index("ix_tfile_case_id", "transferred_files", ["case_id"])

    op.create_table(
        "artifacts",
        sa.Column("artifact_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(64), sa.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", sa.String(64), sa.ForeignKey("acquisition_sessions.session_id", ondelete="SET NULL"), nullable=True),
        sa.Column("artifact_type", sa.String(64), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("original_source_path", sa.Text(), nullable=False),
        sa.Column("stored_copy_path", sa.Text(), nullable=False, server_default=""),
        sa.Column("original_timestamp", sa.String(64), nullable=False, server_default=""),
        sa.Column("original_timezone", sa.String(64), nullable=False, server_default="unknown"),
        sa.Column("normalized_timestamp_utc", sa.String(64), nullable=False, server_default=""),
        sa.Column("normalization_justification", sa.Text(), nullable=False, server_default=""),
        sa.Column("acquisition_method", sa.String(64), nullable=False),
        sa.Column("parser_name", sa.String(128), nullable=False),
        sa.Column("parser_version", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False, server_default=""),
        sa.Column("byte_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("extraction_errors", sa.Text(), nullable=False, server_default=""),
        sa.Column("parsing_errors", sa.Text(), nullable=False, server_default=""),
        sa.Column("provenance_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("content_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_artifacts_case_id", "artifacts", ["case_id"])
    op.create_index("ix_artifacts_device_id", "artifacts", ["device_id"])
    op.create_index("ix_artifacts_type", "artifacts", ["artifact_type"])
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"])

    op.create_table(
        "timeline_events",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(64), sa.ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", sa.String(64), sa.ForeignKey("artifacts.artifact_id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("original_timestamp", sa.String(64), nullable=False),
        sa.Column("original_timezone", sa.String(64), nullable=False),
        sa.Column("normalized_utc", sa.String(64), nullable=False, server_default=""),
        sa.Column("timestamp_confidence", sa.String(32), nullable=False, server_default="unverified"),
        sa.Column("source_path", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_timeline_case_utc", "timeline_events", ["case_id", "normalized_utc"])
    op.create_index("ix_timeline_device", "timeline_events", ["device_id"])

    op.create_table(
        "investigation_findings",
        sa.Column("finding_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False, server_default="informational"),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("linked_artifact_ids_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_findings_case_id", "investigation_findings", ["case_id"])

    op.create_table(
        "analyst_notes",
        sa.Column("note_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("artifact_id", sa.String(64), sa.ForeignKey("artifacts.artifact_id", ondelete="SET NULL"), nullable=True),
        sa.Column("author", sa.String(128), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_notes_case_id", "analyst_notes", ["case_id"])

    op.create_table(
        "ai_analyses",
        sa.Column("analysis_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("model_name", sa.String(64), nullable=False),
        sa.Column("analyst_approved", sa.Boolean(), nullable=False),
        sa.Column("pii_redacted", sa.Boolean(), nullable=False),
        sa.Column("prompt_question", sa.Text(), nullable=False),
        sa.Column("selected_artifact_ids_json", sa.Text(), nullable=False),
        sa.Column("verified_artifact_ids_json", sa.Text(), nullable=False),
        sa.Column("rejected_artifact_ids_json", sa.Text(), nullable=False),
        sa.Column("response_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_ai_case_id", "ai_analyses", ["case_id"])

    op.create_table(
        "report_records",
        sa.Column("report_id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(64), sa.ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_format", sa.String(16), nullable=False),
        sa.Column("output_path", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("generated_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_reports_case_id", "report_records", ["case_id"])

    op.create_table(
        "audit_events",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(64), nullable=False, unique=True),
        sa.Column("case_id", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("prev_event_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(64), nullable=False),
    )
    op.create_index("ix_audit_case_seq", "audit_events", ["case_id", "seq"])


def downgrade() -> None:
    for table in (
        "audit_events",
        "report_records",
        "ai_analyses",
        "analyst_notes",
        "investigation_findings",
        "timeline_events",
        "artifacts",
        "transferred_files",
        "transfer_manifests",
        "acquisition_sessions",
        "authorization_records",
        "devices",
        "cases",
    ):
        op.drop_table(table)
