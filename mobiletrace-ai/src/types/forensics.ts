export interface ForensicCase {
  case_id: string;
  case_number: string;
  title: string;
  examiner: string;
  agency: string;
  status: string;
  notes: string;
  created_at: string;
  updated_at: string;
  device_count?: number;
  artifact_count?: number;
  session_count?: number;
}

export interface ForensicDevice {
  device_id: string;
  case_id: string;
  platform: string;
  serial_or_udid: string;
  manufacturer: string;
  model: string;
  os_version: string;
  build_or_sdk: string;
  connection_state: string;
  metadata_json: string;
  first_seen_at: string;
}

export interface AcquisitionSession {
  session_id: string;
  case_id: string;
  device_id: string;
  acquisition_method: string;
  scope_classification: string;
  source_location: string;
  output_directory: string;
  status: string;
  files_copied: number;
  bytes_copied: number;
  errors_json: string;
  limitations_json: string;
  started_at: string;
  finished_at: string;
}

export interface ForensicArtifact {
  artifact_id: string;
  case_id: string;
  device_id: string;
  session_id: string | null;
  artifact_type: string;
  title: string;
  summary: string;
  original_source_path: string;
  stored_copy_path: string;
  original_timestamp: string;
  original_timezone: string;
  normalized_timestamp_utc: string;
  normalization_justification: string;
  acquisition_method: string;
  parser_name: string;
  parser_version: string;
  sha256: string;
  byte_size: number;
  extraction_errors: string;
  parsing_errors: string;
  provenance_json: string;
  content_json: string;
  created_at: string;
}

export interface TimelineEvent {
  event_id: string;
  case_id: string;
  device_id: string;
  artifact_id: string;
  event_type: string;
  description: string;
  original_timestamp: string;
  original_timezone: string;
  normalized_utc: string;
  timestamp_confidence: string;
  source_path: string;
  device_model?: string;
  device_platform?: string;
}

export interface TransferManifestRecord {
  manifest_id: string;
  case_id: string;
  source_root: string;
  destination_root: string;
  conflict_policy: string;
  status: string;
  total_files: number;
  succeeded_files: number;
  failed_files: number;
  skipped_files: number;
  total_bytes: number;
  manifest_path: string;
  manifest_sha256: string;
  started_at: string;
  finished_at: string;
  files?: Array<{
    file_id: string;
    source_path: string;
    destination_path: string;
    byte_size: number;
    source_sha256: string;
    destination_sha256: string;
    verified: number;
    status: string;
    error_message: string;
  }>;
}

export interface CaseDetailResponse {
  case: ForensicCase;
  devices: ForensicDevice[];
  authorizations: Array<Record<string, any>>;
  sessions: AcquisitionSession[];
  transfers: TransferManifestRecord[];
  artifacts: ForensicArtifact[];
  timeline: TimelineEvent[];
  findings: Array<Record<string, any>>;
  notes: Array<Record<string, any>>;
  ai_analyses: Array<Record<string, any>>;
  reports: Array<{
    report_id: string;
    report_format: string;
    output_path: string;
    sha256: string;
    generated_by: string;
    created_at: string;
  }>;
  audit_events: Array<{
    seq: number;
    event_id: string;
    actor: string;
    action: string;
    target_type: string;
    target_id: string;
    details_json: string;
    prev_event_hash: string;
    event_hash: string;
    created_at: string;
  }>;
}

export interface DiagnosticsResponse {
  host_os: string;
  db_path: string;
  workspace_dir: string;
  gemini_configured: boolean;
  gemini_model: string;
  redact_pii_default: boolean;
  android: {
    adb_available: boolean;
    devices: Array<Record<string, any>>;
    error?: string | null;
  };
  ios: {
    tooling_available: boolean;
    devices: Array<Record<string, any>>;
    guidance?: string;
    error?: string;
  };
  ios_tooling: {
    libimobiledevice_available: boolean;
    binaries: Record<string, string | null>;
    pymobiledevice3_available: boolean;
    encrypted_backup_decrypt_available: boolean;
    host_os: string;
    guidance: string;
  };
  forensic_tools: Record<
    string,
    {
      name: string;
      license: string;
      supported_inputs: string[];
      platform_notes: string;
      installed: boolean;
      binary_path: string | null;
      version: string | null;
    }
  >;
}
