/**
 * SecureMailScope — Strict TypeScript API Types
 * Verified against live FastAPI endpoints and backend models:
 * - src/securemailscope/dashboard/model.py
 * - src/securemailscope/evidence/states.py
 * - src/securemailscope/analysis/model.py
 * - src/securemailscope/session/model.py
 */

export type PostureBand = 
  | 'STRONG' 
  | 'ADEQUATE' 
  | 'WEAK' 
  | 'CRITICAL' 
  | 'INSUFFICIENT_EVIDENCE';

export type EvidenceState = 
  | 'OBSERVED' 
  | 'INFERRED' 
  | 'UNKNOWN' 
  | 'AMBIGUOUS' 
  | 'INCOMPLETE' 
  | 'NOT_OBSERVABLE';

export type FindingStatus = 
  | 'OBSERVED_ISSUE' 
  | 'COMPLIANT' 
  | 'INFORMATIONAL' 
  | 'AMBIGUOUS' 
  | 'INSUFFICIENT_EVIDENCE' 
  | 'NOT_OBSERVABLE';

export type BaselineStatus = 
  | 'ESTABLISHED' 
  | 'INSUFFICIENT_HISTORY' 
  | 'NOT_APPLICABLE';

export type Deviation = 
  | 'NONE' 
  | 'DEVIATION' 
  | 'SUSPICIOUS_DEVIATION' 
  | 'NOT_ASSESSED';

export type JobState = 
  | 'CREATED' 
  | 'VALIDATING' 
  | 'QUEUED' 
  | 'RUNNING' 
  | 'FINALIZING' 
  | 'COMPLETED' 
  | 'FAILED' 
  | 'CANCELLED' 
  | 'RECOVERY_REQUIRED';

export interface HealthResponse {
  status: string;
  version: string;
  backend_schema_version: string;
  posture_schema_version: string;
  posture_engine_version: string;
  database: string;
  artifact_count: number;
  artifact_bytes: number;
  limits: {
    max_upload_bytes: number;
    max_concurrent_analyses: number;
    max_queued_jobs: number;
    max_analysis_seconds: number;
    max_page_size: number;
    default_page_size: number;
    max_json_bytes: number;
  };
  tshark: string;
}

export interface RunResponse {
  run_id: string;
  state: JobState;
  capture_id: string;
  assessment_id: string | null;
  ai_enabled: boolean;
  formula_id: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_ms: number | null;
  ingest_status: string;
  error_code: string | null;
  error_message: string | null;
  source_filename: string;
  backend_version: string;
  replayed: boolean;
  stages: Array<{ stage: string; ms: number }> | null;
  overall_posture: PostureBand | null;
  score_value: number | null;
}

export interface RunListResponse {
  total: number;
  limit: number;
  offset: number;
  items: RunResponse[];
}

export interface Citation {
  standard: string;
  section: string;
  reason: string;
  text: string;
}

export interface Remediation {
  observed: string;
  why_it_matters: string;
  recommended_action: string;
  affected_scope: string;
  verification: string;
  citations: Citation[];
  limitations: string[];
}

export interface ScoreComponentRow {
  issue_class: string;
  issue_class_label: string;
  severity: string | null;
  severity_label: string;
  recurrence: number | null;
  base_weight: number | null;
  recurrence_multiplier: number | null;
  penalty: number | null;
  explanation: string;
}

export interface Posture {
  value: PostureBand;
  label: string;
  tone: string;
  known: boolean;
  withheld: boolean;
  withheld_note: string;
  score_value: number | null;
  score_text: string;
  formula_id: string | null;
  starting_value: number | null;
  total_penalty: number | null;
  basis: string;
  components: ScoreComponentRow[];
}

export interface Identity {
  assessment_id: string;
  capture_id: string;
  run_id: string | null;
  generated_at: string;
  posture_schema_version: string;
  posture_engine_version: string;
  ai_enabled: boolean;
  dashboard_schema_version: string;
  projection_version: string;
}

export interface Coverage {
  sessions_total: number | null;
  sessions_assessed: number | null;
  sessions_abstained: number | null;
  assessed_fraction: number | null;
  percent_text: string;
  summary_text: string;
  observation_counts: Record<EvidenceState, number>;
  observation_fractions: Record<EvidenceState, number>;
  completeness_counts: Record<string, number>;
  protocol_counts: Record<string, number>;
  present: boolean;
}

export interface FindingRow {
  rank: number | null;
  priority_score: number | null;
  ml_adjustment: number | null;
  affected_sessions: number | null;
  affected_stream_keys: string[];
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  severity_label: string;
  severity_marker: string;
  severity_tone: string;
  severity_known: boolean;
  status: FindingStatus | null;
  status_label: string;
  certainty: 'CONFIRMED' | 'PROBABLE' | 'UNCERTAIN' | 'UNDETERMINED' | null;
  certainty_label: string;
  observability: string | null;
  observability_label: string;
  issue_class: string | null;
  issue_class_label: string;
  fact_kind: string | null;
  fact_kind_label: string;
  dimension: string | null;
  dimension_label: string;
  protocol: string | null;
  protocol_key: string;
  protocol_label: string;
  title: string;
  conclusion: string;
  explanation: string;
  penalising: boolean;
  stream_key: string | null;
  tcp_stream_id: number | null;
  frames: number[];
  frames_text: string;
  source_rule_ids: string[];
  citations: Citation[];
  remediation: Remediation | null;
  contradictions: string[];
  limitations: string[];
  factors: Record<string, number>;
  explanation_priority: string;
}

export interface IssueGroupRow {
  issue_class: string | null;
  issue_class_label: string;
  title: string;
  severity: string | null;
  severity_label: string;
  severity_marker: string;
  severity_tone: string;
  fact_kind: string | null;
  fact_kind_label: string;
  dimension: string | null;
  dimension_label: string;
  certainty: string | null;
  certainty_label: string;
  recurrence: number | null;
  protocols: string[];
  affected_stream_keys: string[];
  penalising: boolean;
  finding_count: number | null;
  citations: Citation[];
  remediation: Remediation | null;
}

export interface AbstentionRow {
  reason: string | null;
  reason_label: string;
  issue_class: string | null;
  issue_class_label: string;
  what_could_not_be_concluded: string;
  why: string;
  resolved_by: string;
  rule_id: string;
  protocol: string | null;
  protocol_label: string;
  stream_key: string | null;
  frames: number[];
}

export interface StandardRow {
  standard: string;
  sections: string[];
}

export interface Standards {
  standards: StandardRow[];
  distinct_standards: number | null;
  unmapped_citations: string[];
  note: string;
  present: boolean;
}

export interface MLPanel {
  enabled: boolean;
  role: string;
  note: string;
  facts: Record<string, any>;
  limitations: string[];
  boundary_statement: string;
}

export interface Provenance {
  rule_ids: string[];
  source_counts: Record<string, any>;
  entries: Record<string, any>;
  note: string;
}

export interface FilterOption {
  value: string;
  label: string;
  count: number;
}

export interface Filters {
  severity: FilterOption[];
  status: FilterOption[];
  certainty: FilterOption[];
  observability: FilterOption[];
  fact_kind: FilterOption[];
  issue_class: FilterOption[];
  dimension: FilterOption[];
  protocol: FilterOption[];
}

export interface DashboardViewModel {
  identity: Identity;
  posture: Posture;
  coverage: Coverage;
  distributions: Array<{
    id: string;
    caption: string;
    note: string;
    bars: Array<{
      key: string;
      label: string;
      value: number;
      max_value: number;
      value_text: string;
      tone: string;
    }>;
  }>;
  protocols: Array<{
    protocol: string;
    sessions: number | null;
    band: string | null;
    band_label: string;
    band_tone: string;
    score_value: number | null;
    score_text: string;
    issue_classes: string[];
    dimensions_assessed: string[];
    dimensions_not_observable: string[];
    abstentions: number | null;
  }>;
  findings: FindingRow[];
  issue_groups: IssueGroupRow[];
  abstentions: AbstentionRow[];
  standards: Standards | null;
  remediation: Remediation[];
  ml: MLPanel | null;
  provenance: Provenance | null;
  limitations: string[];
  filters: Filters | null;
  notices: string[];
  unavailable: string[];
}

export interface EvidenceField<T = any> {
  value: T | null;
  state: EvidenceState;
  basis: string | null;
  provenance: string;
  frames: number[];
}

export interface Certificate {
  index: number;
  serial: string;
  version: string;
  not_before: string;
  not_after: string;
  public_key_algorithm: string;
  key_bits: number | null;
  subject_key_id: string | null;
  authority_key_id: string | null;
  self_signed: boolean;
  san_dns_names: string[];
}

export interface Transition {
  from_state: string;
  event: string;
  to_state: string;
  evidence_frames: number[];
  evidence_state: EvidenceState;
  timestamp_epoch: number | null;
  basis: string;
}

export interface ProtocolEvent {
  kind: string;
  direction: 'CLIENT_TO_SERVER' | 'SERVER_TO_CLIENT';
  frame: number;
  detail: string;
}

export interface SessionEvidence {
  stream_key: string;
  capture_id: string;
  tcp_stream_id: number;
  protocol: string;
  client: { ip: string; port: number };
  server: { ip: string; port: number };
  endpoint_basis: string;
  timing: {
    first_frame: number;
    last_frame: number;
    start_epoch: number | null;
    end_epoch: number | null;
    packet_count: number;
  };
  transport_flags: string[];
  completeness: string;
  app_state: string;
  tls_state: string;
  implicit_tls: boolean;
  evidence: {
    starttls_advertised: EvidenceField<boolean>;
    starttls_requested: EvidenceField<boolean>;
    starttls_accepted: EvidenceField<boolean>;
    tls_transition: EvidenceField<string>;
    tls_negotiated_version: EvidenceField<string>;
    tls_cipher_suite: EvidenceField<string>;
    tls_cipher_suite_name: EvidenceField<string>;
    tls_key_exchange: EvidenceField<string>;
    tls_named_group: EvidenceField<string>;
    tls_forward_secrecy: EvidenceField<boolean>;
    tls_certificate_chain: EvidenceField<number>;
    plaintext_continuation: EvidenceField<boolean>;
    auth_activity: EvidenceField<any>;
  };
  certificates: Certificate[];
  certificate_notes: string[];
  transitions: Transition[];
  events: ProtocolEvent[];
  notes: string[];
}

export interface SessionListResponse {
  run_id: string;
  capture_id: string;
  total: number;
  items: SessionEvidence[];
}

export interface AssessmentResponse {
  run_id: string;
  assessment_id: string;
  capture_id: string;
  overall_posture: PostureBand;
  coverage: any;
  limitations: string[];
  assessment: {
    assessment_id: string;
    capture_id: string;
    overall_posture: PostureBand;
    coverage?: Coverage;
    limitations?: string[];
    generated_at: string;
    versions?: Record<string, string>;
    score?: {
      starting_value: number;
      total_penalty: number;
      score_value: number;
      formula_id: string;
      basis: string;
    };
    prioritised?: Array<{
      rank: number;
      priority_score: number;
      ml_adjustment: number;
      affected_sessions: number;
      affected_stream_keys: string[];
      explanation: string;
      representative_finding: any;
    }>;
    issue_groups?: any[];
    abstentions?: any[];
    protocol_posture?: any[];
    standards_summary?: any;
    model_summary?: any;
    provenance?: any;
    risk_summary?: any;
  };
}

export interface ReportItem {
  format: 'html' | 'pdf' | 'json';
  media_type: string;
  filename: string;
  renderer_available: boolean;
  report_schema_version: string;
  renderer_version: string;
  generated: boolean;
  artifact_id: string | null;
  report_sha256: string | null;
  size_bytes: number | null;
  created_at: string | null;
  current: boolean | null;
  integrity: string | null;
}

export interface ReportListResponse {
  run_id: string;
  items: ReportItem[];
}

export const EPISTEMIC_SYMBOLS: Record<EvidenceState, string> = {
  OBSERVED: '●',
  INFERRED: '⊢',
  UNKNOWN: '?',
  AMBIGUOUS: '≬',
  INCOMPLETE: '⋯',
  NOT_OBSERVABLE: '∅',
};

export const EPISTEMIC_DESCRIPTIONS: Record<EvidenceState, string> = {
  OBSERVED: 'Directly and unambiguously demonstrated by passive packet inspection.',
  INFERRED: 'Logically deduced from observed protocol states and deterministic rules.',
  UNKNOWN: 'Expected state could not be determined from the available captured frames.',
  AMBIGUOUS: 'Contradictory or branching signals observed; cannot uniquely establish state.',
  INCOMPLETE: 'Capture boundary severed mid-handshake or dialogue before state resolved.',
  NOT_OBSERVABLE: 'Inherently unobservable by passive capture design (e.g. TLS 1.3 encrypted certs, missing trust store).',
};
