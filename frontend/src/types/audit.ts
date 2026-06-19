export type AuditPhase =
  | "intake"
  | "evidence_mapping"
  | "specialist_review"
  | "verification"
  | "debate"
  | "vote"
  | "synthesis"
  | "complete";

export type Decision = "pending" | "approved" | "conditionally_approved" | "blocked";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type EvidenceRef = {
  ref_id: string;
  title: string;
  artifact: string;
  locator: string;
  sha256: string;
};

export type DataProfile = {
  categories: string[];
  sensitive_data: string[];
  retention: string;
  residency: string;
  training_use: string;
};

export type ToolProfile = {
  integrations: string[];
  read_permissions: string[];
  write_permissions: string[];
  external_side_effects: string[];
  approval_required_for_writes: boolean;
};

export type ControlClaim = {
  control_id: string;
  title: string;
  owner: string;
  status: string;
  required: boolean;
  evidence_refs: string[];
  notes: string;
};

export type EvidenceManifestItem = {
  ref_id: string;
  title: string;
  evidence_type: string;
  artifact: string;
  source: string;
  owner: string;
  linked_control: string;
  linked_risk: string;
  freshness: string;
  status: string;
  sha256: string;
  locator: string;
};

export type PacketAttestation = {
  role: string;
  name: string;
  status: string;
  attested_at: string;
  notes: string;
};

export type ExternalReference = {
  label: string;
  url: string;
  kind: string;
};

export type ReReviewContext = {
  original_room_id: string;
  original_decision: string;
  remediated_findings: string[];
  remediation_summary: string;
};

export type PacketImportArtifact = {
  filename: string;
  mime_type: string;
  sha256: string;
  page_count: number;
  text_char_count: number;
  extraction_method: string;
  ocr_provider: string;
  ocr_model: string;
  pages_processed: number;
  doc_size_bytes: number;
  ocr_text_char_count: number;
  image_count: number;
  table_count: number;
};

export type PacketFieldCitation = {
  field: string;
  page: number | null;
  snippet: string;
  confidence: number;
  status: "pdf_cited" | "needs_review" | "missing" | "manual_override";
};

export type PacketImportFinding = {
  severity: "critical" | "warning" | "info";
  field: string;
  message: string;
  remediation: string;
};

export type PacketImportSummary = {
  source: string;
  artifact: PacketImportArtifact | null;
  citations: PacketFieldCitation[];
  critical_blockers: PacketImportFinding[];
  warnings: PacketImportFinding[];
};

export type AuditPacket = {
  packet_version: string;
  packet_source_mode: string;
  review_type: string;
  target_name: string;
  target_summary: string;
  change_summary: string;
  workflow: string;
  tool_access: string;
  policy_context: string;
  evidence_notes: string;
  business_owner: string;
  technical_owner: string;
  owning_team: string;
  deployment_environment: string;
  affected_users: string;
  criticality: string;
  planned_release_date: string;
  previous_review_id: string;
  ticket_url: string;
  repository_url: string;
  system_type: string;
  autonomy_level: string;
  human_oversight: string;
  data_profile: DataProfile;
  tool_profile: ToolProfile;
  control_claims: ControlClaim[];
  evidence_manifest: EvidenceManifestItem[];
  evaluation_summary: string;
  known_limitations: string;
  release_goal: string;
  rollout_plan: string;
  monitoring_plan: string;
  rollback_plan: string;
  incident_response_owner: string;
  stop_conditions: string[];
  attestations: PacketAttestation[];
  external_references: ExternalReference[];
  re_review_context: ReReviewContext;
  import_summary: PacketImportSummary;
  supporting_evidence_imports: PacketImportSummary[];
};

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type AuditEvent = {
  event_id: string;
  audit_id: string;
  room_id: string;
  agent: string;
  provider: "aiml" | "featherless" | null;
  event_type: string;
  summary: string;
  created_at: string;
  phase: AuditPhase;
  claim_id: string | null;
  severity: Severity;
  confidence: number;
  risk_delta: number;
  evidence_refs: EvidenceRef[];
  consumes_event_ids: string[];
  produces_refs: string[];
  finding_refs: string[];
  vote_refs: string[];
  metadata: Record<string, JsonValue>;
};

export type AgentProfile = {
  id: string;
  name: string;
  role: string;
  provider: string;
  status: "idle" | "active" | "blocked" | "complete";
  current_task: string;
};

export type Finding = {
  claim_id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  owner_agent: string;
  status: "open" | "verified" | "challenged" | "debating" | "accepted" | "blocked";
  summary: string;
  risk_mechanism: string;
  affected_assets: string[];
  release_impact: string;
  remediation: string[];
  verification_notes: string[];
  evidence_refs: EvidenceRef[];
  last_event_id: string;
};

export type VoteRecord = {
  agent: string;
  vote: "approve" | "conditional" | "block";
  rationale: string;
};

export type AuditReport = {
  title: string;
  decision: Decision;
  release_verdict: string;
  executive_summary: string;
  required_remediations: string[];
  re_review_criteria: string[];
  evidence_standard: string;
  event_trace: string[];
  transcript_refs: string[];
};

export type SourceDiagnostics = {
  source: "band";
  requested_mode: string;
  effective_mode: "band";
  audit_id: string;
  room_id: string;
  protocol: string;
  env_file: string;
  env_file_present: boolean;
  env_file_loaded: boolean;
  band_api_key_present: boolean;
  band_room_id_present: boolean;
  band_rest_url_configured: boolean;
  band_sdk_installed: boolean;
  band_sdk_version: string | null;
  last_error: string | null;
};

export type ProviderDiagnostics = {
  provider: "aiml" | "featherless";
  label: string;
  status: "ready" | "missing_configuration" | "error";
  api_key_present: boolean;
  model_configured: boolean;
  base_url: string | null;
  model: string | null;
  last_error: string | null;
};

export type AgentProviderRoute = {
  agent: string;
  provider: "aiml" | "featherless";
  purpose: string;
  model: string | null;
};

export type AgentExecutionDiagnostics = {
  requested_mode: string;
  effective_mode: "mixed" | "live";
  env_file: string;
  env_file_present: boolean;
  env_file_loaded: boolean;
  providers: ProviderDiagnostics[];
  routes: AgentProviderRoute[];
  last_agent: string | null;
  last_provider: "aiml" | "featherless" | null;
  last_error: string | null;
};

export type AuditState = {
  audit_id: string;
  room_id: string;
  title: string;
  subject: string;
  input_packet: AuditPacket;
  phase: AuditPhase;
  decision: Decision;
  risk_score: number;
  risk_level: Severity;
  agents: AgentProfile[];
  findings: Finding[];
  events: AuditEvent[];
  votes: VoteRecord[];
  source: SourceDiagnostics;
  agent_execution: AgentExecutionDiagnostics;
  report: AuditReport | null;
};

export type AdvanceResponse = {
  audit: AuditState;
  appended_events: AuditEvent[];
};

export type CreateRoomResponse = {
  audit: AuditState;
  room_id: string;
  room_url: string | null;
  persisted: boolean;
  message: string;
};

export type PacketImportResponse = {
  extracted_packet: AuditPacket;
  artifact: PacketImportArtifact;
  field_citations: PacketFieldCitation[];
  completeness_findings: PacketImportFinding[];
  critical_blockers: PacketImportFinding[];
  warnings: PacketImportFinding[];
};

export type EvidenceImportResponse = {
  evidence_manifest: EvidenceManifestItem[];
  evidence_notes_append: string;
  evaluation_summary_append: string;
  known_limitations_append: string;
  import_summaries: PacketImportSummary[];
  warnings: PacketImportFinding[];
};
