from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class AuditPhase(StrEnum):
    INTAKE = "intake"
    EVIDENCE_MAPPING = "evidence_mapping"
    SPECIALIST_REVIEW = "specialist_review"
    VERIFICATION = "verification"
    DEBATE = "debate"
    VOTE = "vote"
    SYNTHESIS = "synthesis"
    COMPLETE = "complete"


class Decision(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    CONDITIONALLY_APPROVED = "conditionally_approved"
    BLOCKED = "blocked"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(StrEnum):
    AUDIT_INIT = "audit_init"
    ARTIFACT_INDEXED = "artifact_indexed"
    FINDING = "finding"
    EVIDENCE_REQUEST = "evidence_request"
    VERIFICATION = "verification"
    CHALLENGE = "challenge"
    CONFLICT_DECLARATION = "conflict_declaration"
    DEBATE_POSITION = "debate_position"
    VOTE = "vote"
    HUMAN_ESCALATION = "human_escalation"
    SYNTHESIS_REPORT = "synthesis_report"


class EvidenceRef(BaseModel):
    ref_id: str
    title: str
    artifact: str
    locator: str
    sha256: str


class DataProfile(BaseModel):
    categories: list[str] = Field(default_factory=list)
    sensitive_data: list[str] = Field(default_factory=list)
    retention: str = ""
    residency: str = ""
    training_use: str = ""


class ToolProfile(BaseModel):
    integrations: list[str] = Field(default_factory=list)
    read_permissions: list[str] = Field(default_factory=list)
    write_permissions: list[str] = Field(default_factory=list)
    external_side_effects: list[str] = Field(default_factory=list)
    approval_required_for_writes: bool = True


class ControlClaim(BaseModel):
    control_id: str
    title: str
    owner: str = ""
    status: str = "claimed"
    required: bool = True
    evidence_refs: list[str] = Field(default_factory=list)
    notes: str = ""


class EvidenceManifestItem(BaseModel):
    ref_id: str
    title: str
    evidence_type: str = "document"
    artifact: str
    source: str = ""
    owner: str = ""
    linked_control: str = ""
    linked_risk: str = ""
    freshness: str = ""
    status: str = "submitted"
    sha256: str = ""
    locator: str = ""


class PacketAttestation(BaseModel):
    role: str
    name: str
    status: str = "submitted"
    attested_at: str = ""
    notes: str = ""


class ExternalReference(BaseModel):
    label: str
    url: str
    kind: str = "reference"


class ReReviewContext(BaseModel):
    original_room_id: str = ""
    original_decision: str = ""
    remediated_findings: list[str] = Field(default_factory=list)
    remediation_summary: str = ""


class PacketImportArtifact(BaseModel):
    filename: str = ""
    mime_type: str = "application/pdf"
    sha256: str = ""
    page_count: int = 0
    text_char_count: int = 0
    extraction_method: str = ""
    ocr_provider: str = ""
    ocr_model: str = ""
    pages_processed: int = 0
    doc_size_bytes: int = 0
    ocr_text_char_count: int = 0
    image_count: int = 0
    table_count: int = 0


class PacketFieldCitation(BaseModel):
    field: str
    page: int | None = None
    snippet: str = ""
    confidence: float = Field(default=0.0, ge=0, le=1)
    status: Literal["pdf_cited", "needs_review", "missing", "manual_override"] = "missing"


class PacketImportFinding(BaseModel):
    severity: Literal["critical", "warning", "info"]
    field: str
    message: str
    remediation: str = ""


class PacketImportSummary(BaseModel):
    source: str = ""
    artifact: PacketImportArtifact | None = None
    citations: list[PacketFieldCitation] = Field(default_factory=list)
    critical_blockers: list[PacketImportFinding] = Field(default_factory=list)
    warnings: list[PacketImportFinding] = Field(default_factory=list)


class EvidenceImportResponse(BaseModel):
    evidence_manifest: list[EvidenceManifestItem] = Field(default_factory=list)
    evidence_notes_append: str = ""
    evaluation_summary_append: str = ""
    known_limitations_append: str = ""
    import_summaries: list[PacketImportSummary] = Field(default_factory=list)
    warnings: list[PacketImportFinding] = Field(default_factory=list)


def default_data_profile() -> DataProfile:
    return DataProfile()


def default_tool_profile() -> ToolProfile:
    return ToolProfile()


def default_control_claims() -> list[ControlClaim]:
    return []


def default_evidence_manifest() -> list[EvidenceManifestItem]:
    return []


def default_attestations() -> list[PacketAttestation]:
    return []


def default_external_references() -> list[ExternalReference]:
    return []


class AuditPacket(BaseModel):
    packet_version: str = Field(default="v2", max_length=40)
    packet_source_mode: str = Field(default="manual", max_length=80)
    review_type: str = Field(default="", max_length=120)
    target_name: str = Field(default="", max_length=180)
    target_summary: str = Field(default="", max_length=4000)
    change_summary: str = Field(default="", max_length=4000)
    workflow: str = Field(default="", max_length=4000)
    tool_access: str = Field(default="", max_length=4000)
    policy_context: str = Field(default="", max_length=4000)
    evidence_notes: str = Field(default="", max_length=4000)
    business_owner: str = Field(default="", max_length=400)
    technical_owner: str = Field(default="", max_length=400)
    owning_team: str = Field(default="", max_length=400)
    deployment_environment: str = Field(default="", max_length=400)
    affected_users: str = Field(default="", max_length=400)
    criticality: str = Field(default="", max_length=120)
    planned_release_date: str = Field(default="", max_length=120)
    previous_review_id: str = Field(default="", max_length=300)
    ticket_url: str = Field(default="https://jira.example.com/browse/JSM-7421", max_length=1000)
    repository_url: str = Field(default="https://github.example.com/people/talentscreen-assist", max_length=1000)
    system_type: str = Field(default="", max_length=200)
    autonomy_level: str = Field(default="", max_length=200)
    human_oversight: str = Field(default="", max_length=1000)
    data_profile: DataProfile = Field(default_factory=default_data_profile)
    tool_profile: ToolProfile = Field(default_factory=default_tool_profile)
    control_claims: list[ControlClaim] = Field(default_factory=default_control_claims)
    evidence_manifest: list[EvidenceManifestItem] = Field(default_factory=default_evidence_manifest)
    evaluation_summary: str = Field(default="", max_length=4000)
    known_limitations: str = Field(default="", max_length=4000)
    release_goal: str = Field(default="", max_length=600)
    rollout_plan: str = Field(default="", max_length=4000)
    monitoring_plan: str = Field(default="", max_length=4000)
    rollback_plan: str = Field(default="", max_length=4000)
    incident_response_owner: str = Field(default="", max_length=400)
    stop_conditions: list[str] = Field(default_factory=list)
    attestations: list[PacketAttestation] = Field(default_factory=default_attestations)
    external_references: list[ExternalReference] = Field(default_factory=default_external_references)
    re_review_context: ReReviewContext = Field(default_factory=ReReviewContext)
    import_summary: PacketImportSummary = Field(default_factory=PacketImportSummary)
    supporting_evidence_imports: list[PacketImportSummary] = Field(default_factory=list)


class PacketImportResponse(BaseModel):
    extracted_packet: AuditPacket
    artifact: PacketImportArtifact
    field_citations: list[PacketFieldCitation]
    completeness_findings: list[PacketImportFinding]
    critical_blockers: list[PacketImportFinding]
    warnings: list[PacketImportFinding]


class AuditEvent(BaseModel):
    event_id: str
    audit_id: str
    room_id: str
    agent: str
    provider: Literal["aiml", "featherless"] | None = None
    event_type: EventType
    summary: str
    created_at: datetime
    phase: AuditPhase
    claim_id: str | None = None
    severity: Severity = Severity.INFO
    confidence: float = Field(default=1.0, ge=0, le=1)
    risk_delta: int = 0
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    consumes_event_ids: list[str] = Field(default_factory=list)
    produces_refs: list[str] = Field(default_factory=list)
    finding_refs: list[str] = Field(default_factory=list)
    vote_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentProfile(BaseModel):
    id: str
    name: str
    role: str
    provider: str
    status: Literal["idle", "active", "blocked", "complete"]
    current_task: str


class Finding(BaseModel):
    claim_id: str
    title: str
    category: str
    severity: Severity
    confidence: float
    owner_agent: str
    status: Literal["open", "verified", "challenged", "debating", "accepted", "blocked"]
    summary: str
    risk_mechanism: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    release_impact: str = ""
    remediation: list[str] = Field(default_factory=list)
    verification_notes: list[str] = Field(default_factory=list)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    last_event_id: str


class VoteRecord(BaseModel):
    agent: str
    vote: Literal["approve", "conditional", "block"]
    rationale: str


class AuditReport(BaseModel):
    title: str
    decision: Decision
    release_verdict: str
    executive_summary: str
    required_remediations: list[str]
    re_review_criteria: list[str]
    evidence_standard: str
    event_trace: list[str]
    transcript_refs: list[str]


class SourceDiagnostics(BaseModel):
    source: Literal["band"]
    requested_mode: str
    effective_mode: Literal["band"]
    audit_id: str
    room_id: str
    protocol: str
    env_file: str
    env_file_present: bool
    env_file_loaded: bool
    band_api_key_present: bool
    band_room_id_present: bool
    band_rest_url_configured: bool
    band_sdk_installed: bool
    band_sdk_version: str | None = None
    last_error: str | None = None


class ProviderDiagnostics(BaseModel):
    provider: Literal["aiml", "featherless"]
    label: str
    status: Literal["ready", "missing_configuration", "error"]
    api_key_present: bool
    model_configured: bool
    base_url: str | None = None
    model: str | None = None
    last_error: str | None = None


class AgentProviderRoute(BaseModel):
    agent: str
    provider: Literal["aiml", "featherless"]
    purpose: str
    model: str | None = None


class AgentExecutionDiagnostics(BaseModel):
    requested_mode: str
    effective_mode: Literal["mixed", "live"]
    env_file: str
    env_file_present: bool
    env_file_loaded: bool
    providers: list[ProviderDiagnostics]
    routes: list[AgentProviderRoute]
    last_agent: str | None = None
    last_provider: Literal["aiml", "featherless"] | None = None
    last_error: str | None = None


class AuditState(BaseModel):
    audit_id: str
    room_id: str
    title: str
    subject: str
    input_packet: AuditPacket
    phase: AuditPhase
    decision: Decision
    risk_score: int
    risk_level: Severity
    agents: list[AgentProfile]
    findings: list[Finding]
    events: list[AuditEvent]
    votes: list[VoteRecord]
    source: SourceDiagnostics
    agent_execution: AgentExecutionDiagnostics
    report: AuditReport | None = None


class SourceDiagnosticsResponse(BaseModel):
    status: Literal["ok", "error"]
    diagnostics: SourceDiagnostics
    event_count: int | None = None
    read_error: str | None = None


class AdvanceResponse(BaseModel):
    audit: AuditState
    appended_events: list[AuditEvent]


class CreateRoomResponse(BaseModel):
    audit: AuditState
    room_id: str
    room_url: str | None = None
    persisted: bool = False
    message: str
