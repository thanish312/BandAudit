import {
  ArrowRight,
  BadgeCheck,
  Bot,
  CalendarDays,
  ChevronDown,
  ChevronsUpDown,
  CheckCircle2,
  CircleAlert,
  ClipboardCheck,
  Copy,
  Download,
  FileSearch,
  FileText,
  GitBranch,
  LayoutDashboard,
  MessagesSquare,
  MoreVertical,
  RefreshCcw,
  Search,
  ShieldCheck,
  TriangleAlert,
  UserRound,
  Vote,
  Workflow,
} from "lucide-react";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Avatar,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Container,
  Divider,
  Drawer,
  FormControl,
  IconButton,
  InputLabel,
  LinearProgress,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText as MuiListItemText,
  Menu,
  MenuItem,
  Paper,
  Select,
  Step,
  StepLabel,
  Stepper,
  Stack as MuiStack,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  ToggleButton,
  ToggleButtonGroup,
  Typography as MuiTypography
} from "@mui/material";
import { keyframes } from "@emotion/react";
import type { StackProps, TypographyProps } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef, GridRowParams } from "@mui/x-data-grid";
import { type CSSProperties, type ElementType, type ReactNode, useEffect, useMemo, useState } from "react";
import { advanceAudit, configureAuditPacket, createAuditRoom, getAudit, importAuditPacketPdf, importSupportingEvidence, resetAudit } from "./lib/api";
import { buildAuditReportModel } from "./report/reportModel";
import type {
  AgentProfile,
  AuditEvent,
  AuditPacket,
  AuditState,
  ControlClaim,
  CreateRoomResponse,
  DataProfile,
  Decision,
  EvidenceImportResponse,
  EvidenceManifestItem,
  EvidenceRef,
  Finding,
  PacketAttestation,
  PacketFieldCitation,
  PacketImportFinding,
  PacketImportResponse,
  PacketImportSummary,
  Severity,
  ToolProfile
} from "./types/audit";

type CompatStackProps = StackProps & {
  alignItems?: unknown;
  justifyContent?: unknown;
  flexWrap?: unknown;
  gap?: unknown;
  component?: ElementType;
};

type CompatTypographyProps = TypographyProps & {
  fontWeight?: number | string;
  textAlign?: CSSProperties["textAlign"];
};

function Stack({ alignItems, justifyContent, flexWrap, gap, sx, ...props }: CompatStackProps) {
  return (
    <MuiStack
      {...(props as StackProps)}
      sx={{
        ...(sx as object),
        ...(alignItems !== undefined ? { alignItems } : {}),
        ...(justifyContent !== undefined ? { justifyContent } : {}),
        ...(flexWrap !== undefined ? { flexWrap } : {}),
        ...(gap !== undefined ? { gap } : {})
      }}
    />
  );
}

function Typography({ fontWeight, textAlign, sx, ...props }: CompatTypographyProps) {
  return (
    <MuiTypography
      {...(props as TypographyProps)}
      sx={{
        ...(sx as object),
        ...(fontWeight !== undefined ? { fontWeight } : {}),
        ...(textAlign !== undefined ? { textAlign } : {})
      }}
    />
  );
}

function ListItemText({
  primaryTypographyProps,
  ...props
}: {
  primaryTypographyProps?: Record<string, unknown>;
  [key: string]: unknown;
}) {
  return (
    <MuiListItemText
      {...(props as Record<string, unknown>)}
      slotProps={primaryTypographyProps ? { primary: primaryTypographyProps } : undefined}
    />
  );
}

type ViewMode = "landing" | "setup" | "review" | "protocol" | "timeline" | "report";
type TimelineFilter = "all" | "findings" | "evidence" | "challenges" | "votes" | "decisions";
type SetupMode = "sample" | "custom" | "re_review";
type PacketSourceMode = "manual" | "pdf_packet" | "re_review";
type DashboardTone = "success" | "danger" | "warning" | "neutral";
type SeverityFilter = "all" | Severity;
type FindingStatusFilter = "all" | Finding["status"];
type ReviewRoomMode = "fresh" | "existing";
type PdfImportStage = "idle" | "uploading" | "ocr" | "extracting" | "ready";

type PacketCompletenessItem = {
  id: string;
  label: string;
  complete: boolean;
  severity: "required" | "evidence" | "control";
  detail: string;
};

type ReviewRunState = {
  active: boolean;
  stage: string;
  message: string;
  completedStages: string[];
  appendedEvents: number;
  error: string | null;
};

type RecentReview = {
  id: string;
  target: string;
  decision: string;
  risk: string;
  events: number;
  updated: string;
};

type RemediationTask = {
  id: string;
  findingId: string;
  severity: Severity;
  owner: string;
  status: Finding["status"];
  text: string;
  evidenceRefs: string[];
  requiredEvidenceCount: number;
};

type EvidenceProvenanceRow = {
  id: string;
  evidence: EvidenceRef;
  eventNumbers: string[];
  actors: string[];
  providers: string[];
  roomIds: string[];
};

type ReleaseBoardLaneRow = {
  agent: string;
  lane: string;
  role: string;
  provider: string;
  model: string;
  latestEvent: string;
  eventCount: number;
  participantMode: string;
  participantId: string;
};

type PreflightStatus = "pass" | "warn" | "fail";

type PreflightItem = {
  id: string;
  label: string;
  detail: string;
  status: PreflightStatus;
  blocking: boolean;
};

type AuditIntegrity = {
  roomId: string;
  eventCount: number;
  packetSource: string;
  packetVersion: string;
  evidenceLinks: number;
  artifactHashes: string[];
  repairCount: number;
  synthesisEventId: string;
};

const supportingEvidenceAccept = ".pdf,.txt,.md,.csv,.json,.ndjson";
const supportingEvidenceExtensions = new Set(["pdf", "txt", "md", "csv", "json", "ndjson"]);

const routes: Record<ViewMode, string> = {
  landing: "/",
  setup: "/setup",
  review: "/review",
  protocol: "/protocol",
  timeline: "/timeline",
  report: "/report"
};

const phaseLabels: Record<string, string> = {
  intake: "Intake",
  evidence_mapping: "Evidence mapping",
  specialist_review: "Specialist review",
  verification: "Verification",
  debate: "Debate",
  vote: "Vote",
  synthesis: "Synthesis",
  complete: "Decision complete"
};

const gatePhaseLabels: Record<string, string> = {
  intake: "Not started",
  evidence_mapping: "Evidence indexing",
  specialist_review: "In review",
  verification: "Verification",
  debate: "Debate",
  vote: "Vote",
  synthesis: "Decision complete",
  complete: "Decision complete"
};

const decisionLabels: Record<Decision, string> = {
  pending: "Pending review",
  approved: "Approved",
  conditionally_approved: "Conditional release",
  blocked: "Release hold"
};

const severityLabels: Record<Severity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical"
};

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const reviewStages = [
  { id: "evidence_mapping", label: "Index", events: "evidence_indexed" },
  { id: "specialist_review", label: "Review", events: "finding_created, evidence_linked" },
  { id: "verification", label: "Verify", events: "claim_verified, claim_rejected" },
  { id: "debate", label: "Debate", events: "challenge_raised, response_posted" },
  { id: "vote", label: "Vote", events: "vote_requested, vote_cast" },
  { id: "complete", label: "Decision", events: "decision_synthesized" }
];

const reviewRunStages = [
  { id: "packet_locked", label: "Packet locked" },
  { id: "evidence_mapping", label: "Evidence indexed" },
  { id: "specialist_review", label: "Specialist review" },
  { id: "verification", label: "Verification" },
  { id: "debate", label: "Debate" },
  { id: "vote", label: "Vote" },
  { id: "complete", label: "Decision" }
];

const reviewRunSweep = keyframes`
  0% {
    transform: translateX(-130%);
    opacity: 0.12;
  }
  18% {
    opacity: 0.88;
  }
  100% {
    transform: translateX(320%);
    opacity: 0.18;
  }
`;

const boardProtocol = [
  {
    phase: "Index",
    agents: "EvidenceMapper",
    consumes: "Release packet, tool manifest, policy context, evaluation notes",
    produces: "Evidence refs E-001 to E-007",
    state: "AuditState.events gains indexed evidence and shared context for later agents"
  },
  {
    phase: "Review",
    agents: "SecurityRedTeam, ComplianceAgent, ModelRiskAgent",
    consumes: "Evidence refs, target workflow, tool access, release goal",
    produces: "Evidence-backed findings C-001 to C-003",
    state: "AuditState.findings gains open blockers with owners, severity, and evidence refs"
  },
  {
    phase: "Verify",
    agents: "FactVerifier",
    consumes: "Findings, evidence refs, tool manifest, test notes",
    produces: "Evidence support status and verification notes",
    state: "Findings gain Supported, Verified, Open, or Unsupported evidence states"
  },
  {
    phase: "Debate",
    agents: "ChairAgent and specialist lanes",
    consumes: "Open blockers, challenged claims, verified evidence",
    produces: "Board positions and unresolved-risk record",
    state: "AuditState.events records handoffs and claim-level debate context"
  },
  {
    phase: "Vote",
    agents: "ChairAgent, SecurityRedTeam, ComplianceAgent, ModelRiskAgent, FactVerifier",
    consumes: "Open blockers, evidence support, debate positions",
    produces: "Vote records",
    state: "AuditState.votes records release positions without inventing unanimity"
  },
  {
    phase: "Decision",
    agents: "ChairAgent, Synthesizer",
    consumes: "Band trace, findings, evidence, vote records",
    produces: "Release verdict, report, remediation checklist",
    state: "AuditState.decision and AuditState.report are reconstructed from Band events"
  }
];

const sampleDataProfile: DataProfile = {
  categories: ["Candidate profile", "Resume text", "Recruiter notes", "Interview feedback"],
  sensitive_data: ["Employment decision data", "Candidate PII"],
  retention: "90 days in review workspace, then archived under recruiting retention policy",
  residency: "US production tenant",
  training_use: "No customer data used for model training"
};

const sampleToolProfile = {
  integrations: ["Greenhouse ATS", "Recruiting workflow service", "Notification service"],
  read_permissions: ["Candidate profile", "Resume attachments", "Recruiter notes", "Job requisitions"],
  write_permissions: ["Candidate review state", "Recruiter-facing notes", "Screening recommendation"],
  external_side_effects: ["May change candidate review state and notify recruiters"],
  approval_required_for_writes: true
};

const sampleControlClaims: ControlClaim[] = [
  {
    control_id: "GOV-001",
    title: "Named business and technical owners approve production release",
    owner: "People Operations",
    status: "claimed",
    required: true,
    evidence_refs: ["E-005", "E-007"],
    notes: "Owners are identified, but approval evidence must be tied to the release packet."
  },
  {
    control_id: "SEC-002",
    title: "Untrusted candidate content is isolated from tool-planning instructions",
    owner: "Recruiting Platform Engineering",
    status: "needs_evidence",
    required: true,
    evidence_refs: ["E-003", "E-006"],
    notes: "Prompt-injection tests are included but do not prove the final controlled tool path."
  },
  {
    control_id: "OPS-003",
    title: "Write-capable ATS actions require explicit human approval",
    owner: "Recruiting Platform Engineering",
    status: "needs_evidence",
    required: true,
    evidence_refs: ["E-002", "E-007"],
    notes: "Approval mode is described, but enforcement evidence is incomplete."
  },
  {
    control_id: "MR-004",
    title: "Subgroup performance and adverse-impact monitoring are defined",
    owner: "Model Risk",
    status: "exception_requested",
    required: true,
    evidence_refs: ["E-004", "E-005"],
    notes: "Aggregate evaluation is present; subgroup thresholds remain incomplete."
  }
];

const sampleEvidenceManifest: EvidenceManifestItem[] = [
  {
    ref_id: "E-001",
    title: "System overview and operating mode",
    evidence_type: "architecture",
    artifact: "packet://system-overview",
    source: "Release packet",
    owner: "Recruiting Platform Engineering",
    linked_control: "GOV-001",
    linked_risk: "Autonomous screening changes candidate state",
    freshness: "Current release branch",
    status: "submitted",
    sha256: "f0ade3aea911cc4faac633f4c50299e674297bdacd15cdec81bc6d30aec27382",
    locator: "section: Operating mode"
  },
  {
    ref_id: "E-002",
    title: "Tool manifest and ATS permissions",
    evidence_type: "tool_manifest",
    artifact: "packet://tool-manifest",
    source: "Repository",
    owner: "Recruiting Platform Engineering",
    linked_control: "OPS-003",
    linked_risk: "Write-capable production tool access",
    freshness: "Generated from release candidate",
    status: "submitted",
    sha256: "c1ad36804ece8224c9f00f2930d12d13b8d0229a3346943d9ead08323c0d3cd0",
    locator: "tools[ats_update_candidate]"
  },
  {
    ref_id: "E-003",
    title: "Prompt template and context boundaries",
    evidence_type: "prompt",
    artifact: "packet://workflow-prompts",
    source: "Repository",
    owner: "AI Platform",
    linked_control: "SEC-002",
    linked_risk: "Untrusted resume text reaches shared reasoning context",
    freshness: "Release candidate",
    status: "submitted",
    sha256: "d22c6c9f7803a29ebfc5134170d912b6b42fa3a55fa34ae18df27356508990f5",
    locator: "prompt: screening_system"
  },
  {
    ref_id: "E-004",
    title: "Evaluation summary and subgroup coverage",
    evidence_type: "evaluation",
    artifact: "packet://evaluation-summary",
    source: "Model risk review",
    owner: "Model Risk",
    linked_control: "MR-004",
    linked_risk: "Bias and subgroup safety evidence incomplete",
    freshness: "Last offline eval",
    status: "needs_update",
    sha256: "2c9a8e119454050b81f53ea838ff72544673bd733f30b54d5b1fce134fb0b50b",
    locator: "section: Coverage gaps"
  },
  {
    ref_id: "E-005",
    title: "Policy requirements for high-impact employment workflow",
    evidence_type: "policy",
    artifact: "packet://policy-requirements",
    source: "GRC policy library",
    owner: "Compliance",
    linked_control: "GOV-001",
    linked_risk: "Release approval obligations unclear",
    freshness: "Current policy",
    status: "submitted",
    sha256: "0de434321a9b6712f69160078b0527e145a2847a4f70454a42c5b310feae00a0",
    locator: "control: HIR-02"
  },
  {
    ref_id: "E-006",
    title: "Prompt-injection red-team tests",
    evidence_type: "security_test",
    artifact: "packet://prompt-injection-tests",
    source: "Security review",
    owner: "Security Red Team",
    linked_control: "SEC-002",
    linked_risk: "Tool-planning boundary can be influenced",
    freshness: "Pre-release test run",
    status: "partial",
    sha256: "f9e66a715233c82a3fc58e92f432dfc1f6c23966299df9a333ecfba8fd9ff4fb",
    locator: "test case: PI-03"
  },
  {
    ref_id: "E-007",
    title: "Monitoring, incident, and rollback plan",
    evidence_type: "runbook",
    artifact: "packet://monitoring-rollback",
    source: "Operations runbook",
    owner: "People Systems SRE",
    linked_control: "OPS-003",
    linked_risk: "Recovery path and stop conditions incomplete",
    freshness: "Draft for pilot",
    status: "needs_owner",
    sha256: "829a76982c0e8ed2cab75d81b51f36c4fe06b5a20e5514d64cf0fe308ac69c68",
    locator: "section: Gaps"
  }
];

const sampleAttestations: PacketAttestation[] = [
  {
    role: "requester",
    name: "Maya Chen",
    status: "submitted",
    attested_at: "2026-06-14",
    notes: "Requesting release-board review for the controlled production pilot."
  },
  {
    role: "business_owner",
    name: "People Operations",
    status: "submitted",
    attested_at: "2026-06-14",
    notes: "Acknowledges high-impact employment workflow obligations."
  },
  {
    role: "technical_owner",
    name: "Recruiting Platform Engineering",
    status: "submitted",
    attested_at: "2026-06-14",
    notes: "Submitted release candidate evidence and operational runbook."
  }
];

function emptyImportSummary(): PacketImportSummary {
  return {
    source: "",
    artifact: null,
    citations: [],
    critical_blockers: [],
    warnings: []
  };
}

const samplePacket: AuditPacket = {
  packet_version: "v2",
  packet_source_mode: "manual",
  review_type: "Major change",
  target_name: "TalentScreen Assist v2.4",
  target_summary: "Autonomous candidate screening agent for resume ranking and ATS status updates",
  change_summary: "Production pilot adds write-capable ATS actions and recruiter-facing screening recommendations for engineering roles.",
  workflow: "Ranks applicants, summarizes screening evidence, and updates recruiting review state",
  tool_access: "ATS read/write access including candidate status updates and recruiter-facing notes",
  policy_context: "High-impact employment workflow requiring documented release controls and human approval gates",
  evidence_notes: "System overview, tool manifest, policy requirements, prompt-injection tests, evaluation summary, and rollback plan",
  business_owner: "People Operations",
  technical_owner: "Recruiting Platform Engineering",
  owning_team: "People Systems",
  deployment_environment: "Production ATS pilot",
  affected_users: "Job applicants and recruiting team",
  criticality: "High",
  planned_release_date: "2026-07-15",
  previous_review_id: "",
  ticket_url: "https://jira.example.com/browse/JSM-7421",
  repository_url: "https://github.example.com/people/talentscreen-assist",
  system_type: "Agentic workflow",
  autonomy_level: "Human-approved production actions",
  human_oversight: "Recruiter must approve candidate-status writes before persistence",
  data_profile: sampleDataProfile,
  tool_profile: sampleToolProfile,
  control_claims: sampleControlClaims,
  evidence_manifest: sampleEvidenceManifest,
  evaluation_summary: "Offline evaluation shows aggregate recruiter agreement but lacks complete subgroup recall, false-negative, and adverse-impact evidence.",
  known_limitations: "Prompt-injection test evidence is partial, subgroup safety evidence is incomplete, and rollback ownership needs stronger proof.",
  release_goal: "Production pilot for engineering roles",
  rollout_plan: "Limited pilot for engineering roles with recruiter approval required before ATS state changes.",
  monitoring_plan: "Daily review of candidate-state changes, adverse-impact metrics, model drift, prompt-injection alerts, and recruiter overrides.",
  rollback_plan: "Disable ATS write tools, revert candidate states from audit log, and route all screening decisions to manual recruiter review.",
  incident_response_owner: "People Systems SRE",
  stop_conditions: [
    "Unauthorized candidate-status write",
    "Confirmed prompt-injection tool path",
    "Adverse-impact threshold breach",
    "Monitoring or audit-log failure"
  ],
  attestations: sampleAttestations,
  external_references: [
    { label: "Release ticket JSM-7421", url: "https://jira.example.com/browse/JSM-7421", kind: "ticket" },
    { label: "Release candidate repository", url: "https://github.example.com/people/talentscreen-assist", kind: "repository" }
  ],
  re_review_context: {
    original_room_id: "",
    original_decision: "",
    remediated_findings: [],
    remediation_summary: ""
  },
  import_summary: emptyImportSummary(),
  supporting_evidence_imports: []
};

const sampleAudit = {
  target: "TalentScreen Assist v2.4",
  releaseStatus: "Release hold",
  decision: "Hold release",
  severity: "Critical release risk",
  primaryBlocker: "Prompt-injection path can reach ATS status-update tools",
  bandEvents: 12,
  blockers: 3,
  evidenceLinks: 7,
  boardVotes: 4,
  agents: 7,
  decisions: 1,
  updated: "Just now",
  roomId: "83d07850",
  eventPills: [
    "evidence_indexed",
    "evidence_linked",
    "finding_created",
    "challenge_raised",
    "claim_verified",
    "vote_cast",
    "decision_synthesized",
    "report_exported"
  ],
  trace: [
    { event: "finding_created", actor: "SecurityRedTeam", state: "Critical blocker opened" },
    { event: "evidence_linked", actor: "EvidenceMapper", state: "ATS write-access evidence attached" },
    { event: "claim_verified", actor: "FactVerifier", state: "Tool-access risk partially verified" },
    { event: "vote_cast", actor: "ChairAgent", state: "Board vote recorded" },
    { event: "decision_synthesized", actor: "Synthesizer", state: "Hold release" },
    { event: "report_exported", actor: "BandAudit", state: "Decision record ready" }
  ],
  workflow: [
    {
      title: "Submit audit packet",
      body: "Teams provide the system overview, tool access, policies, evaluations, red-team notes, and release goal."
    },
    {
      title: "Agents review in Band",
      body: "Specialist reviewers publish structured Band events instead of burying release judgment in a chat thread."
    },
    {
      title: "Evidence is verified",
      body: "Claims are linked to evidence, challenged, and checked before they can shape the release decision."
    },
    {
      title: "Decision is exported",
      body: "The board produces a release hold, conditional release, or approval record with traceable rationale."
    }
  ]
} as const;

const customPacket: AuditPacket = {
  packet_version: "v2",
  packet_source_mode: "manual",
  review_type: "",
  target_name: "",
  target_summary: "",
  change_summary: "",
  workflow: "",
  tool_access: "",
  policy_context: "",
  evidence_notes: "",
  business_owner: "",
  technical_owner: "",
  owning_team: "",
  deployment_environment: "",
  affected_users: "",
  criticality: "",
  planned_release_date: "",
  previous_review_id: "",
  ticket_url: "",
  repository_url: "",
  system_type: "",
  autonomy_level: "",
  human_oversight: "",
  data_profile: {
    categories: [],
    sensitive_data: [],
    retention: "",
    residency: "",
    training_use: ""
  },
  tool_profile: {
    integrations: [],
    read_permissions: [],
    write_permissions: [],
    external_side_effects: [],
    approval_required_for_writes: true
  },
  control_claims: [],
  evidence_manifest: [],
  evaluation_summary: "",
  known_limitations: "",
  release_goal: "",
  rollout_plan: "",
  monitoring_plan: "",
  rollback_plan: "",
  incident_response_owner: "",
  stop_conditions: [],
  attestations: [],
  external_references: [],
  re_review_context: {
    original_room_id: "",
    original_decision: "",
    remediated_findings: [],
    remediation_summary: ""
  },
  import_summary: emptyImportSummary(),
  supporting_evidence_imports: []
};

const RECENTS_STORAGE_KEY = "bandaudit.recentReviews.v1";

function viewFromPath(pathname: string): ViewMode {
  if (pathname.startsWith("/setup")) return "setup";
  if (pathname.startsWith("/review")) return "review";
  if (pathname.startsWith("/protocol")) return "protocol";
  if (pathname.startsWith("/timeline")) return "timeline";
  if (pathname.startsWith("/report")) return "report";
  return "landing";
}

function formatEventType(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function statusClass(value: string) {
  return value.replace(/_/g, "-");
}

function titleCase(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function shortRoomId(roomId: string) {
  return roomId.replace(/^band_room_/, "").slice(0, 8);
}

function loadRecentReviews(): RecentReview[] {
  try {
    const raw = window.localStorage.getItem(RECENTS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.slice(0, 6) : [];
  } catch {
    return [];
  }
}

function saveRecentReviews(reviews: RecentReview[]) {
  try {
    window.localStorage.setItem(RECENTS_STORAGE_KEY, JSON.stringify(reviews.slice(0, 6)));
  } catch {
  }
}

function recentReviewFromAudit(audit: AuditState): RecentReview {
  return {
    id: audit.room_id,
    target: audit.input_packet.target_name,
    decision: decisionLabels[audit.decision],
    risk: severityLabels[audit.risk_level],
    events: audit.events.length,
    updated: "Just now"
  };
}

function mergeRecentReview(reviews: RecentReview[], review: RecentReview) {
  return [review, ...reviews.filter((item) => item.id !== review.id)].slice(0, 6);
}

function sourceLabel(_audit: AuditState) {
  return "Band evidence room";
}

function providerLabel(audit: AuditState) {
  if (audit.agent_execution.effective_mode === "live") return `${audit.agents.length} specialist lanes`;
  return "Provider configuration incomplete";
}

function providerName(value: "aiml" | "featherless") {
  if (value === "aiml") return "AI/ML API";
  return "Featherless";
}

function providerUseSummary(value: "aiml" | "featherless") {
  if (value === "aiml") {
    return "Orchestration, evidence mapping, policy reasoning, and report synthesis.";
  }
  return "Independent open-weight review, adversarial checks, model-risk review, and evidence verification.";
}

function providerRoleSummary(value: "aiml" | "featherless") {
  if (value === "aiml") return "Orchestration, evidence mapping, policy reasoning, report synthesis";
  return "Independent open-weight review, adversarial checks, model-risk review, evidence verification";
}

function routeProvider(audit: AuditState, agentName: string) {
  return audit.agent_execution.routes.find((route) => route.agent === agentName)?.provider ?? null;
}

function routeModel(audit: AuditState, agentName: string) {
  return audit.agent_execution.routes.find((route) => route.agent === agentName)?.model ?? null;
}

function eventProvider(audit: AuditState, event: AuditEvent) {
  return event.provider ?? routeProvider(audit, event.agent);
}

function providerLabelForEvent(audit: AuditState, event: AuditEvent) {
  const provider = eventProvider(audit, event);
  return provider ? providerName(provider) : "Provider lane";
}

function modelLabelForEvent(audit: AuditState, event: AuditEvent) {
  const metadataModel = event.metadata.provider_model;
  if (typeof metadataModel === "string" && metadataModel.trim()) return metadataModel;
  return routeModel(audit, event.agent) ?? "Model not recorded";
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function roomManifest(audit: AuditState) {
  const initEvent = audit.events.find((event) => event.event_type === "audit_init");
  return objectRecord(initEvent?.metadata.band_room_manifest);
}

function roomHasLockedPacketManifest(audit: AuditState) {
  const manifest = roomManifest(audit);
  return Boolean(manifest?.canonical_record === true || manifest?.participant_strategy || manifest?.release_board_lanes);
}

function isStaleRoomTrace(audit: AuditState) {
  return audit.events.length > 0 && !roomHasLockedPacketManifest(audit);
}

function manifestString(manifest: Record<string, unknown> | null, key: string, fallback = "") {
  const value = manifest?.[key];
  return typeof value === "string" && value.trim() ? value : fallback;
}

function manifestNumber(manifest: Record<string, unknown> | null, key: string, fallback = 0) {
  const value = manifest?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function releaseBoardRoster(audit: AuditState): ReleaseBoardLaneRow[] {
  const manifest = roomManifest(audit);
  const manifestLanes = Array.isArray(manifest?.release_board_lanes) ? manifest.release_board_lanes : [];
  const manifestByAgent = new Map<string, Record<string, unknown>>();
  manifestLanes.forEach((item) => {
    const row = objectRecord(item);
    const agent = typeof row?.agent === "string" ? row.agent : "";
    if (agent && row) manifestByAgent.set(agent, row);
  });

  return audit.agents.map((agent) => {
    const route = audit.agent_execution.routes.find((item) => item.agent === agent.name);
    const lane = manifestByAgent.get(agent.name);
    const events = audit.events.filter((event) => event.agent === agent.name);
    const latest = events[events.length - 1];
    const participantMode = typeof lane?.participant_mode === "string" ? lane.participant_mode : "structured_lane";
    const participantId = typeof lane?.participant_id === "string" ? lane.participant_id : "";
    return {
      agent: agent.name,
      lane: typeof lane?.lane === "string" ? lane.lane : agent.name.replace(/Agent$/, ""),
      role: typeof lane?.role === "string" ? lane.role : agent.role,
      provider: route?.provider ? providerName(route.provider) : typeof lane?.provider === "string" ? titleCase(lane.provider) : "Provider lane",
      model: route?.model ?? (typeof lane?.model === "string" && lane.model ? lane.model : "Model not recorded"),
      latestEvent: latest ? `${eventNumberById(audit.events, latest.event_id)} ${protocolEventName(latest)}` : "No Band event yet",
      eventCount: events.length,
      participantMode: participantMode === "recruited_band_peer" ? "Recruited Band peer" : "Declared structured lane",
      participantId
    };
  });
}

function participantStrategyLabel(audit: AuditState) {
  const strategy = manifestString(roomManifest(audit), "participant_strategy", "single_band_agent_with_structured_release_board_lanes");
  if (strategy === "band_peer_recruitment_with_structured_lane_fallback") return "Band peer recruitment with structured-lane fallback";
  return "One BandAudit participant with structured release-board lanes";
}

function routeModelSummary(routes: Array<{ model: string | null }>) {
  const models = Array.from(new Set(routes.map((route) => route.model).filter((model): model is string => Boolean(model))));
  if (!models.length) return "No model configured";
  if (models.length <= 2) return models.join(", ");
  return `${models.slice(0, 2).join(", ")} +${models.length - 2}`;
}

function traceabilityCount(audit: AuditState) {
  return audit.findings.reduce((total, finding) => total + finding.evidence_refs.length, 0);
}

function openFindings(audit: AuditState) {
  return audit.findings.filter((finding) => finding.status !== "accepted").length;
}

function verifiedFindings(audit: AuditState) {
  return audit.findings.filter((finding) => finding.status === "verified").length;
}

function recommendation(audit: AuditState) {
  if (audit.decision === "blocked") {
    const primaryFinding = topFinding(audit.findings);
    return {
      label: "Release hold",
      tone: "danger",
      reason: primaryFinding
        ? `${primaryFinding.title} remains unresolved in the Band release-board record.`
        : "The Band release-board record contains unresolved release-blocking findings."
    };
  }
  if (audit.decision === "conditionally_approved") {
    return {
      label: "Conditional release",
      tone: "warning",
      reason: "Approval depends on remediation of the open control gaps identified by the release-board lanes."
    };
  }
  if (audit.decision === "approved") {
    return {
      label: "Release approved",
      tone: "success",
      reason: "The current evidence package satisfies the release-board checks."
    };
  }
  if (audit.risk_level === "critical" || audit.risk_level === "high") {
    return {
      label: "Release hold",
      tone: audit.risk_level === "critical" ? "danger" : "warning",
      reason: "Specialist review has identified release-blocking control gaps that need evidence-backed remediation."
    };
  }
  return {
    label: "Continue review",
    tone: "neutral",
    reason: "The release board is collecting evidence before a production decision."
  };
}

function toneColor(tone: DashboardTone) {
  if (tone === "danger") return "error.main";
  if (tone === "warning") return "warning.main";
  if (tone === "success") return "success.main";
  return "text.secondary";
}

function toneSoftColor(tone: DashboardTone) {
  if (tone === "danger") return "error.light";
  if (tone === "warning") return "warning.light";
  if (tone === "success") return "success.light";
  return "background.default";
}

function chipColorForTone(tone: DashboardTone) {
  if (tone === "danger") return "error";
  if (tone === "warning") return "warning";
  if (tone === "success") return "success";
  return "default";
}

function alertSeverityForTone(tone: DashboardTone) {
  if (tone === "danger") return "error";
  if (tone === "warning") return "warning";
  if (tone === "success") return "success";
  return "info";
}

function severityChipColor(severity: Severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  if (severity === "low") return "success";
  return "default";
}

function statusChipColor(status: Finding["status"]) {
  if (status === "verified" || status === "accepted") return "success";
  if (status === "challenged" || status === "debating") return "warning";
  if (status === "blocked") return "error";
  return "default";
}

function topFinding(findings: Finding[]) {
  return [...findings].sort((a, b) => severityRank[b.severity] - severityRank[a.severity])[0];
}

function consensusLabel(audit: AuditState) {
  if (audit.votes.length) {
    const blockers = audit.votes.filter((voteRecord) => voteRecord.vote === "block").length;
    const conditional = audit.votes.filter((voteRecord) => voteRecord.vote === "conditional").length;
    return `${blockers} hold, ${conditional} conditional`;
  }

  const active = audit.agents.filter((agent) => agent.status === "active").length;
  return active ? `${active} lanes active` : "Awaiting vote";
}

function evidenceStrength(finding: Finding | undefined) {
  if (!finding) return "No finding selected";
  if (finding.evidence_refs.length >= 3) return "Strong evidence";
  if (finding.evidence_refs.length >= 2) return "Supported";
  return "Needs evidence";
}

function clonePacket(packet: AuditPacket): AuditPacket {
  if (typeof structuredClone === "function") return structuredClone(packet);
  return JSON.parse(JSON.stringify(packet)) as AuditPacket;
}

function packetWithDefaults(packet: Partial<AuditPacket>): AuditPacket {
  const base = clonePacket(customPacket);
  return {
    ...base,
    ...packet,
    packet_version: packet.packet_version || base.packet_version,
    packet_source_mode: packet.packet_source_mode || base.packet_source_mode,
    review_type: packet.review_type || base.review_type,
    data_profile: { ...base.data_profile, ...(packet.data_profile ?? {}) },
    tool_profile: { ...base.tool_profile, ...(packet.tool_profile ?? {}) },
    control_claims: Array.isArray(packet.control_claims) ? packet.control_claims : base.control_claims,
    evidence_manifest: Array.isArray(packet.evidence_manifest) ? packet.evidence_manifest : base.evidence_manifest,
    attestations: Array.isArray(packet.attestations) ? packet.attestations : base.attestations,
    external_references: Array.isArray(packet.external_references) ? packet.external_references : base.external_references,
    stop_conditions: Array.isArray(packet.stop_conditions) ? packet.stop_conditions : base.stop_conditions,
    re_review_context: { ...base.re_review_context, ...(packet.re_review_context ?? {}) },
    import_summary: {
      ...base.import_summary,
      ...(packet.import_summary ?? {}),
      citations: Array.isArray(packet.import_summary?.citations) ? packet.import_summary.citations : base.import_summary.citations,
      critical_blockers: Array.isArray(packet.import_summary?.critical_blockers) ? packet.import_summary.critical_blockers : base.import_summary.critical_blockers,
      warnings: Array.isArray(packet.import_summary?.warnings) ? packet.import_summary.warnings : base.import_summary.warnings
    },
    supporting_evidence_imports: Array.isArray(packet.supporting_evidence_imports) ? packet.supporting_evidence_imports : base.supporting_evidence_imports
  };
}

function auditWithPacketDefaults(audit: AuditState): AuditState {
  return {
    ...audit,
    input_packet: packetWithDefaults(audit.input_packet as Partial<AuditPacket>)
  };
}

function packetSourceFromSetupMode(mode: SetupMode): PacketSourceMode {
  if (mode === "re_review") return "re_review";
  return "manual";
}

function reReviewPacket(audit: AuditState): AuditPacket {
  const current = clonePacket(audit.input_packet);
  return {
    ...current,
    packet_version: current.packet_version || "v2",
    packet_source_mode: "re_review",
    review_type: "Re-review",
    previous_review_id: audit.audit_id,
    change_summary: current.change_summary || current.target_summary,
    evidence_manifest: current.evidence_manifest ?? [],
    control_claims: current.control_claims ?? [],
    attestations: current.attestations ?? [],
    re_review_context: {
      original_room_id: audit.room_id,
      original_decision: decisionLabels[audit.decision],
      remediated_findings: audit.findings.map((finding) => finding.claim_id),
      remediation_summary:
        audit.report?.required_remediations.slice(0, 3).join("; ") ||
        audit.findings.flatMap((finding) => finding.remediation).slice(0, 3).join("; ")
    }
  };
}

function packetForSetupMode(mode: SetupMode, audit: AuditState): AuditPacket {
  if (mode === "custom") return clonePacket(customPacket);
  if (mode === "re_review") return reReviewPacket(audit);
  return clonePacket(samplePacket);
}

function sourceModeLabel(mode: PacketSourceMode) {
  if (mode === "pdf_packet") return "PDF packet";
  if (mode === "re_review") return "Re-review";
  return "Manual packet";
}

function citationStatusLabel(status: PacketFieldCitation["status"]) {
  if (status === "pdf_cited") return "Source cited";
  if (status === "needs_review") return "Needs review";
  if (status === "manual_override") return "Manual override";
  return "Missing";
}

function citationStatusColor(status: PacketFieldCitation["status"]): "success" | "info" | "warning" | "error" {
  if (status === "pdf_cited") return "success";
  if (status === "manual_override") return "info";
  if (status === "needs_review") return "warning";
  return "error";
}

function stringList(value: string[]) {
  return value.join(", ");
}

function parseStringList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizePacketForRun(packet: AuditPacket, sourceMode: PacketSourceMode): AuditPacket {
  return {
    ...packet,
    packet_version: packet.packet_version || "v2",
    packet_source_mode: sourceMode,
    review_type: packet.review_type || (sourceMode === "re_review" ? "Re-review" : "Major change"),
    evidence_manifest: packet.evidence_manifest,
    control_claims: packet.control_claims,
    attestations: packet.attestations,
    data_profile: packet.data_profile,
    import_summary: sourceMode === "pdf_packet" || sourceMode === "re_review" ? packet.import_summary : emptyImportSummary()
  };
}

function packetCompleteness(packet: AuditPacket): PacketCompletenessItem[] {
  const hasOwner = Boolean(packet.business_owner.trim() && packet.technical_owner.trim());
  const hasControlOwner = packet.control_claims.some((claim) => claim.required && claim.owner.trim());
  return [
    {
      id: "target",
      label: "System name",
      complete: Boolean(packet.target_name.trim()),
      severity: "required",
      detail: "Name the system under release review."
    },
    {
      id: "owner",
      label: "Owner",
      complete: hasOwner,
      severity: "required",
      detail: "Business and technical owners are required."
    },
    {
      id: "environment",
      label: "Environment",
      complete: Boolean(packet.deployment_environment.trim()),
      severity: "required",
      detail: "Production, pilot, or internal environment must be explicit."
    },
    {
      id: "review_type",
      label: "Review type",
      complete: Boolean(packet.review_type.trim()),
      severity: "required",
      detail: "Classify the change so the board can scope the gate."
    },
    {
      id: "change_summary",
      label: "Change summary",
      complete: Boolean(packet.change_summary.trim()),
      severity: "required",
      detail: "Summarize what is changing in this release."
    },
    {
      id: "autonomy",
      label: "Autonomy level",
      complete: Boolean(packet.autonomy_level.trim() && packet.human_oversight.trim()),
      severity: "required",
      detail: "Describe autonomous actions and human oversight."
    },
    {
      id: "data",
      label: "Data category",
      complete: packet.data_profile.categories.length > 0,
      severity: "required",
      detail: "At least one data category must be declared."
    },
    {
      id: "tool_access",
      label: "Tool access",
      complete: Boolean(packet.tool_access.trim() || packet.tool_profile.integrations.length || packet.tool_profile.write_permissions.length),
      severity: "required",
      detail: "Declare integrations, read permissions, and write permissions."
    },
    {
      id: "evidence",
      label: "Evidence rows",
      complete: packet.evidence_manifest.length >= 4,
      severity: "evidence",
      detail: "At least four evidence rows are needed for an enterprise packet."
    },
    {
      id: "rollout",
      label: "Rollout plan",
      complete: Boolean(packet.rollout_plan.trim()),
      severity: "required",
      detail: "Define release scope and staged rollout behavior."
    },
    {
      id: "rollback",
      label: "Rollback plan",
      complete: Boolean(packet.rollback_plan.trim()),
      severity: "required",
      detail: "Document backout actions and recovery owner."
    },
    {
      id: "incident_owner",
      label: "Incident owner",
      complete: Boolean(packet.incident_response_owner.trim()),
      severity: "required",
      detail: "Name the owner accountable for incident response."
    },
    {
      id: "attestation",
      label: "Attestation",
      complete: packet.attestations.some((item) => item.name.trim()),
      severity: "control",
      detail: "At least one accountable attestation is required."
    },
    {
      id: "control_owner",
      label: "Control owner",
      complete: hasControlOwner,
      severity: "control",
      detail: "At least one required control must have an owner."
    }
  ];
}

function packetReadiness(packet: AuditPacket) {
  const items = packetCompleteness(packet);
  const missing = items.filter((item) => !item.complete);
  if (missing.length === 0) return { label: "Ready", tone: "success" as DashboardTone, missing };
  if (missing.every((item) => item.severity === "evidence")) return { label: "Needs evidence", tone: "warning" as DashboardTone, missing };
  return { label: "Missing owner/control", tone: "danger" as DashboardTone, missing };
}

function validateAuditPacket(packet: AuditPacket) {
  return packetCompleteness(packet)
    .filter((item) => !item.complete)
    .map((item) => item.label);
}

function preflightItemsFor(
  audit: AuditState,
  packet: AuditPacket,
  reviewMode: ReviewRoomMode,
  sourceMode: PacketSourceMode,
  packetLocked: boolean
): PreflightItem[] {
  const missing = validateAuditPacket(packet);
  const aiml = audit.agent_execution.providers.find((provider) => provider.provider === "aiml");
  const featherless = audit.agent_execution.providers.find((provider) => provider.provider === "featherless");
  const allRoutesHaveModels = audit.agent_execution.routes.length > 0 && audit.agent_execution.routes.every((route) => Boolean(route.model?.trim()));
  const bandReady = audit.source.effective_mode === "band" && audit.source.band_api_key_present && audit.source.band_sdk_installed && !audit.source.last_error;
  const currentRoomReady = reviewMode === "fresh" || (!packetLocked && audit.events.length === 0);
  const roomManifestReady = reviewMode === "fresh" || roomHasLockedPacketManifest(audit);
  const optionalWarnings = [
    !packet.ticket_url.trim() ? "missing ticket/change link" : "",
    !packet.repository_url.trim() ? "missing repository link" : "",
    !packet.planned_release_date.trim() ? "missing planned date" : "",
    packet.evidence_manifest.some((item) => !item.sha256.trim()) ? "missing artifact hash" : "",
    packet.supporting_evidence_imports.length === 0 ? "no supporting uploads" : ""
  ].filter(Boolean);

  return [
    {
      id: "packet",
      label: "Packet readiness",
      detail: missing.length ? `Missing ${missing.join(", ")}` : "Required release packet fields are complete.",
      status: missing.length ? "fail" : "pass",
      blocking: missing.length > 0
    },
    {
      id: "room",
      label: "Fresh Band trace",
      detail: currentRoomReady ? "Review will lock into a clean Band event record." : "The selected Band room already contains audit events.",
      status: currentRoomReady ? "pass" : "fail",
      blocking: !currentRoomReady
    },
    {
      id: "band",
      label: "Band diagnostics",
      detail: bandReady ? `Band ${audit.source.effective_mode} mode is ready.` : audit.source.last_error || "Band API key, SDK, or room diagnostics are not ready.",
      status: bandReady ? "pass" : "fail",
      blocking: !bandReady
    },
    {
      id: "aiml",
      label: "AI/ML API",
      detail: aiml?.status === "ready" ? `Ready with ${aiml.model || "configured model"}.` : aiml?.last_error || "AI/ML API provider is not ready.",
      status: aiml?.status === "ready" ? "pass" : "fail",
      blocking: aiml?.status !== "ready"
    },
    {
      id: "featherless",
      label: "Featherless",
      detail: featherless?.status === "ready" ? `Ready with ${featherless.model || "configured model"}.` : featherless?.last_error || "Featherless provider is not ready.",
      status: featherless?.status === "ready" ? "pass" : "fail",
      blocking: featherless?.status !== "ready"
    },
    {
      id: "routes",
      label: "Route-level models",
      detail: allRoutesHaveModels ? `${audit.agent_execution.routes.length} release-board routes have resolved models.` : "One or more release-board routes has no resolved model.",
      status: allRoutesHaveModels ? "pass" : "fail",
      blocking: !allRoutesHaveModels
    },
    {
      id: "manifest",
      label: "Band room manifest",
      detail: roomManifestReady
        ? "Packet lock will publish room purpose, lane roster, provider routes, and participant strategy."
        : "Current room has old events without a room manifest; use a fresh room for this review.",
      status: roomManifestReady ? "pass" : "warn",
      blocking: false
    },
    {
      id: "ocr",
      label: "PDF import OCR",
      detail:
        sourceMode === "pdf_packet"
          ? "PDF import uses AI/ML API Mistral OCR before packet extraction."
          : "Mistral OCR is available for release packet PDFs when AI/ML API is ready.",
      status: aiml?.status === "ready" ? "pass" : "fail",
      blocking: aiml?.status !== "ready"
    },
    {
      id: "exports",
      label: "Report exports",
      detail: "PDF, DOCX, Markdown, JSON, and print exports are available after synthesis.",
      status: "pass",
      blocking: false
    },
    {
      id: "optional",
      label: "Optional metadata",
      detail: optionalWarnings.length ? optionalWarnings.join(", ") : "Optional metadata and hashes are complete enough for review.",
      status: optionalWarnings.length ? "warn" : "pass",
      blocking: false
    }
  ];
}

function blockingPreflightItems(items: PreflightItem[]) {
  return items.filter((item) => item.blocking && item.status === "fail");
}

function preflightIcon(item: PreflightItem) {
  if (item.status === "pass") return <CheckCircle2 size={15} color="#14783e" />;
  if (item.status === "warn") return <CircleAlert size={15} color="#b54708" />;
  return <CircleAlert size={15} color="#b42318" />;
}

function importArtifacts(audit: AuditState) {
  return [audit.input_packet.import_summary, ...(audit.input_packet.supporting_evidence_imports ?? [])]
    .map((summary) => summary.artifact)
    .filter((artifact): artifact is NonNullable<PacketImportSummary["artifact"]> => Boolean(artifact));
}

function auditIntegrity(audit: AuditState): AuditIntegrity {
  const artifacts = importArtifacts(audit);
  const artifactHashes = Array.from(new Set(artifacts.map((artifact) => artifact.sha256).filter(Boolean)));
  const synthesis = [...audit.events].reverse().find((event) => event.event_type === "synthesis_report");
  return {
    roomId: audit.room_id,
    eventCount: audit.events.length,
    packetSource: sourceModeLabel((audit.input_packet.packet_source_mode || "manual") as PacketSourceMode),
    packetVersion: audit.input_packet.packet_version || "v1",
    evidenceLinks: traceabilityCount(audit),
    artifactHashes,
    repairCount: audit.events.filter((event) => event.metadata.structured_output_repair_attempted === true).length,
    synthesisEventId: synthesis?.event_id ?? "Pending"
  };
}

function findingMatchesFilters(finding: Finding, query: string, severity: SeverityFilter, status: FindingStatusFilter) {
  const normalizedQuery = query.trim().toLowerCase();
  const text = [
    finding.claim_id,
    finding.title,
    finding.summary,
    finding.category,
    finding.owner_agent,
    finding.status,
    finding.release_impact,
    ...finding.remediation,
    ...finding.evidence_refs.map((evidence) => `${evidence.ref_id} ${evidence.title} ${evidence.artifact}`)
  ]
    .join(" ")
    .toLowerCase();
  return (
    (!normalizedQuery || text.includes(normalizedQuery)) &&
    (severity === "all" || finding.severity === severity) &&
    (status === "all" || finding.status === status)
  );
}

function remediationTasks(audit: AuditState): RemediationTask[] {
  const sortedFindings = [...audit.findings].sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  return sortedFindings.flatMap((finding) => {
    const items = finding.remediation.length ? finding.remediation : [finding.release_impact || finding.summary];
    return items.map((item, index) => ({
      id: `${finding.claim_id}-${index}`,
      findingId: finding.claim_id,
      severity: finding.severity,
      owner: finding.owner_agent,
      status: finding.status,
      text: item,
      evidenceRefs: evidenceIds(finding.evidence_refs),
      requiredEvidenceCount: Math.max(2, finding.evidence_refs.length)
    }));
  });
}

function evidenceProvenanceRows(audit: AuditState, finding: Finding | undefined): EvidenceProvenanceRow[] {
  if (!finding) return [];
  return finding.evidence_refs.map((evidence) => {
    const linkedEvents = audit.events.filter((event) => event.evidence_refs.some((ref) => ref.ref_id === evidence.ref_id));
    return {
      id: evidence.ref_id,
      evidence,
      eventNumbers: linkedEvents.map((event) => eventNumberById(audit.events, event.event_id)),
      actors: Array.from(new Set(linkedEvents.map((event) => event.agent))),
      providers: Array.from(new Set(linkedEvents.map((event) => providerLabelForEvent(audit, event)))),
      roomIds: Array.from(new Set(linkedEvents.map((event) => shortRoomId(event.room_id))))
    };
  });
}

function artifactFileName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}

function agentStatusLabel(value: AgentProfile["status"]) {
  if (value === "complete") return "Contribution captured";
  if (value === "active") return "Active";
  if (value === "blocked") return "Blocked";
  return "Idle";
}

function eventSequenceNumber(index: number) {
  return `#${String(index + 1).padStart(2, "0")}`;
}

function eventNumberById(events: AuditEvent[], eventId: string) {
  const index = events.findIndex((event) => event.event_id === eventId);
  return index >= 0 ? eventSequenceNumber(index) : eventId;
}

function evidenceIds(refs: EvidenceRef[]) {
  return refs.map((evidence) => evidence.ref_id);
}

function eventFindingRefs(event: AuditEvent) {
  const refs = new Set<string>(event.finding_refs ?? []);
  if (event.claim_id) refs.add(event.claim_id);
  return Array.from(refs);
}

function eventVoteRefs(event: AuditEvent) {
  const refs = new Set<string>(event.vote_refs ?? []);
  const votes = event.metadata?.votes;
  if (Array.isArray(votes)) {
    votes.forEach((vote) => {
      if (vote && typeof vote === "object" && !Array.isArray(vote)) {
        const claimRefs = (vote as { claim_refs?: unknown }).claim_refs;
        if (Array.isArray(claimRefs)) {
          claimRefs.forEach((ref) => refs.add(String(ref)));
        }
        return;
      }
      refs.add(String(vote));
    });
  }
  return Array.from(refs);
}

function eventProducedRefs(event: AuditEvent) {
  const refs = new Set<string>(event.produces_refs ?? []);
  if (event.event_type === "artifact_indexed") {
    evidenceIds(event.evidence_refs).forEach((ref) => refs.add(ref));
  }
  if (event.event_type === "finding" && event.claim_id) refs.add(event.claim_id);
  if (event.event_type === "verification" && event.claim_id) refs.add(`verification:${event.claim_id}`);
  if (event.event_type === "challenge" && event.claim_id) refs.add(`challenge:${event.claim_id}`);
  if (event.event_type === "conflict_declaration" && event.claim_id) refs.add(`debate:${event.claim_id}`);
  if (event.event_type === "vote") {
    const voteRefs = eventVoteRefs(event);
    if (voteRefs.length) voteRefs.forEach((ref) => refs.add(ref));
    else refs.add("vote_records");
  }
  if (event.event_type === "synthesis_report") refs.add("release_report");
  return Array.from(refs);
}

function eventConsumedRefs(event: AuditEvent, events: AuditEvent[]) {
  const refs = new Set<string>(event.consumes_event_ids ?? []);
  if (event.event_type !== "audit_init" && event.event_type !== "artifact_indexed") refs.add("prior_board_context");
  if (event.claim_id) refs.add(event.claim_id);
  evidenceIds(event.evidence_refs).forEach((ref) => refs.add(ref));
  if (event.event_type === "vote") {
    events
      .filter((item) => item.event_type === "finding" && item.claim_id)
      .forEach((item) => refs.add(String(item.claim_id)));
  }
  if (event.event_type === "synthesis_report") {
    refs.add("findings");
    refs.add("vote_records");
    refs.add("band_trace");
  }
  return Array.from(refs);
}

function compactRefs(refs: string[], emptyLabel = "None") {
  if (!refs.length) return emptyLabel;
  if (refs.length <= 4) return refs.join(", ");
  return `${refs.slice(0, 4).join(", ")} +${refs.length - 4}`;
}

function findingEvidenceState(finding: Finding) {
  if (finding.status === "verified" || finding.verification_notes.length > 0) return "Verified";
  if (finding.evidence_refs.length >= 2) return "Supported";
  if (finding.evidence_refs.length > 0) return "Open";
  return "Unsupported";
}

function findingReleaseEffect(finding: Finding) {
  return finding.severity === "critical" || finding.severity === "high" ? "Blocking" : "Non-blocking";
}

function agentContribution(agent: AgentProfile, audit: AuditState) {
  const events = audit.events.filter((event) => event.agent === agent.name);
  const last = events[events.length - 1];
  if (!last) return "Waiting for board event";
  if (last.event_type === "artifact_indexed") return `Mapped ${last.evidence_refs.length} evidence links`;
  if (last.event_type === "finding" && last.claim_id) return `Raised ${last.claim_id}`;
  if (last.event_type === "verification" && last.claim_id) return `Verified ${last.claim_id}`;
  if (last.event_type === "challenge" && last.claim_id) return `Challenged ${last.claim_id}`;
  if (last.event_type === "conflict_declaration" && last.claim_id) return `Opened debate on ${last.claim_id}`;
  if (last.event_type === "debate_position" && last.claim_id) return `Posted position on ${last.claim_id}`;
  if (last.event_type === "vote") return "Opened release decision";
  if (last.event_type === "synthesis_report") return "Generated report";
  if (last.event_type === "audit_init") return "Opened board room";
  return eventHeadline(last);
}

function riskDrivers(audit: AuditState) {
  const drivers = audit.findings
    .filter((finding) => finding.severity === "critical" || finding.severity === "high")
    .map((finding) => `${severityLabels[finding.severity]} blocker: ${finding.title}`);
  if (audit.input_packet.tool_access.toLowerCase().includes("write")) {
    drivers.push(`Production impact: ${audit.input_packet.tool_access}`);
  }
  return drivers.slice(0, 5);
}

function protocolEventName(event: AuditEvent) {
  const names: Record<string, string> = {
    audit_init: "audit_initialized",
    artifact_indexed: "evidence_indexed",
    finding: "finding_created",
    evidence_request: "evidence_requested",
    verification: "claim_verified",
    challenge: "challenge_raised",
    conflict_declaration: "conflict_declared",
    debate_position: "response_posted",
    vote: "vote_requested",
    human_escalation: "human_escalation",
    synthesis_report: "decision_synthesized"
  };
  return names[event.event_type] ?? event.event_type;
}

function eventHeadline(event: AuditEvent) {
  if (event.event_type === "finding") return `${event.agent} created ${event.claim_id}`;
  if (event.event_type === "artifact_indexed") return `${event.agent} indexed evidence`;
  if (event.event_type === "verification") return `${event.agent} verified ${event.claim_id}`;
  if (event.event_type === "challenge") return `${event.agent} challenged ${event.claim_id}`;
  if (event.event_type === "conflict_declaration") return `${event.agent} opened debate on ${event.claim_id}`;
  if (event.event_type === "debate_position") return `${event.agent} posted debate response`;
  if (event.event_type === "vote") return `${event.agent} requested release vote`;
  if (event.event_type === "synthesis_report") return `${event.agent} synthesized release decision`;
  return `${event.agent} published ${formatEventType(event.event_type)}`;
}

function formatEventTime(event: AuditEvent | undefined, fallback = "Pending") {
  if (!event?.created_at) return fallback;
  const date = new Date(event.created_at);
  if (Number.isNaN(date.getTime())) return fallback;
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function latestEvent(audit: AuditState) {
  return audit.events[audit.events.length - 1];
}

function decisionCompletedEvent(audit: AuditState) {
  return audit.events.find((event) => event.event_type === "synthesis_report") ?? latestEvent(audit);
}

function linkedEventNumbersForEvidence(audit: AuditState, evidence: EvidenceRef) {
  return audit.events
    .filter((event) => event.evidence_refs.some((ref) => ref.ref_id === evidence.ref_id))
    .map((event) => eventNumberById(audit.events, event.event_id));
}

function linkedEventNumbersForFinding(audit: AuditState, finding: Finding | undefined) {
  if (!finding) return [];
  const refs = new Set<string>();
  audit.events
    .filter(
      (event) =>
        event.claim_id === finding.claim_id ||
        event.finding_refs.includes(finding.claim_id) ||
        event.evidence_refs.some((ref) => finding.evidence_refs.some((evidence) => evidence.ref_id === ref.ref_id))
    )
    .forEach((event) => refs.add(eventNumberById(audit.events, event.event_id)));
  return Array.from(refs);
}

function agentPositionLabel(event: AuditEvent, finding: Finding) {
  if (event.event_type === "finding") return finding.severity === "critical" || finding.severity === "high" ? "Blocks release" : "Raised finding";
  if (event.event_type === "verification") return "Verified evidence";
  if (event.event_type === "challenge") return "Challenged claim";
  if (event.event_type === "conflict_declaration") return "Declared unresolved risk";
  if (event.event_type === "debate_position") return "Posted board position";
  if (event.event_type === "vote") return "Recorded vote";
  return formatEventType(event.event_type);
}

function agentPositionsForFinding(audit: AuditState, finding: Finding | undefined) {
  if (!finding) return [];
  const byAgent = new Map<string, { agent: string; position: string; provider: string }>();
  audit.events
    .filter((event) => event.claim_id === finding.claim_id || event.finding_refs.includes(finding.claim_id))
    .forEach((event) => {
      byAgent.set(event.agent, {
        agent: event.agent,
        position: agentPositionLabel(event, finding),
        provider: providerLabelForEvent(audit, event)
      });
    });
  if (!byAgent.has(finding.owner_agent)) {
    byAgent.set(finding.owner_agent, {
      agent: finding.owner_agent,
      position: findingReleaseEffect(finding) === "Blocking" ? "Blocks release" : "Raised finding",
      provider: providerName(routeProvider(audit, finding.owner_agent) ?? "aiml")
    });
  }
  return Array.from(byAgent.values()).slice(0, 4);
}

function phaseIndex(phase: string) {
  const index = reviewStages.findIndex((stage) => stage.id === phase);
  if (phase === "intake") return 0;
  if (phase === "synthesis") return reviewStages.length - 1;
  return index === -1 ? 0 : index;
}

function nextSelectedClaimId(current: string | null, findings: Finding[]) {
  if (current && findings.some((finding) => finding.claim_id === current)) return current;
  return topFinding(findings)?.claim_id ?? null;
}

function errorMessage(error: unknown, defaultMessage: string) {
  return error instanceof Error ? error.message : defaultMessage;
}

function agentSummary(agents: AgentProfile[]) {
  const active = agents.filter((agent) => agent.status === "active").length;
  const blocked = agents.filter((agent) => agent.status === "blocked").length;
  const complete = agents.filter((agent) => agent.status === "complete").length;

  if (blocked) return `${blocked} blocked, ${active} active`;
  if (active) return `${active} active, ${complete} contributed`;
  return `${complete}/${agents.length} contributed`;
}

function AgentList({ agents, audit }: { agents: AgentProfile[]; audit: AuditState }) {
  const activeAgent = agents.find((agent) => agent.status === "active") ?? agents[0];

  return (
    <Stack spacing={0.25} sx={{ minHeight: 0, overflow: "auto", pr: 0.25 }}>
      {agents.map((agent) => {
        const expanded = agent.id === activeAgent?.id;
        return (
          <Box
            key={agent.id}
            sx={{
              display: "grid",
              gridTemplateColumns: "10px minmax(0, 1fr)",
              gap: 0.8,
              alignItems: "start",
              py: 0.85,
              px: 1,
              borderLeft: "2px solid",
              borderLeftColor: expanded ? "primary.main" : "transparent",
              borderRadius: 1,
              bgcolor: expanded ? "action.hover" : "transparent"
            }}
          >
            <Box
              aria-hidden="true"
              sx={{
                width: 5,
                height: 5,
                mt: 0.7,
                borderRadius: "50%",
                bgcolor:
                  agent.status === "blocked"
                    ? "error.main"
                    : agent.status === "complete"
                      ? "success.main"
                      : agent.status === "active"
                        ? "primary.main"
                        : "divider"
              }}
            />
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="body2" fontWeight={600} noWrap>
                {agent.name}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.15 }} noWrap>
                {agentContribution(agent, audit)} - {providerName(routeProvider(audit, agent.name) ?? "aiml")}
              </Typography>
            </Box>
          </Box>
        );
      })}
    </Stack>
  );
}

function ReleaseProgress({ phase, compact = false }: { phase: string; compact?: boolean }) {
  const currentIndex = phaseIndex(phase);

  return (
    <Stepper
      activeStep={currentIndex}
      alternativeLabel={!compact}
      aria-label="Audit progress"
      sx={{
        px: { xs: 0, sm: compact ? 0 : 1 },
        py: compact ? 0.75 : 1.25,
        overflowX: "auto",
        "& .MuiStep-root": {
          minWidth: compact ? 96 : { xs: 106, sm: 118 }
        },
        "& .MuiStepLabel-root": {
          gap: compact ? 0.5 : 0.75
        },
        "& .MuiStepLabel-label": {
          mt: compact ? 0.35 : 0.75,
          fontSize: compact ? "var(--audit-type-caption)" : "var(--audit-type-small)",
          fontWeight: 600,
          color: "text.secondary"
        },
        "& .Mui-active .MuiStepLabel-label, & .Mui-completed .MuiStepLabel-label": {
          color: "text.primary"
        },
        "& .MuiStepIcon-root": {
          color: "divider"
        },
        "& .MuiStepIcon-root.Mui-active": {
          color: "primary.main"
        },
        "& .MuiStepIcon-root.Mui-completed": {
          color: "success.main"
        }
      }}
    >
      {reviewStages.map((stage, index) => (
        <Step
          key={stage.id}
          completed={phase === "complete" || index < currentIndex}
          aria-current={index === currentIndex ? "step" : undefined}
          title={`${stage.label}: ${stage.events}`}
        >
          <StepLabel
            optional={
              compact ? undefined : (
                <Typography variant="caption" color="text.secondary" sx={{ display: { xs: "none", xl: "block" } }}>
                  {stage.events}
                </Typography>
              )
            }
          >
            {stage.label}
          </StepLabel>
        </Step>
      ))}
    </Stepper>
  );
}

function ProviderLaneSummary({ audit, compact = false }: { audit: AuditState; compact?: boolean }) {
  const lanes: Array<"aiml" | "featherless"> = ["aiml", "featherless"];

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" },
        gap: 1.5,
        p: compact ? 0 : 2.5,
        pt: compact ? 0 : 0
      }}
    >
      {lanes.map((providerId) => {
        const provider = audit.agent_execution.providers.find((item) => item.provider === providerId);
        const providerRoutes = audit.agent_execution.routes.filter((route) => route.provider === providerId);
        const agents = providerRoutes.map((route) => route.agent);
        return (
          <Paper
            variant="outlined"
            key={providerId}
            sx={{
              p: 2,
              borderLeft: "4px solid",
              borderLeftColor: providerId === "aiml" ? "primary.main" : "#6d5dfc"
            }}
          >
            <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={2}>
              <Box sx={{ minWidth: 0 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  {providerName(providerId)}
                </Typography>
                <Typography variant="body2" fontWeight={600} sx={{ mt: 0.5 }}>
                  {agents.join(", ") || "No routed agents"}
                </Typography>
              </Box>
              <Chip
                size="small"
                variant={provider?.status === "ready" ? "filled" : "outlined"}
                color={provider?.status === "ready" ? "success" : "default"}
                label={provider ? titleCase(provider.status) : "Not routed"}
              />
            </Stack>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1.25 }}>
              {providerRoleSummary(providerId)}
            </Typography>
            {!compact && providerRoutes.length > 0 && (
              <Typography variant="caption" color="text.disabled" sx={{ display: "block", mt: 1, overflowWrap: "anywhere" }}>
                {routeModelSummary(providerRoutes)}
              </Typography>
            )}
          </Paper>
        );
      })}
    </Box>
  );
}

function GridTextCell({ children, muted = false, strong = false }: { children: ReactNode; muted?: boolean; strong?: boolean }) {
  return (
    <Typography
      variant="body2"
      color={muted ? "text.secondary" : "text.primary"}
      fontWeight={strong ? 600 : 500}
      sx={{ whiteSpace: "normal", lineHeight: 1.42, py: 1 }}
    >
      {children}
    </Typography>
  );
}

function CenteredGridCell({ children, muted = false, strong = false }: { children: ReactNode; muted?: boolean; strong?: boolean }) {
  return (
    <Box sx={{ display: "flex", alignItems: "center", minHeight: "100%", width: "100%" }}>
      <Typography
        variant="body2"
        color={muted ? "text.secondary" : "text.primary"}
        fontWeight={strong ? 600 : 500}
        sx={{ overflowWrap: "anywhere" }}
      >
        {children}
      </Typography>
    </Box>
  );
}

function GridChipCell({ children, center = false }: { children: ReactNode; center?: boolean }) {
  return (
    <Box
      sx={{
        display: "flex",
        alignItems: "center",
        justifyContent: center ? "center" : "flex-start",
        width: "100%",
        minHeight: "100%",
        py: 0.75
      }}
    >
      {children}
    </Box>
  );
}

function ProtocolEventGrid({ audit }: { audit: AuditState }) {
  const rows = audit.events.map((event) => ({
    id: event.event_id,
    eventNumber: eventNumberById(audit.events, event.event_id),
    time: formatEventTime(event),
    agent: event.agent,
    type: protocolEventName(event),
    finding: compactRefs(eventFindingRefs(event), "None"),
    evidence: compactRefs(evidenceIds(event.evidence_refs), "None"),
    provider: providerLabelForEvent(audit, event),
    phase: phaseLabels[event.phase],
    summary: event.summary
  }));
  const columns: GridColDef[] = [
    { field: "eventNumber", headerName: "Event #", width: 88, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell strong>{String(value ?? "")}</CenteredGridCell> },
    { field: "time", headerName: "Time", width: 96, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
    { field: "agent", headerName: "Agent", minWidth: 150, flex: 0.9, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell strong>{String(value ?? "")}</CenteredGridCell> },
    { field: "type", headerName: "Type", minWidth: 150, flex: 0.8, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell>{String(value ?? "")}</CenteredGridCell> },
    { field: "finding", headerName: "Finding", width: 112, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
    { field: "evidence", headerName: "Evidence", minWidth: 150, flex: 0.8, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
    { field: "provider", headerName: "Provider", minWidth: 142, flex: 0.8, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
    { field: "phase", headerName: "State", minWidth: 130, flex: 0.7, cellClassName: "event-stream-compact-cell", renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
    { field: "summary", headerName: "Event summary", minWidth: 300, flex: 1.5, cellClassName: "event-stream-summary-cell", renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> }
  ];

  return (
    <Box sx={{ height: 520, width: "100%" }}>
      <DataGrid
        rows={rows}
        columns={columns}
        disableRowSelectionOnClick
        getRowHeight={() => "auto"}
        pageSizeOptions={[10, 25, 50]}
        initialState={{ pagination: { paginationModel: { pageSize: 10, page: 0 } } }}
        sx={{
          "& .MuiDataGrid-cell": {
            px: 1.5
          },
          "& .event-stream-compact-cell": {
            alignItems: "center"
          },
          "& .event-stream-summary-cell": {
            alignItems: "flex-start",
            py: 0.75
          },
          "& .MuiDataGrid-columnHeader": {
            px: 1.5
          }
        }}
      />
    </Box>
  );
}

function PhaseProtocol() {
  const rows = boardProtocol.map((item, index) => ({
    id: item.phase,
    step: index + 1,
    phase: item.phase,
    agents: item.agents,
    consumes: item.consumes,
    produces: item.produces,
    state: item.state
  }));
  const columns: GridColDef[] = [
    { field: "step", headerName: "Step", width: 74 },
    { field: "phase", headerName: "Phase", minWidth: 120, flex: 0.7, renderCell: ({ value }) => <GridTextCell strong>{String(value ?? "")}</GridTextCell> },
    { field: "agents", headerName: "Agents", minWidth: 210, flex: 1, renderCell: ({ value }) => <GridTextCell>{String(value ?? "")}</GridTextCell> },
    { field: "consumes", headerName: "Consumes", minWidth: 260, flex: 1.25, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> },
    { field: "produces", headerName: "Produces", minWidth: 230, flex: 1.05, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> },
    { field: "state", headerName: "State update", minWidth: 320, flex: 1.45, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> }
  ];

  return (
    <Box sx={{ height: 440, width: "100%" }}>
      <DataGrid
        rows={rows}
        columns={columns}
        hideFooter
        disableRowSelectionOnClick
        getRowHeight={() => "auto"}
        sx={{ "& .MuiDataGrid-cell": { alignItems: "flex-start" } }}
      />
    </Box>
  );
}

function ProviderRouteGrid({ audit }: { audit: AuditState }) {
  const rows = audit.agent_execution.routes.map((route) => {
    const provider = audit.agent_execution.providers.find((item) => item.provider === route.provider);
    return {
      id: route.agent,
      provider: providerName(route.provider),
      agent: route.agent,
      purpose: route.purpose,
      status: provider ? titleCase(provider.status) : "Not routed",
      model: route.model ?? provider?.model ?? "Not configured"
    };
  });
  const columns: GridColDef[] = [
    { field: "provider", headerName: "Provider", minWidth: 150, flex: 0.8 },
    { field: "agent", headerName: "Agent", minWidth: 160, flex: 0.9, renderCell: ({ value }) => <GridTextCell strong>{String(value ?? "")}</GridTextCell> },
    { field: "purpose", headerName: "Purpose", minWidth: 320, flex: 1.55, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> },
    {
      field: "status",
      headerName: "Status",
      width: 132,
      align: "center",
      headerAlign: "center",
      cellClassName: "provider-status-cell",
      headerClassName: "provider-status-header",
      renderCell: ({ value }) => (
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", width: "100%", minHeight: "100%" }}>
          <Chip label={String(value ?? "")} color={value === "Ready" ? "success" : "default"} variant={value === "Ready" ? "filled" : "outlined"} />
        </Box>
      )
    },
    {
      field: "model",
      headerName: "Model",
      minWidth: 220,
      flex: 1,
      cellClassName: "provider-model-cell",
      renderCell: ({ value }) => (
        <Box sx={{ display: "flex", alignItems: "center", minHeight: "100%", width: "100%" }}>
          <Typography variant="body2" color="text.secondary">
            {String(value ?? "")}
          </Typography>
        </Box>
      )
    }
  ];

  return (
    <Box sx={{ height: 380, width: "100%" }}>
      <DataGrid
        rows={rows}
        columns={columns}
        hideFooter
        disableRowSelectionOnClick
        getRowHeight={() => "auto"}
        sx={{
          "& .MuiDataGrid-cell": { alignItems: "flex-start" },
          "& .provider-status-cell, & .provider-model-cell": {
            alignItems: "center"
          },
          "& .provider-status-cell": {
            justifyContent: "center"
          },
          "& .provider-status-header .MuiDataGrid-columnHeaderTitleContainer": {
            justifyContent: "center"
          }
        }}
      />
    </Box>
  );
}

function PacketSummary({ audit }: { audit: AuditState }) {
  const packet = audit.input_packet;

  return (
    <Card component="section" variant="outlined" sx={{ height: "100%", border: 0, boxShadow: "none", borderRadius: 0 }}>
      <CardContent sx={{ p: 3, "&:last-child": { pb: 3 } }}>
        <Typography variant="overline" color="text.secondary" fontWeight={600}>
          Input packet
        </Typography>
        <Typography variant="h2" sx={{ mt: 0.5 }}>
          {packet.target_name}
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1 }}>
          {packet.target_summary}
        </Typography>
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2, mt: 2.5, pt: 2.5, borderTop: "1px solid", borderColor: "divider" }}>
          {[
            ["Workflow", packet.workflow],
            ["Tool access", packet.tool_access],
            ["Policy context", packet.policy_context],
            ["Evidence submitted", packet.evidence_notes],
            ["Business owner", packet.business_owner || "Not supplied"],
            ["Release goal", packet.release_goal || "Not supplied"]
          ].map(([label, value]) => (
            <Box key={label} sx={{ minWidth: 0 }}>
              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                {label}
              </Typography>
              <Typography variant="body2" fontWeight={500} sx={{ mt: 0.6 }}>
                {value}
              </Typography>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
}

function ReleaseGate({
  audit,
  selectedFinding,
  busy,
  navigate
}: {
  audit: AuditState;
  selectedFinding: Finding | undefined;
  busy: boolean;
  navigate: (view: ViewMode) => void;
}) {
  const rec = recommendation(audit);
  const tone = rec.tone as DashboardTone;
  const primaryFinding = selectedFinding ?? topFinding(audit.findings);
  const scoreColor = toneColor(tone);
  const scoreBg = toneSoftColor(tone);
  const primaryAction = audit.phase === "complete" ? () => navigate("report") : () => navigate("timeline");
  const primaryActionLabel = audit.phase === "complete" ? "View release report" : "Open live timeline";
  const blockerSummary = primaryFinding?.release_impact || primaryFinding?.summary || rec.reason;
  const nextAction =
    primaryFinding?.remediation[0] ??
    audit.report?.required_remediations[0] ??
    (audit.phase === "complete" ? "Use the report for remediation planning and re-review criteria." : "The board runs automatically after a packet is locked; inspect Timeline for the live event trace.");
  const decisionEvent = decisionCompletedEvent(audit);
  const lastBandEvent = latestEvent(audit);
  const decisionLabel = decisionEvent
    ? `${audit.phase === "complete" ? "Decision completed" : "Decision event"} ${formatEventTime(decisionEvent)}`
    : "Decision pending";
  const lastEventLabel = lastBandEvent ? `Last Band event ${formatEventTime(lastBandEvent)}` : "No Band events yet";
  const verdictText =
    audit.decision === "blocked"
      ? `${audit.input_packet.target_name} is not approved for production deployment.`
      : audit.report?.release_verdict ?? `${audit.input_packet.target_name} is under release-board review.`;

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-labelledby="decision-panel-title"
      sx={{
        display: "grid",
        gap: 2.5,
        p: { xs: 2, md: 2.75 },
        borderLeft: "4px solid",
        borderLeftColor: scoreColor,
        bgcolor: "background.paper",
        boxShadow: "inset 0 1px 0 rgba(16, 24, 40, 0.02)"
      }}
    >
      <Stack direction={{ xs: "column", md: "row" }} justifyContent="space-between" alignItems={{ xs: "stretch", md: "flex-start" }} spacing={2}>
        <Box sx={{ minWidth: 0, maxWidth: 820 }}>
          <Typography variant="subtitle2" color="text.secondary">
            Release decision
          </Typography>
          <Typography id="decision-panel-title" variant="h1" sx={{ mt: 0.35 }}>
            {audit.decision === "blocked" ? "Release blocked" : rec.label}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.8 }}>
            {verdictText}
          </Typography>
          <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 1.25 }}>
            <Chip label={decisionLabel} variant="outlined" />
            <Chip label={lastEventLabel} variant="outlined" color="info" />
          </Stack>
        </Box>
        <Stack direction={{ xs: "column", sm: "row", md: "column" }} spacing={1} sx={{ width: { xs: "100%", md: 184 }, flex: "0 0 auto" }}>
          <Button
            variant="contained"
            color={tone === "danger" ? "error" : tone === "warning" ? "warning" : "primary"}
            onClick={primaryAction}
            disabled={busy && audit.phase !== "complete"}
            startIcon={audit.phase === "complete" ? <FileText size={16} /> : <CalendarDays size={16} />}
            fullWidth
          >
            {primaryActionLabel}
          </Button>
          <Button variant="outlined" color="inherit" onClick={() => navigate("protocol")} fullWidth>
            View protocol
          </Button>
        </Stack>
      </Stack>
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", lg: "minmax(0, 1fr) 220px" },
          gap: 2.5,
          alignItems: "start"
        }}
      >
        <Stack spacing={1.75} sx={{ minWidth: 0 }}>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Primary blocker
            </Typography>
            <Typography variant="h3" sx={{ mt: 0.45 }}>
              {primaryFinding?.title ?? "No primary blocker selected"}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.7, maxWidth: 820 }}>
              {blockerSummary}
            </Typography>
          </Box>
          <Divider />
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Required next action
            </Typography>
            <Typography variant="body2" sx={{ mt: 0.55, maxWidth: 820 }}>
              {nextAction}
            </Typography>
          </Box>
        </Stack>

        <Paper
          variant="outlined"
          sx={{
            display: "grid",
            gap: 1.25,
            p: 2,
            bgcolor: scoreBg,
            borderColor: scoreColor
          }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Risk
            </Typography>
            <Typography variant="h1" component="strong" sx={{ display: "block", mt: 0.45, fontSize: "var(--audit-type-score)" }}>
              {audit.risk_score}/100
            </Typography>
            <Typography color={scoreColor} fontWeight={700}>
              {severityLabels[audit.risk_level]}
            </Typography>
          </Box>
          <Divider />
          <Box sx={{ display: "grid", gap: 0.75 }}>
            <Stack direction="row" justifyContent="space-between" spacing={1.5}>
              <Typography variant="caption" color="text.secondary">Evidence</Typography>
              <Typography variant="caption" fontWeight={600}>{evidenceStrength(primaryFinding)}</Typography>
            </Stack>
            <Stack direction="row" justifyContent="space-between" spacing={1.5}>
              <Typography variant="caption" color="text.secondary">Phase</Typography>
              <Typography variant="caption" fontWeight={600}>{audit.phase === "complete" ? "Decision complete" : gatePhaseLabels[audit.phase]}</Typography>
            </Stack>
          </Box>
        </Paper>
      </Box>
    </Paper>
  );
}

function ReviewMetrics({ audit, selectedFinding }: { audit: AuditState; selectedFinding: Finding | undefined }) {
  const blockers = openFindings(audit);
  const items = [
    { label: "Risk", value: `${audit.risk_score}/100`, detail: severityLabels[audit.risk_level] },
    { label: "Blockers", value: `${audit.findings.length} total`, detail: `${verifiedFindings(audit)} verified` },
    { label: "Evidence", value: `${traceabilityCount(audit)} links`, detail: evidenceStrength(selectedFinding) },
    { label: "Band events", value: `${audit.events.length} total`, detail: consensusLabel(audit) }
  ];

  return (
    <Paper
      component="section"
      variant="outlined"
      aria-label="Audit dashboard metrics"
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "repeat(2, minmax(0, 1fr))", lg: "repeat(4, minmax(0, 1fr))" },
        overflow: "hidden"
      }}
    >
      {items.map((item, index) => (
        <Box
          key={item.label}
          sx={{
            minWidth: 0,
            p: { xs: 1.4, md: 1.6 },
            borderRight: { xs: index % 2 === 0 ? "1px solid" : 0, lg: index < items.length - 1 ? "1px solid" : 0 },
            borderBottom: { xs: index < 2 ? "1px solid" : 0, lg: 0 },
            borderColor: "divider"
          }}
        >
          <Typography variant="caption" color="text.secondary" fontWeight={600}>
            {item.label}
          </Typography>
          <Stack direction="row" alignItems="baseline" spacing={0.8} sx={{ mt: 0.35, minWidth: 0 }}>
            <Typography variant="body1" fontWeight={700} sx={{ overflowWrap: "anywhere" }}>
              {item.value}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
              {item.detail}
            </Typography>
          </Stack>
        </Box>
      ))}
    </Paper>
  );
}

function ReleaseBoardRoster({ audit, compact = false }: { audit: AuditState; compact?: boolean }) {
  const rows = releaseBoardRoster(audit);
  const manifest = roomManifest(audit);
  const recruited = rows.filter((row) => row.participantMode === "Recruited Band peer").length;
  const source = roomHasLockedPacketManifest(audit) ? "Band room manifest" : "Route diagnostics";
  const evidenceCount = manifestNumber(manifest, "evidence_count", traceabilityCount(audit));

  return (
    <Paper component="section" variant="outlined" sx={{ overflow: "hidden", minWidth: 0 }}>
      <Stack
        direction={{ xs: "column", lg: "row" }}
        spacing={1.5}
        alignItems={{ xs: "stretch", lg: "flex-start" }}
        justifyContent="space-between"
        sx={{ p: { xs: 2, md: 2.25 }, borderBottom: "1px solid", borderColor: "divider" }}
      >
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h3">Release board roster</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.45, maxWidth: 780 }}>
            Band room workspace for provider-routed release-board lanes. Participant strategy: {participantStrategyLabel(audit)}.
          </Typography>
        </Box>
        <Stack direction="row" flexWrap="wrap" gap={0.75}>
          <Chip label={source} variant="outlined" />
          <Chip label={`${rows.length} lanes`} variant="outlined" />
          <Chip label={`${recruited} recruited peers`} variant="outlined" color={recruited ? "success" : "default"} />
          <Chip label={`${evidenceCount} evidence refs`} variant="outlined" />
        </Stack>
      </Stack>
      <TableContainer sx={{ overflowX: "auto" }}>
        <Table size="small" aria-label="Release board roster" sx={{ minWidth: compact ? 720 : 940 }}>
          <TableHead>
            <TableRow>
              <TableCell>Lane</TableCell>
              <TableCell>Agent</TableCell>
              <TableCell>Provider</TableCell>
              <TableCell>Model</TableCell>
              {!compact && <TableCell>Role</TableCell>}
              <TableCell>Latest Band event</TableCell>
              <TableCell>Participant mode</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.agent} hover>
                <TableCell>
                  <Typography variant="body2" fontWeight={600}>
                    {row.lane}
                  </Typography>
                </TableCell>
                <TableCell>{row.agent}</TableCell>
                <TableCell>{row.provider}</TableCell>
                <TableCell sx={{ maxWidth: 230, overflowWrap: "anywhere" }}>{row.model}</TableCell>
                {!compact && <TableCell sx={{ minWidth: 280 }}>{row.role}</TableCell>}
                <TableCell>
                  <Typography variant="body2">{row.latestEvent}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {row.eventCount} event{row.eventCount === 1 ? "" : "s"}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Chip
                    label={row.participantMode}
                    variant="outlined"
                    color={row.participantMode === "Recruited Band peer" ? "success" : "default"}
                  />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Paper>
  );
}

function StaleRoomTraceWarning({ audit, navigate }: { audit: AuditState; navigate: (view: ViewMode) => void }) {
  if (!isStaleRoomTrace(audit)) return null;
  return (
    <Alert
      severity="warning"
      variant="outlined"
      action={
        <Button color="inherit" onClick={() => navigate("setup")}>
          Fresh room
        </Button>
      }
    >
      Old or partial room trace. Use a fresh Band room so the packet lock, roster manifest, lane events, and report share one clean trace.
    </Alert>
  );
}

function ReleaseActionPlan({
  audit,
  selectedFinding,
  navigate,
  onPrepareReReview
}: {
  audit: AuditState;
  selectedFinding: Finding | undefined;
  navigate: (view: ViewMode) => void;
  onPrepareReReview: () => void;
}) {
  const tasks = remediationTasks(audit);
  const selectedTasks = selectedFinding ? tasks.filter((task) => task.findingId === selectedFinding.claim_id) : tasks.slice(0, 3);

  return (
    <Paper component="section" variant="outlined" sx={{ overflow: "hidden" }}>
      <Stack
        direction={{ xs: "column", lg: "row" }}
        spacing={2}
        alignItems={{ xs: "stretch", lg: "flex-start" }}
        justifyContent="space-between"
        sx={{ p: { xs: 2, md: 2.25 }, borderBottom: "1px solid", borderColor: "divider", bgcolor: "background.paper" }}
      >
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h3">Release action plan</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.45, maxWidth: 760 }}>
            Operational remediation derived from the current blocker set. Use re-review after owners attach closure evidence.
          </Typography>
        </Box>
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ width: { xs: "100%", lg: "auto" } }}>
          <Button variant="outlined" color="inherit" onClick={() => navigate("timeline")} startIcon={<CalendarDays size={15} />}>
            Open timeline
          </Button>
          <Button variant="outlined" color="inherit" onClick={() => navigate("report")} startIcon={<FileText size={15} />}>
            Open report
          </Button>
          <Button variant="contained" onClick={onPrepareReReview} startIcon={<RefreshCcw size={15} />}>
            Prepare re-review packet
          </Button>
        </Stack>
      </Stack>
      {tasks.length > 0 ? (
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1fr) 280px" }, gap: 0 }}>
          <Box sx={{ minWidth: 0 }}>
            {selectedTasks.map((task, index) => (
              <Box key={task.id}>
                <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "150px minmax(0, 1fr) 180px" }, gap: 1.5, alignItems: "start", p: { xs: 1.75, md: 2 } }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      {task.findingId}
                    </Typography>
                    <Stack direction="row" spacing={0.75} flexWrap="wrap" sx={{ mt: 0.7 }}>
                      <Chip label={severityLabels[task.severity]} color={severityChipColor(task.severity)} variant="outlined" />
                      <Chip label={titleCase(task.status)} color={statusChipColor(task.status)} variant="outlined" />
                    </Stack>
                  </Box>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2" fontWeight={700}>
                      {task.text}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.6 }}>
                      Owner: {task.owner} - Evidence required: {task.requiredEvidenceCount} refs
                    </Typography>
                  </Box>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      Closure evidence
                    </Typography>
                    <Typography variant="body2" sx={{ mt: 0.35, overflowWrap: "anywhere" }}>
                      {compactRefs(task.evidenceRefs, "No evidence linked")}
                    </Typography>
                  </Box>
                </Box>
                {index < selectedTasks.length - 1 && <Divider />}
              </Box>
            ))}
          </Box>
          <Box sx={{ p: 2, borderTop: { xs: "1px solid", xl: 0 }, borderLeft: { xl: "1px solid" }, borderColor: "divider", bgcolor: "background.default" }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Re-review readiness
            </Typography>
            <Typography variant="h3" sx={{ mt: 0.6 }}>
              {audit.decision === "blocked" ? "Blocked until evidence changes" : "Ready for decision follow-up"}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.8 }}>
              A fresh Band room should be created for re-review so the new closure packet has a clean event trace.
            </Typography>
          </Box>
        </Box>
      ) : (
        <Alert severity="success" variant="outlined" sx={{ m: 2 }}>
          No release-blocking remediation tasks are currently open.
        </Alert>
      )}
    </Paper>
  );
}

function SectionTitle({
  title,
  description,
  action
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" alignItems={{ xs: "flex-start", sm: "center" }} spacing={1.5}>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="h3">{title}</Typography>
        {description && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4 }}>
            {description}
          </Typography>
        )}
      </Box>
      {action}
    </Stack>
  );
}

function TopBlockersList({
  findings,
  selectedId,
  onSelect
}: {
  findings: Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [statusFilter, setStatusFilter] = useState<FindingStatusFilter>("all");
  const sorted = useMemo(
    () => [...findings].sort((a, b) => severityRank[b.severity] - severityRank[a.severity]),
    [findings]
  );
  const visible = sorted.filter((finding) => findingMatchesFilters(finding, query, severityFilter, statusFilter));
  const filterActive = query.trim() || severityFilter !== "all" || statusFilter !== "all";
  const rows = visible.map((finding) => ({
    id: finding.claim_id,
    finding,
    title: finding.title,
    severity: finding.severity,
    status: finding.status,
    owner: finding.owner_agent,
    evidence: finding.evidence_refs.length,
    state: selectedId === finding.claim_id ? "Selected" : findingEvidenceState(finding)
  }));
  const blockerSelectionModel = {
    type: "include" as const,
    ids: new Set(selectedId && visible.some((finding) => finding.claim_id === selectedId) ? [selectedId] : [])
  };
  const columns: GridColDef[] = [
    {
      field: "title",
      headerName: "Finding",
      width: 270,
      renderCell: ({ row }) => (
        <Button
          variant="text"
          color="inherit"
          onClick={(event) => {
            event.stopPropagation();
            onSelect(row.finding.claim_id);
          }}
          sx={{
            justifyContent: "flex-start",
            width: "100%",
            minHeight: "auto",
            px: 0,
            py: 1,
            textAlign: "left",
            "&:hover": { bgcolor: "transparent" }
          }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="body2" fontWeight={600} sx={{ color: "text.primary" }}>
              {row.finding.claim_id} - {row.title}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.35, overflowWrap: "anywhere" }}>
              {row.finding.category}
            </Typography>
          </Box>
        </Button>
      )
    },
    {
      field: "severity",
      headerName: "Severity",
      width: 96,
      align: "center",
      headerAlign: "center",
      renderCell: ({ value }) => (
        <GridChipCell center>
          <Chip label={severityLabels[value as Severity]} color={severityChipColor(value as Severity)} variant="outlined" />
        </GridChipCell>
      )
    },
    {
      field: "status",
      headerName: "Status",
      width: 104,
      align: "center",
      headerAlign: "center",
      renderCell: ({ value }) => (
        <GridChipCell center>
          <Chip label={titleCase(String(value))} color={statusChipColor(value as Finding["status"])} variant="outlined" />
        </GridChipCell>
      )
    },
    {
      field: "owner",
      headerName: "Owner",
      width: 124,
      renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell>
    },
    {
      field: "evidence",
      headerName: "Evidence",
      width: 84,
      align: "center",
      headerAlign: "center",
      renderCell: ({ value }) => (
        <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", width: "100%", minHeight: "100%" }}>
          <Typography variant="body2" fontWeight={600}>
            {String(value ?? 0)}
          </Typography>
        </Box>
      )
    },
    {
      field: "state",
      headerName: "State",
      width: 96,
      align: "center",
      headerAlign: "center",
      renderCell: ({ value }) => (
        <GridChipCell center>
          <Chip label={String(value ?? "")} color={value === "Selected" ? "success" : "default"} variant={value === "Selected" ? "filled" : "outlined"} />
        </GridChipCell>
      )
    }
  ];

  function clearFilters() {
    setQuery("");
    setSeverityFilter("all");
    setStatusFilter("all");
  }

  return (
    <Box component="section" aria-labelledby="top-blockers-title" sx={{ minWidth: 0 }}>
      <SectionTitle
        title="Top blockers"
        description={`${visible.length} of ${findings.length} findings in scope. Select a row to update evidence and action-plan context.`}
      />
      <Paper variant="outlined" sx={{ mt: 1.5, overflow: "hidden" }}>
        <Stack
          direction={{ xs: "column", lg: "row" }}
          alignItems={{ xs: "stretch", lg: "center" }}
          justifyContent="space-between"
          spacing={1.25}
          sx={{ p: 1.5, borderBottom: "1px solid", borderColor: "divider", bgcolor: "background.paper" }}
        >
          <TextField
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search blockers"
            aria-label="Search blockers"
            size="small"
            sx={{ minWidth: { xs: "100%", lg: 280 } }}
          />
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ width: { xs: "100%", lg: "auto" } }}>
            <FormControl size="small" sx={{ minWidth: 146 }}>
              <InputLabel id="blocker-severity-filter">Severity</InputLabel>
              <Select
                labelId="blocker-severity-filter"
                value={severityFilter}
                label="Severity"
                onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}
              >
                <MenuItem value="all">All severity</MenuItem>
                {Object.keys(severityLabels).map((severity) => (
                  <MenuItem value={severity} key={severity}>
                    {severityLabels[severity as Severity]}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel id="blocker-status-filter">Status</InputLabel>
              <Select
                labelId="blocker-status-filter"
                value={statusFilter}
                label="Status"
                onChange={(event) => setStatusFilter(event.target.value as FindingStatusFilter)}
              >
                <MenuItem value="all">All status</MenuItem>
                {Array.from(new Set(findings.map((finding) => finding.status))).map((status) => (
                  <MenuItem value={status} key={status}>
                    {titleCase(status)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <Button variant="outlined" color="inherit" onClick={clearFilters} disabled={!filterActive}>
              Clear
            </Button>
          </Stack>
        </Stack>
        {visible.length > 0 ? (
          <>
            <Box sx={{ display: { xs: "none", md: "block" }, height: 430, width: "100%" }}>
              <DataGrid
                rows={rows}
                columns={columns}
                onRowClick={(params: GridRowParams) => onSelect(String(params.id))}
                onCellClick={(params) => onSelect(String(params.id))}
                onRowSelectionModelChange={(model) => {
                  const [nextId] = Array.from(model.ids);
                  if (nextId) onSelect(String(nextId));
                }}
                rowSelectionModel={blockerSelectionModel}
                disableColumnMenu
                disableRowSelectionOnClick={false}
                getRowHeight={() => "auto"}
                pageSizeOptions={[6, 12, 25]}
                initialState={{ pagination: { paginationModel: { pageSize: 6, page: 0 } } }}
                sx={{
                  border: 0,
                  "& .MuiDataGrid-cell": { alignItems: "center", display: "flex", px: 1.25 },
                  "& .MuiDataGrid-columnHeader": { px: 1.5 },
                  "& .MuiDataGrid-row": { cursor: "pointer" }
                }}
              />
            </Box>
            <Box sx={{ display: { xs: "grid", md: "none" } }}>
              {visible.map((finding, index) => {
                const selected = selectedId === finding.claim_id;
                return (
                  <Box key={finding.claim_id}>
                    <Box
                      component="button"
                      type="button"
                      onClick={() => onSelect(finding.claim_id)}
                      aria-pressed={selected}
                      sx={{
                        display: "grid",
                        gap: 0.85,
                        width: "100%",
                        p: 1.75,
                        border: 0,
                        bgcolor: selected ? "action.selected" : "background.paper",
                        color: "text.primary",
                        cursor: "pointer",
                        font: "inherit",
                        textAlign: "left",
                        "&:hover": { bgcolor: selected ? "action.selected" : "background.default" }
                      }}
                    >
                      <Stack direction="row" spacing={0.75} flexWrap="wrap" alignItems="center">
                        <Chip label={finding.claim_id} variant={selected ? "filled" : "outlined"} color={selected ? "success" : "default"} />
                        <Chip label={severityLabels[finding.severity]} color={severityChipColor(finding.severity)} variant="outlined" />
                        <Chip label={titleCase(finding.status)} color={statusChipColor(finding.status)} variant="outlined" />
                      </Stack>
                      <Typography variant="body2" fontWeight={600}>
                        {finding.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {finding.release_impact || finding.summary}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {finding.owner_agent} - {finding.evidence_refs.length} evidence refs - {findingEvidenceState(finding)}
                      </Typography>
                    </Box>
                    {index < visible.length - 1 && <Divider />}
                  </Box>
                );
              })}
            </Box>
          </>
        ) : (
          <Alert severity={findings.length ? "info" : "success"} variant="outlined" sx={{ m: 2 }}>
            {findings.length ? "No findings match the current filters." : "No release blockers have been raised."}
          </Alert>
        )}
      </Paper>
    </Box>
  );
}

function EvidencePreview({ finding, audit }: { finding: Finding | undefined; audit: AuditState }) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const refs = finding?.evidence_refs.slice(0, 3) ?? [];
  const hiddenRefs = finding ? Math.max(0, finding.evidence_refs.length - refs.length) : 0;
  const linkedEvents = linkedEventNumbersForFinding(audit, finding);
  const positions = agentPositionsForFinding(audit, finding);
  const primaryEvidence = refs[0];
  const provenanceRows = evidenceProvenanceRows(audit, finding);
  const primaryProvenance = primaryEvidence ? provenanceRows.find((row) => row.id === primaryEvidence.ref_id) : undefined;

  return (
    <Box component="section" aria-labelledby="evidence-preview-title" sx={{ minWidth: 0 }}>
      <SectionTitle
        title={finding ? `Evidence packet: ${finding.claim_id}` : "Evidence packet"}
        description={
          finding
            ? `${findingEvidenceState(finding)} - ${finding.evidence_refs.length} evidence refs - ${Math.round(finding.confidence * 100)}% confidence - ${linkedEvents.length} linked Band events`
            : "Select a blocker to inspect proof."
        }
        action={
          finding ? (
            <Button variant="outlined" color="inherit" onClick={() => setDrawerOpen(true)}>
              Open evidence drawer
            </Button>
          ) : undefined
        }
      />
      <Paper variant="outlined" sx={{ display: "grid", gap: 1.75, mt: 1.5, p: 2 }}>
        {finding ? (
          <>
            <Box>
              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                Why this matters
              </Typography>
              <Typography variant="body2" sx={{ mt: 0.55 }}>
                {finding.risk_mechanism || finding.release_impact || finding.summary}
              </Typography>
            </Box>
            <Divider />
            <Box sx={{ display: "grid", gap: 0 }}>
              {refs.length > 0 ? (
                refs.map((evidence, index) => {
                  const eventRefs = linkedEventNumbersForEvidence(audit, evidence);
                  return (
                    <Box key={evidence.ref_id}>
                      <Box
                        sx={{
                          display: "grid",
                          gridTemplateColumns: { xs: "1fr", md: "minmax(0, 1fr) auto" },
                          gap: 1,
                          alignItems: "start",
                          py: 1.15
                        }}
                      >
                        <Box sx={{ minWidth: 0 }}>
                          <Typography variant="body2" fontWeight={600}>
                            {evidence.ref_id} - {evidence.title}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
                            {artifactFileName(evidence.artifact)} - {evidence.locator}
                          </Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary" fontWeight={600}>
                          Events {compactRefs(eventRefs, "pending")}
                        </Typography>
                      </Box>
                      {index < refs.length - 1 && <Divider />}
                    </Box>
                  );
                })
              ) : (
                <Alert severity="warning" variant="outlined">
                  This blocker needs linked evidence before release approval.
                </Alert>
              )}
            </Box>
            {hiddenRefs > 0 && (
              <>
                <Divider />
                <Typography variant="caption" color="text.secondary">
                  {hiddenRefs} additional evidence refs are available in Timeline and Report.
                </Typography>
              </>
            )}
            {provenanceRows.length > 0 && (
              <>
                <Divider />
                <Box sx={{ display: "grid", gap: 1 }}>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Provenance
                  </Typography>
                  <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
                    <Table size="small" aria-label="Evidence provenance" sx={{ minWidth: 680 }}>
                      <TableHead>
                        <TableRow>
                          <TableCell>Ref</TableCell>
                          <TableCell>Events</TableCell>
                          <TableCell>Actor</TableCell>
                          <TableCell>Provider</TableCell>
                          <TableCell>Room</TableCell>
                          <TableCell>SHA-256</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {provenanceRows.map((row) => (
                          <TableRow key={row.id}>
                            <TableCell>
                              <Typography variant="body2" fontWeight={600}>
                                {row.id}
                              </Typography>
                            </TableCell>
                            <TableCell>{compactRefs(row.eventNumbers, "pending")}</TableCell>
                            <TableCell>{compactRefs(row.actors, "unknown")}</TableCell>
                            <TableCell>{compactRefs(row.providers, "unknown")}</TableCell>
                            <TableCell>{compactRefs(row.roomIds, "unknown")}</TableCell>
                            <TableCell sx={{ maxWidth: 190, overflowWrap: "anywhere" }}>
                              {row.evidence.sha256 ? `${row.evidence.sha256.slice(0, 14)}...` : "Not supplied"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              </>
            )}
            {positions.length > 0 && (
              <>
                <Divider />
                <Box sx={{ display: "grid", gap: 1 }}>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Agent positions
                  </Typography>
                  {positions.map((position) => (
                    <Stack direction="row" justifyContent="space-between" spacing={1.5} key={position.agent}>
                      <Typography variant="body2" fontWeight={600}>
                        {position.agent}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" textAlign="right">
                        {position.position}
                      </Typography>
                    </Stack>
                  ))}
                </Box>
              </>
            )}
          </>
        ) : (
          <Alert severity="info" variant="outlined">
            Select a blocker to inspect its evidence.
          </Alert>
        )}
      </Paper>
      <Drawer anchor="right" open={drawerOpen} onClose={() => setDrawerOpen(false)}>
        <Box sx={{ width: { xs: 340, sm: 440 }, p: 2.5, display: "grid", gap: 2 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={2}>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Evidence detail
              </Typography>
              <Typography variant="h2" sx={{ mt: 0.35 }}>
                {primaryEvidence?.ref_id ?? "Evidence"}
              </Typography>
            </Box>
            <Button variant="outlined" color="inherit" onClick={() => setDrawerOpen(false)}>
              Close
            </Button>
          </Stack>
          {finding && primaryEvidence ? (
            <>
              <Paper variant="outlined" sx={{ p: 1.75 }}>
                <Typography variant="body2" fontWeight={600}>
                  {primaryEvidence.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                  Type: evidence reference
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Source: {artifactFileName(primaryEvidence.artifact)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Locator: {primaryEvidence.locator}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
                  SHA-256: {primaryEvidence.sha256 || "Not supplied"}
                </Typography>
              </Paper>
              <Box sx={{ display: "grid", gap: 0.8 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Linked Band events
                </Typography>
                <Typography variant="body2">
                  {compactRefs(linkedEventNumbersForEvidence(audit, primaryEvidence), "No linked events")}
                </Typography>
              </Box>
              <Box sx={{ display: "grid", gap: 0.8 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Provenance
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Actor: {compactRefs(primaryProvenance?.actors ?? [], "unknown")}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Provider: {compactRefs(primaryProvenance?.providers ?? [], "unknown")}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Room: {compactRefs(primaryProvenance?.roomIds ?? [], "unknown")}
                </Typography>
              </Box>
              <Box sx={{ display: "grid", gap: 0.8 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Agent
                </Typography>
                <Typography variant="body2">
                  {finding.owner_agent} - {Math.round(finding.confidence * 100)}% confidence
                </Typography>
              </Box>
              <Box sx={{ display: "grid", gap: 1 }}>
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Raw Band event references
                </Typography>
                {audit.events
                  .filter((event) => linkedEventNumbersForEvidence(audit, primaryEvidence).includes(eventNumberById(audit.events, event.event_id)))
                  .slice(0, 5)
                  .map((event) => (
                    <Paper variant="outlined" sx={{ p: 1.25 }} key={event.event_id}>
                      <Typography variant="body2" fontWeight={600}>
                        {eventNumberById(audit.events, event.event_id)} - {eventHeadline(event)}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {event.summary}
                      </Typography>
                    </Paper>
                  ))}
              </Box>
            </>
          ) : (
            <Alert severity="info" variant="outlined">
              Select evidence to inspect.
            </Alert>
          )}
        </Box>
      </Drawer>
    </Box>
  );
}

function RecentActivity({ audit, navigate }: { audit: AuditState; navigate: (view: ViewMode) => void }) {
  const events = [...audit.events].reverse().slice(0, 4);

  return (
    <Box component="section" aria-labelledby="recent-activity-title" sx={{ minWidth: 0 }}>
      <SectionTitle
        title="Recent Activity"
        description="Latest board events only; the complete trace stays on Timeline."
        action={
          <Button variant="outlined" color="inherit" size="small" onClick={() => navigate("timeline")} endIcon={<ArrowRight size={14} />}>
            Timeline
          </Button>
        }
      />
      <Paper variant="outlined" sx={{ mt: 1.5, overflow: "hidden" }}>
        {events.length > 0 ? (
          events.map((event, index) => (
            <Box key={event.event_id}>
              <Stack direction="row" spacing={1.5} alignItems="flex-start" sx={{ p: 1.75 }}>
                <Box
                  sx={{
                    display: "grid",
                    placeItems: "center",
                    width: 32,
                    height: 32,
                    flex: "0 0 auto",
                    border: "1px solid",
                    borderColor: "divider",
                    borderRadius: 1.5,
                    color: severityChipColor(event.severity) === "error" ? "error.main" : "text.secondary",
                    bgcolor: "background.default"
                  }}
                >
                  <EventIcon event={event} />
                </Box>
                <Box sx={{ minWidth: 0, flex: 1 }}>
                  <Typography variant="body2" fontWeight={600}>
                    {eventHeadline(event)}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
                    {event.summary}
                  </Typography>
                  <Stack direction="row" flexWrap="wrap" gap={0.75} sx={{ mt: 0.8 }}>
                    <Chip label={eventNumberById(audit.events, event.event_id)} size="small" variant="outlined" />
                    <Chip label={phaseLabels[event.phase]} size="small" variant="outlined" />
                    <Chip label={providerLabelForEvent(audit, event)} size="small" variant="outlined" />
                    <Chip label={formatEventTime(event)} size="small" variant="outlined" />
                  </Stack>
                </Box>
              </Stack>
              {index < events.length - 1 && <Divider />}
            </Box>
          ))
        ) : (
          <Alert severity="info" variant="outlined" sx={{ m: 2 }}>
            No board events have been captured yet.
          </Alert>
        )}
      </Paper>
    </Box>
  );
}

function ReviewContextPanel({ audit, navigate }: { audit: AuditState; navigate: (view: ViewMode) => void }) {
  const packet = audit.input_packet;
  const facts = [
    { label: "Target", value: packet.target_name },
    { label: "Owner", value: packet.business_owner || "Not supplied" },
    { label: "Environment", value: packet.deployment_environment || "Not supplied" },
    { label: "Release goal", value: packet.release_goal || "Not supplied" },
    { label: "Agents", value: audit.agents.length },
    { label: "Providers", value: providerLabel(audit) }
  ];

  return (
    <Box component="section" aria-labelledby="review-context-title" sx={{ minWidth: 0 }}>
      <SectionTitle
        title="Review Context"
        description="Operational context for the decision; protocol and report pages carry the deeper detail."
      />
      <Paper variant="outlined" sx={{ display: "grid", gap: 2, mt: 1.5, p: 2 }}>
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" }, gap: 1.5 }}>
          {facts.map((fact) => (
            <Box key={fact.label} sx={{ minWidth: 0 }}>
              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                {fact.label}
              </Typography>
              <Typography variant="body2" fontWeight={600} sx={{ mt: 0.4, overflowWrap: "anywhere" }}>
                {fact.value}
              </Typography>
            </Box>
          ))}
        </Box>
        <Divider />
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
          <Button variant="outlined" color="inherit" onClick={() => navigate("protocol")} startIcon={<Workflow size={15} />}>
            Protocol
          </Button>
          <Button variant="outlined" color="inherit" onClick={() => navigate("report")} startIcon={<FileText size={15} />}>
            Report
          </Button>
        </Stack>
      </Paper>
    </Box>
  );
}

function EventIcon({ event }: { event: AuditEvent }) {
  if (event.event_type === "finding") return <TriangleAlert size={15} />;
  if (event.event_type === "artifact_indexed") return <FileSearch size={15} />;
  if (event.event_type === "verification") return <BadgeCheck size={15} />;
  if (event.event_type === "challenge" || event.event_type === "conflict_declaration") return <CircleAlert size={15} />;
  if (event.event_type === "vote") return <Vote size={15} />;
  if (event.event_type === "synthesis_report") return <FileText size={15} />;
  return <MessagesSquare size={15} />;
}

function timelineFilterMatch(event: AuditEvent, filter: TimelineFilter) {
  if (filter === "all") return true;
  if (filter === "findings") return event.event_type === "finding";
  if (filter === "evidence") return event.event_type === "artifact_indexed" || event.evidence_refs.length > 0;
  if (filter === "challenges") return event.event_type === "challenge" || event.event_type === "conflict_declaration";
  if (filter === "votes") return event.event_type === "vote";
  if (filter === "decisions") return event.event_type === "synthesis_report";
  return true;
}

function eventEvidenceProvenance(event: AuditEvent) {
  const supporting = event.metadata.supporting_evidence_imports;
  const supportingCount = Array.isArray(supporting) ? supporting.length : 0;
  if (supportingCount > 0) return `${supportingCount} supporting files`;
  const importSummary = event.metadata.import_summary;
  if (importSummary && typeof importSummary === "object" && !Array.isArray(importSummary) && "artifact" in importSummary) {
    return "Packet PDF";
  }
  if (event.event_type === "artifact_indexed") return `${event.evidence_refs.length} evidence refs`;
  return "Band event";
}

function AuditTimeline({ audit, compact = false }: { audit: AuditState; compact?: boolean }) {
  const [filter, setFilter] = useState<TimelineFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [query, setQuery] = useState("");
  const packet = audit.input_packet;
  const integrity = auditIntegrity(audit);
  const filters: Array<{ id: TimelineFilter; label: string }> = [
    { id: "all", label: "All events" },
    { id: "findings", label: "Findings" },
    { id: "evidence", label: "Evidence" },
    { id: "challenges", label: "Challenges" },
    { id: "votes", label: "Votes" },
    { id: "decisions", label: "Decisions" }
  ];
  const ordered = [...audit.events].reverse();
  const visibleEvents = ordered.filter((event) => {
    const queryText = query.trim().toLowerCase();
    const haystack = [
      eventHeadline(event),
      event.summary,
      protocolEventName(event),
      event.agent,
      providerLabelForEvent(audit, event),
      modelLabelForEvent(audit, event),
      eventEvidenceProvenance(event),
      event.claim_id ?? "",
      ...eventFindingRefs(event),
      ...evidenceIds(event.evidence_refs)
    ]
      .join(" ")
      .toLowerCase();
    return (
      timelineFilterMatch(event, filter) &&
      (severityFilter === "all" || event.severity === severityFilter) &&
      (!queryText || haystack.includes(queryText))
    );
  });
  const rows = (compact ? visibleEvents.slice(0, 4) : visibleEvents).map((event) => ({
    id: event.event_id,
    eventNumber: eventNumberById(audit.events, event.event_id),
    time: formatEventTime(event),
    agent: event.agent,
    type: protocolEventName(event),
    finding: compactRefs(eventFindingRefs(event), "None"),
    evidence: compactRefs(evidenceIds(event.evidence_refs), "None"),
    severity: event.severity,
    provider: providerLabelForEvent(audit, event),
    model: modelLabelForEvent(audit, event),
    provenance: eventEvidenceProvenance(event),
    state: event.severity === "critical" || event.severity === "high" ? "Blocking" : phaseLabels[event.phase],
    summary: event.summary
  }));
  const filterActive = filter !== "all" || severityFilter !== "all" || query.trim();
  const columns: GridColDef[] = compact
    ? [
        { field: "eventNumber", headerName: "Event", width: 92, renderCell: ({ value }) => <CenteredGridCell strong>{String(value ?? "")}</CenteredGridCell> },
        { field: "agent", headerName: "Agent", minWidth: 150, flex: 0.8, renderCell: ({ value }) => <CenteredGridCell strong>{String(value ?? "")}</CenteredGridCell> },
        { field: "summary", headerName: "Summary", minWidth: 320, flex: 1.5, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> }
      ]
    : [
        { field: "eventNumber", headerName: "Event #", width: 88, renderCell: ({ value }) => <CenteredGridCell strong>{String(value ?? "")}</CenteredGridCell> },
        { field: "time", headerName: "Time", width: 100, renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
        { field: "agent", headerName: "Agent", minWidth: 150, flex: 0.8, renderCell: ({ value }) => <CenteredGridCell strong>{String(value ?? "")}</CenteredGridCell> },
        { field: "type", headerName: "Type", minWidth: 170, flex: 0.9, renderCell: ({ value }) => <CenteredGridCell>{String(value ?? "")}</CenteredGridCell> },
        {
          field: "severity",
          headerName: "Severity",
          width: 116,
          align: "center",
          headerAlign: "center",
          renderCell: ({ value }) => (
            <GridChipCell center>
              <Chip label={severityLabels[value as Severity]} color={severityChipColor(value as Severity)} variant="outlined" />
            </GridChipCell>
          )
        },
        { field: "finding", headerName: "Finding", width: 112, renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
        { field: "evidence", headerName: "Evidence", minWidth: 150, flex: 0.8, renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
        { field: "provenance", headerName: "Provenance", minWidth: 160, flex: 0.75, renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
        { field: "provider", headerName: "Provider", minWidth: 150, flex: 0.8, renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
        { field: "model", headerName: "Model", minWidth: 230, flex: 1.05, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> },
        { field: "state", headerName: "State", minWidth: 130, flex: 0.65, renderCell: ({ value }) => <CenteredGridCell muted>{String(value ?? "")}</CenteredGridCell> },
        { field: "summary", headerName: "Summary", minWidth: 320, flex: 1.5, renderCell: ({ value }) => <GridTextCell muted>{String(value ?? "")}</GridTextCell> }
      ];

  function clearFilters() {
    setFilter("all");
    setSeverityFilter("all");
    setQuery("");
  }

  return (
    <Paper component="section" variant="outlined" sx={{ overflow: "hidden", minWidth: 0 }}>
      <Box sx={{ p: { xs: 2, md: 2.25 }, borderBottom: "1px solid", borderColor: "divider" }}>
        <Stack direction={{ xs: "column", xl: "row" }} justifyContent="space-between" alignItems={{ xs: "stretch", xl: "flex-start" }} spacing={1.5}>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="h2">{compact ? "Recent Band events" : "Band event trace"}</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.45, maxWidth: 760 }}>
              {compact ? "Latest board events reconstructed from Band." : "Filterable event trace with claim, evidence, provider, severity, and state columns."}
            </Typography>
            {!compact && (
              <Stack direction="row" flexWrap="wrap" gap={0.75} sx={{ mt: 1.1 }}>
                <Chip label={`Room ${shortRoomId(integrity.roomId)}`} size="small" variant="outlined" />
                <Chip label={`${integrity.eventCount} Band events`} size="small" variant="outlined" />
                <Chip label={`${integrity.evidenceLinks} evidence links`} size="small" variant="outlined" />
                <Chip label={`Packet ${packet.packet_version || "v1"}`} size="small" variant="outlined" />
                <Chip label={packet.review_type || "Review"} size="small" variant="outlined" />
                <Chip label={sourceModeLabel((packet.packet_source_mode || "manual") as PacketSourceMode)} size="small" variant="outlined" />
                <Chip label={`Repairs ${integrity.repairCount}`} size="small" variant="outlined" color={integrity.repairCount ? "warning" : "success"} />
                <Chip label={`Synthesis ${integrity.synthesisEventId}`} size="small" variant="outlined" />
                {packet.import_summary.artifact && (
                  <Chip label={`PDF ${artifactFileName(packet.import_summary.artifact.filename)}`} size="small" variant="outlined" color="info" />
                )}
                {packet.import_summary.artifact?.ocr_model && (
                  <Chip label={`OCR ${packet.import_summary.artifact.ocr_model}`} size="small" variant="outlined" />
                )}
                {packet.import_summary.artifact?.sha256 && (
                  <Chip label={`SHA ${packet.import_summary.artifact.sha256.slice(0, 10)}`} size="small" variant="outlined" />
                )}
                {packet.supporting_evidence_imports.length > 0 && (
                  <Chip label={`${packet.supporting_evidence_imports.length} supporting files`} size="small" variant="outlined" color="info" />
                )}
                {packet.ticket_url && <Chip label={artifactFileName(packet.ticket_url)} size="small" variant="outlined" />}
                {packet.re_review_context.original_room_id && <Chip label={`Original ${shortRoomId(packet.re_review_context.original_room_id)}`} size="small" variant="outlined" color="info" />}
              </Stack>
            )}
          </Box>
          {!compact && (
            <Stack
              direction={{ xs: "column", sm: "row" }}
              spacing={1}
              sx={{
                width: { xs: "100%", xl: "auto" },
                flexWrap: { sm: "wrap" },
                justifyContent: { sm: "flex-start", xl: "flex-end" }
              }}
            >
              <TextField
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search timeline"
                aria-label="Search timeline"
                size="small"
                sx={{ minWidth: { xs: "100%", sm: 220 } }}
              />
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel id="timeline-type-filter">Type</InputLabel>
                <Select
                  labelId="timeline-type-filter"
                  value={filter}
                  label="Type"
                  onChange={(event) => setFilter(event.target.value as TimelineFilter)}
                >
                  {filters.map((item) => (
                    <MenuItem value={item.id} key={item.id}>
                      {item.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <FormControl size="small" sx={{ minWidth: 150 }}>
                <InputLabel id="timeline-severity-filter">Severity</InputLabel>
                <Select
                  labelId="timeline-severity-filter"
                  value={severityFilter}
                  label="Severity"
                  onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}
                >
                  <MenuItem value="all">All severity</MenuItem>
                  {Object.keys(severityLabels).map((severity) => (
                    <MenuItem value={severity} key={severity}>
                      {severityLabels[severity as Severity]}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <Button variant="outlined" color="inherit" onClick={clearFilters} disabled={!filterActive}>
                Clear
              </Button>
            </Stack>
          )}
        </Stack>
      </Box>
      {!compact && (
        <Box sx={{ p: { xs: 2, md: 2.25 }, borderBottom: "1px solid", borderColor: "divider", bgcolor: "background.default" }}>
          <ReleaseBoardRoster audit={audit} compact />
        </Box>
      )}
      <Box sx={{ height: compact ? 320 : 640, width: "100%", minWidth: 0 }}>
        <DataGrid
          rows={rows}
          columns={columns}
          disableRowSelectionOnClick
          getRowHeight={() => "auto"}
          pageSizeOptions={compact ? [4] : [12, 25, 50]}
          initialState={{ pagination: { paginationModel: { pageSize: compact ? 4 : 12, page: 0 } } }}
          sx={{
            border: 0,
            "& .MuiDataGrid-cell": { alignItems: "center", display: "flex", px: 1.5 },
            "& .MuiDataGrid-columnHeader": { px: 1.5 }
          }}
        />
      </Box>
    </Paper>
  );
}

function ProtocolView({ audit, onAdvance, busy }: { audit: AuditState; onAdvance: () => Promise<void>; busy: boolean }) {
  const criticalBlockers = audit.findings.filter((finding) => finding.severity === "critical" && finding.status !== "accepted").length;
  const readyProviders = audit.agent_execution.providers.filter((provider) => provider.status === "ready").length;
  const liveRoutes = audit.agent_execution.routes.length;
  const providerStatus = audit.agent_execution.last_error ?? "No provider errors recorded";
  const stateRows = [
    ["Phase", phaseLabels[audit.phase]],
    ["Open findings", String(openFindings(audit))],
    ["Critical blockers", String(criticalBlockers)],
    ["Verified claims", String(verifiedFindings(audit))],
    ["Vote records", audit.votes.length ? `${audit.votes.length} captured` : "Awaiting vote"],
    ["Release-board lanes", String(audit.agents.length)],
    ["Decision", decisionLabels[audit.decision]],
    ["Provider mode", titleCase(audit.agent_execution.effective_mode)]
  ];
  const robustness = [
    {
      label: "Band replay",
      value: `${audit.events.length} validated room events`,
      detail: "Findings, votes, and the decision are rebuilt from ordered BandAudit events."
    },
    {
      label: "Schema guardrail",
      value: "AuditEvent JSON required",
      detail: "Provider responses must validate before they enter the release record."
    },
    {
      label: "Provider split",
      value: `${liveRoutes} live specialist routes`,
      detail: "AI/ML API and Featherless cover different board duties to reduce single-model judgment."
    },
    {
      label: "Provider readiness",
      value: `${readyProviders}/${audit.agent_execution.providers.length} providers ready`,
      detail: providerStatus
    }
  ];

  return (
    <Stack spacing={2.5} component="section" sx={{ minWidth: 0 }}>
      <Paper variant="outlined" sx={{ overflow: "hidden" }}>
        <Box sx={{ p: { xs: 2, md: 2.5 }, borderBottom: "1px solid", borderColor: "divider" }}>
          <Typography variant="overline" color="text.secondary" fontWeight={600}>
            Protocol
          </Typography>
          <Typography variant="h2" sx={{ mt: 0.4 }}>
            Band event reconstruction
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.7, maxWidth: 820 }}>
            BandAudit treats room activity as the source of truth, then rebuilds audit state from validated structured events.
          </Typography>
        </Box>
        <Box sx={{ px: { xs: 1.5, md: 2.5 }, py: { xs: 2, md: 2.75 } }}>
          <ReleaseProgress phase={audit.phase} />
        </Box>
      </Paper>

      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1.35fr) 360px" }, gap: 2.5, alignItems: "start" }}>
        <Paper variant="outlined" sx={{ overflow: "hidden", minWidth: 0 }}>
          <Box sx={{ p: 2, borderBottom: "1px solid", borderColor: "divider" }}>
            <Typography variant="h3">Band room event stream</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.45 }}>
              Structured events used by the audit reducer.
            </Typography>
          </Box>
          <ProtocolEventGrid audit={audit} />
        </Paper>

        <Paper variant="outlined" sx={{ overflow: "hidden" }}>
          <Box sx={{ p: 2, borderBottom: "1px solid", borderColor: "divider" }}>
            <Typography variant="h3">Reconstructed state</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.45 }}>
              Current board state derived from room activity.
            </Typography>
          </Box>
          <Box sx={{ display: "grid" }}>
            {stateRows.map(([label, value], index) => (
              <Box
                key={label}
                sx={{
                  display: "grid",
                  gridTemplateColumns: "minmax(0, 1fr) auto",
                  gap: 1.5,
                  px: 2,
                  py: 1.25,
                  borderBottom: index < stateRows.length - 1 ? "1px solid" : 0,
                  borderColor: "divider"
                }}
              >
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  {label}
                </Typography>
                <Typography variant="body2" fontWeight={600} textAlign="right">
                  {value}
                </Typography>
              </Box>
            ))}
          </Box>
        </Paper>
      </Box>

      <Paper variant="outlined" sx={{ overflow: "hidden" }}>
        <Accordion defaultExpanded disableGutters elevation={0}>
          <AccordionSummary expandIcon={<ChevronDown size={16} />}>
            <Box>
              <Typography variant="h3">Release-board protocol</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
                Index, review, verify, debate, vote, and decision phases.
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}>
            <PhaseProtocol />
          </AccordionDetails>
        </Accordion>
        <Divider />
        <Accordion disableGutters elevation={0}>
          <AccordionSummary expandIcon={<ChevronDown size={16} />}>
            <Box>
              <Typography variant="h3">Provider lanes</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
                Backend routing for provider-backed agent lanes.
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}>
            <ProviderLaneSummary audit={audit} />
            <ProviderRouteGrid audit={audit} />
          </AccordionDetails>
        </Accordion>
        <Divider />
        <Accordion disableGutters elevation={0}>
          <AccordionSummary expandIcon={<ChevronDown size={16} />}>
            <Box>
              <Typography variant="h3">Operational robustness</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
                Validation and replay controls behind the event record.
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}>
            <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 1.5 }}>
              {robustness.map((item) => (
                <Paper variant="outlined" sx={{ p: 2 }} key={item.label}>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    {item.label}
                  </Typography>
                  <Typography variant="body2" fontWeight={600} sx={{ mt: 0.55 }}>
                    {item.value}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.7 }}>
                    {item.detail}
                  </Typography>
                </Paper>
              ))}
            </Box>
          </AccordionDetails>
        </Accordion>
        <Divider />
        <Accordion disableGutters elevation={0}>
          <AccordionSummary expandIcon={<ChevronDown size={16} />}>
            <Box>
              <Typography variant="h3">Agent roles</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
                Specialists publish scoped findings, verification events, and vote records.
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}>
            <Box sx={{ display: "grid" }}>
              {audit.agents.map((agent, index) => (
                <Box
                  key={agent.id}
                  sx={{
                    display: "grid",
                    gridTemplateColumns: { xs: "1fr", sm: "180px minmax(0, 1fr)" },
                    gap: 1.5,
                    py: 1.25,
                    borderBottom: index < audit.agents.length - 1 ? "1px solid" : 0,
                    borderColor: "divider"
                  }}
                >
                  <Typography variant="body2" fontWeight={600}>
                    {agent.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {agent.role}
                  </Typography>
                </Box>
              ))}
            </Box>
          </AccordionDetails>
        </Accordion>
        <Divider />
        <Accordion disableGutters elevation={0}>
          <AccordionSummary expandIcon={<ChevronDown size={16} />}>
            <Box>
              <Typography variant="h3">Developer controls</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
                Manual stepping is for protocol inspection; production flow runs the board automatically from Release packet.
              </Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails sx={{ pt: 0 }}>
            <Paper variant="outlined" sx={{ p: 2, display: "grid", gap: 1.5 }}>
              <Typography variant="body2" color="text.secondary">
                Append one event to the current Band room when inspecting reducer behavior, provider routing, or event schema validation.
              </Typography>
              <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ xs: "stretch", sm: "center" }}>
                <Button
                  variant="outlined"
                  color="inherit"
                  onClick={() => void onAdvance()}
                  disabled={busy || audit.phase === "complete"}
                  startIcon={<ArrowRight size={15} />}
                >
                  Advance one audit event
                </Button>
                <Chip label={audit.phase === "complete" ? "Decision complete" : phaseLabels[audit.phase]} variant="outlined" />
              </Stack>
            </Paper>
          </AccordionDetails>
        </Accordion>
      </Paper>
    </Stack>
  );
}

function agentForRunStage(stage: string) {
  const map: Record<string, string> = {
    packet_locked: "ChairAgent",
    intake: "ChairAgent",
    evidence_mapping: "EvidenceMapper",
    specialist_review: "ComplianceAgent",
    verification: "FactVerifier",
    debate: "ChairAgent",
    vote: "ChairAgent",
    complete: "Synthesizer",
    synthesis: "Synthesizer"
  };
  return map[stage] ?? "ChairAgent";
}

function runLaneForStage(audit: AuditState, stage: string, failedAgent?: string | null) {
  const agent = failedAgent || agentForRunStage(stage);
  const route = audit.agent_execution.routes.find((item) => item.agent === agent);
  const provider = route?.provider ? providerName(route.provider) : "Provider lane";
  const model = route?.model || "Model not recorded";
  return { agent, provider, model };
}

function nextRunStageForAudit(audit: AuditState) {
  if (audit.phase === "complete") return "complete";
  const count = audit.events.length;
  if (count <= 0) return "packet_locked";
  if (count === 1) return "evidence_mapping";
  if (count < 5) return "specialist_review";
  if (count === 5) return "verification";
  if (count < 10) return "debate";
  if (count === 10) return "vote";
  return "complete";
}

function runStageLabel(stage: string) {
  return reviewRunStages.find((item) => item.id === stage)?.label ?? titleCase(stage);
}

function ReviewRunPanel({
  audit,
  runState,
  navigate,
  onRetry,
  busy
}: {
  audit: AuditState;
  runState: ReviewRunState;
  navigate: (view: ViewMode) => void;
  onRetry: () => Promise<void>;
  busy: boolean;
}) {
  if (!runState.active && !runState.error) return null;
  const currentStage = runState.stage || nextRunStageForAudit(audit);
  const currentIndex = Math.max(0, reviewRunStages.findIndex((stage) => stage.id === currentStage));
  const completedStageIds = new Set(completedRunStagesForAudit(audit));
  const progress = audit.phase === "complete"
    ? 100
    : Math.min(96, Math.round((completedStageIds.size / reviewRunStages.length) * 100));
  const lane = runLaneForStage(audit, currentStage, runState.error ? audit.agent_execution.last_agent : null);
  const stageLabel = runStageLabel(currentStage);

  return (
    <Paper variant="outlined" sx={{ p: { xs: 1.75, md: 2 }, borderColor: runState.error ? "error.main" : "primary.light", bgcolor: runState.error ? "error.light" : "background.paper" }}>
      <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} alignItems={{ xs: "stretch", md: "center" }} justifyContent="space-between">
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h3">{runState.error ? "Review run needs attention" : "Review running"}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.45 }}>
            {runState.error || runState.message || "The board is publishing structured events into Band and reconstructing state from the room."}
          </Typography>
        </Box>
        <Stack direction="row" flexWrap="wrap" gap={0.75} justifyContent={{ xs: "flex-start", md: "flex-end" }}>
          <Chip label={`${runState.appendedEvents} events appended`} color={runState.error ? "error" : "primary"} variant="outlined" />
          {runState.error && audit.agent_execution.last_provider && (
            <Chip label={`${providerName(audit.agent_execution.last_provider)} attention`} color="error" variant="outlined" />
          )}
        </Stack>
      </Stack>
      {!runState.error && (
        <Box
          sx={{
            mt: 1.75,
            position: "relative",
            overflow: "hidden",
            height: 7,
            borderRadius: 999,
            bgcolor: "action.hover",
            "&::after": {
              content: '""',
              position: "absolute",
              top: 0,
              bottom: 0,
              left: 0,
              width: "36%",
              borderRadius: 999,
              background: "linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.82), transparent)",
              animation: `${reviewRunSweep} 1.35s ease-in-out infinite`,
              pointerEvents: "none"
            }
          }}
        >
          <LinearProgress
            aria-label="Review run progress"
            variant="determinate"
            value={progress}
            sx={{
              height: "100%",
              borderRadius: 999,
              bgcolor: "transparent",
              "& .MuiLinearProgress-bar": {
                borderRadius: 999,
                transition: "transform 360ms ease"
              }
            }}
          />
        </Box>
      )}
      <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(4, minmax(0, 1fr))" }, gap: 1, mt: 1.5 }}>
        {[
          ["Next stage", stageLabel],
          ["Expected lane", lane.agent],
          ["Provider", lane.provider],
          ["Model", lane.model]
        ].map(([label, value]) => (
          <Paper variant="outlined" key={label} sx={{ p: 1.15, bgcolor: "background.default", minWidth: 0 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              {label}
            </Typography>
            <Typography variant="body2" fontWeight={600} sx={{ mt: 0.35, overflowWrap: "anywhere" }}>
              {value}
            </Typography>
          </Paper>
        ))}
      </Box>
      {runState.error && (
        <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ mt: 1.5 }}>
          <Button variant="outlined" color="inherit" onClick={() => navigate("protocol")} startIcon={<GitBranch size={15} />}>
            Open protocol
          </Button>
          <Button variant="outlined" color="inherit" onClick={() => navigate("timeline")} startIcon={<CalendarDays size={15} />}>
            Open timeline
          </Button>
          <Button variant="contained" onClick={() => void onRetry()} disabled={busy || audit.phase === "complete"} startIcon={<ArrowRight size={15} />}>
            Retry next event
          </Button>
        </Stack>
      )}
      <Stack direction="row" flexWrap="wrap" gap={0.75} sx={{ mt: 1.5 }}>
        {reviewRunStages.map((stage, index) => {
          const completed = completedStageIds.has(stage.id);
          const active = stage.id === currentStage;
          return (
            <Chip
              key={stage.id}
              label={stage.label}
              size="small"
              color={completed ? "success" : active ? "primary" : "default"}
              variant={completed || active ? "filled" : "outlined"}
            />
          );
        })}
      </Stack>
    </Paper>
  );
}

const idleReviewRunState: ReviewRunState = {
  active: false,
  stage: "packet_locked",
  message: "",
  completedStages: [],
  appendedEvents: 0,
  error: null
};

function runStageForPhase(phase: AuditState["phase"]) {
  if (phase === "intake") return "packet_locked";
  if (phase === "synthesis") return "complete";
  return phase;
}

function completedRunStagesForPhase(phase: AuditState["phase"]) {
  if (phase === "complete") return reviewRunStages.map((stage) => stage.id);
  const stage = runStageForPhase(phase);
  const index = reviewRunStages.findIndex((item) => item.id === stage);
  if (index <= 0) return stage === "packet_locked" ? ["packet_locked"] : [];
  return reviewRunStages.slice(0, index).map((item) => item.id);
}

function completedRunStagesForAudit(audit: AuditState) {
  if (audit.phase === "complete") return reviewRunStages.map((stage) => stage.id);
  const stage = nextRunStageForAudit(audit);
  const index = reviewRunStages.findIndex((item) => item.id === stage);
  if (index <= 0) return audit.events.length > 0 ? ["packet_locked"] : [];
  return reviewRunStages.slice(0, index).map((item) => item.id);
}

function ReviewView({
  audit,
  selectedFinding,
  selectedClaimId,
  onSelectClaim,
  navigate,
  onPrepareReReview,
  onAdvance,
  runState,
  busy
}: {
  audit: AuditState;
  selectedFinding: Finding | undefined;
  selectedClaimId: string | null;
  onSelectClaim: (id: string) => void;
  navigate: (view: ViewMode) => void;
  onPrepareReReview: () => void;
  onAdvance: () => Promise<void>;
  runState: ReviewRunState;
  busy: boolean;
}) {
  return (
    <Paper
      component="section"
      variant="outlined"
      aria-label="Release review workspace"
      sx={{
        display: "grid",
        gap: { xs: 2, md: 2.5 },
        overflow: "hidden",
        p: { xs: 2, md: 3 },
        borderRadius: 2,
        bgcolor: "background.paper"
      }}
    >
      <ReviewRunPanel audit={audit} runState={runState} navigate={navigate} onRetry={onAdvance} busy={busy} />
      <StaleRoomTraceWarning audit={audit} navigate={navigate} />
      <ReleaseGate audit={audit} selectedFinding={selectedFinding} busy={busy} navigate={navigate} />
      <ReviewMetrics audit={audit} selectedFinding={selectedFinding} />
      <ReleaseBoardRoster audit={audit} />
      <ReleaseActionPlan audit={audit} selectedFinding={selectedFinding} navigate={navigate} onPrepareReReview={onPrepareReReview} />
      <Divider />
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1.08fr) minmax(360px, 0.92fr)" },
          gap: { xs: 2, md: 2.5 },
          alignItems: "start"
        }}
      >
        <TopBlockersList findings={audit.findings} selectedId={selectedClaimId} onSelect={onSelectClaim} />
        <EvidencePreview finding={selectedFinding} audit={audit} />
      </Box>
      <Divider />
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "1fr", lg: "minmax(0, 1fr) minmax(360px, 0.75fr)" },
          gap: { xs: 2, md: 2.5 },
          alignItems: "start"
        }}
      >
        <Box sx={{ opacity: 0.92 }}>
          <RecentActivity audit={audit} navigate={navigate} />
        </Box>
        <Box sx={{ opacity: 0.92 }}>
          <ReviewContextPanel audit={audit} navigate={navigate} />
        </Box>
      </Box>
    </Paper>
  );
}

function SetupPage({
  audit,
  navigate,
  onStartReview,
  onCreateRoom,
  busy,
  initialMode
}: {
  audit: AuditState;
  navigate: (view: ViewMode) => void;
  onStartReview: (packet: AuditPacket, roomMode: ReviewRoomMode) => Promise<void>;
  onCreateRoom: () => Promise<CreateRoomResponse>;
  busy: boolean;
  initialMode: SetupMode;
}) {
  const sections = ["Scope", "AI profile", "Data and tools", "Controls", "Evidence", "Rollout", "Attestation"];
  const [activeStep, setActiveStep] = useState(0);
  const [sourceMode, setSourceMode] = useState<PacketSourceMode>(() => packetSourceFromSetupMode(initialMode));
  const [reviewMode, setReviewMode] = useState<ReviewRoomMode>("fresh");
  const [draft, setDraft] = useState<AuditPacket>(() => packetForSetupMode(initialMode, audit));
  const [formError, setFormError] = useState<string | null>(null);
  const [formInfo, setFormInfo] = useState<string | null>(null);
  const [pdfImportResult, setPdfImportResult] = useState<PacketImportResponse | null>(null);
  const [pdfImportBusy, setPdfImportBusy] = useState(false);
  const [pdfImportError, setPdfImportError] = useState<string | null>(null);
  const [pdfImportStage, setPdfImportStage] = useState<PdfImportStage>("idle");
  const [evidenceImportResult, setEvidenceImportResult] = useState<EvidenceImportResponse | null>(null);
  const [evidenceImportBusy, setEvidenceImportBusy] = useState(false);
  const [evidenceImportError, setEvidenceImportError] = useState<string | null>(null);
  const [evidenceImportWarnings, setEvidenceImportWarnings] = useState<PacketImportFinding[]>([]);
  const readiness = packetReadiness(draft);
  const packetLocked = audit.source.source === "band" && audit.events.length > 0 && reviewMode === "existing";
  const primaryActionLabel =
    sourceMode === "re_review"
      ? "Create fresh Band room and start re-review"
      : "Lock packet and start review";
  const fieldSx = { "& .MuiInputBase-root": { alignItems: "flex-start" } };
  const evidenceRows = draft.evidence_manifest.map((row, index) => ({ id: index, ...row }));
  const evidenceColumns: GridColDef[] = [
    { field: "ref_id", headerName: "Ref", width: 84, editable: true },
    { field: "title", headerName: "Title", minWidth: 220, flex: 1.1, editable: true },
    { field: "evidence_type", headerName: "Type", width: 132, editable: true },
    { field: "artifact", headerName: "Artifact/source", minWidth: 190, flex: 0.9, editable: true, renderCell: ({ value }) => <GridTextCell muted>{String(value || "Not supplied")}</GridTextCell> },
    { field: "owner", headerName: "Owner", minWidth: 160, flex: 0.75, editable: true },
    { field: "linked_control", headerName: "Control", width: 132, editable: true },
    { field: "linked_risk", headerName: "Linked risk", minWidth: 190, flex: 0.9, editable: true, renderCell: ({ value }) => <GridTextCell muted>{String(value || "Not linked")}</GridTextCell> },
    { field: "locator", headerName: "Locator", minWidth: 150, flex: 0.7, editable: true, renderCell: ({ value }) => <GridTextCell muted>{String(value || "Not supplied")}</GridTextCell> },
    { field: "status", headerName: "Status", width: 132, editable: true },
    { field: "sha256", headerName: "SHA-256", minWidth: 180, flex: 0.9, editable: true, renderCell: ({ value }) => <GridTextCell muted>{String(value || "generated on lock").slice(0, 18)}</GridTextCell> }
  ];
  const pdfImportSummary = draft.import_summary ?? emptyImportSummary();
  const pdfArtifact = pdfImportResult?.artifact ?? pdfImportSummary.artifact;
  const pdfCitations = pdfImportResult?.field_citations ?? pdfImportSummary.citations;
  const pdfCriticalBlockers = pdfImportResult?.critical_blockers ?? pdfImportSummary.critical_blockers;
  const pdfWarnings = pdfImportResult?.warnings ?? pdfImportSummary.warnings;
  const citedCriticalFields = new Set(pdfCitations.filter((citation) => citation.status === "pdf_cited").map((citation) => citation.field));
  const pdfStageItems: Array<{ id: PdfImportStage; label: string }> = [
    { id: "uploading", label: "Uploading" },
    { id: "ocr", label: "OCR processing" },
    { id: "extracting", label: "Extracting packet" },
    { id: "ready", label: "Ready for review" }
  ];
  const pdfStageIndex = pdfStageItems.findIndex((item) => item.id === pdfImportStage);
  const normalizedDraft = normalizePacketForRun(draft, sourceMode);
  const preflightItems = preflightItemsFor(audit, normalizedDraft, reviewMode, sourceMode, packetLocked);
  const preflightBlockers = blockingPreflightItems(preflightItems);
  const lockDisabled = busy || packetLocked || pdfImportBusy || evidenceImportBusy || preflightBlockers.length > 0;

  useEffect(() => {
    setSourceMode(packetSourceFromSetupMode(initialMode));
    setReviewMode("fresh");
    setDraft(packetForSetupMode(initialMode, audit));
    setActiveStep(0);
    setFormError(null);
    setFormInfo(null);
    setPdfImportResult(null);
    setPdfImportError(null);
    setPdfImportBusy(false);
    setPdfImportStage("idle");
    setEvidenceImportResult(null);
    setEvidenceImportError(null);
    setEvidenceImportBusy(false);
    setEvidenceImportWarnings([]);
  }, [initialMode, audit.room_id]);

  function patchDraft(update: Partial<AuditPacket>) {
    setDraft((current) => ({ ...current, ...update }));
  }

  function updateDraft(field: keyof AuditPacket, value: AuditPacket[keyof AuditPacket]) {
    setDraft((current) => ({ ...current, [field]: value } as AuditPacket));
  }

  function updateDataProfile(field: keyof DataProfile, value: DataProfile[keyof DataProfile]) {
    setDraft((current) => ({ ...current, data_profile: { ...current.data_profile, [field]: value } as DataProfile }));
  }

  function updateToolProfile(field: keyof ToolProfile, value: ToolProfile[keyof ToolProfile]) {
    setDraft((current) => ({ ...current, tool_profile: { ...current.tool_profile, [field]: value } as ToolProfile }));
  }

  function updateControl(index: number, field: keyof ControlClaim, value: ControlClaim[keyof ControlClaim]) {
    setDraft((current) => ({
      ...current,
      control_claims: current.control_claims.map((claim, claimIndex) => (claimIndex === index ? ({ ...claim, [field]: value } as ControlClaim) : claim))
    }));
  }

  function updateAttestation(index: number, field: keyof PacketAttestation, value: PacketAttestation[keyof PacketAttestation]) {
    setDraft((current) => ({
      ...current,
      attestations: current.attestations.map((item, itemIndex) => (itemIndex === index ? ({ ...item, [field]: value } as PacketAttestation) : item))
    }));
  }

  function selectSourceMode(mode: PacketSourceMode) {
    setSourceMode(mode);
    setFormInfo(null);
    setFormError(null);
    setPdfImportError(null);
    if (mode === "re_review") {
      setPdfImportStage("idle");
      setReviewMode("fresh");
      setDraft(reReviewPacket(audit));
      return;
    }
    if (mode === "pdf_packet") {
      setReviewMode("fresh");
      setDraft(pdfImportResult ? packetWithDefaults(pdfImportResult.extracted_packet) : { ...clonePacket(customPacket), packet_source_mode: "pdf_packet", review_type: "PDF packet import" });
      return;
    }
    setPdfImportStage("idle");

    setDraft((current) => {
      return {
        ...current,
        packet_source_mode: mode,
        import_summary: emptyImportSummary()
      };
    });
  }

  function firstInvalidStep(missing: string[]) {
    if (missing.some((field) => ["System name", "Owner", "Environment", "Review type", "Change summary"].includes(field))) return 0;
    if (missing.some((field) => ["Autonomy level"].includes(field))) return 1;
    if (missing.some((field) => ["Data category", "Tool access"].includes(field))) return 2;
    if (missing.some((field) => ["Control owner"].includes(field))) return 3;
    if (missing.some((field) => ["Evidence rows"].includes(field))) return 4;
    if (missing.some((field) => ["Rollout plan", "Rollback plan", "Incident owner"].includes(field))) return 5;
    if (missing.some((field) => ["Attestation"].includes(field))) return 6;
    return 0;
  }

  async function startReview() {
    const packet = normalizedDraft;
    const missing = validateAuditPacket(packet);
    if (missing.length) {
      setFormError(`Complete required fields: ${missing.join(", ")}.`);
      setActiveStep(firstInvalidStep(missing));
      return;
    }
    if (packetLocked) {
      setFormError("The selected Band room already has events. Create a fresh room before locking a changed packet.");
      return;
    }
    if (preflightBlockers.length) {
      setFormError(`Resolve preflight blockers: ${preflightBlockers.map((item) => item.label).join(", ")}.`);
      return;
    }

    try {
      setFormError(null);
      setFormInfo(null);
      await onStartReview(packet, reviewMode);
    } catch (error) {
      setFormError(errorMessage(error, "Could not start review."));
    }
  }

  async function createFreshRoom() {
    try {
      setFormError(null);
      setFormInfo(null);
      const response = await onCreateRoom();
      setReviewMode("fresh");
      setFormInfo(`${response.message} Room ${shortRoomId(response.room_id)} is ready for a clean review trace.`);
    } catch (error) {
      setFormError(errorMessage(error, "Could not create a fresh Band room."));
    }
  }

  async function handlePdfImport(file: File | undefined) {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      setPdfImportError("Upload a .pdf release packet.");
      return;
    }

    try {
      setSourceMode("pdf_packet");
      setReviewMode("fresh");
      setPdfImportBusy(true);
      setPdfImportStage("uploading");
      setPdfImportError(null);
      setFormError(null);
      setFormInfo(null);
      window.setTimeout(() => setPdfImportStage((stage) => (stage === "uploading" ? "ocr" : stage)), 250);
      window.setTimeout(() => setPdfImportStage((stage) => (stage === "ocr" ? "extracting" : stage)), 1800);
      const response = await importAuditPacketPdf(file);
      const importedPacket = packetWithDefaults(response.extracted_packet);
      setPdfImportResult(response);
      setDraft(importedPacket);
      setPdfImportStage("ready");
      const missing = validateAuditPacket(importedPacket);
      setActiveStep(firstInvalidStep(missing));
      setFormInfo(
        response.critical_blockers.length
          ? `PDF imported with ${response.critical_blockers.length} critical fields still needing review.`
          : "PDF imported. Review the cited fields before locking the packet."
      );
    } catch (error) {
      setPdfImportResult(null);
      setPdfImportStage("idle");
      setPdfImportError(errorMessage(error, "Could not import the PDF packet."));
    } finally {
      setPdfImportBusy(false);
    }
  }

  function appendPacketText(current: string, addition: string) {
    const next = addition.trim();
    if (!next) return current;
    return current.trim() ? `${current.trim()}\n${next}` : next;
  }

  async function handleSupportingEvidenceImport(fileList: FileList | null) {
    const files = Array.from(fileList ?? []);
    if (!files.length) return;

    const unsupported = files.find((file) => {
      const extension = file.name.split(".").pop()?.toLowerCase() ?? "";
      return !supportingEvidenceExtensions.has(extension);
    });
    if (unsupported) {
      setEvidenceImportError(`${unsupported.name} is not supported. Upload PDF, TXT, MD, CSV, JSON, or NDJSON evidence.`);
      return;
    }

    try {
      setEvidenceImportBusy(true);
      setEvidenceImportError(null);
      setEvidenceImportWarnings([]);
      setFormError(null);
      setFormInfo(null);
      const response = await importSupportingEvidence(files, normalizePacketForRun(draft, sourceMode));
      setEvidenceImportResult(response);
      setEvidenceImportWarnings(response.warnings);
      setDraft((current) => ({
        ...current,
        evidence_manifest: [...current.evidence_manifest, ...response.evidence_manifest],
        evidence_notes: appendPacketText(current.evidence_notes, response.evidence_notes_append),
        evaluation_summary: appendPacketText(current.evaluation_summary, response.evaluation_summary_append),
        known_limitations: appendPacketText(current.known_limitations, response.known_limitations_append),
        supporting_evidence_imports: [...(current.supporting_evidence_imports ?? []), ...response.import_summaries]
      }));
      setActiveStep(4);
      setFormInfo(`Imported ${response.evidence_manifest.length} supporting evidence rows from ${files.length} file${files.length === 1 ? "" : "s"}.`);
    } catch (error) {
      setEvidenceImportResult(null);
      setEvidenceImportError(errorMessage(error, "Could not import supporting evidence."));
    } finally {
      setEvidenceImportBusy(false);
    }
  }

  function saveDraft() {
    try {
      window.localStorage.setItem("bandaudit.packetDraft.v2", JSON.stringify(normalizePacketForRun(draft, sourceMode)));
      setFormInfo("Draft saved locally in this browser.");
      setFormError(null);
    } catch {
      setFormError("Could not save draft in local storage.");
    }
  }

  function addEvidenceRow() {
    setDraft((current) => ({
      ...current,
      evidence_manifest: [
        ...current.evidence_manifest,
        {
          ref_id: `E-${String(current.evidence_manifest.length + 1).padStart(3, "0")}`,
          title: "",
          evidence_type: "document",
          artifact: "",
          source: "",
          owner: current.technical_owner || current.owning_team,
          linked_control: "",
          linked_risk: "",
          freshness: "",
          status: "submitted",
          sha256: "",
          locator: ""
        }
      ]
    }));
  }

  function seedEvidenceRows() {
    patchDraft({ evidence_manifest: clonePacket(samplePacket).evidence_manifest });
  }

  function addControl() {
    setDraft((current) => ({
      ...current,
      control_claims: [
        ...current.control_claims,
        {
          control_id: `CTRL-${String(current.control_claims.length + 1).padStart(3, "0")}`,
          title: "",
          owner: current.technical_owner || current.business_owner,
          status: "claimed",
          required: true,
          evidence_refs: [],
          notes: ""
        }
      ]
    }));
  }

  function addAttestation() {
    setDraft((current) => ({
      ...current,
      attestations: [
        ...current.attestations,
        {
          role: "approver",
          name: "",
          status: "draft",
          attested_at: "",
          notes: ""
        }
      ]
    }));
  }

  const sourceModes: Array<{ id: PacketSourceMode; label: string; detail: string }> = [
    { id: "manual", label: "Manual packet", detail: "Structured packet entered by the release owner." },
    { id: "pdf_packet", label: "Import release packet PDF", detail: "Import the PDF, then extract cited packet fields." },
    { id: "re_review", label: "Re-review", detail: "Create a fresh room linked to the prior decision." }
  ];

  return (
    <Box component="main" sx={{ minHeight: "100vh", bgcolor: "background.default", p: { xs: 1.5, md: 3 } }}>
      <Container maxWidth="xl" disableGutters>
        <Paper variant="outlined" sx={{ overflow: "hidden", bgcolor: "background.paper" }}>
          <Stack
            component="header"
            direction={{ xs: "column", md: "row" }}
            spacing={2}
            alignItems={{ xs: "stretch", md: "flex-start" }}
            justifyContent="space-between"
            sx={{ p: { xs: 2, md: 3 }, borderBottom: "1px solid", borderColor: "divider" }}
          >
            <Box sx={{ minWidth: 0 }}>
              <Button
                variant="text"
                color="inherit"
                onClick={() => navigate("landing")}
                startIcon={<ShieldCheck size={17} />}
                sx={{ px: 0, justifyContent: "flex-start" }}
              >
                BandAudit
              </Button>
              <Typography variant="h1" sx={{ mt: 1 }}>
                Release packet
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 0.75, maxWidth: 860 }}>
                Create or import a structured enterprise release packet, lock it into a fresh Band room, and run the release board automatically.
              </Typography>
              <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 1.5 }}>
                <Chip label={sourceLabel(audit)} variant="outlined" />
                <Chip label={providerLabel(audit)} variant="outlined" />
                <Chip label={`Current room ${shortRoomId(audit.room_id)}`} variant="outlined" />
                <Chip label={sourceModeLabel(sourceMode)} variant="outlined" color={chipColorForTone(readiness.tone)} />
              </Stack>
            </Box>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ width: { xs: "100%", md: "auto" } }}>
              <Button variant="outlined" color="inherit" onClick={saveDraft} disabled={busy}>
                Save draft
              </Button>
              <Button variant="outlined" color="inherit" onClick={() => navigate("protocol")} startIcon={<GitBranch size={15} />}>
                View protocol
              </Button>
              <Button variant="outlined" color="inherit" onClick={createFreshRoom} disabled={busy} startIcon={<RefreshCcw size={15} />}>
                Create fresh room
              </Button>
            </Stack>
          </Stack>

          <Box sx={{ p: { xs: 2, md: 2.5 }, borderBottom: "1px solid", borderColor: "divider", bgcolor: "background.default" }}>
            <Stepper activeStep={activeStep} alternativeLabel sx={{ overflowX: "auto", pb: 0.5, minWidth: { xs: 860, lg: 0 } }}>
              {sections.map((step) => (
                <Step key={step}>
                  <StepLabel>{step}</StepLabel>
                </Step>
              ))}
            </Stepper>
          </Box>

          <Box
            component="form"
            onSubmit={(event) => {
              event.preventDefault();
              void startReview();
            }}
            sx={{
              display: "grid",
              gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1fr) 360px" },
              gap: 0
            }}
          >
            <Box sx={{ p: { xs: 2, md: 3 }, minWidth: 0 }}>
              <Stack spacing={2.25}>
                {formError && (
                  <Alert severity="error" variant="outlined">
                    {formError}
                  </Alert>
                )}
                {formInfo && (
                  <Alert severity="success" variant="outlined">
                    {formInfo}
                  </Alert>
                )}
                {packetLocked && (
                  <Alert
                    severity="warning"
                    variant="outlined"
                    action={
                      <Button color="inherit" onClick={createFreshRoom} disabled={busy}>
                        Fresh room
                      </Button>
                    }
                  >
                    The selected Band room already has audit events. Production packet changes need a clean room trace.
                  </Alert>
                )}
                {isStaleRoomTrace(audit) && (
                  <Alert
                    severity="warning"
                    variant="outlined"
                    action={
                      <Button color="inherit" onClick={createFreshRoom} disabled={busy}>
                        Fresh room
                      </Button>
                    }
                  >
                    Old or partial room trace. Create a fresh Band room so the packet lock, board roster, lane events, and report are tied to one clean room.
                  </Alert>
                )}

                {activeStep === 0 && (
                  <Stack spacing={2}>
                    <SectionTitle title="Scope" description="Identify the change, accountable owners, release environment, and affected population." />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="Review type" value={draft.review_type} onChange={(event) => updateDraft("review_type", event.target.value)} disabled={packetLocked} required fullWidth />
                      <TextField label="System name" value={draft.target_name} onChange={(event) => updateDraft("target_name", event.target.value)} disabled={packetLocked} required fullWidth />
                      <TextField label="Business owner" value={draft.business_owner} onChange={(event) => updateDraft("business_owner", event.target.value)} disabled={packetLocked} required fullWidth />
                      <TextField label="Technical owner" value={draft.technical_owner} onChange={(event) => updateDraft("technical_owner", event.target.value)} disabled={packetLocked} required fullWidth />
                      <TextField label="Owning team" value={draft.owning_team} onChange={(event) => updateDraft("owning_team", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Environment" value={draft.deployment_environment} onChange={(event) => updateDraft("deployment_environment", event.target.value)} disabled={packetLocked} required fullWidth />
                      <TextField label="Affected users" value={draft.affected_users} onChange={(event) => updateDraft("affected_users", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Criticality" value={draft.criticality} onChange={(event) => updateDraft("criticality", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Planned release date" type="date" value={draft.planned_release_date} onChange={(event) => updateDraft("planned_release_date", event.target.value)} disabled={packetLocked} slotProps={{ inputLabel: { shrink: true } }} fullWidth />
                    </Box>
                    <TextField label="Change summary" value={draft.change_summary} onChange={(event) => updateDraft("change_summary", event.target.value)} disabled={packetLocked} multiline minRows={4} sx={fieldSx} fullWidth />
                  </Stack>
                )}

                {activeStep === 1 && (
                  <Stack spacing={2}>
                    <SectionTitle title="AI profile" description="Describe the system type, autonomy, oversight, workflow, and model/provider operating context." />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="System type" value={draft.system_type} onChange={(event) => updateDraft("system_type", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Autonomy level" value={draft.autonomy_level} onChange={(event) => updateDraft("autonomy_level", event.target.value)} disabled={packetLocked} required fullWidth />
                    </Box>
                    <TextField label="Human oversight mode" value={draft.human_oversight} onChange={(event) => updateDraft("human_oversight", event.target.value)} disabled={packetLocked} required multiline minRows={3} sx={fieldSx} fullWidth />
                    <TextField label="Model/provider summary and system purpose" value={draft.target_summary} onChange={(event) => updateDraft("target_summary", event.target.value)} disabled={packetLocked} required multiline minRows={4} sx={fieldSx} fullWidth />
                    <TextField label="Workflow" value={draft.workflow} onChange={(event) => updateDraft("workflow", event.target.value)} disabled={packetLocked} required multiline minRows={4} sx={fieldSx} fullWidth />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="Evaluation summary" value={draft.evaluation_summary} onChange={(event) => updateDraft("evaluation_summary", event.target.value)} disabled={packetLocked} multiline minRows={3} sx={fieldSx} fullWidth />
                      <TextField label="Known limitations" value={draft.known_limitations} onChange={(event) => updateDraft("known_limitations", event.target.value)} disabled={packetLocked} multiline minRows={3} sx={fieldSx} fullWidth />
                    </Box>
                  </Stack>
                )}

                {activeStep === 2 && (
                  <Stack spacing={2}>
                    <SectionTitle title="Data and tools" description="Declare data categories, sensitive data, integrations, permissions, and side effects." />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="Data categories" value={stringList(draft.data_profile.categories)} onChange={(event) => updateDataProfile("categories", parseStringList(event.target.value))} disabled={packetLocked} required helperText="Comma-separated" fullWidth />
                      <TextField label="Sensitive data flags" value={stringList(draft.data_profile.sensitive_data)} onChange={(event) => updateDataProfile("sensitive_data", parseStringList(event.target.value))} disabled={packetLocked} helperText="Comma-separated" fullWidth />
                      <TextField label="Retention" value={draft.data_profile.retention} onChange={(event) => updateDataProfile("retention", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Residency" value={draft.data_profile.residency} onChange={(event) => updateDataProfile("residency", event.target.value)} disabled={packetLocked} fullWidth />
                    </Box>
                    <TextField label="Training, memory, RAG, or fine-tune use" value={draft.data_profile.training_use} onChange={(event) => updateDataProfile("training_use", event.target.value)} disabled={packetLocked} multiline minRows={3} sx={fieldSx} fullWidth />
                    <TextField label="Tool access summary" value={draft.tool_access} onChange={(event) => updateDraft("tool_access", event.target.value)} disabled={packetLocked} required multiline minRows={3} sx={fieldSx} fullWidth />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="Integrations" value={stringList(draft.tool_profile.integrations)} onChange={(event) => updateToolProfile("integrations", parseStringList(event.target.value))} disabled={packetLocked} helperText="Comma-separated" fullWidth />
                      <TextField label="Read permissions" value={stringList(draft.tool_profile.read_permissions)} onChange={(event) => updateToolProfile("read_permissions", parseStringList(event.target.value))} disabled={packetLocked} helperText="Comma-separated" fullWidth />
                      <TextField label="Write permissions" value={stringList(draft.tool_profile.write_permissions)} onChange={(event) => updateToolProfile("write_permissions", parseStringList(event.target.value))} disabled={packetLocked} helperText="Comma-separated" fullWidth />
                      <TextField label="External side effects" value={stringList(draft.tool_profile.external_side_effects)} onChange={(event) => updateToolProfile("external_side_effects", parseStringList(event.target.value))} disabled={packetLocked} helperText="Comma-separated" fullWidth />
                    </Box>
                    <Box>
                      <Typography variant="caption" color="text.secondary" fontWeight={600}>
                        Approval required for write actions
                      </Typography>
                      <ToggleButtonGroup
                        exclusive
                        value={draft.tool_profile.approval_required_for_writes ? "yes" : "no"}
                        onChange={(_, value: "yes" | "no" | null) => {
                          if (value) updateToolProfile("approval_required_for_writes", value === "yes");
                        }}
                        disabled={packetLocked}
                        sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))" }, gap: 1, mt: 1 }}
                      >
                        <ToggleButton value="yes">Human approval required</ToggleButton>
                        <ToggleButton value="no">No write approval</ToggleButton>
                      </ToggleButtonGroup>
                    </Box>
                  </Stack>
                )}

                {activeStep === 3 && (
                  <Stack spacing={2}>
                    <SectionTitle title="Controls" description="Map policy context, required controls, claimed controls, exceptions, and approval authority." action={<Button variant="outlined" color="inherit" onClick={addControl} disabled={packetLocked}>Add control</Button>} />
                    <TextField label="Policy context" value={draft.policy_context} onChange={(event) => updateDraft("policy_context", event.target.value)} disabled={packetLocked} required multiline minRows={4} sx={fieldSx} fullWidth />
                    {draft.control_claims.length === 0 ? (
                      <Alert severity="warning" variant="outlined">Add at least one control owner or seed the enterprise sample packet.</Alert>
                    ) : (
                      <Stack spacing={1.5}>
                        {draft.control_claims.map((claim, index) => (
                          <Paper variant="outlined" key={`${claim.control_id}-${index}`} sx={{ p: 1.5 }}>
                            <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "120px minmax(0, 1.3fr) minmax(0, 0.8fr) 150px" }, gap: 1.5 }}>
                              <TextField label="ID" value={claim.control_id} onChange={(event) => updateControl(index, "control_id", event.target.value)} disabled={packetLocked} size="small" />
                              <TextField label="Control" value={claim.title} onChange={(event) => updateControl(index, "title", event.target.value)} disabled={packetLocked} size="small" />
                              <TextField label="Owner" value={claim.owner} onChange={(event) => updateControl(index, "owner", event.target.value)} disabled={packetLocked} size="small" />
                              <TextField label="Status" value={claim.status} onChange={(event) => updateControl(index, "status", event.target.value)} disabled={packetLocked} size="small" />
                            </Box>
                            <TextField label="Evidence refs and notes" value={`${claim.evidence_refs.join(", ")}${claim.notes ? ` - ${claim.notes}` : ""}`} onChange={(event) => updateControl(index, "notes", event.target.value)} disabled={packetLocked} size="small" sx={{ mt: 1.25 }} fullWidth />
                          </Paper>
                        ))}
                      </Stack>
                    )}
                  </Stack>
                )}

                {activeStep === 4 && (
                  <Stack spacing={2}>
                    <SectionTitle
                      title="Evidence"
                      description="Attach the evidence manifest used by the board. Desktop rows are editable; mobile shows compact review cards."
                      action={
                        <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                          <Button variant="outlined" color="inherit" onClick={seedEvidenceRows} disabled={packetLocked}>Seed rows</Button>
                          <Button variant="outlined" color="inherit" onClick={addEvidenceRow} disabled={packetLocked}>Add row</Button>
                        </Stack>
                      }
                    />
                    <TextField label="Evidence notes" value={draft.evidence_notes} onChange={(event) => updateDraft("evidence_notes", event.target.value)} disabled={packetLocked} required multiline minRows={3} sx={fieldSx} fullWidth />
                    <Paper variant="outlined" sx={{ p: 1.75, bgcolor: "background.default" }}>
                      <Stack spacing={1.25}>
                        <Stack direction={{ xs: "column", sm: "row" }} alignItems={{ xs: "stretch", sm: "center" }} justifyContent="space-between" spacing={1.25}>
                          <Box sx={{ minWidth: 0 }}>
                            <Typography variant="body2" fontWeight={600}>
                              Supporting evidence
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Upload test reports, issue logs, red-team notes, eval exports, monitoring notes, or rollback evidence.
                            </Typography>
                          </Box>
                          <Button
                            component="label"
                            variant="outlined"
                            color="inherit"
                            disabled={busy || packetLocked || evidenceImportBusy}
                            startIcon={<FileSearch size={15} />}
                          >
                            {evidenceImportBusy ? "Importing evidence" : "Import evidence"}
                            <Box
                              component="input"
                              type="file"
                              multiple
                              accept={supportingEvidenceAccept}
                              sx={{ display: "none" }}
                              onChange={(event) => {
                                const files = event.target.files;
                                event.currentTarget.value = "";
                                void handleSupportingEvidenceImport(files);
                              }}
                            />
                          </Button>
                        </Stack>
                        {evidenceImportBusy && <LinearProgress />}
                        {evidenceImportError && (
                          <Alert severity="error" variant="outlined">
                            {evidenceImportError}
                          </Alert>
                        )}
                        {evidenceImportResult && (
                          <Stack direction="row" flexWrap="wrap" gap={0.75}>
                            <Chip label={`${evidenceImportResult.evidence_manifest.length} rows imported`} size="small" variant="outlined" color="success" />
                            <Chip label={`${evidenceImportResult.import_summaries.length} files processed`} size="small" variant="outlined" />
                            {evidenceImportWarnings.length > 0 && <Chip label={`${evidenceImportWarnings.length} warnings`} size="small" variant="outlined" color="warning" />}
                          </Stack>
                        )}
                        {draft.supporting_evidence_imports.length > 0 && (
                          <Box sx={{ display: "grid", gap: 0.8 }}>
                            <Typography variant="caption" color="text.secondary" fontWeight={600}>
                              Imported supporting files
                            </Typography>
                            {draft.supporting_evidence_imports.slice(-4).map((summary, index) => (
                              <Paper variant="outlined" key={`${summary.artifact?.sha256 ?? index}-${summary.artifact?.filename ?? "evidence"}`} sx={{ p: 1 }}>
                                <Stack direction="row" justifyContent="space-between" spacing={1} alignItems="flex-start">
                                  <Box sx={{ minWidth: 0 }}>
                                    <Typography variant="body2" fontWeight={600} noWrap>
                                      {summary.artifact?.filename ?? "Supporting evidence"}
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {summary.artifact?.extraction_method || "extracted"} - {summary.citations.length} citations
                                    </Typography>
                                  </Box>
                                  {summary.warnings.length > 0 && <Chip label={`${summary.warnings.length} warnings`} size="small" variant="outlined" color="warning" />}
                                </Stack>
                              </Paper>
                            ))}
                          </Box>
                        )}
                        {evidenceImportWarnings.length > 0 && (
                          <Alert severity="warning" variant="outlined">
                            {evidenceImportWarnings.slice(0, 2).map((warning) => warning.message).join(" ")}
                          </Alert>
                        )}
                      </Stack>
                    </Paper>
                    <Box sx={{ display: { xs: "none", md: "block" }, height: 430, width: "100%" }}>
                      <DataGrid
                        rows={evidenceRows}
                        columns={evidenceColumns}
                        disableRowSelectionOnClick
                        processRowUpdate={(newRow) => {
                          const row = newRow as EvidenceManifestItem & { id: number };
                          setDraft((current) => ({
                            ...current,
                            evidence_manifest: current.evidence_manifest.map((item, index) => (index === row.id ? {
                              ...item,
                              ref_id: row.ref_id,
                              title: row.title,
                              evidence_type: row.evidence_type,
                              artifact: row.artifact,
                              source: row.source,
                              owner: row.owner,
                              linked_control: row.linked_control,
                              linked_risk: row.linked_risk,
                              locator: row.locator,
                              status: row.status,
                              sha256: row.sha256
                            } : item))
                          }));
                          return newRow;
                        }}
                        onProcessRowUpdateError={(error) => setFormError(errorMessage(error, "Could not update evidence row."))}
                        sx={{
                          borderColor: "divider",
                          "& .MuiDataGrid-cell": { alignItems: "center", px: 1.25 },
                          "& .MuiDataGrid-columnHeader": { px: 1.25 }
                        }}
                      />
                    </Box>
                    <Box sx={{ display: { xs: "grid", md: "none" }, gap: 1.25 }}>
                      {draft.evidence_manifest.map((row) => (
                        <Paper variant="outlined" key={row.ref_id || row.title} sx={{ p: 1.5 }}>
                          <Stack direction="row" justifyContent="space-between" spacing={1}>
                            <Typography variant="body2" fontWeight={600}>{row.ref_id || "Evidence"}</Typography>
                            <Chip label={row.status || "draft"} variant="outlined" size="small" />
                          </Stack>
                          <Typography variant="body2" sx={{ mt: 0.6 }}>{row.title || "Untitled evidence"}</Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.4 }}>
                            {row.owner || "Owner not supplied"} - {row.linked_control || "No control linked"}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.4, overflowWrap: "anywhere" }}>
                            {artifactFileName(row.artifact || row.source || "No artifact")} - {row.locator || "No locator"} - {row.sha256 ? `SHA ${row.sha256.slice(0, 10)}` : "No hash"}
                          </Typography>
                        </Paper>
                      ))}
                    </Box>
                  </Stack>
                )}

                {activeStep === 5 && (
                  <Stack spacing={2}>
                    <SectionTitle title="Rollout" description="Define rollout intent, monitoring, rollback, incident owner, and stop conditions." />
                    <TextField label="Release goal" value={draft.release_goal} onChange={(event) => updateDraft("release_goal", event.target.value)} disabled={packetLocked} fullWidth />
                    <TextField label="Rollout plan" value={draft.rollout_plan} onChange={(event) => updateDraft("rollout_plan", event.target.value)} disabled={packetLocked} required multiline minRows={4} sx={fieldSx} fullWidth />
                    <TextField label="Monitoring plan" value={draft.monitoring_plan} onChange={(event) => updateDraft("monitoring_plan", event.target.value)} disabled={packetLocked} multiline minRows={4} sx={fieldSx} fullWidth />
                    <TextField label="Rollback/backout plan" value={draft.rollback_plan} onChange={(event) => updateDraft("rollback_plan", event.target.value)} disabled={packetLocked} required multiline minRows={4} sx={fieldSx} fullWidth />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="Incident response owner" value={draft.incident_response_owner} onChange={(event) => updateDraft("incident_response_owner", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Stop conditions" value={stringList(draft.stop_conditions)} onChange={(event) => updateDraft("stop_conditions", parseStringList(event.target.value))} disabled={packetLocked} helperText="Comma-separated" fullWidth />
                    </Box>
                  </Stack>
                )}

                {activeStep === 6 && (
                  <Stack spacing={2}>
                    <SectionTitle title="Attestation" description="Capture request context, ticket/source metadata, accountable signatures, and packet version." action={<Button variant="outlined" color="inherit" onClick={addAttestation} disabled={packetLocked}>Add attestation</Button>} />
                    <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(2, minmax(0, 1fr))" }, gap: 2 }}>
                      <TextField label="Packet version" value={draft.packet_version} onChange={(event) => updateDraft("packet_version", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Review reason" value={draft.change_summary} onChange={(event) => updateDraft("change_summary", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Ticket URL or ID" value={draft.ticket_url} onChange={(event) => updateDraft("ticket_url", event.target.value)} disabled={packetLocked} fullWidth />
                      <TextField label="Repository URL" value={draft.repository_url} onChange={(event) => updateDraft("repository_url", event.target.value)} disabled={packetLocked} fullWidth />
                    </Box>
                    {sourceMode === "re_review" && (
                      <Alert severity="info" variant="outlined">
                        Re-review will create a fresh Band room linked to {shortRoomId(draft.re_review_context.original_room_id || audit.room_id)} and prior decision {draft.re_review_context.original_decision || decisionLabels[audit.decision]}.
                      </Alert>
                    )}
                    <Stack spacing={1.5}>
                      {draft.attestations.map((item, index) => (
                        <Paper variant="outlined" key={`${item.role}-${index}`} sx={{ p: 1.5 }}>
                          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "140px minmax(0, 1fr) 150px 150px" }, gap: 1.5 }}>
                            <TextField label="Role" value={item.role} onChange={(event) => updateAttestation(index, "role", event.target.value)} disabled={packetLocked} size="small" />
                            <TextField label="Name" value={item.name} onChange={(event) => updateAttestation(index, "name", event.target.value)} disabled={packetLocked} size="small" />
                            <TextField label="Status" value={item.status} onChange={(event) => updateAttestation(index, "status", event.target.value)} disabled={packetLocked} size="small" />
                            <TextField label="Date" value={item.attested_at} onChange={(event) => updateAttestation(index, "attested_at", event.target.value)} disabled={packetLocked} size="small" />
                          </Box>
                          <TextField label="Notes" value={item.notes} onChange={(event) => updateAttestation(index, "notes", event.target.value)} disabled={packetLocked} size="small" sx={{ mt: 1.25 }} fullWidth />
                        </Paper>
                      ))}
                    </Stack>
                  </Stack>
                )}

                <Divider />
                <Stack direction={{ xs: "column", sm: "row" }} justifyContent="space-between" spacing={1}>
                  <Button variant="outlined" color="inherit" onClick={() => setActiveStep((step) => Math.max(0, step - 1))} disabled={activeStep === 0 || busy}>
                    Back
                  </Button>
                  <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                    {activeStep < sections.length - 1 ? (
                      <Button variant="contained" onClick={() => setActiveStep((step) => Math.min(sections.length - 1, step + 1))}>
                        Next
                      </Button>
                    ) : (
                      <Button type="submit" variant="contained" disabled={lockDisabled} endIcon={<ArrowRight size={15} />}>
                        {busy ? "Running review" : primaryActionLabel}
                      </Button>
                    )}
                  </Stack>
                </Stack>
              </Stack>
            </Box>

            <Box sx={{ borderTop: { xs: "1px solid", xl: 0 }, borderLeft: { xl: "1px solid" }, borderColor: "divider", bgcolor: "background.default", p: { xs: 2, md: 3 } }}>
              <Stack spacing={2}>
                <Box>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Packet source
                  </Typography>
                  <ToggleButtonGroup
                    exclusive
                    value={sourceMode}
                    onChange={(_, value: PacketSourceMode | null) => {
                      if (value) selectSourceMode(value);
                    }}
                    disabled={busy}
                    sx={{ display: "grid", gridTemplateColumns: "1fr", gap: 1, mt: 1 }}
                  >
                    {sourceModes.map((mode) => (
                      <ToggleButton value={mode.id} key={mode.id} sx={{ justifyContent: "flex-start", textAlign: "left", p: 1.25 }}>
                        <Box>
                          <Typography variant="body2" fontWeight={600}>{mode.label}</Typography>
                          <Typography variant="caption" color="text.secondary">{mode.detail}</Typography>
                        </Box>
                      </ToggleButton>
                    ))}
                  </ToggleButtonGroup>
                  {sourceMode === "pdf_packet" && (
                    <Paper variant="outlined" sx={{ p: 1.5, mt: 1.5, bgcolor: "background.paper" }}>
                      <Stack spacing={1.25}>
                        <Button
                          component="label"
                          variant="outlined"
                          color="inherit"
                          disabled={busy || packetLocked || pdfImportBusy}
                          startIcon={<FileSearch size={15} />}
                          fullWidth
                        >
                          {pdfImportBusy ? "Importing PDF" : "Import PDF"}
                          <Box
                            component="input"
                            type="file"
                            accept="application/pdf,.pdf"
                            sx={{ display: "none" }}
                            onChange={(event) => {
                              const file = event.target.files?.[0];
                              event.currentTarget.value = "";
                              void handlePdfImport(file);
                            }}
                          />
                        </Button>
                        {pdfImportBusy && <LinearProgress />}
                        {(pdfImportBusy || pdfImportStage === "ready") && (
                          <Box sx={{ display: "grid", gap: 0.75 }}>
                            {pdfStageItems.map((stage, index) => {
                              const complete = pdfImportStage === "ready" || (pdfStageIndex >= 0 && index < pdfStageIndex);
                              const active = stage.id === pdfImportStage;
                              return (
                                <Stack key={stage.id} direction="row" spacing={1} alignItems="center">
                                  {complete ? <CheckCircle2 size={14} color="#14783e" /> : <CircleAlert size={14} color={active ? "#b54708" : "#667085"} />}
                                  <Typography variant="caption" color={active ? "text.primary" : "text.secondary"} fontWeight={active ? 600 : 500}>
                                    {stage.label}
                                  </Typography>
                                </Stack>
                              );
                            })}
                          </Box>
                        )}
                        {pdfImportError && (
                          <Alert severity="error" variant="outlined">
                            {pdfImportError}
                          </Alert>
                        )}
                        {pdfArtifact && (
                          <Box sx={{ display: "grid", gap: 0.35 }}>
                            <Typography variant="body2" fontWeight={600}>{pdfArtifact.filename}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {(pdfArtifact.pages_processed || pdfArtifact.page_count).toLocaleString()} pages, {(pdfArtifact.ocr_text_char_count || pdfArtifact.text_char_count).toLocaleString()} OCR chars
                            </Typography>
                            {pdfArtifact.ocr_model && (
                              <Typography variant="caption" color="text.secondary">
                                {pdfArtifact.ocr_provider || "OCR"} - {pdfArtifact.ocr_model}
                              </Typography>
                            )}
                            <Typography variant="caption" color="text.secondary">
                              {pdfArtifact.doc_size_bytes ? `${Math.round(pdfArtifact.doc_size_bytes / 1024).toLocaleString()} KB` : "PDF"} processed by OCR
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ wordBreak: "break-all" }}>
                              SHA-256 {pdfArtifact.sha256.slice(0, 24)}...
                            </Typography>
                          </Box>
                        )}
                        <Alert severity="info" variant="outlined">
                          PDF import is intake only. The canonical record starts when the packet is locked into Band.
                        </Alert>
                        {pdfCriticalBlockers.length > 0 && (
                          <Alert severity="error" variant="outlined">
                            {pdfCriticalBlockers.length} critical imported fields still need correction before review.
                          </Alert>
                        )}
                        {pdfWarnings.length > 0 && (
                          <Alert severity="warning" variant="outlined">
                            {pdfWarnings.length} import warnings should be reviewed before approval.
                          </Alert>
                        )}
                        {pdfCitations.length > 0 && (
                          <Box>
                            <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                              <Typography variant="caption" color="text.secondary" fontWeight={600}>
                                Field citations
                              </Typography>
                              <Chip label={`${citedCriticalFields.size} cited`} size="small" variant="outlined" color="success" />
                            </Stack>
                            <Stack spacing={0.8} sx={{ mt: 1 }}>
                              {pdfCitations.slice(0, 6).map((citation) => (
                                <Paper variant="outlined" key={`${citation.field}-${citation.page}-${citation.snippet.slice(0, 12)}`} sx={{ p: 1 }}>
                                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
                                    <Box sx={{ minWidth: 0 }}>
                                      <Typography variant="body2" fontWeight={600}>{citation.field.replace(/_/g, " ")}</Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {citation.page ? `Page ${citation.page}` : "No page"} - {Math.round(citation.confidence * 100)}%
                                      </Typography>
                                    </Box>
                                    <Chip label={citationStatusLabel(citation.status)} size="small" color={citationStatusColor(citation.status)} variant="outlined" />
                                  </Stack>
                                  {citation.snippet && (
                                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.6 }}>
                                      {citation.snippet.slice(0, 140)}
                                      {citation.snippet.length > 140 ? "..." : ""}
                                    </Typography>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          </Box>
                        )}
                      </Stack>
                    </Paper>
                  )}
                </Box>

                <Divider />
                <Box>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Packet readiness
                  </Typography>
                  <Stack direction="row" alignItems="center" spacing={1} sx={{ mt: 0.7 }}>
                    <Chip label={readiness.label} color={chipColorForTone(readiness.tone)} />
                    <Typography variant="caption" color="text.secondary">
                      {packetCompleteness(draft).filter((item) => item.complete).length}/{packetCompleteness(draft).length} complete
                    </Typography>
                  </Stack>
                </Box>
                <Box sx={{ display: "grid", gap: 0.8 }}>
                  {packetCompleteness(draft).map((item) => (
                    <Stack key={item.id} direction="row" spacing={1} alignItems="flex-start">
                      {item.complete ? <CheckCircle2 size={15} color="#14783e" /> : <CircleAlert size={15} color={item.severity === "evidence" ? "#b54708" : "#b42318"} />}
                      <Box sx={{ minWidth: 0 }}>
                        <Typography variant="body2" fontWeight={600}>{item.label}</Typography>
                        {!item.complete && (
                          <Typography variant="caption" color="text.secondary">{item.detail}</Typography>
                        )}
                      </Box>
                    </Stack>
                  ))}
                </Box>

                <Divider />
                <Box>
                  <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={1}>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      Review preflight
                    </Typography>
                    <Chip
                      label={preflightBlockers.length ? `${preflightBlockers.length} blockers` : "Ready"}
                      size="small"
                      variant="outlined"
                      color={preflightBlockers.length ? "error" : "success"}
                    />
                  </Stack>
                  <Box sx={{ display: "grid", gap: 0.85, mt: 1 }}>
                    {preflightItems.map((item) => (
                      <Stack key={item.id} direction="row" spacing={1} alignItems="flex-start">
                        {preflightIcon(item)}
                        <Box sx={{ minWidth: 0 }}>
                          <Typography variant="body2" fontWeight={600}>
                            {item.label}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {item.detail}
                          </Typography>
                        </Box>
                      </Stack>
                    ))}
                  </Box>
                </Box>

                <Divider />
                <Box>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Band room mode
                  </Typography>
                  <ToggleButtonGroup
                    exclusive
                    value={reviewMode}
                    onChange={(_, value: ReviewRoomMode | null) => {
                      if (value) setReviewMode(value);
                    }}
                    disabled={busy}
                    sx={{ display: "grid", gridTemplateColumns: "1fr", gap: 1, mt: 1 }}
                  >
                    <ToggleButton value="fresh" sx={{ justifyContent: "flex-start", textAlign: "left", p: 1.25 }}>
                      <Box>
                        <Typography variant="body2" fontWeight={600}>Fresh Band room</Typography>
                        <Typography variant="caption" color="text.secondary">Recommended for canonical packet lock and clean replay.</Typography>
                      </Box>
                    </ToggleButton>
                    <ToggleButton value="existing" sx={{ justifyContent: "flex-start", textAlign: "left", p: 1.25 }}>
                      <Box>
                        <Typography variant="body2" fontWeight={600}>Current room</Typography>
                        <Typography variant="caption" color="text.secondary">Only valid before any audit events exist.</Typography>
                      </Box>
                    </ToggleButton>
                  </ToggleButtonGroup>
                </Box>

                <Divider />
                <Box>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Packet preview
                  </Typography>
                  <Typography variant="h3" sx={{ mt: 0.6 }}>
                    {draft.target_name || "Untitled release"}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                    {draft.change_summary || draft.target_summary || "Add a change summary before locking the packet."}
                  </Typography>
                </Box>
                {[
                  ["Owner", draft.business_owner || "Not supplied"],
                  ["Environment", draft.deployment_environment || "Not supplied"],
                  ["Criticality", draft.criticality || "Not supplied"],
                  ["Evidence", `${draft.evidence_manifest.length} rows`],
                  ["Supporting files", `${draft.supporting_evidence_imports.length} imports`],
                  ["Controls", `${draft.control_claims.length} claims`]
                ].map(([label, value]) => (
                  <Box key={label}>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      {label}
                    </Typography>
                    <Typography variant="body2" sx={{ mt: 0.35 }}>
                      {value}
                    </Typography>
                  </Box>
                ))}
                <Alert severity={sourceMode === "re_review" || sourceMode === "pdf_packet" ? "info" : alertSeverityForTone(readiness.tone)} variant="outlined">
                  {sourceMode === "re_review"
                    ? "Re-review creates a fresh Band room and carries prior blocker context into packet metadata."
                    : sourceMode === "pdf_packet"
                      ? "PDF fields are draft values until corrected and locked; the Band room remains the release record."
                      : "Locking writes the packet and evidence manifest into the first Band event before the board runs."}
                </Alert>
                <Button
                  variant="contained"
                  onClick={() => void startReview()}
                  disabled={lockDisabled}
                  endIcon={<ArrowRight size={15} />}
                  fullWidth
                >
                  {busy ? "Running review" : primaryActionLabel}
                </Button>
              </Stack>
            </Box>
          </Box>
        </Paper>
      </Container>
    </Box>
  );
}

function LandingPage({
  audit,
  recentReviews,
  navigate,
  onStartSample,
  onCreateCustom
}: {
  audit: AuditState;
  recentReviews: RecentReview[];
  navigate: (view: ViewMode) => void;
  onStartSample: () => void;
  onCreateCustom: () => void;
}) {
  const activeReview =
    (audit.events.length > 0 ? recentReviewFromAudit(audit) : null) ??
    recentReviews[0] ?? {
      id: sampleAudit.roomId,
      target: sampleAudit.target,
      decision: sampleAudit.releaseStatus,
      risk: "Critical",
      events: sampleAudit.bandEvents,
      updated: sampleAudit.updated
    };
  const proofStats = [
    { label: "Specialist lanes", value: sampleAudit.agents, helper: "reviewed the sample audit", icon: <Bot size={17} /> },
    { label: "Band events", value: sampleAudit.bandEvents, helper: "reconstructed as release state", icon: <MessagesSquare size={17} /> },
    { label: "Evidence links", value: sampleAudit.evidenceLinks, helper: "attached to decision claims", icon: <FileSearch size={17} /> },
    { label: "Board votes", value: sampleAudit.boardVotes, helper: "captured before synthesis", icon: <Vote size={17} /> },
    { label: "Decision", value: sampleAudit.decisions, helper: "export-ready record", icon: <ClipboardCheck size={17} /> }
  ];
  const previewStats = [
    { label: "Band events", value: sampleAudit.bandEvents },
    { label: "Blocking findings", value: sampleAudit.blockers },
    { label: "Board votes", value: sampleAudit.boardVotes }
  ];
  const openReview = () => navigate("review");
  const viewReport = () => navigate("report");

  return (
    <Box component="main" sx={{ minHeight: "100vh", bgcolor: "#fafbfa", color: "text.primary" }}>
      <Box
        component="header"
        sx={{
          borderBottom: "1px solid",
          borderColor: "divider",
          bgcolor: "rgba(250, 251, 250, 0.92)",
          position: "sticky",
          top: 0,
          zIndex: 5,
          backdropFilter: "blur(12px)"
        }}
      >
        <Container maxWidth="lg">
          <Stack
            direction={{ xs: "column", sm: "row" }}
            alignItems={{ xs: "stretch", sm: "center" }}
            justifyContent="space-between"
            spacing={1.5}
            sx={{ py: { xs: 1.5, sm: 1.75 } }}
          >
            <Button
              color="inherit"
              onClick={() => navigate("landing")}
              sx={{
                justifyContent: "flex-start",
                px: 0,
                color: "text.primary",
                "&:hover": { bgcolor: "transparent" }
              }}
            >
              <Stack direction="row" alignItems="center" spacing={1.25}>
                <Avatar variant="rounded" sx={{ width: 38, height: 38, bgcolor: "primary.main" }}>
                  <ShieldCheck size={19} />
                </Avatar>
                <Box sx={{ textAlign: "left" }}>
                  <Typography variant="body1" fontWeight={700} sx={{ lineHeight: 1.15 }}>
                    BandAudit
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", lineHeight: 1.2 }}>
                    Agent Release Board
                  </Typography>
                </Box>
              </Stack>
            </Button>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ width: { xs: "100%", sm: "auto" } }}>
              <Button variant="outlined" color="inherit" onClick={onCreateCustom}>
                Create custom audit
              </Button>
              <Button variant="contained" onClick={onStartSample} endIcon={<ArrowRight size={15} />}>
                Start sample audit
              </Button>
            </Stack>
          </Stack>
        </Container>
      </Box>

      <Container maxWidth="lg" sx={{ py: { xs: 4, md: 6.5 } }}>
        <Stack component="section" spacing={3} alignItems="center" sx={{ maxWidth: 920, mx: "auto", textAlign: "center" }}>
          <Chip
            label="RELEASE-REVIEW CONSOLE"
            variant="outlined"
            size="small"
            sx={{ bgcolor: "background.paper", borderColor: "divider", fontWeight: 700 }}
          />
          <Box>
            <Typography
              variant="h1"
              sx={{
                maxWidth: 820,
                mx: "auto",
                fontSize: { xs: "2.625rem", md: "3.5rem", lg: "4rem" },
                lineHeight: { xs: 1.06, md: 1.02 },
                fontWeight: 800,
                letterSpacing: 0
              }}
            >
              Release gates for production AI agents.
            </Typography>
            <Typography
              color="text.secondary"
              sx={{
                maxWidth: 720,
                mx: "auto",
                mt: 2,
                fontSize: { xs: "1rem", md: "1.125rem" },
                lineHeight: 1.6
              }}
            >
              BandAudit coordinates specialist reviewers in Band, reconstructs the review from room events, and
              exports an evidence-backed release decision.
            </Typography>
          </Box>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1.25} sx={{ width: { xs: "100%", sm: "auto" } }}>
            <Button variant="contained" size="large" onClick={onStartSample} endIcon={<ArrowRight size={16} />}>
              Start sample audit
            </Button>
            <Button variant="outlined" color="inherit" size="large" onClick={onCreateCustom}>
              Create custom audit
            </Button>
          </Stack>
          <Stack direction="row" flexWrap="wrap" justifyContent="center" gap={1}>
            {["Band evidence room", `${sampleAudit.agents} specialist lanes`, `${sampleAudit.bandEvents} events in current room`].map((label) => (
              <Chip key={label} label={label} size="small" variant="outlined" sx={{ bgcolor: "background.paper" }} />
            ))}
          </Stack>
        </Stack>

        <Paper
          variant="outlined"
          role="button"
          tabIndex={0}
          onClick={openReview}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              openReview();
            }
          }}
          sx={{
            mt: { xs: 4, md: 6 },
            overflow: "hidden",
            cursor: "pointer",
            bgcolor: "background.paper",
            boxShadow: "0 20px 45px rgba(16, 24, 40, 0.08)",
            "&:focus-visible": { outline: "3px solid rgba(20, 120, 62, 0.28)", outlineOffset: 3 }
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.75, px: 2, py: 1.2, borderBottom: "1px solid", borderColor: "divider", bgcolor: "#f7f8fa" }}>
            {[0, 1, 2].map((item) => (
              <Box key={item} sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: item === 0 ? "#f04438" : item === 1 ? "#fdb022" : "#12b76a" }} />
            ))}
            <Typography variant="caption" color="text.secondary" sx={{ ml: 1, fontWeight: 600 }}>
              Sample release review
            </Typography>
          </Box>

          <Box sx={{ p: { xs: 2, md: 3 }, display: "grid", gap: 2.5 }}>
            <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ xs: "stretch", md: "center" }} justifyContent="space-between">
              <Box sx={{ minWidth: 0 }}>
                <Stack direction="row" flexWrap="wrap" alignItems="center" gap={1}>
                  <Chip label="Release blocked" color="error" size="small" sx={{ fontWeight: 700 }} />
                  <Chip label={sampleAudit.severity} variant="outlined" size="small" sx={{ bgcolor: "#fff7f5", borderColor: "#fecdca", color: "#b42318", fontWeight: 700 }} />
                </Stack>
                <Typography variant="h2" sx={{ mt: 1.2, mb: 0.5 }}>
                  {sampleAudit.target}
                </Typography>
                <Typography color="text.secondary" sx={{ maxWidth: 740 }}>
                  {samplePacket.target_summary}
                </Typography>
              </Box>
              <Button variant="outlined" color="inherit" endIcon={<ArrowRight size={15} />} sx={{ alignSelf: { xs: "flex-start", md: "center" } }}>
                Open review
              </Button>
            </Stack>

            <Box
              sx={{
                display: "grid",
                gridTemplateColumns: { xs: "1fr", lg: "1.25fr 0.75fr" },
                gap: 2,
                alignItems: "stretch"
              }}
            >
              <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, p: { xs: 1.75, md: 2 }, bgcolor: "#fcfcfd" }}>
                <Typography variant="caption" color="text.secondary" fontWeight={700}>
                  Primary blocker identified
                </Typography>
                <Stack direction="row" spacing={1.25} alignItems="flex-start" sx={{ mt: 1 }}>
                  <Avatar variant="rounded" sx={{ width: 36, height: 36, bgcolor: "#fff1f0", color: "#b42318" }}>
                    <TriangleAlert size={18} />
                  </Avatar>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body1" fontWeight={700}>
                      {sampleAudit.primaryBlocker}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                      Release remains blocked until tool permissions and human approval gates are narrowed.
                    </Typography>
                  </Box>
                </Stack>
                <Divider sx={{ my: 2 }} />
                <Stack direction="row" flexWrap="wrap" gap={1}>
                  {previewStats.map((stat) => (
                    <Box
                      key={stat.label}
                      sx={{
                        minWidth: { xs: "calc(50% - 4px)", sm: 150 },
                        flex: "1 1 150px",
                        border: "1px solid",
                        borderColor: "divider",
                        borderRadius: 2,
                        bgcolor: "background.paper",
                        p: 1.5
                      }}
                    >
                      <Typography variant="h3">{stat.value}</Typography>
                      <Typography variant="caption" color="text.secondary" fontWeight={600}>
                        {stat.label}
                      </Typography>
                    </Box>
                  ))}
                </Stack>
              </Box>

              <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, overflow: "hidden", bgcolor: "background.paper" }}>
                <Box sx={{ px: 1.75, py: 1.4, borderBottom: "1px solid", borderColor: "divider" }}>
                  <Typography variant="caption" color="text.secondary" fontWeight={700}>
                    Recent Band events
                  </Typography>
                </Box>
                {sampleAudit.trace.slice(0, 4).map((item) => (
                  <Stack key={item.event} direction="row" spacing={1.25} alignItems="flex-start" sx={{ px: 1.75, py: 1.35, borderBottom: "1px solid", borderColor: "divider", "&:last-child": { borderBottom: 0 } }}>
                    <Avatar variant="rounded" sx={{ width: 28, height: 28, bgcolor: "#f0fdf4", color: "primary.main" }}>
                      <BadgeCheck size={15} />
                    </Avatar>
                    <Box sx={{ minWidth: 0 }}>
                      <Typography variant="body2" fontWeight={700} noWrap>
                        {item.actor}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }} noWrap>
                        {item.event} - {item.state}
                      </Typography>
                    </Box>
                  </Stack>
                ))}
              </Box>
            </Box>
          </Box>
        </Paper>

        <Paper variant="outlined" sx={{ mt: 2, p: { xs: 1.5, md: 2 }, bgcolor: "background.paper" }}>
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "repeat(2, minmax(0, 1fr))", md: "repeat(5, minmax(0, 1fr))" }, gap: 0 }}>
            {proofStats.map((stat, index) => (
              <Box key={stat.label} sx={{ p: 1.5, borderRight: { xs: index % 2 === 0 ? "1px solid" : 0, md: index < proofStats.length - 1 ? "1px solid" : 0 }, borderBottom: { xs: index < 3 ? "1px solid" : 0, md: 0 }, borderColor: "divider" }}>
                <Stack direction="row" spacing={1} alignItems="center" sx={{ color: "primary.main", mb: 0.75 }}>
                  {stat.icon}
                  <Typography variant="h3">{stat.value}</Typography>
                </Stack>
                <Typography variant="body2" fontWeight={700}>
                  {stat.label}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {stat.helper}
                </Typography>
              </Box>
            ))}
          </Box>
        </Paper>

        <Box component="section" sx={{ mt: { xs: 5, md: 7 } }}>
          <Stack spacing={1} sx={{ mb: 2.5 }}>
            <Typography variant="overline" color="text.secondary" fontWeight={700}>
              Review workflow
            </Typography>
            <Typography variant="h2">From packet to release decision.</Typography>
          </Stack>
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "repeat(4, minmax(0, 1fr))" }, gap: 2 }}>
            {sampleAudit.workflow.map((step, index) => (
              <Card variant="outlined" key={step.title} sx={{ bgcolor: "background.paper" }}>
                <CardContent sx={{ p: 2.25, "&:last-child": { pb: 2.25 } }}>
                  <Avatar variant="rounded" sx={{ width: 34, height: 34, bgcolor: "#f0fdf4", color: "primary.main", mb: 1.5, fontSize: 14, fontWeight: 800 }}>
                    {index + 1}
                  </Avatar>
                  <Typography variant="h3" sx={{ mb: 0.75 }}>
                    {step.title}
                  </Typography>
                  <Typography color="text.secondary">{step.body}</Typography>
                </CardContent>
              </Card>
            ))}
          </Box>
        </Box>

        <Paper variant="outlined" component="section" sx={{ mt: { xs: 5, md: 7 }, overflow: "hidden", bgcolor: "background.paper" }}>
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", lg: "0.9fr 1.1fr" }, gap: 0 }}>
            <Box sx={{ p: { xs: 2.25, md: 3 }, borderRight: { lg: "1px solid" }, borderBottom: { xs: "1px solid", lg: 0 }, borderColor: "divider" }}>
              <Typography variant="overline" color="text.secondary" fontWeight={700}>
                Band traceability
              </Typography>
              <Typography variant="h2" sx={{ mt: 0.75 }}>
                Band is the audit trail.
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 1.25, maxWidth: 520 }}>
                Structured Band room activity becomes the source of truth for findings, challenges, verification,
                voting, and final release synthesis.
              </Typography>
              <Stack direction="row" flexWrap="wrap" gap={1} sx={{ mt: 2.25 }}>
                {sampleAudit.eventPills.map((eventName) => (
                  <Chip key={eventName} label={eventName} size="small" variant="outlined" sx={{ bgcolor: "#f7f8fa", fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" }} />
                ))}
              </Stack>
            </Box>
            <Box sx={{ p: { xs: 2, md: 2.5 }, bgcolor: "#fcfcfd" }}>
              <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "1fr 1fr" }, gap: 2 }}>
                <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, bgcolor: "background.paper", overflow: "hidden" }}>
                  <Box sx={{ px: 1.75, py: 1.35, borderBottom: "1px solid", borderColor: "divider" }}>
                    <Typography variant="caption" color="text.secondary" fontWeight={700}>
                      Band room events
                    </Typography>
                  </Box>
                  {sampleAudit.trace.slice(0, 5).map((item) => (
                    <Box key={`${item.event}-${item.actor}`} sx={{ px: 1.75, py: 1.25, borderBottom: "1px solid", borderColor: "divider", "&:last-child": { borderBottom: 0 } }}>
                      <Typography variant="caption" color="primary.main" fontWeight={700} sx={{ fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" }}>
                        {item.event}
                      </Typography>
                      <Typography variant="body2" fontWeight={700} sx={{ mt: 0.25 }}>
                        {item.actor}
                      </Typography>
                    </Box>
                  ))}
                </Box>
                <Box sx={{ border: "1px solid", borderColor: "divider", borderRadius: 2, bgcolor: "background.paper", overflow: "hidden" }}>
                  <Box sx={{ px: 1.75, py: 1.35, borderBottom: "1px solid", borderColor: "divider" }}>
                    <Typography variant="caption" color="text.secondary" fontWeight={700}>
                      Generated release state
                    </Typography>
                  </Box>
                  {sampleAudit.trace.slice(0, 5).map((item) => (
                    <Stack key={item.state} direction="row" spacing={1} alignItems="center" sx={{ px: 1.75, py: 1.55, borderBottom: "1px solid", borderColor: "divider", "&:last-child": { borderBottom: 0 } }}>
                      <CheckCircle2 size={16} color="#14783e" />
                      <Typography variant="body2" fontWeight={600}>
                        {item.state}
                      </Typography>
                    </Stack>
                  ))}
                </Box>
              </Box>
            </Box>
          </Box>
        </Paper>

        <Box component="section" sx={{ mt: { xs: 5, md: 7 }, display: "grid", gridTemplateColumns: { xs: "1fr", lg: "0.9fr 1.1fr" }, gap: 3, alignItems: "center" }}>
          <Box>
            <Typography variant="overline" color="text.secondary" fontWeight={700}>
              Exportable record
            </Typography>
            <Typography variant="h2" sx={{ mt: 0.75 }}>
              Export a decision record teams can defend.
            </Typography>
            <Typography color="text.secondary" sx={{ mt: 1.25, maxWidth: 560 }}>
              The review outcome is packaged as a decision record with rationale, evidence links, traceability, and
              remediation work that legal, security, compliance, and product teams can inspect.
            </Typography>
            <Button variant="outlined" color="inherit" onClick={viewReport} sx={{ mt: 2.25 }} endIcon={<ArrowRight size={15} />}>
              View report
            </Button>
          </Box>
          <Paper variant="outlined" sx={{ bgcolor: "background.paper", overflow: "hidden" }}>
            <Box sx={{ px: { xs: 2, md: 2.5 }, py: 2, borderBottom: "1px solid", borderColor: "divider", bgcolor: "#f7f8fa" }}>
              <Typography variant="caption" color="text.secondary" fontWeight={700}>
                BandAudit Release Report
              </Typography>
              <Typography variant="h3" sx={{ mt: 0.5 }}>
                {sampleAudit.target}
              </Typography>
            </Box>
            <Box sx={{ p: { xs: 2, md: 2.5 }, display: "grid", gap: 1.75 }}>
              {[
                ["Decision", sampleAudit.decision],
                ["Rationale", "Release remains blocked until the recorded high-risk controls are remediated."],
                ["Traceability", `${sampleAudit.bandEvents} Band events, ${sampleAudit.evidenceLinks} evidence links, ${sampleAudit.boardVotes} board votes.`],
                ["Remediation", "Attach owner-approved remediation evidence and run a fresh re-review."]
              ].map(([label, value]) => (
                <Box key={label} sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "140px minmax(0, 1fr)" }, gap: 1, py: 1.1, borderBottom: "1px solid", borderColor: "divider", "&:last-child": { borderBottom: 0 } }}>
                  <Typography variant="caption" color="text.secondary" fontWeight={700}>
                    {label}
                  </Typography>
                  <Typography variant="body2" fontWeight={label === "Decision" ? 700 : 500} color={label === "Decision" ? "error.main" : "text.primary"}>
                    {value}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Paper>
        </Box>

        <Paper variant="outlined" component="section" sx={{ mt: { xs: 5, md: 7 }, p: { xs: 2, md: 2.75 }, bgcolor: "background.paper" }}>
          <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems={{ xs: "stretch", md: "center" }} justifyContent="space-between">
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="overline" color="text.secondary" fontWeight={700}>
                Recent review
              </Typography>
              <Typography variant="h2" sx={{ mt: 0.5 }}>
                Open the sample release review.
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 0.75 }}>
                {activeReview.target} - {sampleAudit.releaseStatus} - {sampleAudit.severity} - {sampleAudit.bandEvents} Band events - {activeReview.updated}
              </Typography>
              <Typography color="text.secondary" sx={{ mt: 1.25 }}>
                Start with the sample audit. Inspect the board, timeline, evidence packet, and release report.
              </Typography>
            </Box>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ width: { xs: "100%", md: "auto" } }}>
              <Button variant="contained" onClick={openReview} endIcon={<ArrowRight size={15} />}>
                Open review
              </Button>
              <Button variant="outlined" color="inherit" onClick={viewReport}>
                View report
              </Button>
            </Stack>
          </Stack>
        </Paper>
      </Container>

      <Box component="footer" sx={{ borderTop: "1px solid", borderColor: "divider", bgcolor: "#f7f8fa" }}>
        <Container maxWidth="lg">
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems={{ xs: "flex-start", sm: "center" }} justifyContent="space-between" sx={{ py: 2.25 }}>
            <Typography variant="body2" color="text.secondary">
              BandAudit
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Evidence-backed release decisions for production AI agents.
            </Typography>
          </Stack>
        </Container>
      </Box>
    </Box>
  );
}

function ReportSection({
  title,
  subtitle,
  action,
  defaultExpanded = false,
  children
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  defaultExpanded?: boolean;
  children: ReactNode;
}) {
  return (
    <Accordion defaultExpanded={defaultExpanded} disableGutters elevation={0} sx={{ borderTop: "1px solid", borderColor: "divider", "&:before": { display: "none" } }}>
      <AccordionSummary expandIcon={<ChevronDown size={16} />} sx={{ minWidth: 0 }}>
        <Box sx={{ minWidth: 0, pr: 1 }}>
          <Typography variant="h3">{title}</Typography>
          {subtitle && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.35 }}>
              {subtitle}
            </Typography>
          )}
        </Box>
      </AccordionSummary>
      {action && (
        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-start",
            px: { xs: 2, sm: 2.25 },
            pb: 1.75
          }}
        >
          {action}
        </Box>
      )}
      <AccordionDetails sx={{ pt: 0, pb: 2.25 }}>
        {children}
      </AccordionDetails>
    </Accordion>
  );
}

function ReportPage({ audit, navigate }: { audit: AuditState; navigate: (view: ViewMode) => void }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [exporting, setExporting] = useState<"pdf" | "docx" | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null);
  const report = useMemo(() => buildAuditReportModel(audit), [audit]);
  const menuOpen = Boolean(menuAnchor);

  async function copySummary() {
    try {
      await navigator.clipboard.writeText(report.summaryText);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
    window.setTimeout(() => setCopyState("idle"), 1600);
  }

  function downloadBlob(filename: string, blob: Blob) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function downloadText(filename: string, mimeType: string, content: string) {
    downloadBlob(filename, new Blob([content], { type: mimeType }));
  }

  async function exportPdf() {
    setExportError(null);
    setExporting("pdf");
    try {
      const { downloadReportPdf } = await import("./report/pdfExport");
      downloadReportPdf(report);
    } catch (error) {
      setExportError(errorMessage(error, "Unable to generate the PDF report."));
    } finally {
      setExporting(null);
    }
  }

  async function exportDocx() {
    setExportError(null);
    setExporting("docx");
    try {
      const { createReportDocxBlob } = await import("./report/docxExport");
      const blob = await createReportDocxBlob(report);
      downloadBlob(`${report.fileBaseName}.docx`, blob);
    } catch (error) {
      setExportError(errorMessage(error, "Unable to generate the DOCX report."));
    } finally {
      setExporting(null);
    }
  }

  function exportJson() {
    setMenuAnchor(null);
    downloadText(`${report.fileBaseName}.json`, "application/json", JSON.stringify(report.jsonPayload, null, 2));
  }

  async function exportMarkdown() {
    setMenuAnchor(null);
    const { buildReportMarkdown } = await import("./report/markdownExport");
    downloadText(`${report.fileBaseName}.md`, "text/markdown", buildReportMarkdown(report));
  }

  function printReport() {
    setMenuAnchor(null);
    window.print();
  }

  return (
    <Box component="section" sx={{ width: "100%", minWidth: 0 }}>
      <Paper variant="outlined" sx={{ overflow: "hidden", bgcolor: "background.paper" }}>
        <Stack
          direction={{ xs: "column", md: "row" }}
          alignItems={{ xs: "stretch", md: "flex-start" }}
          justifyContent="space-between"
          spacing={2}
          sx={{ p: { xs: 2, md: 3 }, borderBottom: "1px solid", borderColor: "divider" }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="overline" color="text.secondary" fontWeight={600}>
              BandAudit Release Report
            </Typography>
            <Stack direction="row" flexWrap="wrap" alignItems="center" gap={1.25} sx={{ mt: 0.5 }}>
              <Typography variant="h2">{report.target.name}</Typography>
              <Chip label={report.decision.label} color={chipColorForTone(report.decision.tone)} variant={report.decision.tone === "neutral" ? "outlined" : "filled"} />
            </Stack>
            <Typography color="text.secondary" sx={{ mt: 0.75, maxWidth: 860 }}>
              {report.target.summary}
            </Typography>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
              Generated {report.generatedAtLabel}
            </Typography>
            <Stack direction="row" flexWrap="wrap" gap={0.75} sx={{ mt: 1.1 }}>
              <Chip label={`Packet ${audit.input_packet.packet_version || "v1"}`} size="small" variant="outlined" />
              <Chip label={audit.input_packet.review_type || "Review"} size="small" variant="outlined" />
              <Chip label={sourceModeLabel((audit.input_packet.packet_source_mode || "manual") as PacketSourceMode)} size="small" variant="outlined" />
              {audit.input_packet.import_summary.artifact && (
                <Chip label={`PDF ${artifactFileName(audit.input_packet.import_summary.artifact.filename)}`} size="small" variant="outlined" color="info" />
              )}
              {audit.input_packet.import_summary.artifact?.ocr_model && (
                <Chip label={`OCR ${audit.input_packet.import_summary.artifact.ocr_model}`} size="small" variant="outlined" />
              )}
              {audit.input_packet.import_summary.artifact?.sha256 && (
                <Chip label={`SHA ${audit.input_packet.import_summary.artifact.sha256.slice(0, 10)}`} size="small" variant="outlined" />
              )}
              {audit.input_packet.supporting_evidence_imports.length > 0 && (
                <Chip label={`${audit.input_packet.supporting_evidence_imports.length} supporting files`} size="small" variant="outlined" color="info" />
              )}
              {audit.input_packet.ticket_url && <Chip label={artifactFileName(audit.input_packet.ticket_url)} size="small" variant="outlined" />}
              {audit.input_packet.re_review_context.original_room_id && (
                <Chip label={`Original ${shortRoomId(audit.input_packet.re_review_context.original_room_id)}`} size="small" variant="outlined" color="info" />
              )}
            </Stack>
          </Box>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ width: { xs: "100%", md: "auto" } }}>
            <Button variant="outlined" color="inherit" onClick={() => navigate("review")} startIcon={<ArrowRight size={15} style={{ transform: "rotate(180deg)" }} />}>
              Back to review
            </Button>
            <Button variant="contained" onClick={() => void exportPdf()} disabled={exporting !== null} startIcon={<Download size={15} />}>
              {exporting === "pdf" ? "Preparing PDF" : "Download PDF"}
            </Button>
            <Button variant="outlined" color="inherit" onClick={() => void exportDocx()} disabled={exporting !== null} startIcon={<FileText size={15} />}>
              {exporting === "docx" ? "Preparing DOCX" : "Download DOCX"}
            </Button>
            <IconButton
              aria-label="Report export options"
              aria-controls={menuOpen ? "report-export-menu" : undefined}
              aria-haspopup="menu"
              aria-expanded={menuOpen ? "true" : undefined}
              onClick={(event) => setMenuAnchor(event.currentTarget)}
              sx={{ border: "1px solid", borderColor: "divider", bgcolor: "background.paper" }}
            >
              <MoreVertical size={17} />
            </IconButton>
            <Menu
              id="report-export-menu"
              anchorEl={menuAnchor}
              open={menuOpen}
              onClose={() => setMenuAnchor(null)}
              anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
              transformOrigin={{ vertical: "top", horizontal: "right" }}
            >
              <MenuItem onClick={() => void copySummary()}>
                <Copy size={14} />
                <Box component="span" sx={{ ml: 1 }}>
                  {copyState === "copied" ? "Copied summary" : copyState === "failed" ? "Copy failed" : "Copy summary"}
                </Box>
              </MenuItem>
              <MenuItem onClick={exportJson}>
                <Download size={14} />
                <Box component="span" sx={{ ml: 1 }}>
                  Download JSON
                </Box>
              </MenuItem>
              <MenuItem onClick={() => void exportMarkdown()}>
                <Download size={14} />
                <Box component="span" sx={{ ml: 1 }}>
                  Download Markdown
                </Box>
              </MenuItem>
              <MenuItem onClick={printReport}>
                <FileText size={14} />
                <Box component="span" sx={{ ml: 1 }}>
                  Print
                </Box>
              </MenuItem>
            </Menu>
          </Stack>
        </Stack>

        {exportError && (
          <Box sx={{ px: { xs: 2, md: 3 }, pt: 2 }}>
            <Alert severity="error" variant="outlined">
              {exportError}
            </Alert>
          </Box>
        )}

        <Box sx={{ p: { xs: 2, md: 3 } }}>
          <Stack spacing={3}>
            <Box>
              <Typography variant="h3" sx={{ mb: 1.25 }}>
                Executive decision
              </Typography>
              <Stack direction={{ xs: "column", lg: "row" }} spacing={2.5} alignItems="stretch">
                <Box sx={{ minWidth: 0, flex: 1 }}>
                  <Typography variant="h2" color={toneColor(report.decision.tone)} sx={{ mb: 1 }}>
                    {report.decision.label}
                  </Typography>
                  <Typography variant="body1" fontWeight={600} sx={{ mb: 1 }}>
                    {report.decision.verdict}
                  </Typography>
                  <Typography color="text.secondary">{report.decision.rationale}</Typography>
                </Box>
                <Card variant="outlined" sx={{ width: { xs: "100%", lg: 360 } }}>
                  <CardContent sx={{ p: 2, "&:last-child": { pb: 2 } }}>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      Risk snapshot
                    </Typography>
                    <Box sx={{ display: "grid", gridTemplateColumns: "repeat(2, minmax(0, 1fr))", gap: 1.5, mt: 1.5 }}>
                      {[
                        ["Risk score", String(report.risk.score)],
                        ["Risk level", report.risk.levelLabel],
                        ["Open blockers", String(report.risk.blockerCount)],
                        ["Evidence links", String(report.risk.evidenceLinkCount)]
                      ].map(([label, value]) => (
                        <Box key={label}>
                          <Typography variant="caption" color="text.secondary">
                            {label}
                          </Typography>
                          <Typography variant="body1" fontWeight={600}>
                            {value}
                          </Typography>
                        </Box>
                      ))}
                    </Box>
                  </CardContent>
                </Card>
              </Stack>
            </Box>

            <Box>
              <Typography variant="h3" sx={{ mb: 1.25 }}>
                Target context
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small" aria-label="Target context">
                  <TableBody>
                    {[
                      ["Owner", report.target.owner],
                      ["Deployment", report.target.deployment],
                      ["Affected users", report.target.affectedUsers],
                      ["Release goal", report.target.releaseGoal]
                    ].map(([label, value]) => (
                      <TableRow key={label}>
                        <TableCell sx={{ width: 180, color: "text.secondary", fontWeight: 600 }}>{label}</TableCell>
                        <TableCell>{value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            <Box>
              <Typography variant="h3" sx={{ mb: 1.25 }}>
                Audit integrity
              </Typography>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small" aria-label="Audit integrity">
                  <TableBody>
                    {[
                      ["Band room", report.integrity.bandRoomId],
                      ["Packet source", report.integrity.packetSource],
                      ["Packet version", report.integrity.packetVersion],
                      ["Band events", String(report.integrity.eventCount)],
                      ["Evidence links", String(report.integrity.evidenceLinkCount)],
                      ["Artifact hashes", report.integrity.artifactHashes.length ? report.integrity.artifactHashes.map((hash) => `${hash.slice(0, 16)}...`).join(", ") : "None recorded"],
                      ["Structured-output repairs", String(report.integrity.structuredOutputRepairCount)],
                      ["Final synthesis event", report.integrity.finalSynthesisEventId]
                    ].map(([label, value]) => (
                      <TableRow key={label}>
                        <TableCell sx={{ width: 210, color: "text.secondary", fontWeight: 600 }}>{label}</TableCell>
                        <TableCell sx={{ overflowWrap: "anywhere" }}>{value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            <Box>
              <ReleaseBoardRoster audit={audit} compact />
            </Box>
          </Stack>
        </Box>

        <ReportSection title="Release blockers" subtitle="Findings that influence the release decision." action={<Chip label={`${report.findings.length} findings`} variant="outlined" />} defaultExpanded>
          {report.findings.length > 0 ? (
            <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
              <Table size="small" aria-label="Release blockers" sx={{ minWidth: 920 }}>
                <TableHead>
                  <TableRow>
                    <TableCell>Finding</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Effect</TableCell>
                    <TableCell>Evidence</TableCell>
                    <TableCell>Owner</TableCell>
                    <TableCell>Summary</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {report.findings.map((finding) => (
                    <TableRow key={finding.id} hover>
                      <TableCell>
                        <Typography variant="body2" fontWeight={600}>
                          {finding.id}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {finding.title}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={finding.severityLabel} color={severityChipColor(finding.severity)} variant="outlined" />
                      </TableCell>
                      <TableCell>
                        <Chip label={finding.statusLabel} color={statusChipColor(finding.status)} variant="outlined" />
                      </TableCell>
                      <TableCell>{finding.releaseEffect}</TableCell>
                      <TableCell>{finding.evidence.length}</TableCell>
                      <TableCell>{finding.owner}</TableCell>
                      <TableCell sx={{ minWidth: 300 }}>
                        <Typography variant="body2" color="text.secondary">
                          {finding.summary}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Alert severity="info" variant="outlined">
              No release findings have been created yet.
            </Alert>
          )}
        </ReportSection>

        <ReportSection title="Required remediation" subtitle="Actions required before release or re-review.">
          {report.requiredRemediations.length > 0 ? (
            <TableContainer component={Paper} variant="outlined">
              <Table size="small" aria-label="Required remediation">
                <TableBody>
                  {report.requiredRemediations.map((item, index) => (
                    <TableRow key={item}>
                      <TableCell sx={{ width: 60, color: "text.secondary", fontWeight: 600 }}>{index + 1}</TableCell>
                      <TableCell>{item}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Alert severity="info" variant="outlined">
              No required remediations have been synthesized yet.
            </Alert>
          )}
        </ReportSection>

        <ReportSection title="Evidence matrix" subtitle="Evidence references used by the release record.">
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small" aria-label="Evidence matrix" sx={{ minWidth: 1040 }}>
              <TableHead>
                <TableRow>
                  <TableCell>Ref</TableCell>
                  <TableCell>Evidence</TableCell>
                  <TableCell>Source document</TableCell>
                  <TableCell>Extraction</TableCell>
                  <TableCell>Locator</TableCell>
                  <TableCell>SHA-256</TableCell>
                  <TableCell>Warnings</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.evidence.map((evidence) => (
                  <TableRow key={evidence.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={600}>
                        {evidence.id}
                      </Typography>
                    </TableCell>
                    <TableCell>{evidence.title}</TableCell>
                    <TableCell>
                      <Typography variant="body2">{evidence.artifactName}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {evidence.source}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{evidence.extractionMethod}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {evidence.citationState}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ overflowWrap: "anywhere" }}>{evidence.locator}</TableCell>
                    <TableCell sx={{ overflowWrap: "anywhere" }}>{evidence.sha256 ? `${evidence.sha256.slice(0, 18)}...` : "Not supplied"}</TableCell>
                    <TableCell>{evidence.warningState}</TableCell>
                  </TableRow>
                ))}
                {report.evidence.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7}>No evidence linked.</TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </ReportSection>

        <ReportSection title="Vote and provider execution" subtitle="Board vote records and model routing context.">
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", xl: "minmax(0, 1fr) minmax(0, 1fr)" }, gap: 2 }}>
            <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
              <Table size="small" aria-label="Vote record" sx={{ minWidth: 520 }}>
                <TableHead>
                  <TableRow>
                    <TableCell>Agent</TableCell>
                    <TableCell>Vote</TableCell>
                    <TableCell>Rationale</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {report.votes.map((voteRecord) => (
                    <TableRow key={voteRecord.agent}>
                      <TableCell>{voteRecord.agent}</TableCell>
                      <TableCell>{voteRecord.vote}</TableCell>
                      <TableCell>{voteRecord.rationale}</TableCell>
                    </TableRow>
                  ))}
                  {report.votes.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={3}>No vote records yet.</TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
              <Table size="small" aria-label="Provider execution" sx={{ minWidth: 720 }}>
                <TableHead>
                  <TableRow>
                    <TableCell>Provider</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Model policy</TableCell>
                    <TableCell>Agent routes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {report.providers.map((provider) => (
                    <TableRow key={provider.provider}>
                      <TableCell>{provider.label}</TableCell>
                      <TableCell>
                        <Chip label={provider.statusLabel} color={provider.status === "ready" ? "success" : "warning"} variant="outlined" />
                      </TableCell>
                      <TableCell sx={{ overflowWrap: "anywhere" }}>{provider.model}</TableCell>
                      <TableCell sx={{ overflowWrap: "anywhere" }}>
                        {provider.routes.map((route) => `${route.agent}: ${route.model}`).join("; ") || "No agents routed"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        </ReportSection>

        <ReportSection title="Re-review criteria" subtitle="Conditions expected before the next decision run.">
          {report.reReviewCriteria.length > 0 ? (
            <Box component="ol" sx={{ m: 0, pl: 3, color: "text.secondary" }}>
              {report.reReviewCriteria.map((item) => (
                <Typography component="li" key={item} sx={{ mb: 1 }}>
                  {item}
                </Typography>
              ))}
            </Box>
          ) : (
            <Alert severity="info" variant="outlined">
              No re-review criteria have been synthesized yet.
            </Alert>
          )}
        </ReportSection>

        <ReportSection
          title="Appendix: Band event trace"
          subtitle="Full evidence of the board sequence is delegated to Timeline for deep inspection."
          action={
            <Button variant="outlined" color="inherit" size="small" onClick={() => navigate("timeline")} startIcon={<CalendarDays size={15} />}>
              Open full timeline
            </Button>
          }
        >
          <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
            <Table size="small" aria-label="Band event trace" sx={{ minWidth: 980 }}>
              <TableHead>
                <TableRow>
                  <TableCell>Event</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Agent</TableCell>
                  <TableCell>Provider</TableCell>
                  <TableCell>Model</TableCell>
                  <TableCell>Summary</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.events.map((event) => (
                  <TableRow key={event.id}>
                    <TableCell>{event.sequence}</TableCell>
                    <TableCell>{event.type}</TableCell>
                    <TableCell>{event.agent}</TableCell>
                    <TableCell>{event.provider}</TableCell>
                    <TableCell sx={{ overflowWrap: "anywhere" }}>{event.model}</TableCell>
                    <TableCell>{event.summary}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </ReportSection>
      </Paper>
    </Box>
  );
}

function AppShell({
  audit,
  view,
  selectedFinding,
  selectedClaimId,
  onSelectClaim,
  navigate,
  onAdvance,
  onPrepareReReview,
  onReset,
  reviewRunState,
  busy,
  actionError
}: {
  audit: AuditState;
  view: ViewMode;
  selectedFinding: Finding | undefined;
  selectedClaimId: string | null;
  onSelectClaim: (id: string) => void;
  navigate: (view: ViewMode) => void;
  onAdvance: () => Promise<void>;
  onPrepareReReview: () => void;
  onReset: () => Promise<void>;
  reviewRunState: ReviewRunState;
  busy: boolean;
  actionError: string | null;
}) {
  const navItems = [
    { view: "review" as const, label: "Dashboard", icon: <LayoutDashboard size={16} /> },
    { view: "protocol" as const, label: "Protocol", icon: <GitBranch size={16} /> },
    { view: "timeline" as const, label: "Timeline", icon: <CalendarDays size={16} /> },
    { view: "report" as const, label: "Report", icon: <FileText size={16} /> }
  ];
  const sidebarMarkers = [
    { label: "Critical blockers", value: audit.findings.filter((finding) => finding.severity === "critical").length, tone: "danger" },
    { label: "Evidence links", value: traceabilityCount(audit), tone: "success" },
    { label: "Provider routes", value: audit.agent_execution.routes.length, tone: "purple" }
  ];
  const [actionsAnchor, setActionsAnchor] = useState<HTMLElement | null>(null);
  const actionsOpen = Boolean(actionsAnchor);

  async function resetFromMenu() {
    setActionsAnchor(null);
    await onReset();
  }

  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: { xs: "1fr", lg: "292px minmax(0, 1fr)" },
        minHeight: "100vh",
        bgcolor: "background.default"
      }}
    >
      <Paper
        component="aside"
        elevation={0}
        square
        sx={{
          position: { xs: "static", lg: "sticky" },
          top: 0,
          zIndex: 2,
          display: "flex",
          flexDirection: "column",
          gap: { xs: 1.25, lg: 2.25 },
          height: { xs: "auto", lg: "100vh" },
          p: { xs: 1.5, lg: 2.25 },
          borderRight: { xs: 0, lg: "1px solid" },
          borderBottom: { xs: "1px solid", lg: 0 },
          borderColor: "divider",
          bgcolor: "#fbfbfa"
        }}
      >
        <Button
          onClick={() => navigate("landing")}
          variant="outlined"
          color="inherit"
          sx={{
            justifyContent: "stretch",
            minHeight: { xs: 58, lg: 78 },
            p: 1.25,
            borderColor: "divider",
            bgcolor: "background.paper",
            "&:hover": { borderColor: "primary.light", bgcolor: "background.paper" }
          }}
        >
          <Stack direction="row" alignItems="center" spacing={1.5} sx={{ width: "100%" }}>
            <Avatar variant="rounded" sx={{ width: { xs: 38, lg: 50 }, height: { xs: 38, lg: 50 }, bgcolor: "primary.main" }}>
              <ShieldCheck size={22} />
            </Avatar>
            <Box sx={{ minWidth: 0, flex: 1, textAlign: "left" }}>
              <Typography variant="body1" fontWeight={700}>
                BandAudit
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {audit.agents.length} lanes
              </Typography>
            </Box>
            <ChevronsUpDown size={16} />
          </Stack>
        </Button>

        <Box component="nav" aria-label="Workspace">
          <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: { xs: "none", lg: "block" }, mb: 0.75 }}>
            Workspace
          </Typography>
          <List disablePadding sx={{ display: { xs: "grid", sm: "grid", lg: "block" }, gridTemplateColumns: { xs: "repeat(4, minmax(0, 1fr))", lg: "1fr" }, gap: 0.75 }}>
            {navItems.map((item) => (
              <ListItemButton
                selected={view === item.view}
                key={item.view}
                onClick={() => navigate(item.view)}
                aria-current={view === item.view ? "page" : undefined}
                sx={{
                  minHeight: 44,
                  border: "1px solid",
                  borderColor: view === item.view ? "divider" : "transparent",
                  borderRadius: 2,
                  color: view === item.view ? "text.primary" : "text.secondary",
                  bgcolor: view === item.view ? "background.paper" : "transparent",
                  boxShadow: view === item.view ? "inset 3px 0 0 #15722f, 0 1px 2px rgba(32,33,36,0.06)" : "none",
                  "&.Mui-selected": { bgcolor: "background.paper" },
                  "&.Mui-selected:hover, &:hover": { bgcolor: "background.paper" },
                  px: { xs: 1, lg: 1.75 }
                }}
              >
                <ListItemIcon sx={{ minWidth: 30, color: "inherit" }}>{item.icon}</ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{ variant: "body2", fontWeight: view === item.view ? 600 : 500, noWrap: true }}
                />
              </ListItemButton>
            ))}
          </List>
        </Box>

        <Box sx={{ display: { xs: "none", md: "block" } }}>
          <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: "block", mb: 0.75 }}>
            Current audit
          </Typography>
          <Paper variant="outlined" sx={{ p: 1.5 }}>
            <Stack direction="row" spacing={1.25} alignItems="flex-start">
              <FileSearch size={17} color="#15722f" />
              <Box sx={{ minWidth: 0 }}>
                <Typography variant="body2" fontWeight={600} noWrap>
                  {audit.input_packet.target_name}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  Decision: {decisionLabels[audit.decision]}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  Room: {shortRoomId(audit.room_id)}
                </Typography>
              </Box>
            </Stack>
          </Paper>
        </Box>

        <Box sx={{ display: { xs: "none", md: "block" } }}>
          <Typography variant="caption" color="text.secondary" fontWeight={600} sx={{ display: "block", mb: 1 }}>
            Watchlist
          </Typography>
          <Stack spacing={1.25}>
            {sidebarMarkers.map((marker) => {
              const color = marker.tone === "danger" ? "#f04438" : marker.tone === "success" ? "#42c768" : "#6d5dfc";
              return (
                <Stack direction="row" alignItems="center" spacing={1.2} key={marker.label}>
                  <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: color }} />
                  <Typography variant="body2" fontWeight={600} sx={{ minWidth: 0, flex: 1 }} noWrap>
                    {marker.label}
                  </Typography>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    {marker.value}
                  </Typography>
                </Stack>
              );
            })}
          </Stack>
        </Box>

        <Box sx={{ minHeight: 0, flex: 1, display: { xs: "none", lg: "flex" }, flexDirection: "column" }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
            <Typography variant="caption" color="text.secondary" fontWeight={600}>
              Live lanes
            </Typography>
            <Bot size={14} />
          </Stack>
          <AgentList agents={audit.agents} audit={audit} />
        </Box>

        <Divider sx={{ display: { xs: "none", lg: "block" } }} />
        <Stack direction="row" alignItems="center" spacing={1.25} sx={{ display: { xs: "none", lg: "flex" } }}>
          <Avatar sx={{ width: 42, height: 42, bgcolor: "primary.light", color: "primary.main" }}>
            <UserRound size={18} />
          </Avatar>
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography variant="body2" fontWeight={600} noWrap>
              Audit Operator
            </Typography>
            <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
              {providerLabel(audit)}
            </Typography>
          </Box>
          <ChevronsUpDown size={15} />
        </Stack>
      </Paper>

      <Box component="main" sx={{ minWidth: 0, p: { xs: 1.5, md: 3.5 } }}>
        <Stack
          component="header"
          direction={{ xs: "column", md: "row" }}
          alignItems={{ xs: "stretch", md: "flex-start" }}
          justifyContent="space-between"
          spacing={2.5}
          sx={{ mb: { xs: 1.5, md: 2.75 } }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="overline" color="text.secondary" fontWeight={600}>
              Agent release board
            </Typography>
            <Typography variant="h1" sx={{ mt: 0.4 }}>
              {audit.title}
            </Typography>
            <Typography color="text.secondary" sx={{ display: { xs: "none", md: "block" }, mt: 0.75 }}>
              {audit.subject}
            </Typography>
            <Stack direction="row" flexWrap="wrap" gap={1.25} sx={{ display: { xs: "none", md: "flex" }, mt: 1.5 }} title={audit.room_id}>
              {[`Room ${shortRoomId(audit.room_id)}`, sourceLabel(audit), `${audit.events.length} events`, providerLabel(audit), decisionLabels[audit.decision]].map((item) => (
                <Chip key={item} label={item} size="small" variant="outlined" />
              ))}
            </Stack>
          </Box>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1} sx={{ display: { xs: "none", md: "flex" }, width: { xs: "100%", md: "auto" } }}>
            <Button variant="outlined" color="inherit" onClick={() => navigate("protocol")} startIcon={<GitBranch size={15} />}>
              View protocol
            </Button>
            <Button variant="outlined" color="inherit" onClick={() => navigate("timeline")} startIcon={<CalendarDays size={15} />}>
              Open timeline
            </Button>
            <Button variant="contained" onClick={() => navigate("report")} startIcon={<FileText size={15} />}>
              View release report
            </Button>
            <IconButton
              aria-label="More actions"
              aria-controls={actionsOpen ? "app-actions-menu" : undefined}
              aria-haspopup="menu"
              aria-expanded={actionsOpen ? "true" : undefined}
              onClick={(event) => setActionsAnchor(event.currentTarget)}
              sx={{ border: "1px solid", borderColor: "divider", bgcolor: "background.paper" }}
            >
              <MoreVertical size={17} />
            </IconButton>
            <Menu
              id="app-actions-menu"
              anchorEl={actionsAnchor}
              open={actionsOpen}
              onClose={() => setActionsAnchor(null)}
              anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
              transformOrigin={{ vertical: "top", horizontal: "right" }}
            >
              <MenuItem onClick={resetFromMenu} disabled={busy}>
                <RefreshCcw size={14} />
                <Box component="span" sx={{ ml: 1 }}>
                  Reset review
                </Box>
              </MenuItem>
            </Menu>
          </Stack>
        </Stack>

        {actionError && (
          <Paper variant="outlined" role="alert" sx={{ display: "flex", alignItems: "flex-start", gap: 1, p: 1.5, mb: 2, bgcolor: "error.light", borderColor: "error.main", color: "error.main" }}>
            <CircleAlert size={16} />
            <Typography variant="body2" fontWeight={700}>
              {actionError}
            </Typography>
          </Paper>
        )}

        {view === "review" && (
          <ReviewView
            audit={audit}
            selectedFinding={selectedFinding}
            selectedClaimId={selectedClaimId}
            onSelectClaim={onSelectClaim}
            navigate={navigate}
            onPrepareReReview={onPrepareReReview}
            onAdvance={onAdvance}
            runState={reviewRunState}
            busy={busy}
          />
        )}
        {view === "protocol" && <ProtocolView audit={audit} onAdvance={onAdvance} busy={busy} />}
        {view === "timeline" && <AuditTimeline audit={audit} />}
        {view === "report" && <ReportPage audit={audit} navigate={navigate} />}
      </Box>
    </Box>
  );
}

function App() {
  const [audit, setAudit] = useState<AuditState | null>(null);
  const [selectedClaimId, setSelectedClaimId] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<ViewMode>(() => viewFromPath(window.location.pathname));
  const [setupMode, setSetupMode] = useState<SetupMode>("sample");
  const [recentReviews, setRecentReviews] = useState<RecentReview[]>(() => loadRecentReviews());
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reviewRunState, setReviewRunState] = useState<ReviewRunState>(idleReviewRunState);

  function navigate(view: ViewMode) {
    const nextPath = routes[view];
    if (window.location.pathname !== nextPath) {
      window.history.pushState(null, "", nextPath);
    }
    setActiveView(view);
  }

  async function refresh() {
    try {
      setError(null);
      const next = auditWithPacketDefaults(await getAudit());
      setAudit(next);
      setSelectedClaimId((current) => nextSelectedClaimId(current, next.findings));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown request failure");
    } finally {
      setLoading(false);
    }
  }

  async function handleAdvance() {
    try {
      setBusy(true);
      setActionError(null);
      const retryStage = audit ? nextRunStageForAudit(audit) : "packet_locked";
      setReviewRunState((current) =>
        current.error
          ? {
              ...current,
              active: true,
              stage: retryStage,
              completedStages: audit ? completedRunStagesForAudit(audit) : current.completedStages,
              message: "Retrying the next provider event.",
              error: null
            }
          : current
      );
      const response = await advanceAudit();
      const nextAudit = auditWithPacketDefaults(response.audit);
      setAudit(nextAudit);
      setSelectedClaimId((current) => nextSelectedClaimId(current, nextAudit.findings));
      setReviewRunState((current) =>
        current.active
          ? {
              active: false,
              stage: nextRunStageForAudit(nextAudit),
              message: response.appended_events.length
                ? "Retry succeeded; the next Band event was published."
                : "Retry completed; no new Band event was appended.",
              completedStages: completedRunStagesForAudit(nextAudit),
              appendedEvents: current.appendedEvents + response.appended_events.length,
              error: null
            }
          : current
      );
    } catch (error) {
      const message = errorMessage(error, "Could not advance the audit.");
      let latestAudit: AuditState | null = null;
      try {
        latestAudit = auditWithPacketDefaults(await getAudit());
        setAudit(latestAudit);
        setSelectedClaimId((current) => nextSelectedClaimId(current, latestAudit?.findings ?? []));
      } catch {
      }
      setActionError(message);
      setReviewRunState((current) =>
        current.active
          ? {
              ...current,
              active: false,
              stage: latestAudit ? nextRunStageForAudit(latestAudit) : audit ? nextRunStageForAudit(audit) : current.stage,
              completedStages: latestAudit ? completedRunStagesForAudit(latestAudit) : audit ? completedRunStagesForAudit(audit) : current.completedStages,
              error: message
            }
          : current
      );
    } finally {
      setBusy(false);
    }
  }

  async function handleReset() {
    try {
      setBusy(true);
      setActionError(null);
      const response = auditWithPacketDefaults(await resetAudit());
      setAudit(response);
      setSelectedClaimId(topFinding(response.findings)?.claim_id ?? null);
    } catch (error) {
      setActionError(errorMessage(error, "Could not reset the audit."));
    } finally {
      setBusy(false);
    }
  }

  async function handleConfigurePacket(packet: AuditPacket) {
    try {
      setBusy(true);
      setActionError(null);
      const response = auditWithPacketDefaults(await configureAuditPacket(packet));
      setAudit(response);
      setSelectedClaimId(topFinding(response.findings)?.claim_id ?? null);
    } catch (error) {
      setActionError(errorMessage(error, "Could not configure the audit packet."));
      throw error;
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateRoom() {
    try {
      setBusy(true);
      setActionError(null);
      const response = await createAuditRoom();
      const nextAudit = auditWithPacketDefaults(response.audit);
      setAudit(nextAudit);
      setSelectedClaimId(null);
      return { ...response, audit: nextAudit };
    } catch (error) {
      setActionError(errorMessage(error, "Could not create an audit room."));
      throw error;
    } finally {
      setBusy(false);
    }
  }

  async function handleStartReview(packet: AuditPacket, roomMode: ReviewRoomMode) {
    let appendedEvents = 0;
    try {
      setBusy(true);
      setActionError(null);
      setReviewRunState({
        active: true,
        stage: "packet_locked",
        message: roomMode === "fresh" ? "Creating a fresh Band room for the locked packet." : "Locking packet into the current empty Band room.",
        completedStages: [],
        appendedEvents: 0,
        error: null
      });

      if (roomMode === "fresh") {
        const room = await createAuditRoom();
        setAudit(auditWithPacketDefaults(room.audit));
        setSelectedClaimId(null);
      }

      const configured = auditWithPacketDefaults(await configureAuditPacket(packet));
      setAudit(configured);
      setSelectedClaimId(topFinding(configured.findings)?.claim_id ?? null);
      navigate("review");
      setReviewRunState({
        active: true,
        stage: "packet_locked",
        message: "Packet locked into Band. Starting the release-board event loop.",
        completedStages: ["packet_locked"],
        appendedEvents,
        error: null
      });

      let currentAudit = configured;
      for (let guard = 0; guard < 18; guard += 1) {
        if (currentAudit.phase === "complete") break;
        const stage = nextRunStageForAudit(currentAudit);
        setReviewRunState({
          active: true,
          stage,
          message: `Running ${runStageLabel(stage)} from Band event history.`,
          completedStages: completedRunStagesForAudit(currentAudit),
          appendedEvents,
          error: null
        });

        const response = await advanceAudit();
        appendedEvents += response.appended_events.length;
        currentAudit = auditWithPacketDefaults(response.audit);
        setAudit(currentAudit);
        setSelectedClaimId((current) => nextSelectedClaimId(current, currentAudit.findings));
        setReviewRunState({
          active: currentAudit.phase !== "complete",
          stage: nextRunStageForAudit(currentAudit),
          message: currentAudit.phase === "complete" ? "Decision synthesized from Band room events." : "Board event appended; reconstructing dashboard state.",
          completedStages: completedRunStagesForAudit(currentAudit),
          appendedEvents,
          error: null
        });

        if (response.appended_events.length === 0 || currentAudit.phase === "complete") break;
      }

      setReviewRunState((current) => ({
        ...current,
        active: false,
        stage: current.stage || "complete",
        message: current.message || "Review run finished."
      }));
    } catch (error) {
      const message = errorMessage(error, "Could not run the review board.");
      let latestAudit: AuditState | null = null;
      try {
        latestAudit = auditWithPacketDefaults(await getAudit());
        setAudit(latestAudit);
        setSelectedClaimId((current) => nextSelectedClaimId(current, latestAudit?.findings ?? []));
      } catch {
      }
      setActionError(message);
      setReviewRunState({
        active: false,
        stage: latestAudit ? nextRunStageForAudit(latestAudit) : "packet_locked",
        message: "",
        completedStages: latestAudit ? completedRunStagesForAudit(latestAudit) : [],
        appendedEvents,
        error: message
      });
      throw error;
    } finally {
      setBusy(false);
    }
  }

  function startSampleAudit() {
    setSetupMode("sample");
    navigate("setup");
  }

  function createCustomAudit() {
    setSetupMode("custom");
    navigate("setup");
  }

  function prepareReReview() {
    setSetupMode("re_review");
    navigate("setup");
  }

  useEffect(() => {
    void refresh();
  }, []);

  useEffect(() => {
    function handlePopState() {
      setActiveView(viewFromPath(window.location.pathname));
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  useEffect(() => {
    if (!audit || audit.events.length === 0) return;
    setRecentReviews((current) => {
      const next = mergeRecentReview(current, recentReviewFromAudit(audit));
      saveRecentReviews(next);
      return next;
    });
  }, [audit]);

  useEffect(() => {
    if (!audit) return;
    setSelectedClaimId((current) => nextSelectedClaimId(current, audit.findings));
  }, [audit]);

  const selectedFinding = useMemo(
    () => {
      if (!audit) return undefined;
      return audit.findings.find((finding) => finding.claim_id === selectedClaimId) ?? topFinding(audit.findings);
    },
    [audit, selectedClaimId]
  );

  if (loading) {
    return <div className="boot">Loading BandAudit workspace</div>;
  }

  if (error || !audit) {
    return (
      <div className="boot error">
        <strong>Backend unavailable</strong>
        <span>{error ?? "Audit state was not returned."}</span>
      </div>
    );
  }

  if (activeView === "landing") {
    return (
      <LandingPage
        audit={audit}
        recentReviews={recentReviews}
        navigate={navigate}
        onStartSample={startSampleAudit}
        onCreateCustom={createCustomAudit}
      />
    );
  }

  if (activeView === "setup") {
    return (
      <SetupPage
        audit={audit}
        navigate={navigate}
        onStartReview={handleStartReview}
        onCreateRoom={handleCreateRoom}
        busy={busy}
        initialMode={setupMode}
      />
    );
  }

  return (
    <AppShell
      audit={audit}
      view={activeView}
      selectedFinding={selectedFinding}
      selectedClaimId={selectedClaimId}
      onSelectClaim={setSelectedClaimId}
      navigate={navigate}
      onAdvance={handleAdvance}
      onPrepareReReview={prepareReReview}
      onReset={handleReset}
      reviewRunState={reviewRunState}
      busy={busy}
      actionError={actionError}
    />
  );
}

export default App;
