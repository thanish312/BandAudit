import type { AgentProfile, AuditEvent, AuditState, Decision, EvidenceManifestItem, EvidenceRef, Finding, PacketImportSummary, Severity } from "../types/audit";

export type ReportTone = "success" | "danger" | "warning" | "neutral";

export type ReportEvidence = {
  id: string;
  title: string;
  artifact: string;
  artifactName: string;
  source: string;
  extractionMethod: string;
  locator: string;
  sha256: string;
  warningState: string;
  citationState: string;
};

export type ReportFinding = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  severityLabel: string;
  status: Finding["status"];
  statusLabel: string;
  releaseEffect: string;
  evidenceState: string;
  owner: string;
  confidencePercent: number;
  impact: string;
  summary: string;
  riskMechanism: string;
  trace: string;
  evidence: ReportEvidence[];
  remediation: string[];
  verificationNotes: string[];
};

export type ReportVote = {
  agent: string;
  vote: string;
  rationale: string;
};

export type ReportProvider = {
  provider: "aiml" | "featherless";
  label: string;
  status: string;
  statusLabel: string;
  model: string;
  use: string;
  agents: string[];
  routes: ReportProviderRoute[];
};

export type ReportProviderRoute = {
  agent: string;
  model: string;
  purpose: string;
};

export type ReportAgent = {
  name: string;
  role: string;
  status: AgentProfile["status"];
  statusLabel: string;
};

export type ReportEvent = {
  id: string;
  sequence: string;
  type: string;
  agent: string;
  provider: string;
  model: string;
  claimId: string;
  phase: string;
  summary: string;
  time: string;
  consumedRefs: string[];
  producedRefs: string[];
  findingRefs: string[];
  voteRefs: string[];
  evidenceRefs: string[];
};

export type ReportIntegrity = {
  bandRoomId: string;
  packetSource: string;
  packetVersion: string;
  eventCount: number;
  evidenceLinkCount: number;
  artifactHashes: string[];
  structuredOutputRepairCount: number;
  finalSynthesisEventId: string;
};

export type ReportRoomManifest = {
  roomPurpose: string;
  participantStrategy: string;
  humanReviewers: string[];
  peerRecruitmentEnabled: boolean;
  recruitedPeerCount: number;
};

export type ReportLane = {
  lane: string;
  agent: string;
  role: string;
  provider: string;
  model: string;
  latestEvent: string;
  eventCount: number;
  participantMode: string;
};

export type AuditReportModel = {
  fileBaseName: string;
  generatedAtIso: string;
  generatedAtLabel: string;
  target: {
    name: string;
    summary: string;
    owner: string;
    deployment: string;
    affectedUsers: string;
    releaseGoal: string;
  };
  decision: {
    value: Decision;
    label: string;
    tone: ReportTone;
    verdict: string;
    rationale: string;
  };
  risk: {
    score: number;
    level: Severity;
    levelLabel: string;
    blockerCount: number;
    evidenceLinkCount: number;
    eventCount: number;
  };
  providers: ReportProvider[];
  agents: ReportAgent[];
  integrity: ReportIntegrity;
  roomManifest: ReportRoomManifest;
  laneRoster: ReportLane[];
  votes: ReportVote[];
  findings: ReportFinding[];
  evidence: ReportEvidence[];
  requiredRemediations: string[];
  reReviewCriteria: string[];
  eventTrace: string[];
  events: ReportEvent[];
  summaryText: string;
  jsonPayload: Record<string, unknown>;
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

const decisionLabels: Record<Decision, string> = {
  pending: "Pending review",
  approved: "Release approved",
  conditionally_approved: "Conditional release",
  blocked: "Release hold"
};

function recommendation(audit: AuditState): { label: string; tone: ReportTone; reason: string } {
  if (audit.decision === "blocked") {
    const primaryFinding = [...audit.findings].sort((a, b) => severityRank[b.severity] - severityRank[a.severity])[0];
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

function titleCase(value: string) {
  return value
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

function artifactFileName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
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

function routeProvider(audit: AuditState, agentName: string) {
  return audit.agent_execution.routes.find((route) => route.agent === agentName)?.provider ?? null;
}

function routeModel(audit: AuditState, agentName: string) {
  return audit.agent_execution.routes.find((route) => route.agent === agentName)?.model ?? null;
}

function eventProvider(audit: AuditState, event: AuditEvent) {
  return event.provider ?? routeProvider(audit, event.agent);
}

function eventModel(audit: AuditState, event: AuditEvent) {
  const metadataModel = event.metadata.provider_model;
  if (typeof metadataModel === "string" && metadataModel.trim()) return metadataModel;
  return routeModel(audit, event.agent) ?? "Model not recorded";
}

function routeModelSummary(routes: Array<{ model: string | null }>) {
  const models = Array.from(new Set(routes.map((route) => route.model).filter((model): model is string => Boolean(model))));
  if (!models.length) return "No model configured";
  if (models.length <= 2) return models.join(", ");
  return `${models.slice(0, 2).join(", ")} +${models.length - 2}`;
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function roomManifest(audit: AuditState) {
  const initEvent = audit.events.find((event) => event.event_type === "audit_init" && objectRecord(event.metadata.band_room_manifest));
  return objectRecord(initEvent?.metadata.band_room_manifest) ?? null;
}

function manifestString(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function manifestBool(value: unknown) {
  return value === true;
}

function manifestStringArray(value: unknown) {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())) : [];
}

function participantStrategyLabel(value: string) {
  if (value === "band_peer_recruited_lanes") return "Band peer recruited lanes";
  if (value === "single_band_agent_with_structured_release_board_lanes") {
    return "Single Band agent with structured release-board lanes";
  }
  return titleCase(value || "structured_release_board_lanes");
}

function participantModeLabel(value: string) {
  if (value === "recruited_band_peer") return "Recruited Band peer";
  if (value === "structured_lane") return "Declared structured lane";
  return titleCase(value || "structured_lane");
}

function providerLabel(value: unknown) {
  if (value === "aiml") return "AI/ML API";
  if (value === "featherless") return "Featherless";
  return manifestString(value, "Provider lane");
}

function latestLaneEvent(audit: AuditState, agent: string) {
  const matching = audit.events.filter((event) => event.agent === agent);
  const latest = matching[matching.length - 1];
  return {
    label: latest ? `${eventNumberById(audit.events, latest.event_id)} ${protocolEventName(latest)}` : "No Band event yet",
    count: matching.length
  };
}

function releaseBoardRoster(audit: AuditState): ReportLane[] {
  const manifest = roomManifest(audit);
  const manifestLanes = Array.isArray(manifest?.release_board_lanes)
    ? manifest.release_board_lanes.map(objectRecord).filter((lane): lane is Record<string, unknown> => Boolean(lane))
    : [];
  const agentRoles = new Map(audit.agents.map((agent) => [agent.name, agent.role]));
  const fallbackRoutes = audit.agent_execution.routes.map((route) => ({
    lane: route.agent.replace(/Agent$/, "").replace(/([a-z])([A-Z])/g, "$1 $2"),
    agent: route.agent,
    role: route.purpose,
    provider: route.provider,
    model: route.model ?? "",
    participant_mode: "structured_lane"
  }));
  const rows = manifestLanes.length ? manifestLanes : fallbackRoutes;

  return rows.map((lane) => {
    const agent = manifestString(lane.agent, "Unassigned");
    const latest = latestLaneEvent(audit, agent);
    const model = manifestString(lane.model, routeModel(audit, agent) ?? "Model not recorded");
    return {
      lane: manifestString(lane.lane, agent),
      agent,
      role: manifestString(lane.role, agentRoles.get(agent) ?? "Release-board lane"),
      provider: providerLabel(lane.provider),
      model,
      latestEvent: latest.label,
      eventCount: latest.count,
      participantMode: participantModeLabel(manifestString(lane.participant_mode, "structured_lane"))
    };
  });
}

function reportRoomManifest(audit: AuditState): ReportRoomManifest {
  const manifest = roomManifest(audit);
  const recruitedPeers = Array.isArray(manifest?.recruited_peers)
    ? manifest.recruited_peers.map(objectRecord).filter((peer): peer is Record<string, unknown> => Boolean(peer))
    : [];
  const recruitedPeerCount = recruitedPeers.filter((peer) => peer.status === "recruited").length;

  return {
    roomPurpose: manifestString(manifest?.room_purpose, "Canonical Band release-board room for packet review."),
    participantStrategy: participantStrategyLabel(manifestString(manifest?.participant_strategy, "single_band_agent_with_structured_release_board_lanes")),
    humanReviewers: manifestStringArray(manifest?.human_reviewers),
    peerRecruitmentEnabled: manifestBool(manifest?.peer_recruitment_enabled),
    recruitedPeerCount
  };
}

function traceabilityCount(audit: AuditState) {
  return audit.findings.reduce((total, finding) => total + finding.evidence_refs.length, 0);
}

function sourceModeLabel(value: string) {
  if (value === "pdf_packet") return "PDF packet";
  if (value === "re_review") return "Re-review";
  return "Manual packet";
}

function importArtifacts(audit: AuditState) {
  return [audit.input_packet.import_summary, ...(audit.input_packet.supporting_evidence_imports ?? [])]
    .map((summary) => summary.artifact)
    .filter((artifact): artifact is NonNullable<PacketImportSummary["artifact"]> => Boolean(artifact));
}

function reportIntegrity(audit: AuditState): ReportIntegrity {
  const synthesis = [...audit.events].reverse().find((event) => event.event_type === "synthesis_report");
  return {
    bandRoomId: audit.room_id,
    packetSource: sourceModeLabel(audit.input_packet.packet_source_mode || "manual"),
    packetVersion: audit.input_packet.packet_version || "v1",
    eventCount: audit.events.length,
    evidenceLinkCount: traceabilityCount(audit),
    artifactHashes: Array.from(new Set(importArtifacts(audit).map((artifact) => artifact.sha256).filter(Boolean))),
    structuredOutputRepairCount: audit.events.filter((event) => event.metadata.structured_output_repair_attempted === true).length,
    finalSynthesisEventId: synthesis?.event_id ?? "Pending"
  };
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

function compactRefs(refs: string[], emptyLabel = "None") {
  if (!refs.length) return emptyLabel;
  if (refs.length <= 4) return refs.join(", ");
  return `${refs.slice(0, 4).join(", ")} +${refs.length - 4}`;
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

function eventFindingRefs(event: AuditEvent) {
  const refs = new Set<string>(event.finding_refs ?? []);
  if (event.claim_id) refs.add(event.claim_id);
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

function formatEventTime(event: AuditEvent) {
  return new Date(event.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function findingTrace(finding: Finding, events: AuditEvent[]) {
  const evidence = evidenceIds(finding.evidence_refs);
  const eventNumbers = events
    .filter((event) => event.claim_id === finding.claim_id)
    .map((event) => eventNumberById(events, event.event_id));
  return `${finding.claim_id} -> ${compactRefs(evidence)} -> Events ${compactRefs(eventNumbers, "pending")}`;
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

function agentStatusLabel(value: AgentProfile["status"]) {
  if (value === "complete") return "Contribution captured";
  if (value === "active") return "Active";
  if (value === "blocked") return "Blocked";
  return "Idle";
}

function evidenceManifestByRef(audit: AuditState) {
  return new Map(audit.input_packet.evidence_manifest.map((item) => [item.ref_id, item]));
}

function evidenceRefFromManifest(item: EvidenceManifestItem): EvidenceRef {
  return {
    ref_id: item.ref_id,
    title: item.title,
    artifact: item.artifact,
    locator: item.locator,
    sha256: item.sha256
  };
}

function importForEvidence(audit: AuditState, evidence: EvidenceRef, manifest?: EvidenceManifestItem): PacketImportSummary | undefined {
  const imports = [audit.input_packet.import_summary, ...(audit.input_packet.supporting_evidence_imports ?? [])].filter(
    (summary) => summary.artifact
  );
  return imports.find((summary) => {
    const artifact = summary.artifact;
    if (!artifact) return false;
    return (
      Boolean(evidence.sha256 && artifact.sha256 === evidence.sha256) ||
      Boolean(manifest?.sha256 && artifact.sha256 === manifest.sha256) ||
      artifact.filename === evidence.artifact ||
      artifact.filename === manifest?.artifact
    );
  });
}

function evidenceModel(evidence: EvidenceRef, audit: AuditState): ReportEvidence {
  const manifest = evidenceManifestByRef(audit).get(evidence.ref_id);
  const sourceImport = importForEvidence(audit, evidence, manifest);
  const warnings = sourceImport?.warnings.length ?? 0;
  const citations = sourceImport?.citations.length ?? 0;
  return {
    id: evidence.ref_id,
    title: manifest?.title || evidence.title,
    artifact: manifest?.artifact || evidence.artifact,
    artifactName: artifactFileName(manifest?.artifact || evidence.artifact),
    source: manifest?.source || sourceImport?.source || "Band event",
    extractionMethod: sourceImport?.artifact?.extraction_method || "packet",
    locator: manifest?.locator || evidence.locator,
    sha256: manifest?.sha256 || evidence.sha256,
    warningState: warnings ? `${warnings} warning${warnings === 1 ? "" : "s"}` : "No warnings",
    citationState: citations ? `${citations} citation${citations === 1 ? "" : "s"}` : "No citations"
  };
}

function uniqueEvidenceRefs(audit: AuditState) {
  const findingRefs = audit.findings.flatMap((finding) => finding.evidence_refs);
  const manifestRefs = audit.input_packet.evidence_manifest.map(evidenceRefFromManifest);
  return Array.from(new Map([...findingRefs, ...manifestRefs].map((evidence) => [evidence.ref_id, evidence])).values());
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function safeFileBaseName(name: string) {
  const cleaned = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `bandaudit-${cleaned || "release"}-report`;
}

export function buildAuditReportModel(audit: AuditState, generatedAt = new Date()): AuditReportModel {
  const rec = recommendation(audit);
  const sortedFindings = [...audit.findings].sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  const evidence = uniqueEvidenceRefs(audit).map((item) => evidenceModel(item, audit));
  const requiredRemediations = uniqueStrings(audit.report?.required_remediations ?? sortedFindings.flatMap((finding) => finding.remediation));
  const reReviewCriteria = uniqueStrings(audit.report?.re_review_criteria ?? []);
  const eventTrace =
    audit.report?.event_trace ??
    audit.events.map((event) => `${formatEventTime(event)} ${protocolEventName(event)} by ${event.agent}`);
  const releaseVerdict = audit.report?.release_verdict ?? `${audit.input_packet.target_name} is under release review.`;
  const rationale = audit.report?.executive_summary ?? rec.reason;
  const generatedAtLabel = generatedAt.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });

  const findings: ReportFinding[] = sortedFindings.map((finding) => ({
    id: finding.claim_id,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    severityLabel: severityLabels[finding.severity],
    status: finding.status,
    statusLabel: titleCase(finding.status),
    releaseEffect: findingReleaseEffect(finding),
    evidenceState: findingEvidenceState(finding),
    owner: finding.owner_agent,
    confidencePercent: Math.round(finding.confidence * 100),
    impact: finding.release_impact || "Under review",
    summary: finding.summary,
    riskMechanism: finding.risk_mechanism,
    trace: findingTrace(finding, audit.events),
    evidence: finding.evidence_refs.map((item) => evidenceModel(item, audit)),
    remediation: finding.remediation,
    verificationNotes: finding.verification_notes
  }));

  const providers: ReportProvider[] = audit.agent_execution.providers.map((provider) => {
    const routes = audit.agent_execution.routes.filter((route) => route.provider === provider.provider);
    return {
      provider: provider.provider,
      label: provider.label,
      status: provider.status,
      statusLabel: titleCase(provider.status),
      model: routeModelSummary(routes),
      use: providerUseSummary(provider.provider),
      agents: routes.map((route) => route.agent),
      routes: routes.map((route) => ({
        agent: route.agent,
        model: route.model ?? provider.model ?? "No model configured",
        purpose: route.purpose
      }))
    };
  });

  const agents = audit.agents.map((agent) => ({
    name: agent.name,
    role: agent.role,
    status: agent.status,
    statusLabel: agentStatusLabel(agent.status)
  }));

  const votes = audit.votes.map((voteRecord) => ({
    agent: voteRecord.agent,
    vote: voteRecord.vote === "block" ? "Hold" : titleCase(voteRecord.vote),
    rationale: voteRecord.rationale
  }));
  const integrity = reportIntegrity(audit);
  const manifest = reportRoomManifest(audit);
  const laneRoster = releaseBoardRoster(audit);

  const events = audit.events.map((event) => {
    const provider = eventProvider(audit, event);
    return {
      id: event.event_id,
      sequence: eventNumberById(audit.events, event.event_id),
      type: protocolEventName(event),
      agent: event.agent,
      provider: provider ? providerName(provider) : "Provider lane",
      model: eventModel(audit, event),
      claimId: event.claim_id ?? "None",
      phase: titleCase(event.phase),
      summary: event.summary,
      time: formatEventTime(event),
      consumedRefs: eventConsumedRefs(event, audit.events),
      producedRefs: eventProducedRefs(event),
      findingRefs: eventFindingRefs(event),
      voteRefs: eventVoteRefs(event),
      evidenceRefs: evidenceIds(event.evidence_refs)
    };
  });

  const summaryText = [
    "BandAudit Release Report",
    `Target system: ${audit.input_packet.target_name} - ${audit.input_packet.target_summary}`,
    `Decision: ${rec.label}`,
    `Release verdict: ${releaseVerdict}`,
    `Executive rationale: ${rationale}`,
    `Traceability: ${audit.events.length} Band room events, ${traceabilityCount(audit)} evidence links`
  ].join("\n");

  const jsonPayload = {
    target_system: audit.input_packet,
    decision: audit.decision,
    decision_label: rec.label,
    risk_score: audit.risk_score,
    risk_level: audit.risk_level,
    release_verdict: releaseVerdict,
    executive_rationale: rationale,
    findings: sortedFindings,
    evidence,
    agent_participation: agents,
    vote_records: audit.votes,
    provider_execution: {
      source_mode: audit.source.effective_mode,
      agent_mode: audit.agent_execution.effective_mode,
      providers,
      routes: audit.agent_execution.routes,
      last_error: audit.agent_execution.last_error
    },
    audit_integrity: integrity,
    band_room_manifest: manifest,
    release_board_roster: laneRoster,
    supporting_evidence_imports: audit.input_packet.supporting_evidence_imports,
    required_remediation: requiredRemediations,
    re_review_criteria: reReviewCriteria,
    band_events: events
  };

  return {
    fileBaseName: safeFileBaseName(audit.input_packet.target_name),
    generatedAtIso: generatedAt.toISOString(),
    generatedAtLabel,
    target: {
      name: audit.input_packet.target_name,
      summary: audit.input_packet.target_summary,
      owner: audit.input_packet.business_owner || "Not supplied",
      deployment: audit.input_packet.deployment_environment || "Not supplied",
      affectedUsers: audit.input_packet.affected_users || "Not supplied",
      releaseGoal: audit.input_packet.release_goal || "Not supplied"
    },
    decision: {
      value: audit.decision,
      label: rec.label,
      tone: rec.tone,
      verdict: releaseVerdict,
      rationale
    },
    risk: {
      score: audit.risk_score,
      level: audit.risk_level,
      levelLabel: severityLabels[audit.risk_level],
      blockerCount: sortedFindings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length,
      evidenceLinkCount: traceabilityCount(audit),
      eventCount: audit.events.length
    },
    providers,
    agents,
    integrity,
    roomManifest: manifest,
    laneRoster,
    votes,
    findings,
    evidence,
    requiredRemediations,
    reReviewCriteria,
    eventTrace,
    events,
    summaryText,
    jsonPayload
  };
}
