import type { AuditReportModel } from "./reportModel";

export function buildReportMarkdown(report: AuditReportModel) {
  const lines = [
    "# BandAudit Release Report",
    "",
    `Generated: ${report.generatedAtLabel}`,
    "",
    "## Target system",
    `${report.target.name} - ${report.target.summary}`,
    "",
    `Owner: ${report.target.owner}`,
    `Deployment: ${report.target.deployment}`,
    `Affected users: ${report.target.affectedUsers}`,
    `Release goal: ${report.target.releaseGoal}`,
    "",
    "## Release decision",
    report.decision.label,
    "",
    report.decision.verdict,
    "",
    "## Executive rationale",
    report.decision.rationale,
    "",
    "## Risk summary",
    `Risk score: ${report.risk.score}`,
    `Risk level: ${report.risk.levelLabel}`,
    `Open blockers: ${report.risk.blockerCount}`,
    `Evidence links: ${report.risk.evidenceLinkCount}`,
    `Band events: ${report.risk.eventCount}`,
    "",
    "## Audit integrity",
    `Band room: ${report.integrity.bandRoomId}`,
    `Packet source: ${report.integrity.packetSource}`,
    `Packet version: ${report.integrity.packetVersion}`,
    `Room purpose: ${report.roomManifest.roomPurpose}`,
    `Participant strategy: ${report.roomManifest.participantStrategy}`,
    `Human reviewers: ${report.roomManifest.humanReviewers.length ? report.roomManifest.humanReviewers.join(", ") : "None declared"}`,
    `Recruited Band peers: ${report.roomManifest.recruitedPeerCount}`,
    `Structured-output repairs: ${report.integrity.structuredOutputRepairCount}`,
    `Final synthesis event: ${report.integrity.finalSynthesisEventId}`,
    `Artifact hashes: ${report.integrity.artifactHashes.length ? report.integrity.artifactHashes.join(", ") : "None recorded"}`,
    "",
    "## Release board roster",
    ...report.laneRoster.map(
      (lane) =>
        `- ${lane.lane} (${lane.agent}): ${lane.provider} / ${lane.model}; ${lane.participantMode}; latest ${lane.latestEvent}; ${lane.eventCount} event${lane.eventCount === 1 ? "" : "s"}`
    ),
    "",
    "## Provider execution",
    ...report.providers.flatMap((provider) => [
      `### ${provider.label}`,
      `Status: ${provider.statusLabel}`,
      `Model policy: ${provider.model}`,
      `Use: ${provider.use}`,
      `Agent routes: ${provider.routes.map((route) => `${route.agent}: ${route.model}`).join("; ") || "No agents routed"}`,
      ""
    ]),
    "## Release-board lanes and vote records",
    `Release-board lanes: ${report.agents.length}`,
    `Vote records: ${report.votes.length}`,
    "",
    ...report.votes.map((voteRecord) => `- ${voteRecord.agent}: ${voteRecord.vote} - ${voteRecord.rationale}`),
    "",
    "## Findings",
    ...report.findings.flatMap((finding) => [
      "",
      `### ${finding.id} ${finding.severityLabel} - ${finding.title}`,
      `Status: ${finding.statusLabel}`,
      `Release effect: ${finding.releaseEffect}`,
      `Evidence state: ${finding.evidenceState}`,
      `Owner agent: ${finding.owner}`,
      `Confidence: ${finding.confidencePercent}%`,
      `Release impact: ${finding.impact}`,
      `Trace: ${finding.trace}`,
      "",
      finding.summary,
      "",
      `Risk mechanism: ${finding.riskMechanism}`,
      "",
      "Evidence:",
      ...finding.evidence.map((evidence) => `- ${evidence.id} ${evidence.artifactName} - ${evidence.locator} - ${evidence.extractionMethod} - ${evidence.warningState}`),
      "",
      "Verification notes:",
      ...(finding.verificationNotes.length ? finding.verificationNotes : ["No independent verification notes have been recorded yet."]).map(
        (note) => `- ${note}`
      ),
      "",
      "Required remediation:",
      ...(finding.remediation.length ? finding.remediation : ["No remediation has been synthesized yet."]).map((item) => `- ${item}`)
    ]),
    "",
    "## Evidence table",
    ...report.evidence.map((evidence) => `- ${evidence.id}: ${evidence.title} (${evidence.artifactName}; ${evidence.source}; ${evidence.extractionMethod}; ${evidence.locator}; SHA ${evidence.sha256 || "not supplied"}; ${evidence.warningState})`),
    "",
    "## Required remediation before release",
    ...(report.requiredRemediations.length ? report.requiredRemediations : ["No required remediations have been synthesized yet."]).map(
      (item, index) => `${index + 1}. ${item}`
    ),
    "",
    "## Re-review criteria",
    ...(report.reReviewCriteria.length ? report.reReviewCriteria : ["No re-review criteria have been synthesized yet."]).map(
      (item, index) => `${index + 1}. ${item}`
    ),
    "",
    "## Band event trace",
    ...report.events.map((event) => `- ${event.sequence} ${event.type} by ${event.agent} via ${event.provider} (${event.model}): ${event.summary}`)
  ];

  return lines.join("\n");
}
