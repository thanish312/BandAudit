import pdfMake from "pdfmake/build/pdfmake";
import pdfFonts from "pdfmake/build/vfs_fonts";
import type { Content, TDocumentDefinitions } from "pdfmake/interfaces";
import type { AuditReportModel, ReportFinding } from "./reportModel";

const vfsBundle = pdfFonts as {
  pdfMake?: { vfs: Record<string, string> };
  vfs?: Record<string, string>;
};

pdfMake.vfs = vfsBundle.pdfMake?.vfs ?? vfsBundle.vfs ?? (pdfFonts as Record<string, string>);

function empty(value: string) {
  return value.trim() || "Not supplied";
}

function paragraph(text: string, style = "body", margin: [number, number, number, number] = [0, 0, 0, 7]): Content {
  return { text: empty(text), style, margin } as Content;
}

function sectionTitle(text: string): Content {
  return { text, style: "sectionTitle", margin: [0, 18, 0, 7] } as Content;
}

function table(headers: string[], rows: string[][], widths?: Array<string | number>): Content {
  const body = [
    headers.map((header) => ({ text: header, style: "tableHeader" })),
    ...rows.map((row) => row.map((cell) => ({ text: empty(cell), style: "tableCell" })))
  ];

  return {
    table: {
      headerRows: 1,
      widths: widths ?? headers.map(() => "*"),
      body
    },
    layout: {
      hLineColor: () => "#E4E7EC",
      vLineColor: () => "#E4E7EC",
      hLineWidth: () => 0.6,
      vLineWidth: () => 0.6,
      paddingLeft: () => 7,
      paddingRight: () => 7,
      paddingTop: () => 6,
      paddingBottom: () => 6,
      fillColor: (rowIndex: number) => (rowIndex === 0 ? "#F9FAFB" : null)
    },
    margin: [0, 0, 0, 9]
  } as Content;
}

function findingRows(findings: ReportFinding[]) {
  return findings.map((finding) => [
    finding.id,
    finding.severityLabel,
    finding.statusLabel,
    finding.releaseEffect,
    String(finding.evidence.length),
    finding.owner,
    finding.title
  ]);
}

function findingEvidenceRows(finding: ReportFinding) {
  if (finding.evidence.length === 0) {
    return [["None", "No evidence linked", "Not supplied", "Not supplied", "None"]];
  }
  return finding.evidence.map((evidence) => [
    evidence.id,
    evidence.artifactName,
    evidence.locator,
    evidence.sha256 ? `${evidence.sha256.slice(0, 16)}...` : "Not supplied",
    evidence.warningState
  ]);
}

function findingDetailContent(report: AuditReportModel): Content[] {
  if (report.findings.length === 0) {
    return [sectionTitle("Finding detail appendix"), paragraph("No release-board findings have been recorded yet.")];
  }

  return [
    sectionTitle("Finding detail appendix"),
    paragraph("Each blocker below is tied to the Band event trace, cited evidence, verification notes, and concrete remediation expected before re-review."),
    ...report.findings.flatMap((finding) => [
      { text: `${finding.id} - ${finding.title}`, style: "findingTitle", margin: [0, 10, 0, 5] } as Content,
      table(
        ["Severity", "Status", "Effect", "Owner", "Confidence", "Evidence state"],
        [[finding.severityLabel, finding.statusLabel, finding.releaseEffect, finding.owner, `${finding.confidencePercent}%`, finding.evidenceState]],
        ["auto", "auto", "auto", "*", "auto", "auto"]
      ),
      table(["Release impact", "Trace"], [[finding.impact, finding.trace]], ["*", "*"]),
      paragraph(`Finding summary: ${finding.summary}`),
      paragraph(`Risk mechanism: ${finding.riskMechanism}`),
      table(["Ref", "Artifact", "Locator", "SHA-256", "Warnings"], findingEvidenceRows(finding), [28, "*", 90, 70, 52]),
      table(
        ["Verification notes"],
        (finding.verificationNotes.length ? finding.verificationNotes : ["No independent verification notes have been recorded yet."]).map((note) => [note]),
        ["*"]
      ),
      table(
        ["Required remediation"],
        (finding.remediation.length ? finding.remediation : ["No remediation has been synthesized yet."]).map((item) => [item]),
        ["*"]
      )
    ])
  ];
}

function remediationRows(report: AuditReportModel) {
  if (report.requiredRemediations.length === 0) {
    return [["1", "No required remediations have been synthesized yet."]];
  }
  return report.requiredRemediations.map((item, index) => [String(index + 1), item]);
}

function evidenceRows(report: AuditReportModel) {
  if (report.evidence.length === 0) {
    return [["None", "No evidence linked", "Not supplied", "Not supplied", "Not supplied", "Not supplied", "None"]];
  }
  return report.evidence.map((evidence) => [
    evidence.id,
    evidence.title,
    `${evidence.artifactName} (${evidence.source})`,
    evidence.extractionMethod,
    evidence.locator,
    evidence.sha256 ? `${evidence.sha256.slice(0, 16)}...` : "Not supplied",
    evidence.warningState
  ]);
}

function voteRows(report: AuditReportModel) {
  if (report.votes.length === 0) {
    return [["No vote records", "Pending", "The release board has not recorded a final vote."]];
  }
  return report.votes.map((vote) => [vote.agent, vote.vote, vote.rationale]);
}

function laneRows(report: AuditReportModel) {
  if (report.laneRoster.length === 0) {
    return [["No lanes recorded", "No agent", "No provider", "No model", "No participant mode", "No event"]];
  }
  return report.laneRoster.map((lane) => [
    lane.lane,
    lane.agent,
    lane.provider,
    lane.model,
    lane.participantMode,
    `${lane.latestEvent} (${lane.eventCount})`
  ]);
}

function eventRows(report: AuditReportModel) {
  if (report.events.length === 0) {
    return [["None", "No events", "No agent", "No provider", "No model", "No summary"]];
  }
  return report.events.map((event) => [event.sequence, event.type, event.agent, event.provider, event.model, event.summary]);
}

export function buildReportPdfDefinition(report: AuditReportModel): TDocumentDefinitions {
  const decisionTone = report.decision.tone === "danger" ? "danger" : report.decision.tone === "warning" ? "warning" : "success";

  return {
    pageSize: "A4",
    pageMargins: [42, 46, 42, 52],
    info: {
      title: `BandAudit Release Report - ${report.target.name}`,
      author: "BandAudit",
      subject: "Release-board decision report"
    },
    footer: (currentPage: number, pageCount: number) => ({
      columns: [
        { text: "BandAudit release report", style: "footer" },
        { text: `Page ${currentPage} of ${pageCount}`, alignment: "right", style: "footer" }
      ],
      margin: [42, 14, 42, 0]
    }),
    defaultStyle: {
      font: "Roboto",
      fontSize: 9.5,
      lineHeight: 1.35,
      color: "#101828"
    },
    styles: {
      eyebrow: { fontSize: 8, color: "#667085", bold: true, characterSpacing: 0.5 },
      title: { fontSize: 22, bold: true, color: "#101828", lineHeight: 1.1 },
      subtitle: { fontSize: 10, color: "#475467" },
      decision: { fontSize: 12, bold: true, color: "#101828" },
      danger: { color: "#B42318" },
      warning: { color: "#B54708" },
      success: { color: "#067647" },
      sectionTitle: { fontSize: 12, bold: true, color: "#101828" },
      findingTitle: { fontSize: 10.5, bold: true, color: "#101828" },
      body: { fontSize: 9.5, color: "#344054" },
      caption: { fontSize: 8, color: "#667085" },
      tableHeader: { fontSize: 8, bold: true, color: "#475467" },
      tableCell: { fontSize: 8.5, color: "#101828" },
      footer: { fontSize: 8, color: "#98A2B3" }
    },
    content: [
      { text: "BANDAUDIT RELEASE REPORT", style: "eyebrow", margin: [0, 0, 0, 5] },
      {
        columns: [
          {
            width: "*",
            stack: [
              { text: report.target.name, style: "title" },
              { text: report.target.summary, style: "subtitle", margin: [0, 4, 0, 0] }
            ]
          },
          {
            width: 130,
            stack: [
              { text: report.decision.label, style: ["decision", decisionTone], alignment: "right" },
              { text: `Risk ${report.risk.score} - ${report.risk.levelLabel}`, style: "caption", alignment: "right", margin: [0, 4, 0, 0] }
            ]
          }
        ],
        columnGap: 16,
        margin: [0, 0, 0, 14]
      } as Content,
      table(
        ["Generated", "Owner", "Deployment", "Affected users"],
        [[report.generatedAtLabel, report.target.owner, report.target.deployment, report.target.affectedUsers]],
        ["auto", "*", "*", "*"]
      ),
      sectionTitle("Executive decision"),
      paragraph(report.decision.verdict, "decision"),
      paragraph(report.decision.rationale),
      table(
        ["Risk score", "Risk level", "Open blockers", "Evidence links", "Band events"],
        [[String(report.risk.score), report.risk.levelLabel, String(report.risk.blockerCount), String(report.risk.evidenceLinkCount), String(report.risk.eventCount)]],
        ["auto", "auto", "auto", "auto", "auto"]
      ),
      sectionTitle("Audit integrity"),
      table(
        ["Band room", "Packet source", "Packet version", "Repairs", "Synthesis", "Artifact hashes"],
        [[
          report.integrity.bandRoomId,
          report.integrity.packetSource,
          report.integrity.packetVersion,
          String(report.integrity.structuredOutputRepairCount),
          report.integrity.finalSynthesisEventId,
          report.integrity.artifactHashes.length ? report.integrity.artifactHashes.map((hash) => `${hash.slice(0, 16)}...`).join("; ") : "None recorded"
        ]],
        [82, 58, 48, 38, 62, "*"]
      ),
      table(
        ["Room purpose", "Participant strategy", "Human reviewers", "Recruited peers"],
        [[
          report.roomManifest.roomPurpose,
          report.roomManifest.participantStrategy,
          report.roomManifest.humanReviewers.length ? report.roomManifest.humanReviewers.join("; ") : "None declared",
          String(report.roomManifest.recruitedPeerCount)
        ]],
        ["*", 115, 78, 52]
      ),
      sectionTitle("Release board roster"),
      table(["Lane", "Agent", "Provider", "Model", "Mode", "Latest Band event"], laneRows(report), [56, 70, 58, 105, 70, "*"]),
      sectionTitle("Release blockers"),
      table(["Finding", "Severity", "Status", "Effect", "Evidence", "Owner", "Title"], findingRows(report.findings), [45, 45, 55, 62, 42, 78, "*"]),
      ...findingDetailContent(report),
      sectionTitle("Required remediation before release"),
      table(["#", "Remediation"], remediationRows(report), [24, "*"]),
      sectionTitle("Evidence matrix"),
      table(["Ref", "Evidence", "Source", "Extraction", "Locator", "SHA-256", "Warnings"], evidenceRows(report), [26, "*", 80, 48, 70, 68, 50]),
      sectionTitle("Vote record"),
      table(["Agent", "Vote", "Rationale"], voteRows(report), [85, 55, "*"]),
      sectionTitle("Provider execution"),
      table(
        ["Provider", "Status", "Model policy", "Agent routes", "Use"],
        report.providers.map((provider) => [
          provider.label,
          provider.statusLabel,
          provider.model,
          provider.routes.map((route) => `${route.agent}: ${route.model}`).join("; ") || "No agents routed",
          provider.use
        ]),
        [62, 50, 105, 130, "*"]
      ),
      sectionTitle("Re-review criteria"),
      {
        ol: report.reReviewCriteria.length ? report.reReviewCriteria : ["No re-review criteria have been synthesized yet."],
        style: "body",
        margin: [0, 0, 0, 8]
      } as Content,
      sectionTitle("Appendix: Band event trace"),
      table(["Event", "Type", "Agent", "Provider", "Model", "Summary"], eventRows(report), [34, 70, 72, 62, 115, "*"])
    ]
  };
}

export function downloadReportPdf(report: AuditReportModel) {
  pdfMake.createPdf(buildReportPdfDefinition(report)).download(`${report.fileBaseName}.pdf`);
}
