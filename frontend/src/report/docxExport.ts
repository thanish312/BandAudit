import {
  AlignmentType,
  BorderStyle,
  Document,
  FileChild,
  HeadingLevel,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableLayoutType,
  TableRow,
  TextRun,
  VerticalAlignTable,
  WidthType
} from "docx";
import type { AuditReportModel, ReportFinding } from "./reportModel";

const COLORS = {
  text: "101828",
  muted: "475467",
  border: "E4E7EC",
  headerFill: "F9FAFB",
  danger: "B42318",
  warning: "B54708",
  success: "067647"
};

function text(value: string) {
  return value.trim() || "Not supplied";
}

function run(value: string, options: { bold?: boolean; color?: string; size?: number } = {}) {
  return new TextRun({
    text: text(value),
    bold: options.bold,
    color: options.color ?? COLORS.text,
    size: options.size ?? 20,
    font: "Aptos"
  });
}

function paragraph(value: string, options: { bold?: boolean; color?: string; size?: number; spacingAfter?: number } = {}) {
  return new Paragraph({
    children: [run(value, options)],
    spacing: { after: options.spacingAfter ?? 120 }
  });
}

function heading(value: string, level: (typeof HeadingLevel)[keyof typeof HeadingLevel] = HeadingLevel.HEADING_2) {
  return new Paragraph({
    text: value,
    heading: level,
    spacing: { before: 220, after: 120 }
  });
}

function bullet(value: string) {
  return new Paragraph({
    children: [run(value, { color: COLORS.text })],
    bullet: { level: 0 },
    spacing: { after: 80 }
  });
}

function cell(value: string, options: { header?: boolean; width?: number } = {}) {
  return new TableCell({
    width: options.width ? { size: options.width, type: WidthType.PERCENTAGE } : undefined,
    shading: options.header ? { fill: COLORS.headerFill } : undefined,
    verticalAlign: VerticalAlignTable.CENTER,
    margins: { top: 110, bottom: 110, left: 120, right: 120 },
    borders: {
      top: { style: BorderStyle.SINGLE, size: 1, color: COLORS.border },
      bottom: { style: BorderStyle.SINGLE, size: 1, color: COLORS.border },
      left: { style: BorderStyle.SINGLE, size: 1, color: COLORS.border },
      right: { style: BorderStyle.SINGLE, size: 1, color: COLORS.border }
    },
    children: [
      new Paragraph({
        children: [run(value, { bold: options.header, color: options.header ? COLORS.muted : COLORS.text, size: options.header ? 18 : 19 })],
        spacing: { after: 0 }
      })
    ]
  });
}

function table(headers: string[], rows: string[][], widths?: number[]) {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    layout: TableLayoutType.FIXED,
    rows: [
      new TableRow({
        tableHeader: true,
        children: headers.map((header, index) => cell(header, { header: true, width: widths?.[index] }))
      }),
      ...rows.map(
        (row) =>
          new TableRow({
            children: row.map((value, index) => cell(value, { width: widths?.[index] }))
          })
      )
    ]
  });
}

function decisionColor(tone: AuditReportModel["decision"]["tone"]) {
  if (tone === "danger") return COLORS.danger;
  if (tone === "warning") return COLORS.warning;
  if (tone === "success") return COLORS.success;
  return COLORS.text;
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

function findingDetailChildren(report: AuditReportModel): FileChild[] {
  if (report.findings.length === 0) {
    return [heading("Finding detail appendix"), paragraph("No release-board findings have been recorded yet.")];
  }

  return [
    heading("Finding detail appendix"),
    paragraph("Each blocker below is tied to the Band event trace, cited evidence, verification notes, and concrete remediation expected before re-review.", {
      color: COLORS.muted
    }),
    ...report.findings.flatMap((finding) => [
      paragraph(`${finding.id} - ${finding.title}`, { bold: true, size: 22, spacingAfter: 80 }),
      table(
        ["Severity", "Status", "Effect", "Owner", "Confidence", "Evidence state"],
        [[finding.severityLabel, finding.statusLabel, finding.releaseEffect, finding.owner, `${finding.confidencePercent}%`, finding.evidenceState]],
        [12, 12, 13, 25, 13, 25]
      ),
      table(["Release impact", "Trace"], [[finding.impact, finding.trace]], [50, 50]),
      paragraph(`Finding summary: ${finding.summary}`),
      paragraph(`Risk mechanism: ${finding.riskMechanism}`),
      table(["Ref", "Artifact", "Locator", "SHA-256", "Warnings"], findingEvidenceRows(finding), [8, 34, 24, 18, 16]),
      table(
        ["Verification notes"],
        (finding.verificationNotes.length ? finding.verificationNotes : ["No independent verification notes have been recorded yet."]).map((note) => [note]),
        [100]
      ),
      table(
        ["Required remediation"],
        (finding.remediation.length ? finding.remediation : ["No remediation has been synthesized yet."]).map((item) => [item]),
        [100]
      ),
      spacer(80)
    ])
  ];
}

function remediationRows(report: AuditReportModel) {
  if (report.requiredRemediations.length === 0) return [["1", "No required remediations have been synthesized yet."]];
  return report.requiredRemediations.map((item, index) => [String(index + 1), item]);
}

function evidenceRows(report: AuditReportModel) {
  if (report.evidence.length === 0) return [["None", "No evidence linked", "Not supplied", "Not supplied", "Not supplied", "Not supplied", "None"]];
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
  if (report.votes.length === 0) return [["No vote records", "Pending", "The release board has not recorded a final vote."]];
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
  if (report.events.length === 0) return [["None", "No events", "No agent", "No provider", "No model", "No summary"]];
  return report.events.map((event) => [event.sequence, event.type, event.agent, event.provider, event.model, event.summary]);
}

function spacer(size = 120) {
  return new Paragraph({ children: [], spacing: { after: size } });
}

function buildChildren(report: AuditReportModel): FileChild[] {
  const children: FileChild[] = [
    new Paragraph({
      text: "BandAudit Release Report",
      heading: HeadingLevel.TITLE,
      alignment: AlignmentType.LEFT,
      spacing: { after: 80 }
    }),
    paragraph(report.target.name, { bold: true, size: 30, spacingAfter: 90 }),
    paragraph(report.target.summary, { color: COLORS.muted, spacingAfter: 160 }),
    table(
      ["Generated", "Owner", "Deployment", "Affected users"],
      [[report.generatedAtLabel, report.target.owner, report.target.deployment, report.target.affectedUsers]],
      [20, 26, 26, 28]
    ),
    heading("Executive decision"),
    paragraph(report.decision.label, { bold: true, color: decisionColor(report.decision.tone), size: 25, spacingAfter: 80 }),
    paragraph(report.decision.verdict, { bold: true }),
    paragraph(report.decision.rationale, { color: COLORS.muted }),
    table(
      ["Risk score", "Risk level", "Open blockers", "Evidence links", "Band events"],
      [[String(report.risk.score), report.risk.levelLabel, String(report.risk.blockerCount), String(report.risk.evidenceLinkCount), String(report.risk.eventCount)]],
      [18, 18, 21, 21, 22]
    ),
    heading("Audit integrity"),
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
      [19, 15, 13, 9, 14, 30]
    ),
    table(
      ["Room purpose", "Participant strategy", "Human reviewers", "Recruited peers"],
      [[
        report.roomManifest.roomPurpose,
        report.roomManifest.participantStrategy,
        report.roomManifest.humanReviewers.length ? report.roomManifest.humanReviewers.join("; ") : "None declared",
        String(report.roomManifest.recruitedPeerCount)
      ]],
      [35, 30, 23, 12]
    ),
    heading("Release board roster"),
    table(["Lane", "Agent", "Provider", "Model", "Mode", "Latest Band event"], laneRows(report), [12, 15, 13, 23, 17, 20]),
    heading("Release blockers"),
    table(["Finding", "Severity", "Status", "Effect", "Evidence", "Owner", "Title"], findingRows(report.findings), [10, 11, 12, 13, 10, 17, 27]),
    ...findingDetailChildren(report),
    heading("Required remediation before release"),
    table(["#", "Remediation"], remediationRows(report), [8, 92]),
    heading("Evidence matrix"),
    table(["Ref", "Evidence", "Source", "Extraction", "Locator", "SHA-256", "Warnings"], evidenceRows(report), [8, 25, 20, 11, 14, 12, 10]),
    heading("Vote record"),
    table(["Agent", "Vote", "Rationale"], voteRows(report), [22, 16, 62]),
    heading("Provider execution"),
    table(
      ["Provider", "Status", "Model policy", "Agent routes", "Use"],
      report.providers.map((provider) => [
        provider.label,
        provider.statusLabel,
        provider.model,
        provider.routes.map((route) => `${route.agent}: ${route.model}`).join("; ") || "No agents routed",
        provider.use
      ]),
      [15, 12, 23, 27, 23]
    ),
    heading("Re-review criteria"),
    ...(report.reReviewCriteria.length ? report.reReviewCriteria : ["No re-review criteria have been synthesized yet."]).map(bullet),
    spacer(),
    heading("Appendix: Band event trace"),
    table(["Event", "Type", "Agent", "Provider", "Model", "Summary"], eventRows(report), [8, 15, 14, 13, 21, 29])
  ];

  return children;
}

export async function createReportDocxBlob(report: AuditReportModel) {
  const document = new Document({
    creator: "BandAudit",
    title: `BandAudit Release Report - ${report.target.name}`,
    subject: "Release-board decision report",
    description: report.decision.verdict,
    sections: [
      {
        properties: {
          page: {
            margin: {
              top: 720,
              right: 720,
              bottom: 720,
              left: 720
            }
          }
        },
        children: buildChildren(report)
      }
    ]
  });

  return Packer.toBlob(document);
}
