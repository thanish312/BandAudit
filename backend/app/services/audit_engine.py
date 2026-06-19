from __future__ import annotations

import os
from collections import OrderedDict

from app.data.sample_audit import AGENTS, AUDIT_ID, ROOM_ID
from app.models import (
    AdvanceResponse,
    AgentExecutionDiagnostics,
    AgentProfile,
    AuditEvent,
    AuditPacket,
    AuditPhase,
    AuditReport,
    AuditState,
    CreateRoomResponse,
    Decision,
    EventType,
    Finding,
    Severity,
    SourceDiagnostics,
    SourceDiagnosticsResponse,
    VoteRecord,
)
from app.services.event_sources import AuditEventSource
from app.services.env import set_project_env_value


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 18,
    Severity.HIGH: 30,
    Severity.CRITICAL: 42,
}


class PacketReadinessError(ValueError):
    pass


def _packet_readiness_missing(packet: AuditPacket) -> list[str]:
    missing: list[str] = []

    def require(label: str, complete: bool) -> None:
        if not complete:
            missing.append(label)

    has_owner = bool(packet.business_owner.strip() and packet.technical_owner.strip())
    has_tool_access = bool(
        packet.tool_access.strip()
        or packet.tool_profile.integrations
        or packet.tool_profile.read_permissions
        or packet.tool_profile.write_permissions
    )
    has_control_owner = any(claim.required and claim.owner.strip() for claim in packet.control_claims)

    require("System name", bool(packet.target_name.strip()))
    require("Owner", has_owner)
    require("Environment", bool(packet.deployment_environment.strip()))
    require("Review type", bool(packet.review_type.strip()))
    require("Change summary", bool(packet.change_summary.strip()))
    require("Autonomy level", bool(packet.autonomy_level.strip() and packet.human_oversight.strip()))
    require("Data category", bool(packet.data_profile.categories))
    require("Tool access", has_tool_access)
    require("Evidence rows", len(packet.evidence_manifest) >= 4)
    require("Rollout plan", bool(packet.rollout_plan.strip()))
    require("Rollback plan", bool(packet.rollback_plan.strip()))
    require("Incident owner", bool(packet.incident_response_owner.strip()))
    require("Attestation", any(item.name.strip() for item in packet.attestations))
    require("Control owner", has_control_owner)

    return missing


class AuditEngine:
    def __init__(self, event_source: AuditEventSource) -> None:
        self._event_source = event_source

    @property
    def source_name(self) -> str:
        return self._event_source.source_name

    def diagnostics(self) -> SourceDiagnostics:
        return self._event_source.diagnostics()

    def agent_diagnostics(self) -> AgentExecutionDiagnostics:
        return self._event_source.agent_diagnostics()

    def source_status(self) -> SourceDiagnosticsResponse:
        diagnostics = self.diagnostics()
        try:
            event_count = len(self.events())
        except Exception as error:
            return SourceDiagnosticsResponse(
                status="error",
                diagnostics=diagnostics.model_copy(update={"last_error": str(error)}),
                event_count=None,
                read_error=str(error),
            )

        return SourceDiagnosticsResponse(
            status="ok",
            diagnostics=diagnostics,
            event_count=event_count,
        )

    def use_room(self, room_id: str) -> None:
        room_id = room_id.strip()
        if self._event_source.source_name == "band" and room_id:
            self._event_source.room_id = room_id

    def reset(self) -> AuditState:
        self._event_source.reset()
        return self.state()

    def configure_packet(self, packet: AuditPacket) -> AuditState:
        if self._event_source.source_name == "band" and self.events():
            raise RuntimeError(
                "Cannot change the audit packet after Band room events exist. "
                "Use a fresh Band room for a new enterprise test packet."
            )
        missing = _packet_readiness_missing(packet)
        if missing:
            raise PacketReadinessError(f"Complete required fields before locking the packet: {', '.join(missing)}.")
        self._event_source.configure_packet(packet)
        return self.state()

    def create_room(self, task_id: str | None = None) -> CreateRoomResponse:
        result = self._event_source.create_room(task_id=task_id)
        persisted = False
        if self._event_source.source_name == "band" and not os.getenv("VERCEL"):
            try:
                persisted = set_project_env_value("BAND_ROOM_ID", result.room_id)
            except OSError:
                persisted = False
        return CreateRoomResponse(
            audit=self.state(),
            room_id=result.room_id,
            room_url=result.room_url,
            persisted=persisted,
            message=(
                "Audit room created."
                if persisted or not os.getenv("VERCEL")
                else "Audit room created for this browser session."
            ),
        )

    def advance(self) -> AdvanceResponse:
        appended = self._event_source.advance()
        return AdvanceResponse(audit=self.state(), appended_events=appended)

    def state(self) -> AuditState:
        events = self._event_source.events()
        input_packet = self._event_source.audit_packet()
        phase = events[-1].phase if events else AuditPhase.INTAKE
        findings = self._build_findings(events, input_packet)
        decision = self._decision(events)
        risk_score = self._risk_score(findings, events)
        report = self._report(events, decision, input_packet, findings)
        agents = self._agent_statuses(events, phase)
        votes = self._votes(events)
        target_name = self._target_name(input_packet)

        return AuditState(
            audit_id=AUDIT_ID,
            room_id=self._event_source.room_id or ROOM_ID,
            title=self._state_title(target_name),
            subject=input_packet.target_summary or input_packet.change_summary or "Release-board decision reconstructed from Band events.",
            input_packet=input_packet,
            phase=phase,
            decision=decision,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            agents=agents,
            findings=findings,
            events=events,
            votes=votes,
            source=self.diagnostics(),
            agent_execution=self.agent_diagnostics(),
            report=report,
        )

    def events(self) -> list[AuditEvent]:
        return self._event_source.events()

    def _build_findings(self, events: list[AuditEvent], packet: AuditPacket) -> list[Finding]:
        findings: OrderedDict[str, Finding] = OrderedDict()

        for event in events:
            if not event.claim_id:
                continue

            if event.event_type == EventType.FINDING:
                defaults = self._finding_defaults(event.claim_id, packet)
                metadata_title = str(event.metadata.get("title", "")).strip()
                title = metadata_title or str(defaults.get("title", event.summary))
                if self._is_weak_title(title):
                    title = str(defaults.get("title", title))
                findings[event.claim_id] = Finding(
                    claim_id=event.claim_id,
                    title=title,
                    category=str(event.metadata.get("category", defaults.get("category", "General"))),
                    severity=event.severity,
                    confidence=event.confidence,
                    owner_agent=event.agent,
                    status="open",
                    summary=str(defaults.get("summary", event.summary)),
                    risk_mechanism=str(event.metadata.get("risk_mechanism", defaults.get("risk_mechanism", ""))),
                    affected_assets=self._metadata_string_list(
                        event.metadata.get("affected_assets"),
                        fallback=defaults.get("affected_assets"),
                    ),
                    release_impact=str(event.metadata.get("release_impact", defaults.get("release_impact", ""))),
                    remediation=self._metadata_string_list(
                        event.metadata.get("remediation"),
                        fallback=defaults.get("remediation"),
                    ),
                    evidence_refs=event.evidence_refs,
                    last_event_id=event.event_id,
                )
                continue

            if event.claim_id not in findings:
                continue

            finding = findings[event.claim_id]
            finding.last_event_id = event.event_id
            finding.confidence = max(finding.confidence, event.confidence)
            finding.severity = self._max_severity(finding.severity, event.severity)
            verification_note = event.metadata.get("verification_note")
            if isinstance(verification_note, str) and verification_note not in finding.verification_notes:
                finding.verification_notes.append(verification_note)
            for evidence in event.evidence_refs:
                if all(existing.ref_id != evidence.ref_id for existing in finding.evidence_refs):
                    finding.evidence_refs.append(evidence)

            if event.event_type == EventType.VERIFICATION:
                finding.status = "verified"
            elif event.event_type == EventType.CHALLENGE:
                finding.status = "challenged"
            elif event.event_type in {EventType.CONFLICT_DECLARATION, EventType.DEBATE_POSITION}:
                finding.status = "debating"
            elif event.event_type == EventType.VOTE:
                finding.status = "blocked"

        return list(findings.values())

    def _decision(self, events: list[AuditEvent]) -> Decision:
        for event in reversed(events):
            if event.event_type == EventType.SYNTHESIS_REPORT:
                raw = event.metadata.get("decision")
                if raw == "approved":
                    return Decision.APPROVED
                if raw == "conditionally_approved":
                    return Decision.CONDITIONALLY_APPROVED
                if raw == "blocked":
                    return Decision.BLOCKED
        return Decision.PENDING

    def _risk_score(self, findings: list[Finding], events: list[AuditEvent]) -> int:
        if not findings:
            return 12
        base = sum(SEVERITY_WEIGHT[finding.severity] for finding in findings)
        debate_weight = 8 if any(event.event_type == EventType.CONFLICT_DECLARATION for event in events) else 0
        risk_adjustment = 0
        for event in events:
            if event.event_type != EventType.VERIFICATION or not event.claim_id:
                continue
            risk_effect = str(event.metadata.get("risk_effect", "")).lower()
            status = str(event.metadata.get("status", "")).lower()
            resolved = event.metadata.get("resolved_claim") is True or risk_effect in {"resolved", "disproven", "mitigated"}
            confirmed = risk_effect in {"confirmed", "release_blocking", "escalated"} or "blocker" in status
            if resolved:
                risk_adjustment -= 10
            elif confirmed:
                risk_adjustment += 6
        return max(0, min(100, base + debate_weight + risk_adjustment))

    def _risk_level(self, score: int) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 60:
            return Severity.HIGH
        if score >= 35:
            return Severity.MEDIUM
        if score >= 15:
            return Severity.LOW
        return Severity.INFO

    def _report(
        self,
        events: list[AuditEvent],
        decision: Decision,
        packet: AuditPacket,
        findings: list[Finding],
    ) -> AuditReport | None:
        if not any(event.event_type == EventType.SYNTHESIS_REPORT for event in events):
            return None

        transcript_refs = [
            str(event.metadata["band_permalink"])
            for event in events
            if "band_permalink" in event.metadata
        ]
        synthesis = next((event for event in reversed(events) if event.event_type == EventType.SYNTHESIS_REPORT), None)
        synthesis_metadata = synthesis.metadata if synthesis else {}
        release_verdict = str(synthesis_metadata.get("release_verdict") or self._release_verdict(packet, decision))
        executive_summary = str(synthesis_metadata.get("executive_summary") or self._executive_summary(packet, decision, findings, events))
        required_remediations = self._metadata_string_list(
            synthesis_metadata.get("required_remediations"),
            fallback=self._required_remediations(findings),
        )
        re_review_criteria = self._metadata_string_list(
            synthesis_metadata.get("re_review_criteria"),
            fallback=self._re_review_criteria(findings),
        )
        evidence_standard = str(
            synthesis_metadata.get("evidence_standard")
            or "Every material claim must link to Band events plus cited packet or artifact evidence."
        )
        target_name = self._target_name(packet)

        return AuditReport(
            title=f"Release Decision Report: {target_name}",
            decision=decision,
            release_verdict=release_verdict,
            executive_summary=executive_summary,
            required_remediations=required_remediations,
            re_review_criteria=re_review_criteria,
            evidence_standard=evidence_standard,
            event_trace=self._event_trace(events),
            transcript_refs=transcript_refs[-5:],
        )

    def _release_verdict(self, packet: AuditPacket, decision: Decision) -> str:
        target_name = self._target_name(packet)
        if decision == Decision.BLOCKED:
            return f"{target_name} is not approved for production deployment until recorded blockers are remediated."
        if decision == Decision.CONDITIONALLY_APPROVED:
            return f"{target_name} may proceed only after recorded release conditions are satisfied."
        if decision == Decision.APPROVED:
            return f"{target_name} is approved for production deployment based on the current Band record."
        return f"{target_name} is still under release review."

    def _executive_summary(
        self,
        packet: AuditPacket,
        decision: Decision,
        findings: list[Finding],
        events: list[AuditEvent],
    ) -> str:
        target_name = self._target_name(packet)
        top_findings = ", ".join(finding.title.lower() for finding in findings[:3]) or "release evidence"
        return (
            f"The release board reconstructed the {decision.value.replace('_', ' ')} decision for {target_name} "
            f"from {len(events)} Band events, cited evidence, provider-routed agent lanes, verification, debate, "
            f"votes, and synthesis. The material review areas are {top_findings}."
        )

    def _required_remediations(self, findings: list[Finding]) -> list[str]:
        seen: set[str] = set()
        remediations: list[str] = []
        for finding in findings:
            for item in finding.remediation:
                if item not in seen:
                    seen.add(item)
                    remediations.append(item)

        if remediations:
            return remediations

        return [
            "Resolve open release-board findings with cited remediation evidence.",
            "Attach owner-approved controls, rollout, monitoring, and rollback evidence.",
            "Run a fresh Band re-review after remediation is complete.",
        ]

    def _re_review_criteria(self, findings: list[Finding]) -> list[str]:
        criteria = [
            f"Attach remediation evidence for {finding.claim_id}: {finding.title}."
            for finding in findings
            if finding.severity in {Severity.HIGH, Severity.CRITICAL}
        ]
        if criteria:
            return criteria
        return ["Attach final release evidence and run a fresh Band room re-review before changing the decision record."]

    def _event_trace(self, events: list[AuditEvent]) -> list[str]:
        trace: list[str] = []
        for event in events:
            timestamp = event.created_at.strftime("%H:%M")
            claim = f" {event.claim_id}" if event.claim_id else ""
            trace.append(f"{timestamp} {event.event_type.value}{claim} by {event.agent}")
        return trace

    def _votes(self, events: list[AuditEvent]) -> list[VoteRecord]:
        vote_event = next((event for event in reversed(events) if event.event_type == EventType.VOTE), None)
        if vote_event is None:
            synthesis_event = next((event for event in reversed(events) if event.event_type == EventType.SYNTHESIS_REPORT), None)
            vote_source = synthesis_event.metadata.get("votes") if synthesis_event else None
        else:
            vote_source = vote_event.metadata.get("votes")

        if not isinstance(vote_source, list):
            return []

        votes: list[VoteRecord] = []
        for item in vote_source:
            if isinstance(item, dict):
                agent = str(item.get("agent") or "").strip()
                raw_vote = str(item.get("vote") or "").strip().lower()
                rationale = str(item.get("rationale") or "").strip()
            else:
                parts = str(item).split(":", 1)
                agent = parts[0].strip()
                raw_vote = parts[1].strip().lower() if len(parts) == 2 else "conditional"
                rationale = f"{agent} recorded a {raw_vote or 'conditional'} release vote."

            vote = self._normalize_vote(raw_vote)
            if agent and vote:
                votes.append(VoteRecord(agent=agent, vote=vote, rationale=rationale or f"{agent} voted {vote}."))
        return votes

    def _normalize_vote(self, value: str) -> str | None:
        if value in {"approve", "approved", "yes"}:
            return "approve"
        if value in {"block", "blocked", "hold", "reject"}:
            return "block"
        if value in {"conditional", "conditionally_approved", "condition"}:
            return "conditional"
        return None

    def _agent_statuses(self, events: list[AuditEvent], phase: AuditPhase) -> list[AgentProfile]:
        last_by_agent = {event.agent: event for event in events}
        active_agents = {
            AuditPhase.INTAKE: {"ChairAgent"},
            AuditPhase.EVIDENCE_MAPPING: {"EvidenceMapper"},
            AuditPhase.SPECIALIST_REVIEW: {"ComplianceAgent", "SecurityRedTeam", "ModelRiskAgent"},
            AuditPhase.VERIFICATION: {"FactVerifier", "ComplianceAgent"},
            AuditPhase.DEBATE: {"ChairAgent", "SecurityRedTeam", "FactVerifier"},
            AuditPhase.VOTE: {"ChairAgent"},
            AuditPhase.SYNTHESIS: {"Synthesizer"},
            AuditPhase.COMPLETE: set(),
        }.get(phase, set())

        agents: list[AgentProfile] = []
        for agent in AGENTS:
            copy = agent.model_copy(deep=True)
            if phase == AuditPhase.COMPLETE:
                copy.status = "complete"
                copy.current_task = "Audit complete"
            elif copy.name in active_agents:
                copy.status = "active"
                copy.current_task = "Publishing Band coordination event"
            elif copy.name in last_by_agent:
                copy.status = "complete"
                copy.current_task = f"Last event: {last_by_agent[copy.name].event_type.value}"
            else:
                copy.status = "idle"
            agents.append(copy)
        return agents

    def _max_severity(self, left: Severity, right: Severity) -> Severity:
        return left if SEVERITY_WEIGHT[left] >= SEVERITY_WEIGHT[right] else right

    def _metadata_string_list(self, value: object, fallback: object = None) -> list[str]:
        source = value if isinstance(value, list) else fallback
        if not isinstance(source, list):
            return []
        return [str(item) for item in source if isinstance(item, str)]

    def _is_weak_title(self, title: str) -> bool:
        weak_fragments = (
            "potential issues flagged",
            "requires prompt-injection review",
            "evaluation and monitoring evidence needs review",
            "workflow lacks documented release controls",
            "employment decision workflow lacks documented release controls",
            "prompt injection path can reach ats update tool",
            "bias and subgroup coverage evidence is missing",
        )
        normalized = title.strip().lower()
        return any(fragment in normalized for fragment in weak_fragments)

    def _target_name(self, packet: AuditPacket) -> str:
        return packet.target_name.strip() or "Submitted release"

    def _state_title(self, target_name: str) -> str:
        if target_name == "Submitted release":
            return "Submitted Release Review"
        return f"{target_name} Release Review"

    def _finding_defaults(self, claim_id: str, packet: AuditPacket) -> dict[str, object]:
        target_name = self._target_name(packet)
        tool_access = packet.tool_access.strip() or "write-capable or production tool access"
        policy_context = packet.policy_context.strip().lower() or "the declared release policy context"
        deployment_environment = packet.deployment_environment.strip() or "Production workflow"
        affected_users = packet.affected_users.strip() or "Affected users"
        is_ats = "ats" in tool_access.lower()
        if claim_id == "C-002":
            write_tool_title = (
                "Prompt-injection path can reach ATS status-update tools"
                if is_ats
                else "Untrusted input can influence production write tools"
            )
            return {
                "category": "Security",
                "title": write_tool_title,
                "summary": (
                    "Uploaded or user-provided content is treated as model context without a proven "
                    "untrusted-content boundary while the agent can call write-capable production tools."
                ),
                "risk_mechanism": (
                    f"Untrusted content can enter the same reasoning context used for tool planning. "
                    f"Because the agent has {tool_access.lower()}, adversarial text may influence "
                    "persistent records or user-facing operational updates."
                ),
                "affected_assets": [
                    tool_access,
                    "Prompt context",
                    "Production records",
                ],
                "release_impact": "Blocks production release because untrusted content can affect write-capable operational tools.",
                "remediation": [
                    "Isolate untrusted user or document text from system and tool instructions.",
                    "Gate write-capable tool calls behind explicit human approval.",
                    "Rerun prompt-injection tests and attach passing results.",
                ],
            }

        if claim_id == "C-001":
            return {
                "category": "Compliance",
                "title": "Human approval and release controls are not proven",
                "summary": (
                    "The packet does not prove that human approval gates, release sign-off, rollback ownership, "
                    "and business accountability are enforced before production use."
                ),
                "risk_mechanism": (
                    f"{target_name} operates in {policy_context}, but the submitted packet "
                    "does not demonstrate enforceable approval, rollback, and audit controls."
                ),
                "affected_assets": [
                    deployment_environment,
                    affected_users,
                    "Release sign-off",
                ],
                "release_impact": "Blocks release until governance controls are documented, owned, and enforceable.",
                "remediation": [
                    "Name the business owner and accountable release approvers.",
                    "Require explicit human confirmation before production write actions.",
                    "Document rollback ownership, audit logging, and escalation path.",
                ],
            }

        if claim_id == "C-003":
            return {
                "category": "Model Risk",
                "title": "Bias and subgroup performance evidence is incomplete",
                "summary": (
                    "The evaluation packet reports aggregate performance but does not demonstrate subgroup recall, "
                    "false-negative rates, adverse-impact thresholds, or production monitoring."
                ),
                "risk_mechanism": (
                    "Aggregate evaluation evidence does not establish safe performance across affected user groups "
                    "or define production monitoring thresholds for the release workflow."
                ),
                "affected_assets": [
                    packet.evidence_notes.strip() or "Evaluation evidence",
                    "Subgroup evaluation",
                    "Monitoring thresholds",
                ],
                "release_impact": "Blocks release until evaluation evidence supports the production workflow and affected population.",
                "remediation": [
                    "Provide subgroup recall, false-negative rates, and adverse-impact review.",
                    "Define monitoring thresholds and drift escalation criteria.",
                    "Attach rollback criteria for production failures.",
                ],
            }

        return {}
