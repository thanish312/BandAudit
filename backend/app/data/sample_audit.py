from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256

from app.models import (
    AgentProfile,
    AuditEvent,
    AuditPacket,
    AuditPhase,
    ControlClaim,
    DataProfile,
    EventType,
    EvidenceManifestItem,
    EvidenceRef,
    ExternalReference,
    PacketAttestation,
    Severity,
    ToolProfile,
)


AUDIT_ID = "aud_01JZBANDAUDIT000001"
ROOM_ID = "band_room_agent_release_board_demo"

DEFAULT_AUDIT_PACKET = AuditPacket()

LANE_ROSTER = [
    {
        "lane": "Chair",
        "agent": "ChairAgent",
        "role": "Phase control, conflict detection, voting, and release-board orchestration",
        "provider": "aiml",
        "participant_mode": "structured_lane",
    },
    {
        "lane": "Evidence",
        "agent": "EvidenceMapper",
        "role": "Evidence extraction, packet indexing, source hashing, and artifact linking",
        "provider": "aiml",
        "participant_mode": "structured_lane",
    },
    {
        "lane": "Compliance",
        "agent": "ComplianceAgent",
        "role": "Governance, policy, approval, and control-claim review",
        "provider": "aiml",
        "participant_mode": "structured_lane",
    },
    {
        "lane": "Security",
        "agent": "SecurityRedTeam",
        "role": "Prompt-injection, tool-misuse, side-effect, and boundary review",
        "provider": "featherless",
        "participant_mode": "structured_lane",
    },
    {
        "lane": "Model Risk",
        "agent": "ModelRiskAgent",
        "role": "Evaluation quality, bias evidence, drift, and oversight review",
        "provider": "featherless",
        "participant_mode": "structured_lane",
    },
    {
        "lane": "Verification",
        "agent": "FactVerifier",
        "role": "Independent disputed-claim and evidence-strength verification",
        "provider": "featherless",
        "participant_mode": "structured_lane",
    },
    {
        "lane": "Synthesis",
        "agent": "Synthesizer",
        "role": "Final release decision, remediation summary, and report synthesis",
        "provider": "aiml",
        "participant_mode": "structured_lane",
    },
]


AGENTS: list[AgentProfile] = [
    AgentProfile(
        id="chair",
        name="ChairAgent",
        role="Phase control, conflict detection, voting, escalation",
        provider="AI/ML API orchestration lane",
        status="active",
        current_task="Opening the release-board audit",
    ),
    AgentProfile(
        id="evidence",
        name="EvidenceMapper",
        role="Extracts claims and links them to source artifacts",
        provider="AI/ML API extraction lane",
        status="idle",
        current_task="Waiting for audit initialization",
    ),
    AgentProfile(
        id="compliance",
        name="ComplianceAgent",
        role="Maps facts to policy, governance, and regulatory obligations",
        provider="AI/ML API policy reasoning lane",
        status="idle",
        current_task="Waiting for indexed artifacts",
    ),
    AgentProfile(
        id="security",
        name="SecurityRedTeam",
        role="Tests prompt injection, tool misuse, and data exposure risk",
        provider="Featherless open-weight review lane",
        status="idle",
        current_task="Waiting for indexed artifacts",
    ),
    AgentProfile(
        id="model-risk",
        name="ModelRiskAgent",
        role="Reviews eval quality, bias evidence, drift, and human oversight",
        provider="Featherless open-weight review lane",
        status="idle",
        current_task="Waiting for indexed artifacts",
    ),
    AgentProfile(
        id="verifier",
        name="FactVerifier",
        role="Checks unsupported claims and evidence strength",
        provider="Independent verification lane",
        status="idle",
        current_task="Waiting for challenges",
    ),
    AgentProfile(
        id="synthesizer",
        name="Synthesizer",
        role="Produces the final release decision and traceable report",
        provider="AI/ML API synthesis lane",
        status="idle",
        current_task="Waiting for vote results",
    ),
]


EVIDENCE: dict[str, EvidenceRef] = {
    "E-001": EvidenceRef(
        ref_id="E-001",
        title="System overview: autonomous candidate screening",
        artifact="packet://system-overview",
        locator="section: Operating mode",
        sha256="f0ade3aea911cc4faac633f4c50299e674297bdacd15cdec81bc6d30aec27382",
    ),
    "E-002": EvidenceRef(
        ref_id="E-002",
        title="Tool manifest: ATS write access",
        artifact="packet://tool-manifest",
        locator="tools[ats_update_candidate]",
        sha256="c1ad36804ece8224c9f00f2930d12d13b8d0229a3346943d9ead08323c0d3cd0",
    ),
    "E-003": EvidenceRef(
        ref_id="E-003",
        title="Prompt template: resume text enters shared context",
        artifact="packet://workflow-prompts",
        locator="prompt: screening_system",
        sha256="d22c6c9f7803a29ebfc5134170d912b6b42fa3a55fa34ae18df27356508990f5",
    ),
    "E-004": EvidenceRef(
        ref_id="E-004",
        title="Eval summary: demographic parity not measured",
        artifact="packet://evaluation-summary",
        locator="section: Coverage gaps",
        sha256="2c9a8e119454050b81f53ea838ff72544673bd733f30b54d5b1fce134fb0b50b",
    ),
    "E-005": EvidenceRef(
        ref_id="E-005",
        title="Policy requirements: high impact employment decisions",
        artifact="packet://policy-requirements",
        locator="control: HIR-02",
        sha256="0de434321a9b6712f69160078b0527e145a2847a4f70454a42c5b310feae00a0",
    ),
    "E-006": EvidenceRef(
        ref_id="E-006",
        title="Red-team tests: prompt injection reaches tool planning",
        artifact="packet://prompt-injection-tests",
        locator="test case: PI-03",
        sha256="f9e66a715233c82a3fc58e92f432dfc1f6c23966299df9a333ecfba8fd9ff4fb",
    ),
    "E-007": EvidenceRef(
        ref_id="E-007",
        title="Rollback plan: missing owner and ATS recovery path",
        artifact="packet://monitoring-rollback",
        locator="section: Gaps",
        sha256="829a76982c0e8ed2cab75d81b51f36c4fe06b5a20e5514d64cf0fe308ac69c68",
    ),
}


SAMPLE_AUDIT_PACKET = AuditPacket(
    packet_version="v2",
    packet_source_mode="manual",
    review_type="Major change",
    target_name="TalentScreen Assist v2.4",
    target_summary="Autonomous candidate screening agent for resume ranking and ATS status updates",
    change_summary="Production pilot adds write-capable ATS actions and recruiter-facing screening recommendations for engineering roles.",
    workflow="Ranks applicants, summarizes screening evidence, and updates recruiting review state",
    tool_access="ATS read/write access including candidate status updates and recruiter-facing notes",
    policy_context="High-impact employment workflow requiring documented release controls and human approval gates",
    evidence_notes="System overview, tool manifest, policy requirements, prompt-injection tests, evaluation summary, and rollback plan",
    business_owner="People Operations",
    technical_owner="Recruiting Platform Engineering",
    owning_team="People Systems",
    deployment_environment="Production ATS pilot",
    affected_users="Job applicants and recruiting team",
    criticality="High",
    planned_release_date="2026-07-15",
    ticket_url="https://jira.example.com/browse/JSM-7421",
    repository_url="https://github.example.com/people/talentscreen-assist",
    system_type="Agentic workflow",
    autonomy_level="Human-approved production actions",
    human_oversight="Recruiter must approve candidate-status writes before persistence",
    data_profile=DataProfile(
        categories=["Candidate profile", "Resume text", "Recruiter notes", "Interview feedback"],
        sensitive_data=["Employment decision data", "Candidate PII"],
        retention="90 days in review workspace, then archived under recruiting retention policy",
        residency="US production tenant",
        training_use="No customer data used for model training",
    ),
    tool_profile=ToolProfile(
        integrations=["Greenhouse ATS", "Recruiting workflow service", "Notification service"],
        read_permissions=["Candidate profile", "Resume attachments", "Recruiter notes", "Job requisitions"],
        write_permissions=["Candidate review state", "Recruiter-facing notes", "Screening recommendation"],
        external_side_effects=["May change candidate review state and notify recruiters"],
        approval_required_for_writes=True,
    ),
    control_claims=[
        ControlClaim(
            control_id="GOV-001",
            title="Named business and technical owners approve production release",
            owner="People Operations",
            status="claimed",
            evidence_refs=["E-005", "E-007"],
            notes="Owners are identified, but approval evidence must be tied to the release packet.",
        ),
        ControlClaim(
            control_id="SEC-002",
            title="Untrusted candidate content is isolated from tool-planning instructions",
            owner="Recruiting Platform Engineering",
            status="needs_evidence",
            evidence_refs=["E-003", "E-006"],
            notes="Prompt-injection tests are included but do not prove the final controlled tool path.",
        ),
        ControlClaim(
            control_id="OPS-003",
            title="Write-capable ATS actions require explicit human approval",
            owner="Recruiting Platform Engineering",
            status="needs_evidence",
            evidence_refs=["E-002", "E-007"],
        ),
        ControlClaim(
            control_id="MR-004",
            title="Subgroup performance and adverse-impact monitoring are defined",
            owner="Model Risk",
            status="exception_requested",
            evidence_refs=["E-004", "E-005"],
        ),
    ],
    evidence_manifest=[
        EvidenceManifestItem(
            ref_id=ref.ref_id,
            title="System overview and operating mode" if ref.ref_id == "E-001" else ref.title,
            evidence_type={
                "E-001": "architecture",
                "E-002": "tool_manifest",
                "E-003": "prompt",
                "E-004": "evaluation",
                "E-005": "policy",
                "E-006": "security_test",
                "E-007": "runbook",
            }[ref.ref_id],
            artifact=ref.artifact,
            source={
                "E-001": "Release packet",
                "E-002": "Repository",
                "E-003": "Repository",
                "E-004": "Model risk review",
                "E-005": "GRC policy library",
                "E-006": "Security review",
                "E-007": "Operations runbook",
            }[ref.ref_id],
            owner={
                "E-001": "Recruiting Platform Engineering",
                "E-002": "Recruiting Platform Engineering",
                "E-003": "AI Platform",
                "E-004": "Model Risk",
                "E-005": "Compliance",
                "E-006": "Security Red Team",
                "E-007": "People Systems SRE",
            }[ref.ref_id],
            linked_control={
                "E-001": "GOV-001",
                "E-002": "OPS-003",
                "E-003": "SEC-002",
                "E-004": "MR-004",
                "E-005": "GOV-001",
                "E-006": "SEC-002",
                "E-007": "OPS-003",
            }[ref.ref_id],
            linked_risk={
                "E-001": "Autonomous screening changes candidate state",
                "E-002": "Write-capable production tool access",
                "E-003": "Untrusted resume text reaches shared reasoning context",
                "E-004": "Bias and subgroup safety evidence incomplete",
                "E-005": "Release approval obligations unclear",
                "E-006": "Tool-planning boundary can be influenced",
                "E-007": "Recovery path and stop conditions incomplete",
            }[ref.ref_id],
            freshness="Current release branch" if ref.ref_id in {"E-001", "E-003"} else "Pre-release evidence",
            status="partial" if ref.ref_id == "E-006" else "needs_update" if ref.ref_id == "E-004" else "submitted",
            sha256=ref.sha256,
            locator=ref.locator,
        )
        for ref in EVIDENCE.values()
    ],
    evaluation_summary="Offline evaluation shows aggregate recruiter agreement but lacks complete subgroup recall, false-negative, and adverse-impact evidence.",
    known_limitations="Prompt-injection test evidence is partial, subgroup safety evidence is incomplete, and rollback ownership needs stronger proof.",
    release_goal="Production pilot for engineering roles",
    rollout_plan="Limited pilot for engineering roles with recruiter approval required before ATS state changes.",
    monitoring_plan="Daily review of candidate-state changes, adverse-impact metrics, model drift, prompt-injection alerts, and recruiter overrides.",
    rollback_plan="Disable ATS write tools, revert candidate states from audit log, and route all screening decisions to manual recruiter review.",
    incident_response_owner="People Systems SRE",
    stop_conditions=[
        "Unauthorized candidate-status write",
        "Confirmed prompt-injection tool path",
        "Adverse-impact threshold breach",
        "Monitoring or audit-log failure",
    ],
    attestations=[
        PacketAttestation(role="requester", name="Maya Chen", status="submitted", attested_at="2026-06-14"),
        PacketAttestation(role="business_owner", name="People Operations", status="submitted", attested_at="2026-06-14"),
        PacketAttestation(role="technical_owner", name="Recruiting Platform Engineering", status="submitted", attested_at="2026-06-14"),
    ],
    external_references=[
        ExternalReference(label="Release ticket JSM-7421", url="https://jira.example.com/browse/JSM-7421", kind="ticket"),
        ExternalReference(label="Release candidate repository", url="https://github.example.com/people/talentscreen-assist", kind="repository"),
    ],
)


def ts(minutes: int, seconds: int = 0) -> datetime:
    return datetime(2026, 6, 14, 9, minutes, seconds, tzinfo=timezone.utc)


DEMO_EVENTS: list[AuditEvent] = [
    AuditEvent(
        event_id="evt_0001",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="ChairAgent",
        event_type=EventType.AUDIT_INIT,
        summary="Opened a Band release-board room for TalentScreen Assist v2.4 and requested parallel specialist review.",
        created_at=ts(0),
        phase=AuditPhase.INTAKE,
        severity=Severity.INFO,
        metadata={"band_permalink": "https://band.ai/rooms/demo/messages/evt_0001"},
    ),
    AuditEvent(
        event_id="evt_0002",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="EvidenceMapper",
        event_type=EventType.ARTIFACT_INDEXED,
        summary="Indexed seven audit artifacts and published source hashes for downstream agents.",
        created_at=ts(1),
        phase=AuditPhase.EVIDENCE_MAPPING,
        severity=Severity.INFO,
        evidence_refs=list(EVIDENCE.values()),
        metadata={"band_permalink": "https://band.ai/rooms/demo/messages/evt_0002"},
    ),
    AuditEvent(
        event_id="evt_0003",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="ComplianceAgent",
        event_type=EventType.FINDING,
        claim_id="C-001",
        summary="The packet does not prove that human approval gates, release sign-off, rollback ownership, and recruiter accountability are enforced before the agent changes candidate review state.",
        created_at=ts(2),
        phase=AuditPhase.SPECIALIST_REVIEW,
        severity=Severity.HIGH,
        confidence=0.91,
        risk_delta=28,
        evidence_refs=[EVIDENCE["E-001"], EVIDENCE["E-005"], EVIDENCE["E-007"]],
        metadata={
            "category": "Compliance",
            "title": "Human approval and release controls are not proven",
            "risk_mechanism": "TalentScreen Assist operates inside a high-impact employment workflow, but the packet does not demonstrate enforceable approval gates before ATS state is changed.",
            "affected_assets": ["ATS candidate status", "Recruiter review workflow", "Hiring release sign-off"],
            "release_impact": "Blocks release until governance controls are documented, owned, and enforceable.",
            "remediation": [
                "Document the named business owner and release approvers.",
                "Require explicit recruiter confirmation before candidate status writes.",
                "Add rollback ownership and audit logging for status changes.",
            ],
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0003",
        },
    ),
    AuditEvent(
        event_id="evt_0004",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="SecurityRedTeam",
        event_type=EventType.FINDING,
        claim_id="C-002",
        summary="Uploaded resume and cover-letter text is treated as model context without a proven untrusted-content boundary, while the agent can call ATS write tools.",
        created_at=ts(3),
        phase=AuditPhase.SPECIALIST_REVIEW,
        severity=Severity.CRITICAL,
        confidence=0.9,
        risk_delta=34,
        evidence_refs=[EVIDENCE["E-006"], EVIDENCE["E-002"], EVIDENCE["E-003"]],
        metadata={
            "category": "Security",
            "title": "Prompt-injection path can reach ATS status-update tools",
            "risk_mechanism": "Candidate-provided text enters the same reasoning context used for tool planning, so adversarial resume instructions may influence ats_update_candidate or recruiter-facing notes.",
            "affected_assets": ["ats_update_candidate", "ats_append_note", "Candidate-provided resumes and cover letters"],
            "release_impact": "Blocks production release because untrusted content can affect write-capable operational tools.",
            "remediation": [
                "Isolate untrusted candidate text from system and tool instructions.",
                "Add a tool-call approval gate for ATS writes.",
                "Rerun prompt-injection tests PI-01 through PI-05 and attach passing results.",
            ],
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0004",
        },
    ),
    AuditEvent(
        event_id="evt_0005",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="ModelRiskAgent",
        event_type=EventType.FINDING,
        claim_id="C-003",
        summary="The evaluation packet reports aggregate agreement but does not demonstrate subgroup recall, false-negative rates, adverse-impact thresholds, or production monitoring.",
        created_at=ts(4),
        phase=AuditPhase.SPECIALIST_REVIEW,
        severity=Severity.HIGH,
        confidence=0.87,
        risk_delta=26,
        evidence_refs=[EVIDENCE["E-004"], EVIDENCE["E-005"], EVIDENCE["E-007"]],
        metadata={
            "category": "Model Risk",
            "title": "Bias and subgroup performance evidence is incomplete",
            "risk_mechanism": "Aggregate recruiter-agreement metrics do not prove safe performance for protected or job-relevant candidate groups in an employment screening workflow.",
            "affected_assets": ["Evaluation summary", "Subgroup monitoring thresholds", "Adverse-impact review"],
            "release_impact": "Blocks release for a high-impact employment workflow until subgroup safety evidence is supplied.",
            "remediation": [
                "Provide subgroup recall and false-negative rates by relevant cohort.",
                "Define adverse-impact thresholds and monitoring cadence.",
                "Attach production drift and rollback criteria for screening decisions.",
            ],
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0005",
        },
    ),
    AuditEvent(
        event_id="evt_0006",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="FactVerifier",
        event_type=EventType.VERIFICATION,
        claim_id="C-001",
        summary="Verified the packet describes ATS write capability and high-impact employment use, but does not show an enforceable human approval gate.",
        created_at=ts(5),
        phase=AuditPhase.VERIFICATION,
        severity=Severity.HIGH,
        confidence=0.89,
        evidence_refs=[EVIDENCE["E-001"], EVIDENCE["E-002"], EVIDENCE["E-005"]],
        metadata={
            "status": "verified",
            "verification_note": "FactVerifier confirmed the release-control gap from the system overview, policy requirements, and ATS write manifest.",
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0006",
        },
    ),
    AuditEvent(
        event_id="evt_0007",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="FactVerifier",
        event_type=EventType.CHALLENGE,
        claim_id="C-002",
        summary="Challenged whether the prompt-injection evidence proves a persistent ATS write risk or only a draft-recommendation risk.",
        created_at=ts(6),
        phase=AuditPhase.VERIFICATION,
        severity=Severity.MEDIUM,
        confidence=0.76,
        evidence_refs=[EVIDENCE["E-006"], EVIDENCE["E-002"], EVIDENCE["E-003"]],
        metadata={
            "target_agent": "SecurityRedTeam",
            "verification_note": "FactVerifier requested a narrower claim: tool access is proven, while a full injected write log is not included.",
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0007",
        },
    ),
    AuditEvent(
        event_id="evt_0008",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="ChairAgent",
        event_type=EventType.CONFLICT_DECLARATION,
        claim_id="C-002",
        summary="Opened a Band debate because the board agrees the prompt boundary is weak but disputes whether the evidence proves full exploit impact.",
        created_at=ts(7),
        phase=AuditPhase.DEBATE,
        severity=Severity.HIGH,
        confidence=0.82,
        metadata={
            "rounds": 2,
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0008",
        },
    ),
    AuditEvent(
        event_id="evt_0009",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="SecurityRedTeam",
        event_type=EventType.DEBATE_POSITION,
        claim_id="C-002",
        summary="Argued that ATS write access makes the prompt boundary failure release-blocking until untrusted text is isolated and tool permissions are gated.",
        created_at=ts(8),
        phase=AuditPhase.DEBATE,
        severity=Severity.CRITICAL,
        confidence=0.88,
        evidence_refs=[EVIDENCE["E-006"], EVIDENCE["E-002"], EVIDENCE["E-003"]],
        metadata={
            "position": "block",
            "verification_note": "SecurityRedTeam tied the disputed claim to PI-03, the prompt template, and ATS write capability.",
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0009",
        },
    ),
    AuditEvent(
        event_id="evt_0010",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="FactVerifier",
        event_type=EventType.VERIFICATION,
        claim_id="C-002",
        summary="Verified the release blocker: ATS write access and shared prompt context are proven, while the missing injected-write log increases rather than reduces release risk.",
        created_at=ts(9),
        phase=AuditPhase.DEBATE,
        severity=Severity.HIGH,
        confidence=0.81,
        evidence_refs=[EVIDENCE["E-006"], EVIDENCE["E-002"], EVIDENCE["E-003"]],
        metadata={
            "status": "verified_release_blocker",
            "verification_note": "FactVerifier confirmed the evidence link and recommended treating the gap as release-blocking until the red-team test is rerun with controls.",
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0010",
        },
    ),
    AuditEvent(
        event_id="evt_0011",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="ChairAgent",
        event_type=EventType.VOTE,
        claim_id="C-002",
        summary="Requested release decision votes after debate closed with unresolved prompt-injection, approval-gate, rollback, and subgroup-evidence gaps.",
        created_at=ts(10),
        phase=AuditPhase.VOTE,
        severity=Severity.HIGH,
        confidence=0.9,
        metadata={
            "votes": ["ComplianceAgent:conditional", "SecurityRedTeam:block", "ModelRiskAgent:block", "FactVerifier:conditional"],
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0011",
        },
    ),
    AuditEvent(
        event_id="evt_0012",
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="Synthesizer",
        event_type=EventType.SYNTHESIS_REPORT,
        summary="Synthesized a Hold release decision pending remediation of ATS write approval, prompt isolation, rollback controls, and subgroup safety evidence.",
        created_at=ts(11),
        phase=AuditPhase.COMPLETE,
        severity=Severity.CRITICAL,
        confidence=0.92,
        evidence_refs=list(EVIDENCE.values()),
        metadata={
            "decision": "blocked",
            "band_permalink": "https://band.ai/rooms/demo/messages/evt_0012",
        },
    ),
]


def review_events_for_packet(packet: AuditPacket) -> list[AuditEvent]:
    evidence = _evidence_for_packet(packet)
    evidence_refs = list(evidence.values())
    review_plan = _review_plan_for_packet(packet, evidence)
    primary_item = _highest_risk_item(review_plan)
    decision = _decision_for_plan(review_plan)
    votes = _votes_for_plan(review_plan, primary_item)
    remediations = _unique_list(
        item
        for plan_item in review_plan
        for item in _as_string_list(plan_item.get("remediation"))
    )
    re_review_criteria = _re_review_criteria(packet, review_plan)
    packet_metadata = _packet_metadata(packet)
    room_manifest = _band_room_manifest(packet=packet, evidence_count=len(evidence_refs))
    base_metadata = {
        **packet_metadata,
        "review_plan": review_plan,
        "source_of_truth": "band_room_events",
    }

    return [
        AuditEvent(
            event_id="evt_0001",
            audit_id=AUDIT_ID,
            room_id=ROOM_ID,
            agent="ChairAgent",
            event_type=EventType.AUDIT_INIT,
            summary=(
                f"Locked enterprise release packet {packet.packet_version} for {packet.target_name or 'the submitted system'}: "
                f"{packet.change_summary or packet.review_type or 'release review'}."
            ),
            created_at=_event_ts(0),
            phase=AuditPhase.INTAKE,
            severity=Severity.INFO,
            metadata={
                **base_metadata,
                "locked_packet": True,
                "locked_by": packet.attestations[0].name if packet.attestations else packet.business_owner,
                "packet_locked_at": _now_iso(),
                "band_room_manifest": room_manifest,
            },
        ),
        AuditEvent(
            event_id="evt_0002",
            audit_id=AUDIT_ID,
            room_id=ROOM_ID,
            agent="EvidenceMapper",
            event_type=EventType.ARTIFACT_INDEXED,
            summary=(
                f"Indexed {len(evidence_refs)} release-packet evidence rows and generated {len(review_plan)} "
                "review-plan claims with source hashes, owners, and control links."
            ),
            created_at=_event_ts(1),
            phase=AuditPhase.EVIDENCE_MAPPING,
            severity=Severity.INFO,
            evidence_refs=evidence_refs,
            metadata={
                **base_metadata,
                "evidence_ref_count": len(evidence_refs),
                "control_claim_count": len(packet.control_claims),
            },
        ),
        _finding_event("evt_0003", review_plan[0], 2),
        _finding_event("evt_0004", review_plan[1], 3),
        _finding_event("evt_0005", review_plan[2], 4),
        _verification_event("evt_0006", review_plan[0], 5, confirmed=True),
        _challenge_event("evt_0007", primary_item, 6),
        _conflict_event("evt_0008", primary_item, 7),
        _debate_event("evt_0009", primary_item, 8),
        _verification_event("evt_0010", primary_item, 9, confirmed=True),
        AuditEvent(
            event_id="evt_0011",
            audit_id=AUDIT_ID,
            room_id=ROOM_ID,
            agent="ChairAgent",
            event_type=EventType.VOTE,
            claim_id=str(primary_item["claim_id"]),
            summary=(
                f"Requested release decision votes after debate closed with {len(review_plan)} "
                f"review-plan claims still requiring release-board disposition."
            ),
            created_at=_event_ts(10),
            phase=AuditPhase.VOTE,
            severity=_severity(primary_item["severity"]),
            confidence=0.9,
            evidence_refs=_plan_evidence(primary_item),
            metadata={
                "review_plan_item_id": primary_item["claim_id"],
                "votes": votes,
                "vote_summary": _vote_summary(votes),
                "risk_effect": "pending_synthesis",
            },
        ),
        AuditEvent(
            event_id="evt_0012",
            audit_id=AUDIT_ID,
            room_id=ROOM_ID,
            agent="Synthesizer",
            event_type=EventType.SYNTHESIS_REPORT,
            summary=_synthesis_summary(packet, decision, review_plan),
            created_at=_event_ts(11),
            phase=AuditPhase.COMPLETE,
            severity=_overall_severity(review_plan),
            confidence=0.92,
            evidence_refs=evidence_refs,
            metadata={
                "decision": decision,
                "release_verdict": _release_verdict(packet, decision),
                "executive_summary": _executive_summary(packet, decision, review_plan),
                "required_remediations": remediations,
                "re_review_criteria": re_review_criteria,
                "evidence_standard": "Every material release claim must resolve to Band events plus cited packet or artifact evidence.",
                "votes": votes,
                "review_plan": review_plan,
            },
        ),
    ]


def demo_events_for_packet(packet: AuditPacket) -> list[AuditEvent]:
    return review_events_for_packet(packet)


def _band_room_manifest(*, packet: AuditPacket, evidence_count: int) -> dict[str, object]:
    return {
        "room_purpose": "Canonical release-board workspace for a BandAudit AI-agent release decision.",
        "canonical_record": True,
        "room_id": ROOM_ID,
        "room_url": "",
        "packet_source": packet.packet_source_mode or "manual",
        "packet_version": packet.packet_version or "v2",
        "review_type": packet.review_type,
        "target_name": packet.target_name,
        "evidence_count": evidence_count,
        "participant_strategy": "single_band_agent_with_structured_release_board_lanes",
        "human_reviewers": [],
        "release_board_lanes": LANE_ROSTER,
        "provider_routes": [],
        "recruited_peers": [],
        "peer_recruitment_enabled": False,
    }


def _review_plan_for_packet(packet: AuditPacket, evidence: dict[str, EvidenceRef]) -> list[dict[str, object]]:
    control_gaps = [
        claim
        for claim in packet.control_claims
        if claim.required and claim.status not in {"implemented", "approved", "verified"}
    ]
    owner_gap = not (packet.business_owner.strip() and packet.technical_owner.strip())
    attestation_gap = not any(item.name.strip() for item in packet.attestations)
    control_gap = bool(control_gaps or owner_gap or attestation_gap)
    write_access = _has_write_access(packet)
    eval_gap = _has_evaluation_gap(packet)

    governance_severity = Severity.CRITICAL if owner_gap or attestation_gap else Severity.HIGH if control_gap else Severity.MEDIUM
    boundary_severity = Severity.CRITICAL if write_access and not packet.tool_profile.approval_required_for_writes else Severity.HIGH if write_access else Severity.MEDIUM
    model_severity = Severity.HIGH if eval_gap else Severity.MEDIUM
    if packet.criticality.lower() in {"critical", "high"} and eval_gap:
        model_severity = Severity.HIGH

    return [
        {
            "claim_id": "GOV-001",
            "title": "Release ownership and control evidence requires board review",
            "category": "Governance",
            "severity": governance_severity.value,
            "assigned_agent": "ComplianceAgent",
            "summary": (
                f"{packet.target_name or 'The submitted system'} needs release ownership, required controls, "
                "attestation, rollout, and rollback evidence verified before production approval."
            ),
            "risk_mechanism": (
                f"The packet identifies {packet.deployment_environment or 'a release environment'} and "
                f"{packet.affected_users or 'affected users'}, but unresolved control status can leave release "
                "accountability, approvals, or rollback obligations unenforced."
            ),
            "affected_assets": _compact_list([packet.deployment_environment, packet.affected_users, packet.release_goal]),
            "release_impact": "Blocks or conditions release until required owners, controls, attestations, and recovery obligations are proven.",
            "remediation": _compact_list(
                [
                    "Name accountable business and technical owners.",
                    f"Resolve required control gaps: {_control_gap_summary(packet)}.",
                    "Attach approval, rollback, and incident-response evidence with owner and hash.",
                ]
            ),
            "required_verification": "Verify owner, attestation, rollout, rollback, and required-control evidence.",
            "evidence_refs": _evidence_refs_for_terms(evidence, ["policy", "control", "approval", "rollout", "rollback", "runbook"], ["E-001", "E-005", "E-007"]),
            "blocking": governance_severity in {Severity.HIGH, Severity.CRITICAL},
        },
        {
            "claim_id": "SEC-001",
            "title": "Data, tool, and instruction-boundary evidence requires review",
            "category": "Security",
            "severity": boundary_severity.value,
            "assigned_agent": "SecurityRedTeam",
            "summary": (
                f"{packet.target_name or 'The submitted system'} has declared tool or data access that needs proof of "
                "least privilege, approval before side effects, and isolation of untrusted inputs."
            ),
            "risk_mechanism": (
                f"Tool access is declared as: {packet.tool_access or 'not supplied'}. Without evidence-backed boundaries, "
                "agent reasoning can trigger unintended reads, writes, external actions, or policy violations."
            ),
            "affected_assets": _compact_list([packet.tool_access, ", ".join(packet.tool_profile.write_permissions), ", ".join(packet.data_profile.categories)]),
            "release_impact": "Blocks or conditions release until tool permissions, side effects, and input-boundary controls are proven.",
            "remediation": _compact_list(
                [
                    "Document read/write permissions and external side effects.",
                    "Require explicit approval for write-capable or externally visible actions.",
                    "Attach misuse, prompt-boundary, or tool-execution tests tied to the release package.",
                ]
            ),
            "required_verification": "Verify tool permissions, side-effect approval, and untrusted-input controls from cited artifacts.",
            "evidence_refs": _evidence_refs_for_terms(evidence, ["tool", "permission", "security", "prompt", "red", "misuse", "data"], ["E-002", "E-003", "E-006"]),
            "blocking": boundary_severity in {Severity.HIGH, Severity.CRITICAL},
        },
        {
            "claim_id": "MR-001",
            "title": "Evaluation, monitoring, and limitation evidence requires review",
            "category": "Model Risk",
            "severity": model_severity.value,
            "assigned_agent": "ModelRiskAgent",
            "summary": (
                f"{packet.target_name or 'The submitted system'} needs release evidence that evaluation coverage, "
                "known limitations, monitoring, stop conditions, and rollback criteria match the planned rollout."
            ),
            "risk_mechanism": (
                f"Evaluation summary: {packet.evaluation_summary or packet.evidence_notes or 'not supplied'}. "
                f"Monitoring plan: {packet.monitoring_plan or 'not supplied'}."
            ),
            "affected_assets": _compact_list([packet.evaluation_summary, packet.monitoring_plan, packet.known_limitations]),
            "release_impact": "Blocks or conditions release until evaluation coverage, monitoring, and limitation handling are evidence-backed.",
            "remediation": _compact_list(
                [
                    "Attach evaluation evidence appropriate to the use case and affected population.",
                    "Define production monitoring thresholds and stop conditions.",
                    "Tie known limitations to rollout scope, rollback triggers, and incident ownership.",
                ]
            ),
            "required_verification": "Verify evaluation, monitoring, limitation, and rollback evidence against release criticality.",
            "evidence_refs": _evidence_refs_for_terms(evidence, ["eval", "metric", "monitor", "limitation", "rollback", "incident", "risk"], ["E-004", "E-005", "E-007"]),
            "blocking": model_severity in {Severity.HIGH, Severity.CRITICAL},
        },
    ]


def _finding_event(event_id: str, item: dict[str, object], offset: int) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent=str(item["assigned_agent"]),
        event_type=EventType.FINDING,
        claim_id=str(item["claim_id"]),
        summary=str(item["summary"]),
        created_at=_event_ts(offset),
        phase=AuditPhase.SPECIALIST_REVIEW,
        severity=_severity(item["severity"]),
        confidence=0.86,
        risk_delta=_risk_delta(_severity(item["severity"])),
        evidence_refs=_plan_evidence(item),
        metadata=_plan_metadata(item, risk_effect="open"),
    )


def _verification_event(event_id: str, item: dict[str, object], offset: int, *, confirmed: bool) -> AuditEvent:
    risk_effect = "confirmed" if confirmed else "resolved"
    return AuditEvent(
        event_id=event_id,
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="FactVerifier",
        event_type=EventType.VERIFICATION,
        claim_id=str(item["claim_id"]),
        summary=(
            f"Verified {item['claim_id']} against cited packet evidence: {item['required_verification']} "
            f"The claim remains {'release-blocking' if item.get('blocking') else 'conditional'} until evidence-backed remediation is supplied."
        ),
        created_at=_event_ts(offset),
        phase=AuditPhase.DEBATE if event_id == "evt_0010" else AuditPhase.VERIFICATION,
        severity=_severity(item["severity"]),
        confidence=0.84,
        evidence_refs=_plan_evidence(item),
        metadata={
            **_plan_metadata(item, risk_effect=risk_effect),
            "status": "verified_release_blocker" if item.get("blocking") else "verified",
            "resolved_claim": False,
            "verification_note": str(item["required_verification"]),
        },
    )


def _challenge_event(event_id: str, item: dict[str, object], offset: int) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="FactVerifier",
        event_type=EventType.CHALLENGE,
        claim_id=str(item["claim_id"]),
        summary=f"Challenged whether {item['claim_id']} has enough direct evidence for release disposition: {item['title']}.",
        created_at=_event_ts(offset),
        phase=AuditPhase.VERIFICATION,
        severity=Severity.MEDIUM if _severity(item["severity"]) == Severity.HIGH else _severity(item["severity"]),
        confidence=0.76,
        evidence_refs=_plan_evidence(item),
        metadata={
            **_plan_metadata(item, risk_effect="needs_evidence"),
            "target_agent": item["assigned_agent"],
            "verification_note": "Requested tighter evidence linkage before final release vote.",
        },
    )


def _conflict_event(event_id: str, item: dict[str, object], offset: int) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent="ChairAgent",
        event_type=EventType.CONFLICT_DECLARATION,
        claim_id=str(item["claim_id"]),
        summary=f"Opened Band debate for {item['claim_id']} because the board needs explicit disposition of {item['title']}.",
        created_at=_event_ts(offset),
        phase=AuditPhase.DEBATE,
        severity=_severity(item["severity"]),
        confidence=0.82,
        metadata={**_plan_metadata(item, risk_effect="debate_required"), "rounds": 2},
    )


def _debate_event(event_id: str, item: dict[str, object], offset: int) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        audit_id=AUDIT_ID,
        room_id=ROOM_ID,
        agent=str(item["assigned_agent"]),
        event_type=EventType.DEBATE_POSITION,
        claim_id=str(item["claim_id"]),
        summary=f"Argued that {item['title']} remains material to the release decision until remediation is attached and verified.",
        created_at=_event_ts(offset),
        phase=AuditPhase.DEBATE,
        severity=_severity(item["severity"]),
        confidence=0.88,
        evidence_refs=_plan_evidence(item),
        metadata={**_plan_metadata(item, risk_effect="release_blocking"), "position": "block" if item.get("blocking") else "conditional"},
    )


def _plan_metadata(item: dict[str, object], *, risk_effect: str) -> dict[str, object]:
    return {
        "review_plan_item_id": item["claim_id"],
        "title": item["title"],
        "category": item["category"],
        "risk_mechanism": item["risk_mechanism"],
        "affected_assets": _as_string_list(item.get("affected_assets")),
        "release_impact": item["release_impact"],
        "remediation": _as_string_list(item.get("remediation")),
        "required_verification": item["required_verification"],
        "risk_effect": risk_effect,
    }


def _evidence_refs_for_terms(
    evidence: dict[str, EvidenceRef],
    terms: list[str],
    fallback_refs: list[str],
    *,
    limit: int = 3,
) -> list[dict[str, str]]:
    matches: list[EvidenceRef] = []
    for ref in evidence.values():
        haystack = f"{ref.ref_id} {ref.title} {ref.artifact} {ref.locator}".lower()
        if any(term in haystack for term in terms):
            matches.append(ref)
    for ref_id in fallback_refs:
        ref = evidence.get(ref_id)
        if ref and all(existing.ref_id != ref.ref_id for existing in matches):
            matches.append(ref)
    if not matches:
        matches = list(evidence.values())[:limit]
    return [ref.model_dump(mode="json") for ref in matches[:limit]]


def _plan_evidence(item: dict[str, object]) -> list[EvidenceRef]:
    refs = item.get("evidence_refs")
    if not isinstance(refs, list):
        return []
    result: list[EvidenceRef] = []
    for ref in refs:
        if isinstance(ref, EvidenceRef):
            result.append(ref)
        elif isinstance(ref, dict):
            result.append(EvidenceRef.model_validate(ref))
    return result


def _highest_risk_item(review_plan: list[dict[str, object]]) -> dict[str, object]:
    return max(review_plan, key=lambda item: SEVERITY_ORDER[_severity(item["severity"])])


def _overall_severity(review_plan: list[dict[str, object]]) -> Severity:
    return _severity(_highest_risk_item(review_plan)["severity"])


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value))
    except ValueError:
        return Severity.MEDIUM


def _risk_delta(severity: Severity) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 8,
        Severity.MEDIUM: 16,
        Severity.HIGH: 28,
        Severity.CRITICAL: 38,
    }[severity]


def _decision_for_plan(review_plan: list[dict[str, object]]) -> str:
    if any(item.get("blocking") for item in review_plan):
        return "blocked"
    if any(_severity(item["severity"]) in {Severity.MEDIUM, Severity.HIGH} for item in review_plan):
        return "conditionally_approved"
    return "approved"


def _votes_for_plan(review_plan: list[dict[str, object]], primary_item: dict[str, object]) -> list[dict[str, object]]:
    item_by_agent = {str(item["assigned_agent"]): item for item in review_plan}
    votes: list[dict[str, object]] = []
    for agent in ("ComplianceAgent", "SecurityRedTeam", "ModelRiskAgent", "FactVerifier"):
        item = item_by_agent.get(agent, primary_item)
        severity = _severity(item["severity"])
        vote = "block" if item.get("blocking") and severity in {Severity.HIGH, Severity.CRITICAL} else "conditional"
        votes.append(
            {
                "agent": agent,
                "vote": vote,
                "claim_refs": [item["claim_id"]],
                "rationale": f"{item['title']} requires {'remediation' if vote == 'block' else 'verification'} before unrestricted release.",
            }
        )
    return votes


def _vote_summary(votes: list[dict[str, object]]) -> str:
    blocks = sum(1 for vote in votes if vote.get("vote") == "block")
    conditional = sum(1 for vote in votes if vote.get("vote") == "conditional")
    approvals = sum(1 for vote in votes if vote.get("vote") == "approve")
    return f"{blocks} block, {conditional} conditional, {approvals} approve"


def _release_verdict(packet: AuditPacket, decision: str) -> str:
    target = packet.target_name or "The submitted release"
    if decision == "approved":
        return f"{target} is approved for production release based on the current Band event record."
    if decision == "conditionally_approved":
        return f"{target} may proceed only after the recorded release conditions are satisfied and attached to Band."
    return f"{target} is not approved for production release until the recorded blockers are remediated and re-reviewed."


def _executive_summary(packet: AuditPacket, decision: str, review_plan: list[dict[str, object]]) -> str:
    target = packet.target_name or "the submitted system"
    top_items = ", ".join(str(item["title"]).lower() for item in review_plan if item.get("blocking")) or "release controls"
    return (
        f"The release board reconstructed the decision for {target} from the locked packet, cited evidence, "
        f"provider-diverse agent lanes, debate, votes, and synthesis events in Band. The decision is {decision.replace('_', ' ')} "
        f"because the record still requires disposition of {top_items}."
    )


def _synthesis_summary(packet: AuditPacket, decision: str, review_plan: list[dict[str, object]]) -> str:
    target = packet.target_name or "the submitted system"
    top_item = _highest_risk_item(review_plan)
    if decision == "approved":
        return f"Synthesized an approved release decision for {target} from Band evidence, votes, and agent-lane review."
    if decision == "conditionally_approved":
        return f"Synthesized a conditional release decision for {target}; {top_item['title']} must be verified before broad rollout."
    return f"Synthesized a blocked release decision for {target}; {top_item['title']} remains release-blocking."


def _re_review_criteria(packet: AuditPacket, review_plan: list[dict[str, object]]) -> list[str]:
    criteria = [
        f"Attach remediation evidence for {item['claim_id']}: {item['title']}."
        for item in review_plan
        if item.get("blocking")
    ]
    criteria.append("Run a fresh Band room re-review so the new decision is separated from the original trace.")
    if packet.incident_response_owner:
        criteria.append(f"Confirm {packet.incident_response_owner} owns incident response, rollback evidence, and stop-condition sign-off.")
    return _unique_list(criteria)


def _has_write_access(packet: AuditPacket) -> bool:
    text = " ".join(
        [
            packet.tool_access,
            " ".join(packet.tool_profile.write_permissions),
            " ".join(packet.tool_profile.external_side_effects),
        ]
    ).lower()
    return bool(packet.tool_profile.write_permissions or any(term in text for term in ("write", "update", "delete", "send", "external", "side effect", "mutate")))


def _has_evaluation_gap(packet: AuditPacket) -> bool:
    text = " ".join([packet.evaluation_summary, packet.evidence_notes, packet.known_limitations, packet.monitoring_plan]).lower()
    if not packet.evaluation_summary.strip():
        return True
    return any(term in text for term in ("missing", "gap", "partial", "incomplete", "not supplied", "unknown", "exception"))


def _compact_list(values: list[str | object]) -> list[str]:
    return _unique_list(str(value).strip() for value in values if str(value).strip())


def _as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _unique_list(values: object) -> list[str]:
    result: list[str] = []
    for value in values:
        item = str(value).strip()
        if item and item not in result:
            result.append(item)
    return result


def _event_ts(offset: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=offset)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence_for_packet(packet: AuditPacket) -> dict[str, EvidenceRef]:
    evidence: dict[str, EvidenceRef] = {}
    for index, item in enumerate(packet.evidence_manifest, start=1):
        ref = _manifest_evidence(item, index)
        evidence[ref.ref_id] = ref

    fallback = {
        "E-001": _packet_evidence(
            "E-001",
            "System overview",
            "submitted_packet/system_overview.md",
            "target_summary",
            packet.target_summary,
        ),
        "E-002": _packet_evidence(
            "E-002",
            "Tool access",
            "submitted_packet/tool_access.md",
            "tool_access",
            packet.tool_access,
        ),
        "E-003": _packet_evidence(
            "E-003",
            "Workflow description",
            "submitted_packet/workflow.md",
            "workflow",
            packet.workflow,
        ),
        "E-004": _packet_evidence(
            "E-004",
            "Evaluation evidence",
            "submitted_packet/evaluation_notes.md",
            "evidence_notes",
            packet.evidence_notes,
        ),
        "E-005": _packet_evidence(
            "E-005",
            "Policy context",
            "submitted_packet/policy_context.md",
            "policy_context",
            packet.policy_context,
        ),
        "E-006": _packet_evidence(
            "E-006",
            "Prompt-injection or misuse tests",
            "submitted_packet/security_tests.md",
            "evidence_notes",
            packet.evidence_notes,
        ),
        "E-007": _packet_evidence(
            "E-007",
            "Monitoring and rollback plan",
            "submitted_packet/release_controls.md",
            "release_goal",
            packet.release_goal,
        ),
    }
    for ref_id, ref in fallback.items():
        evidence.setdefault(ref_id, ref)
    return evidence


def _packet_evidence(ref_id: str, title: str, artifact: str, locator: str, content: str) -> EvidenceRef:
    return EvidenceRef(
        ref_id=ref_id,
        title=title,
        artifact=artifact,
        locator=locator,
        sha256=sha256(content.encode("utf-8")).hexdigest(),
    )


def _manifest_evidence(item: EvidenceManifestItem, index: int) -> EvidenceRef:
    ref_id = item.ref_id.strip() or f"E-{index:03d}"
    locator = item.locator or item.linked_control or item.linked_risk or item.evidence_type
    content = "|".join(
        [
            ref_id,
            item.title,
            item.evidence_type,
            item.artifact,
            item.source,
            item.owner,
            item.linked_control,
            item.linked_risk,
            item.freshness,
            item.status,
            locator,
        ]
    )
    return EvidenceRef(
        ref_id=ref_id,
        title=item.title,
        artifact=item.artifact,
        locator=locator,
        sha256=item.sha256 or sha256(content.encode("utf-8")).hexdigest(),
    )


def _packet_metadata(packet: AuditPacket) -> dict[str, object]:
    return {
        "packet_version": packet.packet_version,
        "packet_source_mode": packet.packet_source_mode,
        "review_type": packet.review_type,
        "target_name": packet.target_name,
        "target_summary": packet.target_summary,
        "change_summary": packet.change_summary,
        "workflow": packet.workflow,
        "tool_access": packet.tool_access,
        "policy_context": packet.policy_context,
        "evidence_notes": packet.evidence_notes,
        "business_owner": packet.business_owner,
        "technical_owner": packet.technical_owner,
        "owning_team": packet.owning_team,
        "deployment_environment": packet.deployment_environment,
        "affected_users": packet.affected_users,
        "criticality": packet.criticality,
        "planned_release_date": packet.planned_release_date,
        "previous_review_id": packet.previous_review_id,
        "ticket_url": packet.ticket_url,
        "repository_url": packet.repository_url,
        "system_type": packet.system_type,
        "autonomy_level": packet.autonomy_level,
        "human_oversight": packet.human_oversight,
        "data_profile": packet.data_profile.model_dump(mode="json"),
        "tool_profile": packet.tool_profile.model_dump(mode="json"),
        "control_claims": [item.model_dump(mode="json") for item in packet.control_claims],
        "evidence_manifest": [item.model_dump(mode="json") for item in packet.evidence_manifest],
        "evaluation_summary": packet.evaluation_summary,
        "known_limitations": packet.known_limitations,
        "release_goal": packet.release_goal,
        "rollout_plan": packet.rollout_plan,
        "monitoring_plan": packet.monitoring_plan,
        "rollback_plan": packet.rollback_plan,
        "incident_response_owner": packet.incident_response_owner,
        "stop_conditions": packet.stop_conditions,
        "attestations": [item.model_dump(mode="json") for item in packet.attestations],
        "external_references": [item.model_dump(mode="json") for item in packet.external_references],
        "re_review_context": packet.re_review_context.model_dump(mode="json"),
        "import_summary": packet.import_summary.model_dump(mode="json"),
        "supporting_evidence_imports": [item.model_dump(mode="json") for item in packet.supporting_evidence_imports],
    }


def _control_gap_summary(packet: AuditPacket) -> str:
    gaps = [
        f"{claim.control_id} {claim.status}"
        for claim in packet.control_claims
        if claim.required and claim.status not in {"implemented", "approved", "verified"}
    ]
    return ", ".join(gaps[:4]) or "no claimed control gaps supplied"
