from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from app.models import (
    AgentExecutionDiagnostics,
    AgentProviderRoute,
    AuditEvent,
    ProviderDiagnostics,
    Severity,
)
from app.services.env import EnvLoadStatus, load_project_env
from app.services.model_providers import (
    ChatCompletionProvider,
    ProviderId,
    build_provider_registry,
)


logger = logging.getLogger(__name__)

AGENT_PROVIDER_ASSIGNMENTS: dict[str, ProviderId] = {
    "ChairAgent": "aiml",
    "EvidenceMapper": "aiml",
    "ComplianceAgent": "aiml",
    "SecurityRedTeam": "featherless",
    "ModelRiskAgent": "featherless",
    "FactVerifier": "featherless",
    "Synthesizer": "aiml",
}

AGENT_PROVIDER_PURPOSES: dict[str, str] = {
    "ChairAgent": "AI/ML API phase control and release-board orchestration",
    "EvidenceMapper": "AI/ML API evidence extraction and artifact linking",
    "ComplianceAgent": "AI/ML API policy and governance reasoning",
    "SecurityRedTeam": "Featherless open-weight adversarial review",
    "ModelRiskAgent": "Featherless open-weight model-risk and bias review",
    "FactVerifier": "Featherless independent claim verification",
    "Synthesizer": "AI/ML API final decision synthesis",
}

AGENT_MODEL_ENV_NAMES: dict[str, tuple[str, ...]] = {
    "ChairAgent": ("AIML_CHAIR_MODEL",),
    "EvidenceMapper": ("AIML_EVIDENCE_MODEL",),
    "ComplianceAgent": ("AIML_COMPLIANCE_MODEL",),
    "SecurityRedTeam": ("FEATHERLESS_SECURITY_MODEL",),
    "ModelRiskAgent": ("FEATHERLESS_MODEL_RISK_MODEL",),
    "FactVerifier": ("FEATHERLESS_VERIFIER_MODEL",),
    "Synthesizer": ("AIML_SYNTHESIZER_MODEL",),
}

LIVE_AGENT_MODES = {"auto", "live"}

SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

LOW_SIGNAL_CLEARANCE_FRAGMENTS = (
    "no immediate issues",
    "no issues detected",
    "no material issues",
    "safe to release",
    "ready for production",
    "approved for production",
    "cleared for release",
    "fully compliant",
)

BLOCKED_DECISION_FRAGMENTS = (
    "block",
    "blocked",
    "hold",
    "not approved",
    "not proceed",
    "pending remediation",
    "release-blocking",
    "remediate",
)


@dataclass(frozen=True)
class AgentExecutionConfig:
    requested_mode: str
    env_status: EnvLoadStatus
    timeout_seconds: float
    max_tokens: int
    temperature: float


class AgentExecutionService:
    def __init__(
        self,
        *,
        config: AgentExecutionConfig,
        providers: dict[ProviderId, ChatCompletionProvider],
    ) -> None:
        self._config = config
        self._providers = providers
        self._last_agent: str | None = None
        self._last_provider: ProviderId | None = None
        self._last_error: str | None = None

    def execute_next_event(
        self,
        *,
        existing_events: list[AuditEvent],
        template_event: AuditEvent,
        room_id: str,
    ) -> AuditEvent:
        requested_mode = self._config.requested_mode
        if requested_mode not in LIVE_AGENT_MODES:
            raise RuntimeError(
                f"BAND_AGENT_MODE={requested_mode} is not supported. "
                "BandAudit now requires live AI/ML API and Featherless execution."
            )

        assigned_provider = AGENT_PROVIDER_ASSIGNMENTS.get(template_event.agent)
        if assigned_provider is None:
            raise RuntimeError(f"No live provider route is configured for {template_event.agent}")
        provider = self._providers[assigned_provider]
        if not provider.ready:
            self._last_agent = template_event.agent
            self._last_provider = assigned_provider
            self._last_error = f"{provider.label} is not fully configured"
            raise RuntimeError(self._last_error)

        try:
            return self._run_provider(
                provider_id=assigned_provider,
                existing_events=existing_events,
                template_event=template_event,
                room_id=room_id,
            )
        except Exception as error:
            logger.warning("Agent provider %s failed: %s", assigned_provider, error)
            self._last_agent = template_event.agent
            self._last_provider = assigned_provider
            self._last_error = str(error)
            raise

    def diagnostics(self) -> AgentExecutionDiagnostics:
        provider_diagnostics = [
            self._provider_diagnostics(provider)
            for provider in self._providers.values()
        ]
        return AgentExecutionDiagnostics(
            requested_mode=self._config.requested_mode,
            effective_mode=self._effective_mode(),
            env_file=str(self._config.env_status.path),
            env_file_present=self._config.env_status.present,
            env_file_loaded=self._config.env_status.loaded,
            providers=provider_diagnostics,
            routes=self._provider_routes(),
            last_agent=self._last_agent,
            last_provider=self._last_provider,
            last_error=self._last_error,
        )

    def reset_diagnostics(self) -> None:
        self._last_agent = None
        self._last_provider = None
        self._last_error = None

    def _run_provider(
        self,
        *,
        provider_id: ProviderId,
        existing_events: list[AuditEvent],
        template_event: AuditEvent,
        room_id: str,
    ) -> AuditEvent:
        provider = self._providers[provider_id]
        route_model = self._model_for_agent(template_event.agent, provider_id)
        if template_event.event_type.value == "synthesis_report":
            event = self._template_fallback_event(
                existing_events=existing_events,
                template_event=template_event,
                room_id=room_id,
                validation_error="not_applicable_synthesis_projected_from_band_events",
            )
            event_metadata = {
                **event.metadata,
                "provider": provider_id,
                "provider_label": provider.label,
                "provider_model": route_model,
                "structured_output_mode": "not_called_deterministic_synthesis",
                "structured_output_repair_attempted": False,
                "structured_output_fallback": "deterministic_synthesis_from_band_events",
                "synthesis_source": "band_room_events",
            }
            event = event.model_copy(update={"provider": provider_id, "metadata": event_metadata})
            self._last_agent = template_event.agent
            self._last_provider = provider_id
            self._last_error = None
            return event

        messages = self._messages(existing_events=existing_events, template_event=template_event)
        content = provider.complete(
            messages=messages,
            max_tokens=self._config.max_tokens,
            temperature=self._config.temperature,
            model=route_model,
            response_format={"type": "json_object"},
        )
        repair_attempted = False
        fallback_reason: str | None = None
        fallback_error: str | None = None
        try:
            event = self._event_from_provider_output(
                content=content,
                existing_events=existing_events,
                template_event=template_event,
                room_id=room_id,
            )
        except (ValidationError, ValueError) as error:
            repair_attempted = True
            repair_messages = self._repair_messages(
                messages=messages,
                invalid_content=content,
                validation_error=str(error),
            )
            content = provider.complete(
                messages=repair_messages,
                max_tokens=self._config.max_tokens,
                temperature=0,
                model=route_model,
                response_format={"type": "json_object"},
            )
            try:
                event = self._event_from_provider_output(
                    content=content,
                    existing_events=existing_events,
                    template_event=template_event,
                    room_id=room_id,
                )
            except (ValidationError, ValueError) as repair_error:
                if not _can_use_template_fallback(template_event):
                    raise ValueError(
                        f"Provider output remained invalid after structured-output repair: {repair_error}"
                    ) from repair_error
                fallback_reason = "template_after_invalid_structured_output"
                fallback_error = str(repair_error)
                event = self._template_fallback_event(
                    existing_events=existing_events,
                    template_event=template_event,
                    room_id=room_id,
                    validation_error=fallback_error,
                )
        event_metadata = {
            **event.metadata,
            "provider": provider_id,
            "provider_label": provider.label,
            "provider_model": route_model,
            "structured_output_mode": provider.structured_output_mode,
            "structured_output_repair_attempted": repair_attempted,
        }
        if fallback_reason:
            event_metadata.update(
                {
                    "structured_output_fallback": fallback_reason,
                    "structured_output_fallback_error": (fallback_error or "")[:500],
                }
            )
        event = event.model_copy(update={"provider": provider_id, "metadata": event_metadata})

        self._last_agent = template_event.agent
        self._last_provider = provider_id
        self._last_error = None
        return event

    def _template_fallback_event(
        self,
        *,
        existing_events: list[AuditEvent],
        template_event: AuditEvent,
        room_id: str,
        validation_error: str,
    ) -> AuditEvent:
        normalized_consumes_event_ids = _merge_ordered(
            template_event.consumes_event_ids,
            _default_consumes_event_ids(existing_events=existing_events, template_event=template_event),
        )
        normalized_produces_refs = _merge_ordered(
            template_event.produces_refs,
            _default_produces_refs(
                event=template_event,
                template_event=template_event,
                evidence_refs=template_event.evidence_refs,
            ),
        )
        normalized_finding_refs = _merge_ordered(
            template_event.finding_refs,
            [template_event.claim_id] if template_event.claim_id else [],
        )
        normalized_vote_refs = _merge_ordered(
            template_event.vote_refs,
            _default_vote_refs(event=template_event, template_event=template_event, existing_events=existing_events),
        )
        metadata = {
            **template_event.metadata,
            "quality_gates": {
                "schema_validated": True,
                "template_event_id_preserved": True,
                "severity_floor_applied": False,
                "deterministic_template_fallback": True,
                "deterministic_control_plane_fallback": template_event.event_type.value != "synthesis_report",
                "evidence_ref_count": len(template_event.evidence_refs),
                "consumed_event_count": len(normalized_consumes_event_ids),
                "produced_ref_count": len(normalized_produces_refs),
            },
            "fallback_note": (
                "Provider returned malformed structured output after repair; "
                "BandAudit published the validated template event instead."
            ),
            "fallback_validation_error": validation_error[:500],
        }
        event = template_event.model_copy(
            deep=True,
            update={
                "room_id": room_id,
                "consumes_event_ids": normalized_consumes_event_ids,
                "produces_refs": normalized_produces_refs,
                "finding_refs": normalized_finding_refs,
                "vote_refs": normalized_vote_refs,
                "metadata": metadata,
            },
        )
        _validate_event_quality(event=event, template_event=template_event)
        return event

    def _repair_messages(
        self,
        *,
        messages: list[dict[str, str]],
        invalid_content: str,
        validation_error: str,
    ) -> list[dict[str, str]]:
        return [
            *messages,
            {
                "role": "assistant",
                "content": invalid_content[:4000],
            },
            {
                "role": "user",
                "content": (
                    "The previous response failed BandAudit event patch validation. "
                    f"Validation error: {validation_error[:1200]}\n"
                    "Return only one compact JSON object with these optional keys: summary, severity, "
                    "confidence, risk_delta, evidence_ref_ids, consumes_event_ids, produces_refs, "
                    "finding_refs, vote_refs, metadata. Do not return the full AuditEvent object."
                ),
            },
        ]

    def _messages(
        self,
        *,
        existing_events: list[AuditEvent],
        template_event: AuditEvent,
    ) -> list[dict[str, str]]:
        prior_events = [
            {
                "event_id": event.event_id,
                "agent": event.agent,
                "event_type": event.event_type.value,
                "phase": event.phase.value,
                "claim_id": event.claim_id,
                "summary": event.summary,
            }
            for event in existing_events[-8:]
        ]
        target_name = str(template_event.metadata.get("target_name") or "the target system")
        workflow = str(template_event.metadata.get("workflow") or "the submitted enterprise workflow")
        tool_access = str(template_event.metadata.get("tool_access") or "the submitted tool-access scope")
        policy_context = str(template_event.metadata.get("policy_context") or "the submitted policy context")
        provider_purpose = AGENT_PROVIDER_PURPOSES.get(template_event.agent, "Specialist release-board review")
        supporting_imports = template_event.metadata.get("supporting_evidence_imports")
        supporting_evidence = supporting_imports if isinstance(supporting_imports, list) else []
        review_plan = template_event.metadata.get("review_plan")
        evidence_refs = [
            {
                "ref_id": evidence.ref_id,
                "title": evidence.title,
                "artifact": evidence.artifact,
                "locator": evidence.locator,
            }
            for evidence in template_event.evidence_refs
        ]
        template_defaults = {
            "event_id": template_event.event_id,
            "event_type": template_event.event_type.value,
            "phase": template_event.phase.value,
            "claim_id": template_event.claim_id,
            "agent": template_event.agent,
            "summary": template_event.summary,
            "severity": template_event.severity.value,
            "confidence": template_event.confidence,
            "risk_delta": template_event.risk_delta,
            "evidence_ref_ids": [evidence.ref_id for evidence in template_event.evidence_refs],
            "metadata": _compact_metadata(template_event.metadata),
        }

        return [
            {
                "role": "system",
                "content": (
                    "You are a BandAudit release-board lane. Return exactly one compact JSON object, "
                    "with no markdown or commentary. The backend will merge your patch into a trusted "
                    "Band AuditEvent template and validate it before publishing."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Generate the next structured audit event for the {target_name} release review.\n"
                    f"Agent lane: {template_event.agent}. Practical purpose: {provider_purpose}.\n"
                    f"Workflow under review: {workflow}.\n"
                    f"Tool access under review: {tool_access}.\n"
                    f"Policy context: {policy_context}.\n\n"
                    f"Current review plan:\n{json.dumps(review_plan if isinstance(review_plan, list) else [], indent=2)}\n\n"
                    f"Supporting evidence imports available to the board:\n{json.dumps(supporting_evidence[:8], indent=2)}\n\n"
                    "Return a compact patch only. Allowed keys: summary, severity, confidence, "
                    "risk_delta, evidence_ref_ids, consumes_event_ids, produces_refs, finding_refs, "
                    "vote_refs, metadata. Do not include event_id, audit_id, room_id, agent, "
                    "event_type, phase, claim_id, created_at, or a full schema.\n"
                    "You may improve summary, severity, confidence, risk_delta, evidence_ref_ids, "
                    "and metadata only when the evidence supports it.\n"
                    "Do not remove evidence references already present in the template. Do not downgrade "
                    "high or critical severity. Do not say the review found no issues unless the template "
                    "event is already an approval. For artifact_indexed events, say what was indexed, not "
                    "whether the release is safe. For blocked synthesis events, make the hold/blocked "
                    "release decision explicit and name the practical remediation area.\n\n"
                    f"Current event evidence references:\n{json.dumps(evidence_refs, indent=2)}\n\n"
                    f"Prior events:\n{json.dumps(prior_events, indent=2)}\n\n"
                    f"Template defaults to preserve:\n{json.dumps(template_defaults, indent=2)}\n\n"
                    "Example shape:\n"
                    '{"summary":"...","severity":"high","confidence":0.9,"risk_delta":12,'
                    '"evidence_ref_ids":["E-001"],"metadata":{"risk_effect":"confirmed_blocker"}}'
                ),
            },
        ]

    def _event_from_provider_output(
        self,
        *,
        content: str,
        existing_events: list[AuditEvent],
        template_event: AuditEvent,
        room_id: str,
    ) -> AuditEvent:
        payload = _extract_json_object(content)
        if "event_id" not in payload:
            return self._event_from_provider_patch(
                payload=payload,
                existing_events=existing_events,
                template_event=template_event,
                room_id=room_id,
            )

        try:
            candidate = AuditEvent.model_validate(payload)
        except ValidationError as error:
            raise ValueError(f"Provider output did not validate as AuditEvent: {error}") from error

        normalized_metadata = {**template_event.metadata, **candidate.metadata}
        normalized_evidence_refs = candidate.evidence_refs or template_event.evidence_refs
        normalized_severity = _stronger_severity(candidate.severity, template_event.severity)
        normalized_consumes_event_ids = _merge_ordered(
            candidate.consumes_event_ids or template_event.consumes_event_ids,
            _default_consumes_event_ids(existing_events=existing_events, template_event=template_event),
        )
        normalized_produces_refs = _merge_ordered(
            candidate.produces_refs or template_event.produces_refs,
            _default_produces_refs(event=candidate, template_event=template_event, evidence_refs=normalized_evidence_refs),
        )
        normalized_finding_refs = _merge_ordered(
            candidate.finding_refs or template_event.finding_refs,
            [template_event.claim_id] if template_event.claim_id else [],
        )
        normalized_vote_refs = _merge_ordered(
            candidate.vote_refs or template_event.vote_refs,
            _default_vote_refs(event=candidate, template_event=template_event, existing_events=existing_events),
        )
        normalized_metadata["quality_gates"] = {
            "schema_validated": True,
            "template_event_id_preserved": True,
            "severity_floor_applied": _severity_rank(candidate.severity) < _severity_rank(template_event.severity),
            "evidence_ref_count": len(normalized_evidence_refs),
            "consumed_event_count": len(normalized_consumes_event_ids),
            "produced_ref_count": len(normalized_produces_refs),
        }

        event = candidate.model_copy(
            deep=True,
            update={
                "event_id": template_event.event_id,
                "audit_id": template_event.audit_id,
                "room_id": room_id,
                "agent": template_event.agent,
                "event_type": template_event.event_type,
                "phase": template_event.phase,
                "claim_id": template_event.claim_id,
                "created_at": template_event.created_at,
                "severity": normalized_severity,
                "evidence_refs": normalized_evidence_refs,
                "consumes_event_ids": normalized_consumes_event_ids,
                "produces_refs": normalized_produces_refs,
                "finding_refs": normalized_finding_refs,
                "vote_refs": normalized_vote_refs,
                "metadata": normalized_metadata,
            },
        )
        _validate_event_quality(event=event, template_event=template_event)
        return event

    def _event_from_provider_patch(
        self,
        *,
        payload: dict[str, Any],
        existing_events: list[AuditEvent],
        template_event: AuditEvent,
        room_id: str,
    ) -> AuditEvent:
        metadata_patch = payload.get("metadata")
        if metadata_patch is not None and not isinstance(metadata_patch, dict):
            raise ValueError("Provider patch metadata must be an object")

        evidence_refs = _evidence_refs_from_patch(payload.get("evidence_ref_ids"), template_event.evidence_refs)
        candidate = template_event.model_copy(
            deep=True,
            update={
                "room_id": room_id,
                "summary": _patch_string(payload.get("summary"), template_event.summary),
                "severity": _patch_severity(payload.get("severity"), template_event.severity),
                "confidence": _patch_float(payload.get("confidence"), template_event.confidence, minimum=0, maximum=1),
                "risk_delta": _patch_int(payload.get("risk_delta"), template_event.risk_delta),
                "evidence_refs": evidence_refs,
                "consumes_event_ids": _patch_string_list(payload.get("consumes_event_ids"), template_event.consumes_event_ids),
                "produces_refs": _patch_string_list(payload.get("produces_refs"), template_event.produces_refs),
                "finding_refs": _patch_string_list(payload.get("finding_refs"), template_event.finding_refs),
                "vote_refs": _patch_string_list(payload.get("vote_refs"), template_event.vote_refs),
                "metadata": {**template_event.metadata, **(metadata_patch or {})},
            },
        )

        normalized_metadata = dict(candidate.metadata)
        normalized_consumes_event_ids = _merge_ordered(
            candidate.consumes_event_ids,
            _default_consumes_event_ids(existing_events=existing_events, template_event=template_event),
        )
        normalized_produces_refs = _merge_ordered(
            candidate.produces_refs,
            _default_produces_refs(event=candidate, template_event=template_event, evidence_refs=evidence_refs),
        )
        normalized_finding_refs = _merge_ordered(
            candidate.finding_refs,
            [template_event.claim_id] if template_event.claim_id else [],
        )
        normalized_vote_refs = _merge_ordered(
            candidate.vote_refs,
            _default_vote_refs(event=candidate, template_event=template_event, existing_events=existing_events),
        )
        normalized_metadata["quality_gates"] = {
            "schema_validated": True,
            "template_event_id_preserved": True,
            "patch_output": True,
            "severity_floor_applied": _severity_rank(candidate.severity) < _severity_rank(template_event.severity),
            "evidence_ref_count": len(evidence_refs),
            "consumed_event_count": len(normalized_consumes_event_ids),
            "produced_ref_count": len(normalized_produces_refs),
        }

        event = candidate.model_copy(
            deep=True,
            update={
                "event_id": template_event.event_id,
                "audit_id": template_event.audit_id,
                "room_id": room_id,
                "agent": template_event.agent,
                "event_type": template_event.event_type,
                "phase": template_event.phase,
                "claim_id": template_event.claim_id,
                "created_at": template_event.created_at,
                "severity": _stronger_severity(candidate.severity, template_event.severity),
                "evidence_refs": evidence_refs,
                "consumes_event_ids": normalized_consumes_event_ids,
                "produces_refs": normalized_produces_refs,
                "finding_refs": normalized_finding_refs,
                "vote_refs": normalized_vote_refs,
                "metadata": normalized_metadata,
            },
        )
        _validate_event_quality(event=event, template_event=template_event)
        return event

    def _provider_diagnostics(self, provider: ChatCompletionProvider) -> ProviderDiagnostics:
        return provider.diagnostics()

    def _provider_routes(self) -> list[AgentProviderRoute]:
        return [
            AgentProviderRoute(
                agent=agent,
                provider=provider,
                purpose=AGENT_PROVIDER_PURPOSES[agent],
                model=self._model_for_agent(agent, provider),
            )
            for agent, provider in AGENT_PROVIDER_ASSIGNMENTS.items()
        ]

    def _model_for_agent(self, agent: str, provider_id: ProviderId) -> str | None:
        for env_name in AGENT_MODEL_ENV_NAMES.get(agent, ()):
            value = os.getenv(env_name)
            if value:
                return value
        return self._providers[provider_id].model

    def _effective_mode(self) -> str:
        requested_mode = self._config.requested_mode
        if requested_mode not in LIVE_AGENT_MODES:
            return "mixed"

        live_providers = [self._providers["aiml"], self._providers["featherless"]]
        ready_count = sum(1 for provider in live_providers if provider.ready)
        if ready_count == len(live_providers):
            return "live"
        return "mixed"


def build_agent_executor(env_status: EnvLoadStatus | None = None) -> AgentExecutionService:
    if env_status is None:
        env_status = load_project_env()

    timeout_seconds = _env_float("BAND_AGENT_TIMEOUT_SECONDS", default=20.0)
    config = AgentExecutionConfig(
        requested_mode=os.getenv("BAND_AGENT_MODE", "live").strip().lower(),
        env_status=env_status,
        timeout_seconds=timeout_seconds,
        max_tokens=_env_int("BAND_AGENT_MAX_TOKENS", default=1400),
        temperature=_env_float("BAND_AGENT_TEMPERATURE", default=0.2),
    )
    return AgentExecutionService(
        config=config,
        providers=build_provider_registry(timeout_seconds=timeout_seconds),
    )


def _extract_json_object(content: str) -> dict[str, Any]:
    candidate = content.strip()
    if candidate.startswith("```"):
        lines = candidate.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        candidate = "\n".join(lines).strip()

    try:
        data = json.loads(candidate)
    except json.JSONDecodeError as error:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Provider output did not contain a JSON object") from error
        try:
            data = json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as inner_error:
            raise ValueError(f"Provider output JSON was malformed: {inner_error}") from inner_error

    if not isinstance(data, dict):
        raise ValueError("Provider output JSON was not an object")
    return data


def _compact_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    keys = {
        "category",
        "title",
        "risk_mechanism",
        "release_impact",
        "remediation",
        "verification_note",
        "risk_effect",
        "decision",
        "release_verdict",
        "executive_summary",
        "required_remediations",
        "re_review_criteria",
        "votes",
        "vote_summary",
        "review_plan_item_id",
    }
    compact = {key: value for key, value in metadata.items() if key in keys}
    review_plan = metadata.get("review_plan")
    if isinstance(review_plan, list):
        compact["review_plan"] = [
            {
                "claim_id": item.get("claim_id"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "assigned_agent": item.get("assigned_agent"),
                "status": item.get("status"),
            }
            for item in review_plan
            if isinstance(item, dict)
        ]
    return compact


def _patch_string(value: Any, fallback: str) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _patch_float(value: Any, fallback: float, *, minimum: float, maximum: float) -> float:
    if isinstance(value, (int, float)):
        return max(minimum, min(maximum, float(value)))
    return fallback


def _patch_int(value: Any, fallback: int) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return fallback


def _patch_severity(value: Any, fallback: Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    if isinstance(value, str):
        try:
            return Severity(value.lower())
        except ValueError:
            return fallback
    return fallback


def _patch_string_list(value: Any, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return fallback
    result = [str(item).strip() for item in value if str(item).strip()]
    return result or fallback


def _evidence_refs_from_patch(value: Any, template_refs: list[Any]) -> list[Any]:
    if not isinstance(value, list):
        return template_refs
    requested = [str(item).strip() for item in value if str(item).strip()]
    by_id = {str(getattr(ref, "ref_id", "")): ref for ref in template_refs}
    merged = list(template_refs)
    for ref_id in requested:
        ref = by_id.get(ref_id)
        if ref is not None and all(getattr(item, "ref_id", None) != ref_id for item in merged):
            merged.append(ref)
    return merged


def _stronger_severity(candidate: Any, template: Any) -> Any:
    if _severity_rank(candidate) < _severity_rank(template):
        return template
    return candidate


def _severity_rank(value: Any) -> int:
    raw = getattr(value, "value", value)
    return SEVERITY_RANK.get(str(raw), 0)


def _merge_ordered(primary: list[str], fallback: list[str]) -> list[str]:
    merged: list[str] = []
    for value in [*primary, *fallback]:
        if value and value not in merged:
            merged.append(value)
    return merged


def _can_use_template_fallback(template_event: AuditEvent) -> bool:
    return template_event.event_type.value in {"audit_init", "artifact_indexed", "vote", "synthesis_report"}


def _default_consumes_event_ids(*, existing_events: list[AuditEvent], template_event: AuditEvent) -> list[str]:
    if not existing_events:
        return []

    event_type = template_event.event_type.value
    claim_id = template_event.claim_id

    if event_type == "audit_init":
        relevant: list[AuditEvent] = []
    elif event_type == "artifact_indexed":
        relevant = [event for event in existing_events if event.event_type.value == "audit_init"]
    elif event_type == "finding":
        relevant = [
            event
            for event in existing_events
            if event.event_type.value in {"audit_init", "artifact_indexed"}
        ]
    elif event_type in {"verification", "challenge", "conflict_declaration", "debate_position"} and claim_id:
        relevant = [
            event
            for event in existing_events
            if event.claim_id == claim_id or event.event_type.value in {"audit_init", "artifact_indexed"}
        ]
    elif event_type == "vote":
        relevant = [
            event
            for event in existing_events
            if event.event_type.value
            in {"finding", "verification", "challenge", "conflict_declaration", "debate_position"}
        ]
    elif event_type == "synthesis_report":
        relevant = existing_events
    else:
        relevant = existing_events[-4:]

    return [event.event_id for event in relevant]


def _default_produces_refs(*, event: AuditEvent, template_event: AuditEvent, evidence_refs: list[Any]) -> list[str]:
    event_type = template_event.event_type.value
    claim_id = template_event.claim_id

    if event_type == "artifact_indexed":
        return [str(getattr(evidence, "ref_id", "")) for evidence in evidence_refs if getattr(evidence, "ref_id", "")]
    if event_type == "finding" and claim_id:
        return [claim_id]
    if event_type == "verification" and claim_id:
        return [f"verification:{claim_id}"]
    if event_type == "challenge" and claim_id:
        return [f"challenge:{claim_id}"]
    if event_type == "conflict_declaration" and claim_id:
        return [f"debate:{claim_id}"]
    if event_type == "debate_position" and claim_id:
        return [f"position:{event.agent}:{claim_id}"]
    if event_type == "vote":
        return ["release_vote"]
    if event_type == "synthesis_report":
        return ["release_decision", "release_report"]
    return []


def _default_vote_refs(*, event: AuditEvent, template_event: AuditEvent, existing_events: list[AuditEvent]) -> list[str]:
    if template_event.event_type.value != "vote":
        return []

    refs = [
        prior.claim_id
        for prior in existing_events
        if prior.claim_id and prior.event_type.value in {"finding", "verification", "challenge", "debate_position"}
    ]
    metadata_votes = event.metadata.get("votes")
    if isinstance(metadata_votes, list):
        for vote in metadata_votes:
            if isinstance(vote, dict):
                claim_refs = vote.get("claim_refs")
                if isinstance(claim_refs, list):
                    refs.extend(str(ref) for ref in claim_refs if ref)
                elif vote.get("claim_id"):
                    refs.append(str(vote["claim_id"]))
            elif vote:
                refs.append(str(vote))
    return _merge_ordered([], refs)


def _validate_event_quality(*, event: AuditEvent, template_event: AuditEvent) -> None:
    summary = event.summary.strip()
    normalized_summary = summary.lower()
    event_type = event.event_type.value
    template_decision = str(template_event.metadata.get("decision", "")).lower()

    if len(summary) < 24:
        raise ValueError("Provider output summary was too short for an enterprise audit event")

    if event_type == "artifact_indexed" and _contains_fragment(
        normalized_summary,
        LOW_SIGNAL_CLEARANCE_FRAGMENTS,
    ):
        raise ValueError("Provider output made a clearance claim during evidence indexing")

    if _severity_rank(template_event.severity) >= SEVERITY_RANK["high"] and _contains_fragment(
        normalized_summary,
        LOW_SIGNAL_CLEARANCE_FRAGMENTS,
    ):
        raise ValueError("Provider output contradicted a high-risk template event")

    if event_type == "synthesis_report" and template_decision == "blocked" and not _contains_fragment(
        normalized_summary,
        BLOCKED_DECISION_FRAGMENTS,
    ):
        raise ValueError("Provider output did not make the blocked release decision explicit")


def _contains_fragment(value: str, fragments: tuple[str, ...]) -> bool:
    return any(fragment in value for fragment in fragments)


def _env_int(name: str, *, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, *, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default
