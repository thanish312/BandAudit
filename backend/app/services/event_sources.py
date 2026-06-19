from __future__ import annotations

import json
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from typing import Any, Protocol

from pydantic import ValidationError

from app.data.sample_audit import AUDIT_ID, DEFAULT_AUDIT_PACKET, review_events_for_packet
from app.models import AgentExecutionDiagnostics, AuditEvent, AuditPacket, SourceDiagnostics
from app.services.agent_execution import AgentExecutionService, build_agent_executor
from app.services.env import PROJECT_ROOT, EnvLoadStatus, env_flag, load_project_env


logger = logging.getLogger(__name__)

BAND_AUDIT_PROTOCOL = "bandaudit.audit_event.v1"
BAND_ACTIVITY_PROTOCOL = "bandaudit.agent_activity.v1"


class AuditEventSource(Protocol):
    audit_id: str
    room_id: str
    source_name: str

    def events(self) -> list[AuditEvent]:
        ...

    def audit_packet(self) -> AuditPacket:
        ...

    def configure_packet(self, packet: AuditPacket) -> None:
        ...

    def advance(self) -> list[AuditEvent]:
        ...

    def reset(self) -> None:
        ...

    def create_room(self, task_id: str | None = None) -> CreatedRoom:
        ...

    def diagnostics(self) -> SourceDiagnostics:
        ...

    def agent_diagnostics(self) -> AgentExecutionDiagnostics:
        ...


@dataclass(frozen=True)
class SourceConfig:
    requested_mode: str
    env_status: EnvLoadStatus
    band_api_key_present: bool
    band_room_id_present: bool
    band_rest_url_configured: bool
    band_sdk_installed: bool
    band_sdk_version: str | None
    last_error: str | None = None


@dataclass(frozen=True)
class CreatedRoom:
    room_id: str
    room_url: str | None = None
    title: str | None = None


class BandSdkEventSource:
    audit_id = AUDIT_ID
    source_name = "band"

    def __init__(
        self,
        *,
        api_key: str,
        room_id: str,
        rest_url: str | None = None,
        page_size: int = 100,
        max_pages: int = 20,
        read_after_write_attempts: int = 4,
        read_after_write_delay_seconds: float = 0.35,
        agent_executor: AgentExecutionService | None = None,
    ) -> None:
        from band.client.rest import DEFAULT_REQUEST_OPTIONS, ChatEventRequest, ChatRoomRequest, ParticipantRequest, RestClient

        self.room_id = room_id
        self._rest_url = rest_url or "https://app.band.ai"
        self._page_size = page_size
        self._max_pages = max_pages
        self._read_after_write_attempts = read_after_write_attempts
        self._read_after_write_delay_seconds = read_after_write_delay_seconds
        self._request_options = DEFAULT_REQUEST_OPTIONS
        self._chat_event_request = ChatEventRequest
        self._chat_room_request = ChatRoomRequest
        self._participant_request = ParticipantRequest
        self._config = _source_config(requested_mode="band")
        self._audit_packet = DEFAULT_AUDIT_PACKET
        self._agent_executor = agent_executor or build_agent_executor()
        self._last_peer_recruitment: list[dict[str, Any]] = []
        self._client = RestClient(
            api_key=api_key,
            base_url=rest_url,
        )

    def reset(self) -> None:
        self._agent_executor.reset_diagnostics()
        logger.info("Band event source reset requested; Band room history is preserved")

    def create_room(self, task_id: str | None = None) -> CreatedRoom:
        response = self._client.agent_api_chats.create_agent_chat(
            chat=self._chat_room_request(task_id=task_id),
            request_options=self._request_options,
        )
        chat = getattr(response, "data", response)
        room_id = getattr(chat, "id", None)
        if not room_id:
            raise RuntimeError("Band created a chat room but did not return a room id.")

        self.room_id = str(room_id)
        self._audit_packet = DEFAULT_AUDIT_PACKET
        self._agent_executor.reset_diagnostics()
        self._last_peer_recruitment = self._recruit_lane_peers()

        return CreatedRoom(
            room_id=self.room_id,
            room_url=f"{self._rest_url.rstrip('/')}/chats/{self.room_id}",
            title=getattr(chat, "title", None),
        )

    def audit_packet(self) -> AuditPacket:
        events = self.events()
        for event in events:
            if event.event_type.value == "audit_init":
                metadata_packet = _packet_from_metadata(event.metadata)
                if metadata_packet is not None:
                    self._audit_packet = metadata_packet
                break
        return self._audit_packet

    def configure_packet(self, packet: AuditPacket) -> None:
        self._audit_packet = packet
        self._agent_executor.reset_diagnostics()

    def advance(self) -> list[AuditEvent]:
        before = self.events()
        existing_event_ids = {event.event_id for event in before}
        next_event = self._next_review_event(existing_event_ids)
        if next_event is None:
            return []

        route = self._route_for_agent(next_event.agent)
        expected_output = _expected_output_for_event(next_event)
        starts_synthesis = next_event.event_type.value == "synthesis_report"
        self._publish_activity_event(
            message_type="tool_call",
            content=(
                f"{next_event.agent} started deterministic synthesis from Band room events."
                if starts_synthesis
                else f"{next_event.agent} started {next_event.event_type.value} for {next_event.phase.value}."
            ),
            metadata={
                "activity": "synthesis_projection_started" if starts_synthesis else "provider_call_started",
                "template_event_id": next_event.event_id,
                "lane": _lane_label_for_agent(next_event.agent),
                "agent": next_event.agent,
                "phase": next_event.phase.value,
                "event_type": next_event.event_type.value,
                "claim_id": next_event.claim_id,
                "expected_output": expected_output,
                "source_of_truth": "band_room_events",
                "provider_call_required": not starts_synthesis,
                **route,
            },
        )

        try:
            agent_event = self._agent_executor.execute_next_event(
                existing_events=before,
                template_event=next_event,
                room_id=self.room_id,
            )
            event = self._prepare_event_for_room(agent_event)
            self._publish_event(event)
            self._publish_activity_event(
                message_type="tool_result",
                content=f"{next_event.agent} published validated {event.event_type.value} event {event.event_id}.",
                metadata={
                    "activity": "validated_event_published",
                    "audit_event_id": event.event_id,
                    "template_event_id": next_event.event_id,
                    "lane": _lane_label_for_agent(event.agent),
                    "agent": event.agent,
                    "phase": event.phase.value,
                    "event_type": event.event_type.value,
                    "claim_id": event.claim_id,
                    "expected_output": expected_output,
                    "schema_validated": True,
                    "consumes_event_ids": event.consumes_event_ids,
                    "produces_refs": event.produces_refs,
                    "finding_refs": event.finding_refs,
                    "vote_refs": event.vote_refs,
                    "evidence_ref_count": len(event.evidence_refs),
                    "structured_output_repair_attempted": event.metadata.get("structured_output_repair_attempted") is True,
                    "structured_output_fallback": event.metadata.get("structured_output_fallback", ""),
                    **route,
                },
            )
        except Exception as error:
            self._publish_activity_event(
                message_type="error",
                content=f"{next_event.agent} failed before publishing {next_event.event_type.value}: {error}",
                metadata={
                    "activity": "provider_call_failed",
                    "template_event_id": next_event.event_id,
                    "lane": _lane_label_for_agent(next_event.agent),
                    "agent": next_event.agent,
                    "phase": next_event.phase.value,
                    "event_type": next_event.event_type.value,
                    "claim_id": next_event.claim_id,
                    "expected_output": expected_output,
                    "error_type": type(error).__name__,
                    "error": str(error)[:500],
                    **route,
                },
            )
            raise

        for attempt in range(self._read_after_write_attempts):
            current = self.events()
            appended = [
                item for item in current if item.event_id not in existing_event_ids
            ]
            if any(item.event_id == event.event_id for item in appended):
                return appended
            if attempt < self._read_after_write_attempts - 1:
                time.sleep(self._read_after_write_delay_seconds)

        logger.warning(
            "Published Band audit event %s but it was not visible in context yet",
            event.event_id,
        )
        return []

    def events(self) -> list[AuditEvent]:
        events: OrderedDict[str, AuditEvent] = OrderedDict()
        for item in self._context_items():
            event = self._audit_event_from_context_item(item)
            if event is not None:
                events[event.event_id] = event

        return sorted(
            events.values(),
            key=lambda event: (event.created_at, event.event_id),
        )

    def diagnostics(self) -> SourceDiagnostics:
        return _diagnostics(
            config=self._config,
            source="band",
            effective_mode="band",
            room_id=self.room_id,
        )

    def agent_diagnostics(self) -> AgentExecutionDiagnostics:
        return self._agent_executor.diagnostics()

    def _context_items(self) -> list[Any]:
        items: list[Any] = []
        page = 1

        while page <= self._max_pages:
            response = self._client.agent_api_context.get_agent_chat_context(
                chat_id=self.room_id,
                page=page,
                page_size=self._page_size,
                request_options=self._request_options,
            )
            data = list(getattr(response, "data", None) or [])
            items.extend(data)

            meta = getattr(response, "metadata", None) or getattr(response, "meta", None)
            total_pages = getattr(meta, "total_pages", None)
            has_more = getattr(meta, "has_more", None)

            if total_pages is not None:
                if page >= int(total_pages):
                    break
            elif has_more is False or not data:
                break

            page += 1

        return items

    def _audit_event_from_context_item(self, item: Any) -> AuditEvent | None:
        metadata = _as_dict(getattr(item, "metadata", None))
        if metadata.get("protocol") != BAND_AUDIT_PROTOCOL:
            return None
        if metadata.get("audit_id") != self.audit_id:
            return None

        payload = metadata.get("audit_event")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                logger.warning("Skipping Band audit event with invalid JSON payload")
                return None

        if not isinstance(payload, dict):
            logger.warning("Skipping Band audit event with missing structured payload")
            return None

        try:
            event = AuditEvent.model_validate(payload)
        except ValidationError as error:
            logger.warning("Skipping invalid Band audit event payload: %s", error)
            return None

        if event.audit_id != self.audit_id:
            return None

        return event.model_copy(update={"room_id": self.room_id})

    def _next_review_event(self, existing_event_ids: set[str]) -> AuditEvent | None:
        for event in review_events_for_packet(self._audit_packet):
            if event.event_id not in existing_event_ids:
                return event
        return None

    def _prepare_event_for_room(self, event: AuditEvent) -> AuditEvent:
        metadata = dict(event.metadata)
        metadata["band_permalink"] = f"{self._rest_url.rstrip('/')}/chats/{self.room_id}"
        if event.event_type.value == "audit_init":
            metadata["band_room_manifest"] = self._room_manifest(metadata.get("band_room_manifest"))

        return event.model_copy(
            deep=True,
            update={
                "room_id": self.room_id,
                "metadata": metadata,
            },
        )

    def _publish_event(self, event: AuditEvent) -> None:
        payload = {
            "protocol": BAND_AUDIT_PROTOCOL,
            "audit_id": event.audit_id,
            "audit_event_id": event.event_id,
            "audit_event_type": event.event_type.value,
            "audit_event": event.model_dump(mode="json"),
        }
        self._client.agent_api_events.create_agent_chat_event(
            chat_id=self.room_id,
            event=self._chat_event_request(
                content=event.summary,
                message_type="task",
                metadata=payload,
            ),
            request_options=self._request_options,
        )

    def _publish_activity_event(self, *, message_type: str, content: str, metadata: dict[str, Any]) -> None:
        payload = {
            "protocol": BAND_ACTIVITY_PROTOCOL,
            "audit_id": self.audit_id,
            "room_id": self.room_id,
            **metadata,
        }
        try:
            self._client.agent_api_events.create_agent_chat_event(
                chat_id=self.room_id,
                event=self._chat_event_request(
                    content=content,
                    message_type=message_type,
                    metadata=payload,
                ),
                request_options=self._request_options,
            )
        except Exception as error:
            logger.warning("Could not publish Band activity event: %s", error)

    def _route_for_agent(self, agent: str) -> dict[str, Any]:
        for route in self._agent_executor.diagnostics().routes:
            if route.agent == agent:
                return {
                    "provider": route.provider,
                    "provider_model": route.model,
                    "provider_purpose": route.purpose,
                }
        return {}

    def _room_manifest(self, manifest_value: Any) -> dict[str, Any]:
        manifest = dict(manifest_value) if isinstance(manifest_value, dict) else {}
        routes = [
            {
                "agent": route.agent,
                "provider": route.provider,
                "model": route.model,
                "purpose": route.purpose,
            }
            for route in self._agent_executor.diagnostics().routes
        ]
        recruited_agents = {
            str(item.get("agent"))
            for item in self._last_peer_recruitment
            if item.get("status") == "recruited" and item.get("agent")
        }
        lanes = []
        for lane in manifest.get("release_board_lanes", []):
            if not isinstance(lane, dict):
                continue
            agent = str(lane.get("agent") or "")
            route = next((item for item in routes if item["agent"] == agent), None)
            lanes.append(
                {
                    **lane,
                    "provider": route["provider"] if route else lane.get("provider", ""),
                    "model": route["model"] if route else lane.get("model", ""),
                    "purpose": route["purpose"] if route else lane.get("role", ""),
                    "participant_mode": "recruited_band_peer" if agent in recruited_agents else lane.get("participant_mode", "structured_lane"),
                }
            )
        return {
            **manifest,
            "room_id": self.room_id,
            "room_url": f"{self._rest_url.rstrip('/')}/chats/{self.room_id}",
            "canonical_record": True,
            "participant_strategy": (
                "band_peer_recruitment_with_structured_lane_fallback"
                if env_flag("BAND_RECRUIT_LANE_PEERS", default=False)
                else "single_band_agent_with_structured_release_board_lanes"
            ),
            "human_reviewers": [],
            "release_board_lanes": lanes,
            "provider_routes": routes,
            "recruited_peers": self._last_peer_recruitment,
            "peer_recruitment_enabled": env_flag("BAND_RECRUIT_LANE_PEERS", default=False),
        }

    def _recruit_lane_peers(self) -> list[dict[str, Any]]:
        if not env_flag("BAND_RECRUIT_LANE_PEERS", default=False):
            return []
        peer_map = _lane_peer_map()
        if not peer_map:
            self._publish_activity_event(
                message_type="error",
                content="Band lane peer recruitment was enabled but BAND_LANE_PEERS_JSON was empty.",
                metadata={
                    "activity": "lane_peer_recruitment_skipped",
                    "peer_recruitment_enabled": True,
                    "reason": "empty_peer_map",
                },
            )
            return []

        results: list[dict[str, Any]] = []
        for agent, participant_id in peer_map.items():
            if not participant_id:
                continue
            try:
                self._client.agent_api_participants.add_agent_chat_participant(
                    chat_id=self.room_id,
                    participant=self._participant_request(participant_id=str(participant_id), role="member"),
                    request_options=self._request_options,
                )
                result = {
                    "agent": agent,
                    "participant_id": str(participant_id),
                    "status": "recruited",
                }
                results.append(result)
                self._publish_activity_event(
                    message_type="tool_result",
                    content=f"Recruited Band peer for {agent}.",
                    metadata={
                        "activity": "lane_peer_recruited",
                        **result,
                    },
                )
            except Exception as error:
                result = {
                    "agent": agent,
                    "participant_id": str(participant_id),
                    "status": "failed",
                    "error": str(error)[:500],
                }
                results.append(result)
                self._publish_activity_event(
                    message_type="error",
                    content=f"Could not recruit Band peer for {agent}: {error}",
                    metadata={
                        "activity": "lane_peer_recruitment_failed",
                        **result,
                    },
                )
        return results


def build_event_source() -> AuditEventSource:
    env_status = load_project_env()
    agent_executor = build_agent_executor(env_status=env_status)

    mode = os.getenv("BAND_AUDIT_MODE", "band").strip().lower()
    sdk_installed, sdk_version = _band_sdk_status()

    if mode not in {"auto", "band", "live"}:
        raise RuntimeError(
            f"BAND_AUDIT_MODE={mode} is not supported. "
            "BandAudit now requires a live Band event source."
        )
    if not sdk_installed:
        raise RuntimeError("band-sdk is required for BandAudit; install backend requirements.")

    api_key = os.getenv("BAND_API_KEY")
    room_id = os.getenv("BAND_ROOM_ID")
    if not api_key or not room_id:
        missing = [
            name
            for name, value in {
                "BAND_API_KEY": api_key,
                "BAND_ROOM_ID": room_id,
            }.items()
            if not value
        ]
        raise RuntimeError(
            f"{', '.join(missing)} required. "
            "BandAudit no longer starts without a live Band room."
        )

    source = BandSdkEventSource(
        api_key=api_key,
        room_id=room_id,
        rest_url=os.getenv("BAND_REST_URL") or None,
        agent_executor=agent_executor,
    )
    source._config = _source_config(
        requested_mode=mode,
        env_status=env_status,
        band_sdk_installed=sdk_installed,
        band_sdk_version=sdk_version,
    )
    if env_flag("BAND_VERIFY_ON_STARTUP", default=True):
        source.events()
    return source


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _lane_peer_map() -> dict[str, str]:
    raw = os.getenv("BAND_LANE_PEERS_JSON", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("BAND_LANE_PEERS_JSON is not valid JSON")
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(agent): str(participant_id) for agent, participant_id in data.items() if participant_id}


def _lane_label_for_agent(agent: str) -> str:
    return {
        "ChairAgent": "Chair",
        "EvidenceMapper": "Evidence",
        "ComplianceAgent": "Compliance",
        "SecurityRedTeam": "Security",
        "ModelRiskAgent": "Model Risk",
        "FactVerifier": "Verification",
        "Synthesizer": "Synthesis",
    }.get(agent, agent)


def _expected_output_for_event(event: AuditEvent) -> str:
    return {
        "audit_init": "locked packet manifest and Band room setup record",
        "artifact_indexed": "cited evidence index and review plan",
        "finding": "specialist finding with risk, severity, owner, and evidence refs",
        "verification": "claim verification with risk effect and cited proof",
        "challenge": "challenge requiring stronger evidence or control proof",
        "conflict_declaration": "debate opening with disputed claim context",
        "debate_position": "lane position on release-blocking impact",
        "vote": "release vote request with claim-linked vote records",
        "synthesis_report": "final decision, rationale, remediation, and re-review criteria",
    }.get(event.event_type.value, "validated AuditEvent JSON")


def _packet_from_metadata(metadata: dict[str, Any]) -> AuditPacket | None:
    required_keys = {
        "target_name",
        "target_summary",
        "workflow",
        "tool_access",
        "policy_context",
        "evidence_notes",
    }
    packet_keys = required_keys | {
        "packet_version",
        "packet_source_mode",
        "review_type",
        "change_summary",
        "business_owner",
        "technical_owner",
        "owning_team",
        "deployment_environment",
        "affected_users",
        "criticality",
        "planned_release_date",
        "previous_review_id",
        "ticket_url",
        "repository_url",
        "system_type",
        "autonomy_level",
        "human_oversight",
        "data_profile",
        "tool_profile",
        "control_claims",
        "evidence_manifest",
        "evaluation_summary",
        "known_limitations",
        "release_goal",
        "rollout_plan",
        "monitoring_plan",
        "rollback_plan",
        "incident_response_owner",
        "stop_conditions",
        "attestations",
        "external_references",
        "re_review_context",
        "import_summary",
        "supporting_evidence_imports",
    }
    if not required_keys.issubset(metadata):
        return None
    try:
        packet_data = {key: metadata[key] for key in packet_keys if key in metadata}
        return AuditPacket.model_validate(packet_data)
    except Exception:
        return None


def _band_sdk_status() -> tuple[bool, str | None]:
    try:
        return True, package_version("band-sdk")
    except PackageNotFoundError:
        return False, None


def _source_config(
    *,
    requested_mode: str,
    env_status: EnvLoadStatus | None = None,
    band_sdk_installed: bool | None = None,
    band_sdk_version: str | None = None,
    last_error: str | None = None,
) -> SourceConfig:
    if env_status is None:
        env_status = EnvLoadStatus(
            path=PROJECT_ROOT / ".env",
            present=(PROJECT_ROOT / ".env").exists(),
            loaded=False,
        )
    if band_sdk_installed is None:
        band_sdk_installed, band_sdk_version = _band_sdk_status()

    return SourceConfig(
        requested_mode=requested_mode,
        env_status=env_status,
        band_api_key_present=bool(os.getenv("BAND_API_KEY")),
        band_room_id_present=bool(os.getenv("BAND_ROOM_ID")),
        band_rest_url_configured=bool(os.getenv("BAND_REST_URL")),
        band_sdk_installed=band_sdk_installed,
        band_sdk_version=band_sdk_version,
        last_error=last_error,
    )


def _diagnostics(
    *,
    config: SourceConfig,
    source: str,
    effective_mode: str,
    room_id: str,
) -> SourceDiagnostics:
    return SourceDiagnostics(
        source=source,
        requested_mode=config.requested_mode,
        effective_mode=effective_mode,
        audit_id=AUDIT_ID,
        room_id=room_id,
        protocol=BAND_AUDIT_PROTOCOL,
        env_file=str(config.env_status.path),
        env_file_present=config.env_status.present,
        env_file_loaded=config.env_status.loaded,
        band_api_key_present=config.band_api_key_present,
        band_room_id_present=config.band_room_id_present,
        band_rest_url_configured=config.band_rest_url_configured,
        band_sdk_installed=config.band_sdk_installed,
        band_sdk_version=config.band_sdk_version,
        last_error=config.last_error,
    )
