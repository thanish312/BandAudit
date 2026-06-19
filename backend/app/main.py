from __future__ import annotations

import os

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.models import (
    AdvanceResponse,
    AgentExecutionDiagnostics,
    AuditPacket,
    AuditEvent,
    AuditState,
    CreateRoomResponse,
    EvidenceImportResponse,
    PacketImportResponse,
    SourceDiagnosticsResponse,
)
from app.services.audit_engine import AuditEngine, PacketReadinessError
from app.services.env import load_project_env
from app.services.event_sources import build_event_source
from app.services.model_providers import ProviderConfigurationError, ProviderRequestError
from app.services.packet_import import PacketImportError, import_packet_from_pdf, import_supporting_evidence


load_project_env()

DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5175",
]


def configured_cors_origins() -> list[str]:
    raw = os.getenv("BAND_CORS_ORIGINS", "")
    configured = [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]
    return [*DEFAULT_CORS_ORIGINS, *configured]


app = FastAPI(
    title="BandAudit API",
    description="Live Band API for the BandAudit Agent Release Board.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = AuditEngine(build_event_source())


@app.middleware("http")
async def bind_client_room(request: Request, call_next):
    room_id = request.headers.get("x-bandaudit-room-id", "").strip()
    if room_id and request.url.path.startswith("/api/audit"):
        engine.use_room(room_id)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, object]:
    source = engine.source_status()
    agent_execution = engine.agent_diagnostics()
    return {
        "status": "ok",
        "event_source": source.diagnostics.source,
        "requested_mode": source.diagnostics.requested_mode,
        "effective_mode": source.diagnostics.effective_mode,
        "band_room_id_present": source.diagnostics.band_room_id_present,
        "band_api_key_present": source.diagnostics.band_api_key_present,
        "band_sdk_version": source.diagnostics.band_sdk_version,
        "agent_mode": agent_execution.requested_mode,
        "agent_effective_mode": agent_execution.effective_mode,
        "provider_statuses": {
            provider.provider: provider.status
            for provider in agent_execution.providers
        },
        "event_count": source.event_count,
        "read_status": source.status,
    }


@app.get("/api/audit/source", response_model=SourceDiagnosticsResponse)
def get_source_diagnostics() -> SourceDiagnosticsResponse:
    return engine.source_status()


@app.get("/api/audit/providers", response_model=AgentExecutionDiagnostics)
def get_provider_diagnostics() -> AgentExecutionDiagnostics:
    return engine.agent_diagnostics()


@app.get("/api/audit", response_model=AuditState)
def get_audit() -> AuditState:
    return engine.state()


@app.put("/api/audit/packet", response_model=AuditState)
def configure_audit_packet(packet: AuditPacket) -> AuditState:
    try:
        return engine.configure_packet(packet)
    except PacketReadinessError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/api/audit/packet/import/pdf", response_model=PacketImportResponse)
async def import_audit_packet_pdf(file: UploadFile = File(...)) -> PacketImportResponse:
    try:
        data = await file.read()
        return import_packet_from_pdf(
            filename=file.filename or "release-packet.pdf",
            content_type=file.content_type,
            data=data,
        )
    except PacketImportError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.post("/api/audit/packet/import/evidence", response_model=EvidenceImportResponse)
async def import_audit_supporting_evidence(
    files: list[UploadFile] = File(...),
    packet_json: str = Form(...),
) -> EvidenceImportResponse:
    try:
        packet = AuditPacket.model_validate_json(packet_json)
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"Could not read packet_json: {error}") from error

    try:
        payloads = [
            (file.filename or "supporting-evidence", file.content_type, await file.read())
            for file in files
        ]
        return import_supporting_evidence(files=payloads, packet=packet)
    except PacketImportError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.post("/api/audit/room", response_model=CreateRoomResponse)
def create_audit_room() -> CreateRoomResponse:
    try:
        return engine.create_room()
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Could not create Band room: {error}") from error


@app.get("/api/audit/events", response_model=list[AuditEvent])
def get_events() -> list[AuditEvent]:
    return engine.events()


@app.post("/api/audit/advance", response_model=AdvanceResponse)
def advance_audit() -> AdvanceResponse:
    try:
        return engine.advance()
    except ProviderConfigurationError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ProviderRequestError as error:
        raise HTTPException(status_code=502, detail=f"Provider call failed while publishing the next BandAudit event: {error}") from error
    except RuntimeError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Could not publish the next BandAudit event: {error}") from error


@app.post("/api/audit/reset", response_model=AuditState)
def reset_audit() -> AuditState:
    return engine.reset()
