import type { AdvanceResponse, AgentExecutionDiagnostics, AuditPacket, AuditState, CreateRoomResponse, EvidenceImportResponse, PacketImportResponse } from "../types/audit";

const LOOPBACK_API_RE = /^https?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:\/|$)/i;
const LOOPBACK_ORIGIN_RE = /^https?:\/\/(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?$/i;
const ACTIVE_ROOM_STORAGE_KEY = "bandaudit.activeRoomId.v1";

function apiBaseUrl(): string {
  const configured = (import.meta.env.VITE_API_BASE_URL ?? "").trim();
  const productionBrowser = !import.meta.env.DEV && typeof window !== "undefined";
  const publicOrigin = productionBrowser && !LOOPBACK_ORIGIN_RE.test(window.location.origin);

  if (configured && !(publicOrigin && LOOPBACK_API_RE.test(configured))) {
    return configured.replace(/\/+$/, "");
  }

  return import.meta.env.DEV ? "http://127.0.0.1:8000" : "";
}

const API_BASE = apiBaseUrl();

function getActiveRoomId(): string {
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem(ACTIVE_ROOM_STORAGE_KEY)?.trim() ?? "";
  } catch {
    return "";
  }
}

function setActiveRoomId(roomId: string): void {
  if (typeof window === "undefined" || !roomId.trim()) return;
  try {
    window.localStorage.setItem(ACTIVE_ROOM_STORAGE_KEY, roomId.trim());
  } catch {
  }
}

function requestHeaders(headers?: HeadersInit): HeadersInit {
  const roomId = getActiveRoomId();
  return {
    ...(roomId ? { "X-BandAudit-Room-Id": roomId } : {}),
    ...(headers ?? {})
  };
}

function formatLocation(loc: unknown): string {
  if (!Array.isArray(loc)) return "Request";
  const parts = loc.filter((part) => part !== "body").map(String);
  if (parts.length === 0) return "Request";
  return parts
    .map((part) =>
      part
        .replace(/_/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase())
    )
    .join(" ");
}

function formatErrorDetail(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object" || !("detail" in body)) return fallback;

  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (!item || typeof item !== "object") return null;
        const error = item as { loc?: unknown; msg?: unknown };
        if (typeof error.msg !== "string") return null;
        return `${formatLocation(error.loc)}: ${error.msg}`;
      })
      .filter(Boolean);

    if (messages.length > 0) return messages.join(" ");
  }

  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...requestHeaders(init?.headers)
    }
  });

  if (!response.ok) {
    let detail = `Request failed: ${response.status}`;
    try {
      const body = await response.json();
      detail = formatErrorDetail(body, detail);
    } catch {
    }
    throw new Error(detail);
  }

  return response.json() as Promise<T>;
}

async function upload<T>(path: string, body: FormData): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    body,
    headers: requestHeaders()
  });

  if (!response.ok) {
    let detail = `Request failed: ${response.status}`;
    try {
      const responseBody = await response.json();
      detail = formatErrorDetail(responseBody, detail);
    } catch {
    }
    throw new Error(detail);
  }

  return response.json() as Promise<T>;
}

export function getAudit(): Promise<AuditState> {
  return request<AuditState>("/api/audit");
}

export function getProviderDiagnostics(): Promise<AgentExecutionDiagnostics> {
  return request<AgentExecutionDiagnostics>("/api/audit/providers");
}

export function advanceAudit(): Promise<AdvanceResponse> {
  return request<AdvanceResponse>("/api/audit/advance", { method: "POST" });
}

export function configureAuditPacket(packet: AuditPacket): Promise<AuditState> {
  return request<AuditState>("/api/audit/packet", {
    method: "PUT",
    body: JSON.stringify(packet)
  });
}

export function importAuditPacketPdf(file: File): Promise<PacketImportResponse> {
  const formData = new FormData();
  formData.append("file", file);
  return upload<PacketImportResponse>("/api/audit/packet/import/pdf", formData);
}

export function importSupportingEvidence(files: File[], packet: AuditPacket): Promise<EvidenceImportResponse> {
  const formData = new FormData();
  files.forEach((file) => formData.append("files", file));
  formData.append("packet_json", JSON.stringify(packet));
  return upload<EvidenceImportResponse>("/api/audit/packet/import/evidence", formData);
}

export function createAuditRoom(): Promise<CreateRoomResponse> {
  return request<CreateRoomResponse>("/api/audit/room", { method: "POST" }).then((response) => {
    setActiveRoomId(response.room_id);
    return response;
  });
}

export function resetAudit(): Promise<AuditState> {
  return request<AuditState>("/api/audit/reset", { method: "POST" });
}
