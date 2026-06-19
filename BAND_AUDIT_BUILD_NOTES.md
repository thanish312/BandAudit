# BandAudit Build Notes

This file is for implementation continuity only. The public-facing documentation should remain the README.

## Current Status

- Project root created at `C:\Users\Thanish urs\BandAudit`.
- Backend scaffolded with FastAPI and a Band SDK event-source adapter.
- Frontend scaffolded with React, Vite, TypeScript, and lucide-react.
- Sample audit artifacts added for the Candidate Screening Agent scenario.
- README added with concise setup and submission positioning.
- `.env.example` added for live Band and provider credentials.
- Backend import and compile checks pass.
- Frontend production build passes.
- NPM audit is clean after moving to patched Vite tooling.
- Browser render check passes at desktop and mobile widths with no console errors.
- Demo flow advances to a final `Blocked` decision.
- Stage 3 adds AI/ML API and Featherless model-provider adapters behind an agent execution layer.
- Agent outputs are parsed through the chat-completions-style adapter interface and validated as `AuditEvent` objects before entering the reducer or Band publisher.
- Provider diagnostics are exposed through `/api/audit/providers`, `/health`, and a compact dashboard badge.
- Stage 3.5 now uses the enterprise model policy: `gpt-4.1-mini` for orchestration, `gpt-4.1` for compliance/synthesis, and `Qwen/Qwen2.5-72B-Instruct` for Featherless specialist review.
- Stage 3.5 live smoke passed: AI/ML API generated the ComplianceAgent event, Featherless generated SecurityRedTeam and FactVerifier events, and AI/ML API generated the final Synthesizer event after adding the adapter `User-Agent` header.
- Stage 4 added Windows operational scripts: `scripts/start.ps1`, `scripts/stop.ps1`, and `scripts/verify.ps1`.
- Stage 4 tightened the README with the run path, demo flow, and submission positioning.
- Stage 5 redesigned the frontend around a decision-first enterprise review workspace with Review, Protocol, and Timeline views.
- Stage 5 demoted raw protocol details from the main review screen, compacted the sidebar agent list, and made release recommendation, risk, findings, evidence, and timeline the primary visual hierarchy.
- Stage 6 added URL-backed pages for `/`, `/review`, `/protocol`, `/timeline`, and `/report`.
- Stage 6 reshaped the product flow around Landing, Release Gate, Release Blockers, Evidence Dossier, Band protocol reconstruction, Timeline filters, and an exportable Release Report.
- Stage 7 made provider routing explicit in backend diagnostics and the Protocol page, showing AI/ML API and Featherless AI lanes.
- Stage 8 replaced the generic landing flow with a release-review intake packet so enterprise users can understand and submit the target system, workflow, tool access, policy context, and evidence notes.
- Stage 8 added `/api/audit/packet`; custom packets shape future BandAudit events, and live Band mode blocks packet changes after room history exists.
- Stage 9 replaces fixed sample findings with packet-derived review-plan claims, dynamic votes, Band-trace-derived synthesis, and fail-closed provider repair/error handling.
- Stage 10 hardens the recording path: fresh Band rooms persist to `.env`, final synthesis no longer depends on a provider returning a giant JSON event, and verification scripts are non-mutating.

## Product Decisions

- No marketing landing page. The first screen is the working audit workspace.
- The first screen is now the audit packet intake. Review remains the primary workspace once a packet is submitted.
- No emoji in UI or documentation.
- UI direction: calm enterprise SaaS, evidence-first, decision-focused, with Lucide icons and an Inter/system font stack.
- Band is modeled as the source of truth through structured events.
- Live Band mode publishes and reads `bandaudit.audit_event.v1` room events through the Band SDK.
- Stage 2 hardens mode selection, `.env` loading, startup Band verification, and source diagnostics.
- AI/ML API owns evidence extraction, compliance reasoning, and final synthesis. Featherless owns red-team, model-risk, and independent verification work.
- Kubernetes, Helm, Redis, and full observability are out of MVP scope.

## Next Work

1. Create cover image and slide/video assets outside the codebase.
2. Record the fresh-room PDF import and release-board run.
3. Make a checkpoint commit before submission packaging.

## Known Risks

- Live Band mode requires `BAND_API_KEY` and `BAND_ROOM_ID`; without them, startup fails.
- Live provider mode requires model IDs that match the available AI/ML API and Featherless account access.
- Never commit `.env` or paste production keys into source files.
