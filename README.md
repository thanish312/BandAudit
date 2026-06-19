# BandAudit

BandAudit is an Agent Release Board for enterprise AI systems. It uses Band as the coordination layer where specialist release-board lanes share structured context, challenge claims, verify evidence, debate conflicts, vote, and produce a traceable release decision.

The built-in sample audits TalentScreen Assist v2.4 before production deployment. The release board blocks the launch because the system operates in a high-impact employment workflow, has write-capable ATS access, and lacks sufficient prompt-injection isolation, human approval gates, rollback controls, and subgroup evaluation evidence.

## Demo

<p align="center">
  <a href="https://pub-03c83e0aa4104454a0a4ec620cfb16de.r2.dev/bandaudit-demo-clean.mp4">
    <img src="https://pub-03c83e0aa4104454a0a4ec620cfb16de.r2.dev/demo-poster-2-clean.png" alt="Watch the BandAudit demo" width="760">
  </a>
</p>

<p align="center">
  <a href="https://pub-03c83e0aa4104454a0a4ec620cfb16de.r2.dev/bandaudit-demo-clean.mp4">Watch the 5-minute BandAudit walkthrough</a>
</p>

## Why Band Is Central

BandAudit treats the Band room as the operational source of truth. Every material step is represented as a structured room event:

- `audit_init`
- `artifact_indexed`
- `finding`
- `evidence_request`
- `verification`
- `challenge`
- `conflict_declaration`
- `debate_position`
- `vote`
- `human_escalation`
- `synthesis_report`

The dashboard reconstructs audit state from these events. Band is not a notification layer; it is the collaboration and traceability layer for the release decision.

## Agent Roles

- `ChairAgent`: controls phases, detects conflicts, requests votes, and handles escalation.
- `EvidenceMapper`: extracts claims from audit artifacts and links them to source hashes.
- `ComplianceAgent`: maps facts to governance, policy, and regulatory obligations.
- `SecurityRedTeam`: reviews prompt injection, tool misuse, and data exposure risk.
- `ModelRiskAgent`: checks eval quality, bias evidence, drift, and human oversight.
- `FactVerifier`: verifies weak or disputed claims.
- `Synthesizer`: creates the final release report.

## Technology

- Backend: FastAPI, Pydantic
- Frontend: React, Vite, TypeScript, Material UI
- UI icons: lucide-react
- Event source: live Band SDK adapter
- Model providers: AI/ML API and Featherless AI

AI/ML API is the general reasoning, extraction, chairing, and compliance lane. Featherless AI is the independent open-weight review lane for red-team, model-risk, and verification work. The final release decision is assembled from the Band room trace, not from one hidden final chatbot response. This separation is intentional: release governance should not depend on a single model family judging the system alone.

## Local Setup

Recommended Windows startup:

```powershell
.\scripts\start.ps1 -Install
```

After dependencies are installed, use:

```powershell
.\scripts\start.ps1
```

Stop the local servers:

```powershell
.\scripts\stop.ps1
```

Run non-mutating verification:

```powershell
.\scripts\verify.ps1
```

Open:

```text
http://127.0.0.1:5173
```

Manual backend/frontend startup is also supported.

Run the backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Run the frontend in another terminal:

```bash
cd frontend
npm install
npm run dev
```

## Docker Compose

```bash
docker compose up --build
```

## Vercel Deployment

The included `vercel.json` deploys the React/Vite frontend and the FastAPI backend together on Vercel. The frontend calls the backend through same-origin `/api/*` routes, so `VITE_API_BASE_URL` is optional for a normal Vercel deployment.

In Vercel:

1. Import `thanish312/BandAudit`.
2. Leave the root directory as the repository root.
3. Use the checked-in `vercel.json` settings:
   - install: `npm --prefix frontend ci`
   - build: `npm --prefix frontend run build`
   - output: `frontend/dist`
4. Set the Band, AI/ML API, and Featherless environment variables from `.env.example` in the Vercel dashboard.
5. Keep `BAND_PACKET_IMPORT_MAX_MB=4` on Vercel unless you move file intake to object storage, because Vercel Functions reject request bodies above 4.5 MB.

For a separate backend host, set the frontend API target explicitly:

```text
VITE_API_BASE_URL=https://bandaudit-api.example.com
```

If the backend is separate from Vercel, also allow the deployed frontend origin on the backend:

```text
BAND_CORS_ORIGINS=https://your-bandaudit-app.vercel.app
```

Vercel runs the FastAPI app as a Python Function. The default function duration in `vercel.json` is 60 seconds for plan compatibility; raise it only if your Vercel plan supports longer Python Functions.

## Environment Variables

BandAudit requires live Band, AI/ML API, and Featherless credentials. Copy `.env.example` to `.env` and set the relevant values:

```text
BAND_AUDIT_MODE=band
BAND_API_KEY=
BAND_ROOM_ID=
BAND_REST_URL=
BAND_VERIFY_ON_STARTUP=true
BAND_RECRUIT_LANE_PEERS=false
BAND_LANE_PEERS_JSON={}
BAND_CORS_ORIGINS=
BAND_AGENT_MODE=live
BAND_AGENT_TIMEOUT_SECONDS=60
BAND_AGENT_MAX_TOKENS=1600
BAND_AGENT_TEMPERATURE=0.15
BAND_PROVIDER_MAX_ATTEMPTS=3
BAND_PACKET_IMPORT_MAX_MB=50
BAND_PACKET_IMPORT_MAX_TOKENS=5000
BAND_PACKET_IMPORT_TEMPERATURE=0
AIML_API_KEY=
AIML_BASE_URL=https://api.aimlapi.com/v1
AIML_MODEL=openai/gpt-4.1-mini-2025-04-14
AIML_CHAIR_MODEL=openai/gpt-4.1-2025-04-14
AIML_COMPLIANCE_MODEL=openai/gpt-4.1-2025-04-14
AIML_SYNTHESIZER_MODEL=openai/gpt-4.1-2025-04-14
AIML_PACKET_IMPORT_MODEL=
AIML_OCR_MODEL=mistral/mistral-ocr-latest
FEATHERLESS_API_KEY=
FEATHERLESS_BASE_URL=https://api.featherless.ai/v1
FEATHERLESS_MODEL=Qwen/Qwen2.5-72B-Instruct
```

`BAND_AUDIT_MODE=band` is the normal mode. `auto` and `live` are accepted aliases, but there is no local event-source fallback.

`BAND_AGENT_MODE=live` is the normal mode. `auto` is accepted as a live mode, but provider failures stop the event instead of generating substitute output.
`BAND_PROVIDER_MAX_ATTEMPTS` controls bounded automatic retry for transient provider failures such as rate limits, timeouts, and 5xx responses.

Backend diagnostics are available at `/health`, `/api/audit/source`, and `/api/audit/providers`. The dashboard shows whether the current audit state is reconstructed from Band live events and whether both model-provider lanes are ready.

By default, BandAudit runs as one real Band external agent that declares structured release-board lanes inside the room manifest. Optional peer recruitment is available only when real Band peer IDs are configured: set `BAND_RECRUIT_LANE_PEERS=true` and `BAND_LANE_PEERS_JSON` to a map such as `{"SecurityRedTeam":"peer-id"}`. Recruitment failures are non-blocking and are recorded as Band activity events; no human reviewers are implied or added by default.

The default live-provider choices are judge-ready rather than cheapest-possible: `openai/gpt-4.1-mini-2025-04-14` for lower-risk AI/ML API evidence flow, full `openai/gpt-4.1-2025-04-14` where the configured route needs stronger governance reasoning, and `Qwen/Qwen2.5-72B-Instruct` for the Featherless independent open-weight challenge lane. If 72B latency is too high during local testing, use `Qwen/Qwen2.5-32B-Instruct` as the faster Featherless fallback.

Provider routing is explicit in `/api/audit/providers` and the Protocol page:

- AI/ML API: `ChairAgent`, `EvidenceMapper`, `ComplianceAgent`, `Synthesizer`
- Featherless AI: `SecurityRedTeam`, `ModelRiskAgent`, `FactVerifier`

## Practical Provider Use

BandAudit uses the two live model providers for different release-board jobs:

- AI/ML API orchestrates release-board control events, turns submitted packets into structured evidence, and maps findings to policy and governance obligations.
- Featherless AI provides an independent open-weight review lane for adversarial security analysis, model-risk review, and disputed-claim verification.
- The final Synthesizer event is a deterministic projection over Band room history. That keeps the release artifact replayable and avoids making one final model call the hidden source of truth.

Per-agent model overrides are supported with `AIML_CHAIR_MODEL`, `AIML_EVIDENCE_MODEL`, `AIML_COMPLIANCE_MODEL`, `AIML_SYNTHESIZER_MODEL`, `FEATHERLESS_SECURITY_MODEL`, `FEATHERLESS_MODEL_RISK_MODEL`, and `FEATHERLESS_VERIFIER_MODEL`. Empty override values fall back to `AIML_MODEL` or `FEATHERLESS_MODEL`.

PDF packet import uses AI/ML API twice during setup, before the packet is locked into Band: `AIML_OCR_MODEL` performs OCR over every uploaded PDF, then `AIML_PACKET_IMPORT_MODEL` extracts the structured release packet from the OCR markdown. When `AIML_PACKET_IMPORT_MODEL` is empty, extraction falls back to `AIML_MODEL`.
`BAND_PACKET_IMPORT_MAX_MB` controls PDF upload size, while `BAND_PACKET_IMPORT_MAX_TOKENS` and `BAND_PACKET_IMPORT_TEMPERATURE` tune only the structured extraction call, not the release-board agents.

Live provider output must validate before it can be published to Band or reduced into dashboard state. Provider lanes return compact event patches that the backend merges into trusted event templates, preserving evidence references and fixed room metadata. The execution layer prevents high-risk severity downgrades, rejects weak clearance claims during risky phases, and records repair/fallback metadata in the Band trace. Deterministic control-plane events such as packet lock, evidence indexing, vote request, and final synthesis can continue from validated templates without hiding provider validation failures.

## Band Credentials

For live Band mode, `BAND_API_KEY` means the API key for a Band Remote/External Agent. `BAND_ROOM_ID` means the UUID of the Band chat room where that agent is a participant.

Create these in Band:

1. Open Band and go to Agents.
2. Create a new Remote or External Agent for BandAudit.
3. Copy the API key from the creation popup immediately; Band only shows it once.
4. Copy the Agent UUID from the agent settings page for your own records.
5. Open Chats, create a chat room, and add the BandAudit agent as a participant.
6. Copy the chat room UUID from the Band URL or from the chat room details.
7. Put the values in `.env`:

```text
BAND_AUDIT_MODE=band
BAND_API_KEY=
BAND_ROOM_ID=
BAND_RECRUIT_LANE_PEERS=false
BAND_LANE_PEERS_JSON={}
BAND_AGENT_MODE=live
```

## Demo Flow

1. Open `/`. The landing page gives the release-board story, Band event vocabulary, and recent review shortcuts.
2. Click `Start sample audit` or `Create custom audit` to open `/setup`.
3. Submit the audit packet. The built-in sample packet is TalentScreen Assist v2.4 with ATS write access, prompt-injection tests, evaluation evidence, and rollback gaps. For PDF intake, upload your own release packet PDF and review the cited extracted fields before lock.
4. Click `Lock packet and start review`. BandAudit creates or uses a clean Band room, locks the packet into the first event, and opens `/review`.
5. The release-board lanes automatically publish structured Band events through indexing, review, verification, debate, vote, and synthesis.
6. Inspect the Release Gate, Release Blockers, Evidence Dossier, and Release Decision on the main Review page.
7. Use Protocol to inspect the event schema and developer-only single-step control, Timeline for the complete Band trace, and Report for the exportable enterprise release artifact.

In live Band mode, the audit packet can only be changed before the room contains BandAudit events. After events exist, use the same room to continue the current review or use the intake-page `Create fresh Band room` action for a new enterprise test packet. The app switches the running backend to the new room and persists the new `BAND_ROOM_ID` into `.env` for restart safety.

The intended demo decision is `Blocked`. That is the point: BandAudit is a release board, not a chatbot, and it should be willing to stop a risky AI agent from shipping.

## Submission Positioning

Title: `BandAudit: Agent Release Board`

Short description: BandAudit convenes Band-recorded release-board lanes to audit enterprise AI agents before deployment, producing traceable release decisions from cited evidence, debate, votes, provider provenance, and human-ready remediation steps.

Track: Regulated and High-Stakes Workflows

Technology tags: Band, multi-agent systems, AI governance, compliance, risk review, AI/ML API, Featherless AI, FastAPI, React

BandAudit directly demonstrates the hackathon's core requirement through specialist release-board lanes that coordinate through Band across planning, review, decision-making, and handoff. The Band room is the replayable decision record; the dashboard and exports are projections over that event history.
