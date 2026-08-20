# NHI Governance — Non-Human Identity Discovery & Risk Evaluation

A web application that discovers machine credentials (API keys, service accounts) used
by AI agents, maps them to registered owners, and evaluates them against three security
principles — **Least Privilege**, **Segregation of Duties (SoD)**, and **Purpose
Boundaries** — using mock cloud directory + activity-log data.

> Built for the "Non-Human Identity Governance" challenge. No live cloud integration —
> the app ingests mock JSON payloads that simulate an AWS/Azure directory scan and a
> 30-day activity log pull.

---

## 1. The problem, in one paragraph

Human logins are tightly monitored (password + MFA). The credentials AI agents and
scripts use — API keys, service accounts, tokens — usually aren't. They outnumber human
identities by orders of magnitude, get over-provisioned during testing, and are rarely
cleaned up. This app automates the three things a human reviewer would otherwise have to
do by hand: **find every credential**, **check whether its access matches how it's
actually used**, and **catch dangerous permission combinations** before they're abused.

## 2. Architecture

![architecture](docs/architecture.svg)

**Flow:** mock JSON → upload UI → FastAPI ingestion → PostgreSQL → policy-driven risk
engine → read API → React dashboard.

The two screens intentionally hit the *same* read API. The risk engine re-evaluates an
identity live on every request to `/api/agents/{id}/risk` rather than only trusting a
cached scan result, so the detail view is never stale relative to newly uploaded data.

### Why this data model

| Table | Purpose |
|---|---|
| `identities` | One row per discovered NHI (API key or service account) — its type, owner agent, registered purpose, and the raw `granted_permissions` list from the directory scan. `is_orphan` is set at ingestion time: true when a discovered account has no `owner_agent` **and** no `registered_purpose`. |
| `activity_events` | One row per logged action (`action` + `resource` + `timestamp`) from the 30-day log. Normalized to the same `action:resource` shape as `granted_permissions` so usage can be diffed directly against grants. |
| `risk_findings` | One row per violation the engine produces, tagged by `check_type` (`orphan` / `least_privilege` / `sod` / `purpose_boundary`), `severity`, and a **plain-language `message`** — this is what lets a reviewer understand *why* something failed without reading code. |
| `scan_runs` | Metadata for each discovery-scan trigger (counts, timestamp) — powers the summary strip. |

### Why the policy rules live in `config.py`, not hardcoded `if` statements

The brief explicitly asks for a design that's "flexible enough to support different
permission structures [and] policy rules." `SOD_CONFLICT_PAIRS`,
`PURPOSE_RESOURCE_ALLOWLIST`, and `SENSITIVE_RESOURCES` are plain Python data
structures the risk engine iterates over — adding a new conflicting-permission pair or a
new agent purpose means editing a list/dict, not the evaluation code. In production
this table would live in the database so a security team could edit it without a
redeploy; keeping it isolated in one module makes that migration trivial.

## 3. The evaluation pipeline (the actual substance)

Implemented in `backend/app/risk_engine.py`, run per-identity:

1. **Orphan Identity Check** — flags any identity with no registered owner/agent. Severity: `warning`.
2. **Least Privilege Check** — diffs `granted_permissions` against every `action:resource` pair actually seen in the 30-day log. Any granted-but-unused permission is flagged; unused permissions on `SENSITIVE_RESOURCES` (salaries, payroll, payments…) are escalated to `critical`. Also flags dangerously broad grants (`read:all_data`, `*:*`) on unowned identities.
3. **Segregation of Duties Check** — checks the identity's granted permissions against `SOD_CONFLICT_PAIRS` (e.g. `write:payments` + `approve:payments`). Any conflicting pair held simultaneously is `critical`, independent of whether it was actually *used* — holding the *capability* is the risk, not just exercising it.
4. **Purpose Boundary Check** — compares each *used* resource against the allow-list for the identity's `registered_purpose`. An agent registered for "Customer Support" that gets caught reading `hr_salaries` in the logs is flagged even if that permission was technically granted — usage outside the agent's stated job is itself a signal.

Each finding carries `title`, `message` (the audit-reasoning sentence), and
`recommended_action` (e.g. *"Revoke 'read:hr_salaries' — unused in last 30 days"*), which
is rendered directly in the UI — nothing is left as a raw status code.

## 4. Screens

**Screen 1 — Discovery & Asset Register** (`/`): upload the directory-discovery JSON and
the activity-log JSON, trigger the scan, and see every identity in a table with its
credential type, assigned agent, and an orphan warning tag.

**Screen 2 — Agent Risk Analysis**: select any identity and see (a) Permissions Granted
vs. Used with per-permission revoke recommendations, (b) a chronological activity
timeline with flagged SoD/purpose events inline, and (c) the full list of findings in
plain language.

## 5. Project structure

```
nhi-governance/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, CORS, router wiring
│   │   ├── database.py        # SQLAlchemy engine/session (SQLite by default, Postgres via env)
│   │   ├── models.py          # Identity, ActivityEvent, RiskFinding, ScanRun
│   │   ├── schemas.py         # Pydantic request/response models
│   │   ├── config.py          # Policy rules as data (SoD pairs, purpose allow-lists...)
│   │   ├── ingestion.py       # Maps raw JSON -> ORM rows
│   │   ├── risk_engine.py     # The 4 evaluation checks
│   │   └── routers/
│   │       ├── upload.py      # POST /api/ingest/*, /api/scan/run
│   │       ├── identities.py  # GET /api/identities, /api/dashboard/summary
│   │       └── agents.py      # GET /api/agents/{id}/risk
│   ├── mock_data/              # Example directory + activity log JSON (7 identities)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/client.js       # fetch wrapper for the backend
│   │   ├── components/
│   │   │   ├── DiscoveryScreen.jsx     # Screen 1
│   │   │   ├── AgentDetailScreen.jsx   # Screen 2
│   │   │   ├── FileDropzone.jsx
│   │   │   └── StatusBadge.jsx
│   │   ├── App.jsx
│   │   └── index.css           # design system
│   └── package.json
└── docs/architecture.svg
```

## 6. Running it locally

### Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

By default this uses a local SQLite file (`nhi_governance.db`) so there's zero setup
friction. To use PostgreSQL instead:

```bash
export DATABASE_URL="postgresql://nhi_user:nhi_pass@localhost:5432/nhi_governance"
uvicorn app.main:app --reload --port 8000
```

No application code changes — `database.py` is dialect-agnostic SQLAlchemy.

API docs are auto-generated at `http://localhost:8000/docs`.

### Frontend

```bash
cd frontend
npm install
cp .env.example .env   # points VITE_API_URL at the backend; defaults to localhost:8000
npm run dev
```

Open `http://localhost:5173`, upload `backend/mock_data/directory_discovery.json` and
`backend/mock_data/activity_logs.json` on Screen 1, click **Run Discovery Scan**, then
switch to Screen 2 to inspect any identity.

### Quick backend-only smoke test (no UI)

```bash
curl -X POST http://localhost:8000/api/ingest/directory -F "file=@mock_data/directory_discovery.json"
curl -X POST http://localhost:8000/api/ingest/activity  -F "file=@mock_data/activity_logs.json"
curl -X POST http://localhost:8000/api/scan/run
curl http://localhost:8000/api/agents/svc-invoice-bot-prod/risk
```

The last call reproduces the exact example from the problem statement: an orphan
warning on `test-key-2023-legacy`, an unused `read:hr_salaries` grant flagged on the
invoice bot, and a `write:payments` + `approve:payments` SoD violation.

## 7. Mock dataset

`backend/mock_data/` ships with 7 identities designed to exercise every check:

| Account | Demonstrates |
|---|---|
| `svc-invoice-bot-prod` | Least-privilege violation (unused `read:hr_salaries`) + SoD violation (`write` + `approve` payments) |
| `test-key-2023-legacy` | Orphan identity, holding a dangerously broad `read:all_data` grant |
| `svc-support-copilot` | Purpose-boundary violation — a support bot caught reading `hr_salaries` in the logs |
| `svc-hr-analytics-agent` | SoD violation on payroll (`write` + `approve`) |
| `svc-devops-deployer` | A **clean** identity — everything granted is used, no conflicts (shows the "no violations" state) |
| `api-key-marketing-dashboard` | Orphan + unused permission, on a lower-sensitivity resource |
| `svc-vendor-onboarding-bot` | SoD violation (`create:vendor` + `approve:vendor`) where the conflicting permission is also unused |

Re-upload different JSON files at any time — `POST /api/reset` clears all ingested data
for a clean demo run.

## 8. Design decisions worth calling out

- **Findings are re-derived live, not just cached.** `GET /api/agents/{id}/risk` calls
  the risk engine directly against current DB state rather than only reading
  previously-stored `RiskFinding` rows. This means re-uploading a corrected activity log
  updates the dashboard immediately without requiring a full re-scan.
- **SoD checks capability, not usage.** An identity is flagged the moment it *holds*
  both conflicting permissions, even if the logs show it only ever used one of them —
  because the risk is the latent ability to abuse both, not whether it already has.
- **"Shadow access" detection.** The permission-comparison view also surfaces
  permissions that were *used* in the logs but never appear in `granted_permissions` —
  a real-world signal of stale roles or logging drift that a pure granted-vs-used diff
  would otherwise miss.
- **Flexible ingestion shape.** The activity-log endpoint accepts a single account
  object, a bare list, or a `{"logs": [...]}` wrapper, since real log exports rarely
  agree on a single envelope shape.

## 9. Deployment

- **Backend**: any ASGI host (Render, Railway, Fly.io, AWS App Runner) — set
  `DATABASE_URL` to a managed Postgres instance and run
  `uvicorn app.main:app --host 0.0.0.0 --port $PORT`.
- **Frontend**: static host (Vercel, Netlify, Render static site) — `npm run build`,
  set `VITE_API_URL` to the deployed backend URL.

*(Add your live deployment link here once deployed.)*

## 10. Stack

Python · FastAPI · SQLAlchemy · PostgreSQL (SQLite fallback for local dev) · React
(Vite) · plain fetch (no extra state library needed for two screens).

No agent framework (LangGraph, etc.) is used — the evaluation pipeline is deterministic
policy logic against structured data, which doesn't benefit from an LLM/agent loop. Per
the challenge brief, an agent framework is only worth including when it adds clear
value; here it wouldn't.
