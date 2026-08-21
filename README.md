# NHI Governance

A tool that discovers machine credentials (API keys, service accounts) used by AI agents and flags security risks — orphaned credentials, unused permissions, dangerous permission combinations, and out-of-scope activity. Built for the Non-Human Identity Governance assignment, using mock JSON instead of live cloud APIs.

## Architecture

![architecture](docs/architecture.svg)

Flow: upload two JSON files -> FastAPI ingests into Postgres -> risk engine checks each identity -> React dashboard shows results.

Screen 2's risk detail (`/api/agents/{id}/risk`) re-runs the checks live on every request instead of only reading old scan results, so re-uploading corrected data reflects immediately.

## The 4 checks (`backend/app/risk_engine.py`)

1. **Orphan Identity** — no owner_agent and no registered_purpose in the directory data -> flagged.
2. **Least Privilege** — compares `granted_permissions` against everything actually seen in the 30-day activity log. Anything granted but never used gets flagged, escalated to critical if it touches something sensitive (salaries, payroll, payments).
3. **Segregation of Duties** — checks if an identity holds both halves of a known-conflicting pair (e.g. `write:payments` + `approve:payments`). This only looks at what's granted, not usage — holding both is the risk regardless of whether it's been exercised.
4. **Purpose Boundary** — checks if any *logged* activity touches a resource outside what that identity's registered purpose is expected to touch.

Which permission pairs conflict and which resources count as sensitive are defined in `config.py` rather than hardcoded into the checks, so new rules don't require touching the logic.

## Screens

- **Screen 1** — upload the directory-discovery JSON and activity-log JSON, run the scan, see all identities in a table with orphan tags.
- **Screen 2** — click into an identity, see granted-vs-used permissions, an activity timeline with flagged events, and the findings written in plain language.

## Project structure
backend/
  app/
    main.py            # FastAPI app + router setup
    database.py         # SQLAlchemy session (sqlite default, postgres via env var)
    models.py            # DB tables
    schemas.py            # request/response shapes
    config.py               # policy rules (SoD pairs, sensitive resources, purpose allowlists)
    ingestion.py              # JSON -> DB rows
    risk_engine.py             # the 4 checks
    routers/                    # API endpoints
  mock_data/                     # example directory + activity log JSON
frontend/
  src/
    api/client.js                # calls to the backend
    components/                   # DiscoveryScreen, AgentDetailScreen, etc.
    App.jsx
docs/architecture.svg


## Running locally

**Backend**
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Uses SQLite by default (zero setup). To use Postgres instead:
```bash
export DATABASE_URL="postgresql://user@localhost:5432/nhi_governance"
uvicorn app.main:app --reload --port 8000
```
No code changes needed either way — `database.py` just reads the env var.

**Frontend**
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```
Open `http://localhost:5173`, upload the two files from `backend/mock_data/`, click Run Discovery Scan, then check Screen 2.

## Mock data

`backend/mock_data/` has 7 identities covering each type of issue — an invoice bot with unused salary access + a payments SoD violation, an orphaned key with broad access, a support bot caught reading salaries, an HR bot with a payroll SoD violation, one clean identity with no issues, and two more orphan/SoD cases. `POST /api/reset` clears data if you want to re-test from scratch.

## Notes on approach

- No LLM/agent framework used — these checks are deterministic (does this identity hold X and Y, yes/no), so a plain rules engine gives consistent, explainable results without the non-determinism of an LLM call. This also matches the brief, which says an agent framework should only be used if it adds real value.
- SoD checks capability, not usage — flags the moment two conflicting permissions are both granted, since the risk is what the identity *could* do, not just what it has done so far.
- Known limitation: permission matching is exact string comparison (`read:invoices` has to match exactly on both sides), so naming differences between systems would need a mapping layer to reconcile in a real deployment.

## Stack

Python, FastAPI, SQLAlchemy, PostgreSQL (SQLite fallback for local dev), React (Vite).