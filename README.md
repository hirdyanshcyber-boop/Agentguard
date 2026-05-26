# AgentGuard

**Open-source Non-Human Identity (NHI) security monitor for AI agent stacks.**

Banks run hundreds of AI agents in production. None of them know what credentials those agents are accumulating. AgentGuard fixes that.

APRA CPS 234 aligned. Built for Australian financial services.

[![CI](https://github.com/hirdyansh/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/hirdyansh/agentguard/actions)
[![Security Scan](https://github.com/hirdyansh/agentguard/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hirdyansh/agentguard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## The Problem

Every AI agent creates, inherits, or accumulates credentials — API keys, OAuth tokens, IAM roles, service accounts. These Non-Human Identities (NHIs) outnumber human identities in modern cloud environments by 40:1.

No existing tool monitors them end-to-end in AI agent pipelines.

When an agent is compromised, security teams cannot answer:
- What credentials did it have access to?
- What could an attacker reach from those credentials?
- What did the agent actually do with them?

AgentGuard answers all three.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AgentGuard                           │
├──────────────┬──────────────┬──────────────┬────────────────┤
│  NHI Scanner │  Blast Radius│  Rotation    │  Rogue Agent   │
│  (AWS/Azure/ │  Analyser    │  Monitor     │  Simulator     │
│   GCP)       │  (pgvector)  │  (alerts)    │  (CrewAI)      │
├──────────────┴──────────────┴──────────────┴────────────────┤
│              FastAPI + LangGraph (Agent Orchestration)       │
├──────────────────────────────┬──────────────────────────────┤
│  PostgreSQL + pgvector        │  OpenTelemetry → Grafana     │
│  (Identity Graph + Embeddings)│  (Full observability)        │
├──────────────────────────────┴──────────────────────────────┤
│              APRA CPS 234 Audit Log (structured JSON)        │
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### 1. NHI Inventory Scanner
Scans AWS (Azure + GCP in progress) and builds a live graph of every API key, OAuth token, service account, and AI agent credential. Shows owner, last rotation date, attached permissions, and risk level.

```bash
POST /api/v1/inventory/scan/aws
GET  /api/v1/inventory/nhis?risk_level=critical
GET  /api/v1/inventory/stats
```

### 2. Blast Radius Analyser *(Week 3)*
If credential X is compromised, what can an attacker reach? AgentGuard maps the full propagation path through the identity graph using pgvector similarity search. Required reading for APRA post-incident reports.

### 3. Credential Rotation Monitor *(Week 2)*
Flags credentials exceeding your rotation policy window (default 90 days). Sends webhook alerts. Auto-generates rotation reports.

### 4. Rogue Agent Simulator *(Week 4)*
CrewAI-powered red team agent that tries to escalate privileges and accumulate credentials. AgentGuard detects the escalation, logs every step, and shows exactly how far the attack got. Runs live in interviews.

### 5. APRA CPS 234 Audit Dashboard *(Week 5)*
Every action, every credential change, every anomaly — timestamped, actor-attributed, exportable as structured JSON. Aligns to APRA CPS 234 Attachment G requirements.

```bash
GET /api/v1/audit/export/cps234
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/hirdyansh/agentguard.git
cd agentguard

# Configure
cp .env.example .env
# Add your AWS credentials and API keys

# Run
docker compose up

# API docs
open http://localhost:8000/docs

# Grafana observability
open http://localhost:3001  # admin / agentguard
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI + Pydantic v2 |
| Agent orchestration | LangGraph |
| Red team simulation | CrewAI |
| Identity graph | PostgreSQL + pgvector |
| Observability | OpenTelemetry → Grafana |
| Security scanning | Snyk + Trivy (GitHub Actions) |
| Dashboard | React + Tailwind + shadcn *(Week 5)* |
| Deployment | Docker + Kubernetes (GCP) |
| Auth | OAuth2 (Zero Trust) |
| Audit | APRA CPS 234 structured JSON logs |

---

## API Reference

Full OpenAPI spec at `/docs` when running locally.

```
GET  /health                        — health check
GET  /api/v1/inventory/nhis         — list all NHIs
POST /api/v1/inventory/scan/aws     — trigger AWS scan
GET  /api/v1/inventory/stats        — risk summary
GET  /api/v1/audit/logs             — audit log query
GET  /api/v1/audit/export/cps234    — APRA CPS 234 export
GET  /api/v1/alerts                 — active alerts
```

---

## Development

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Run with hot reload
uvicorn main:app --reload

# Tests
pytest tests/ -v --cov
```

---

## Roadmap

- [x] Week 1 — NHI inventory scanner (AWS), FastAPI core, audit log, CI/CD
- [ ] Week 2 — Credential rotation monitor, webhook alerts
- [ ] Week 3 — Blast radius analyser, Azure + GCP connectors, pgvector identity graph
- [ ] Week 4 — CrewAI rogue agent simulator
- [ ] Week 5 — React dashboard, Kubernetes manifests, GCP deployment

---

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Hirdyansh Dudi](https://linkedin.com/in/hirdyansh-dudi) to solve the credential sprawl problem in AI agent stacks.
