# SOCMind AI: Multi-Agent Autonomous Threat Triage & Incident Response Copilot

**Academic Cybersecurity Project**  
**Team Number**: 150  
**Team Leader**: Chandresh Kumar  
**Team Member**: Kalpna Chaudhary  
**Mentor**: Sachin Kumar Yadav  

---

## 🛡️ Executive Summary

Modern Enterprise Security Operations Centers (SOCs) face an overwhelming volume of security alerts from SIEM, EDR/XDR, Cloud Security, and Network monitors. SOC analysts suffer from **alert fatigue**, leading to high rates of false positives, missed critical threats, and increased Mean Time to Respond (MTTR).

**SOCMind AI** is an AI-assisted security orchestration platform powered by **five specialized AI agents**. It helps SOC analysts ingest security alerts, normalize and correlate them into unified incidents, enrich indicators of compromise (IOCs) with threat intelligence, reconstruct attack timelines through log analysis, and generate actionable, human-in-the-loop response recommendations.

---

## ⚠️ Important Safety & Scope Boundaries

> [!IMPORTANT]
> This is an **academic cybersecurity research project**.
> 1. **Synthetic Data Only**: All alerts, logs, IP addresses, domains, and endpoint payloads are 100% synthetic, public, or explicitly authorized test data.
> 2. **Zero Credentials**: Real credentials, API keys, or enterprise infrastructure connections are strictly prohibited.
> 3. **Controlled & Simulated Remediation**: **NO** automated destructive or impactful remediation actions are performed. Every response recommendation requires explicit human analyst approval and runs in a simulated sandbox or audit logger.
> 4. **Payload Handling**: Executable command-line strings are treated strictly as **DATA ONLY** and are never executed by backend or frontend services.

---

## 🔄 Phase 2 Alert Ingestion & Normalization Pipeline

```
Synthetic SIEM / EDR Alert Payload
               │
               ▼
      POST /api/v1/alerts
               │
               ▼
      Pydantic Input Validation
               │
               ▼
  Deterministic Normalization Engine
  (Normalizes Severity, Source System,
   and Entities: Host, User, IPs, Hash)
               │
               ▼
  Database Persistence (SQLite/PostgreSQL)
               │
               ▼
      GET /api/v1/alerts
               │
               ▼
   React Security Alerts Workspace
```

### Controlled Enumeration Values

- **Severity Ratings**: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- **Alert Status Lifecycle**: `NEW`, `TRIAGED`, `CORRELATED`, `CLOSED`

---

## 🔌 API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/alerts` | Ingests a raw or semi-structured alert, normalizes fields, and persists record to database. |
| `GET` | `/api/v1/alerts` | Returns normalized alerts from database. Supports `severity`, `status`, `source`, `search`, `limit`, and `offset`. |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieves full normalized details for a single alert by ID. |
| `DELETE` | `/api/v1/alerts/{alert_id}` | Marks alert status as `CLOSED` (safe status update). |
| `POST` | `/api/v1/alerts/seed` | Idempotently populates database with 10 synthetic test alerts. Prevents duplicate creation. |
| `GET` | `/api/v1/health` | Health check endpoint returning backend database and environment status. |
| `GET` | `/api/v1/version` | Version endpoint returning team metadata and runtime platform details. |

---

## 🧪 Running Automated Tests

To run the automated backend test suite (ingestion, normalization, persistence, filtering, search, and seeding):

```bash
cd SOCMind-AI/backend
pytest tests/test_alerts.py
```

---

## 🚀 Local Setup & Quickstart

### 1. Start Backend (FastAPI)
```bash
cd SOCMind-AI/backend
pip install -r requirements.txt
python app/main.py
```
- Backend API: `http://localhost:8000`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`

### 2. Seed Synthetic Dataset
```bash
curl -X POST http://localhost:8000/api/v1/alerts/seed
```

### 3. Start Frontend (React + Vite)
```bash
cd SOCMind-AI/frontend
npm install
npm run dev
```
- Frontend UI Workspace: `http://localhost:5173`

---

## 👥 Project Team & Credits

- **Team**: 150
- **Team Leader**: Chandresh Kumar
- **Team Member**: Kalpna Chaudhary
- **Mentor**: Sachin Kumar Yadav
