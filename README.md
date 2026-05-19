# DFIR Investigation Suite v1.0
### AI-Powered Forensic Investigation Platform

---

## Quick Start

---- python 3 needed for this installer

### Windows
```
Double-click: start_windows.bat
```

### Linux / Mac
```bash
chmod +x start_linux.sh
./start_linux.sh
```

Then open: `frontend/index.html` in your browser
API Docs: http://localhost:8000/api/docs

---

## Default Login
| Field    | Value        |
|----------|-------------|
| Username | admin        |
| Password | Admin@1234   |

**Change the password after first login!**

---

## Prerequisites

### Required
- Python 3.10 or higher
- pip (Python package manager)

### Optional (for AI features)
- Ollama — https://ollama.ai
- Run: `ollama pull mistral` (recommended model)
- Or: `ollama pull llama3.2` (faster, smaller)

### Install Python deps manually
```bash
cd backend
pip install -r requirements.txt
```

---

## Features

| Module            | What it does                                      |
|-------------------|---------------------------------------------------|
| Case Management   | Create/manage DFIR cases with full lifecycle      |
| Evidence Upload   | Upload files with SHA256 hash verification        |
| Artifact Collect  | Registry, browser, prefetch, event logs, tasks    |
| Timeline Engine   | Build chronological event timeline from artifacts |
| IOC Management    | Add/import/export Indicators of Compromise        |
| YARA Scanner      | Scan evidence files with built-in YARA rules      |
| Sigma Rules       | Detect suspicious patterns in event logs          |
| Persistence Scan  | Detect run keys, services, tasks, startup items   |
| Network Analysis  | Capture active connections, ports, processes      |
| AI Assistant      | Ollama-powered forensic chat (fully offline)      |
| AI Summarization  | Auto-generate case summaries with AI              |
| PDF Reports       | Professional investigation reports                |
| HTML Reports      | Browser-viewable investigation reports            |
| User Management   | Admin / Investigator / Viewer roles               |
| Audit Logging     | Full action audit trail                           |

---

## Folder Structure

```
dfir-suite/
├── backend/
│   ├── main.py              # FastAPI app entry
│   ├── database.py          # SQLite setup
│   ├── models.py            # Database models
│   ├── schemas.py           # API schemas
│   ├── auth.py              # JWT authentication
│   ├── requirements.txt     # Python packages
│   ├── routers/             # API route handlers
│   │   ├── cases.py
│   │   ├── evidence.py
│   │   ├── artifacts.py
│   │   ├── timeline.py
│   │   ├── iocs.py
│   │   ├── scanner.py
│   │   ├── ai_assistant.py
│   │   └── misc_routers.py
│   ├── services/            # Business logic
│   │   ├── artifact_service.py
│   │   ├── scanner_service.py
│   │   └── all_services.py
│   ├── yara_rules/          # YARA detection rules
│   └── sigma_rules/         # Sigma detection rules
├── frontend/
│   └── index.html           # Full React UI (single file)
├── evidence_store/          # Uploaded evidence files
├── reports/                 # Generated PDF/HTML reports
├── dfir_suite.db            # SQLite database (auto-created)
├── start_windows.bat        # Windows launcher
├── start_linux.sh           # Linux launcher
└── README.md
```

---

## API Reference

| Method | Endpoint                        | Description                  |
|--------|---------------------------------|------------------------------|
| POST   | /api/auth/login                 | Login, get JWT token         |
| GET    | /api/dashboard/stats            | Dashboard statistics         |
| GET    | /api/cases/                     | List all cases               |
| POST   | /api/cases/                     | Create new case              |
| GET    | /api/cases/{id}/summary         | Case summary                 |
| POST   | /api/evidence/upload            | Upload evidence file         |
| GET    | /api/evidence/{id}/verify       | Verify file integrity        |
| POST   | /api/artifacts/collect/{ev_id}  | Collect artifacts from evidence |
| GET    | /api/artifacts/case/{id}        | List case artifacts          |
| POST   | /api/timeline/case/{id}/build   | Build timeline               |
| GET    | /api/timeline/case/{id}         | Get timeline events          |
| POST   | /api/iocs/                      | Add IOC                      |
| POST   | /api/scanner/yara/{ev_id}       | Run YARA scan                |
| POST   | /api/scanner/sigma/{case_id}    | Run Sigma scan               |
| POST   | /api/scanner/ioc/{case_id}      | Run IOC scan                 |
| POST   | /api/ai/query                   | Ask AI assistant             |
| POST   | /api/ai/summarize/{case_id}     | AI case summary              |
| POST   | /api/ai/attack-chain/{case_id}  | AI attack chain analysis     |
| POST   | /api/network/collect/{case_id}  | Collect network artifacts    |
| POST   | /api/persistence/scan/{case_id} | Detect persistence           |
| POST   | /api/reports/generate           | Generate PDF/HTML report     |
| GET    | /api/reports/download/{id}      | Download report file         |

Full interactive docs: http://localhost:8000/api/docs

---

## YARA Rules

Add custom rules to: `backend/yara_rules/`
Files must end with `.yar` or `.yara`

## Sigma Rules

Built-in Sigma rules: `backend/sigma_rules/builtin_sigma.json`
These detect: encoded PowerShell, LSASS access, scheduled tasks,
new services, MSHTA execution, WMI execution, CertUtil download,
SAM hive export, log clearing, new admin accounts, Pass-The-Hash.

---

## Security Notes

- This tool is for **authorized** forensic investigations only
- Change the default admin password immediately
- The SQLite database contains sensitive case data — protect it
- Evidence files contain sensitive forensic data — use full disk encryption
- JWT secret key in auth.py should be changed in production
- Run on a dedicated forensic workstation, not a production system

---

## Enabling AI (Ollama)

1. Install Ollama: https://ollama.ai
2. Run: `ollama serve`
3. Pull a model: `ollama pull mistral`
4. AI features activate automatically in the tool

Recommended models:
- `mistral` — best balance of speed and quality
- `llama3.2` — fast, good for quick analysis
- `phi3` — very lightweight, runs on low-end hardware

---

## Roles

| Role          | Permissions                                    |
|---------------|------------------------------------------------|
| Admin         | Full access — users, cases, all features       |
| Investigator  | Create/edit cases, upload evidence, run scans  |
| Viewer        | Read-only — view cases, artifacts, reports     |

---

Built for: Digital Forensics & Incident Response (DFIR)
Inspired by: Velociraptor, Autopsy, Timesketch, KAPE
