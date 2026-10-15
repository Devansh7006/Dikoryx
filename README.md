<div align="center">

# 🛡️ Dikoryx
### **Next-Gen Insider Threat Detection & Automated CIS Compliance Platform**

*Watching for the threats that come from inside the walls — and actively enforcing endpoint security baselines.*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61DAFB.svg)](https://reactjs.org/)
[![Compliance](https://img.shields.io/badge/Compliance-CIS%20Benchmarks%20%7C%20Zero%20Trust-2ea44f.svg)](#-cis-compliance-benchmarks--active-enforcement)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%7C%20SQLite-336791.svg)](https://www.postgresql.org/)
[![Auth](https://img.shields.io/badge/Auth-Argon2-orange.svg)](https://en.wikipedia.org/wiki/Argon2)

</div>

---

## 📸 Dashboard & UI Showcase

<div align="center">

### Real-Time Threat Vector, Network Telemetry & CIS Compliance Dashboard
![Dikoryx Dashboard](docs/screenshots/dashboard.png)
*Featuring live Risk Score assessment (84 CRITICAL), detected VPN network egress (104.28.247.83), uplink/downlink volume sparklines, and active CIS Compliance Enforcement controls.*

<br/>

| Monitored Endpoints View | Authentication Portal |
| :---: | :---: |
| ![Active Agents](docs/screenshots/agent_select.png) | ![Login Portal](docs/screenshots/login.png) |

</div>

---

## 🔑 Default Credentials (Instant Access)

For evaluation, demonstrations, and test deployments, Dikoryx is pre-configured with default administrator credentials:

| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin` | Full System & Endpoint Telemetry Access |

> **Note:** Additional accounts can be registered dynamically via the `POST /api/v1/signup` API endpoint. All database passwords are cryptographically hashed using **Argon2**.

---

## 🌐 What is Dikoryx?

Most security software guards the perimeter — firewalls, proxies, and external intrusion detection. Dikoryx focuses on what occurs **within the endpoint**:
- **Behavioral Anomaly Detection:** Flags disgruntled employees exfiltrating confidential files to USB drives, rapid file modifications/deletions, abnormal clipboard activity, or developer workstations tunneling traffic through VPNs/proxies.
- **Continuous CIS Compliance & Automated Enforcement:** Continuously audits endpoint configurations against CIS benchmarks (Firewall, BitLocker, Screen Lock, Windows Defender, USB storage restrictions) and automatically enforces compliant system states when deviations occur.

Dikoryx couples a lightweight endpoint agent with a high-throughput FastAPI backend and a cyber-themed React dashboard to evaluate behavioral risk scores and compliance postures in real time.

---

## 🏗️ Architecture & Entity-Relationship (ER) Schema

> 📄 **Complete Architectural Blueprint, Data Dictionary & Threat Model:** [Read the full ARCHITECTURE.md](docs/ARCHITECTURE.md)  
> 🖼️ **Direct Asset Links:** [System Architecture Diagram (PNG)](docs/architecture.png) • [ER Schema Diagram (PNG)](docs/er_diagram.png)

<div align="center">

### High-Level System Architecture & Data Pipeline
[![System Architecture](docs/architecture.png)](docs/architecture.png)

<br/>

### Relational Entity-Relationship (ER) Schema
[![Entity Relationship Diagram](docs/er_diagram.png)](docs/er_diagram.png)

</div>

<br/>

### 📐 Mermaid Interactive Architecture Diagram


```mermaid
flowchart TD
    subgraph AnalystLayer ["Analysis & Security Operations (SOC)"]
        Analyst["🧑‍💻 Security Analyst / SOC Operator<br/>(Interactive Web Browser)"]
    end

    subgraph PresentationLayer ["Presentation Layer"]
        Frontend["💻 React 18 + Vite Dashboard<br/>Threat Matrix • Live Network Telemetry • CIS Compliance Panel"]
    end

    subgraph BackendLayer ["Backend Microservices"]
        Backend["⚙️ FastAPI Gateway & Ingestion<br/>Telemetry API • Auth & Tokens • Compliance Router"]
        RiskEngine["🧠 Hybrid Risk Engine<br/>IsolationForest ML • Rule Heuristics • Compliance Posture Weighting"]
    end

    subgraph DataLayer ["Data Persistence"]
        DB[("🗄️ PostgreSQL / SQLite Database<br/>Users • Events • Logs • Telemetry • Compliance Audits")]
    end

    subgraph AgentLayer ["Endpoint Agent (Python Daemon)"]
        direction TB
        TelemetryCollector["📡 Telemetry Collectors<br/>USB • Files • psutil Network • Processes • Clipboard"]
        ComplianceAuditor["🛡️ CIS Compliance Auditor<br/>Firewall • BitLocker • Screen Lock • Antivirus • USBSTOR"]
        AutoEnforcer["⚡ Automated Policy Enforcer<br/>Self-Healing Registry & Netsh Auto-Remediation"]
        
        TelemetryCollector --> AgentCore["Agent Orchestrator & Batcher"]
        ComplianceAuditor --> AutoEnforcer
        AutoEnforcer --> AgentCore
    end

    Analyst <-->|"HTTPS / Web GUI"| Frontend
    Frontend <-->|"REST API (JSON)"| Backend
    Backend <-->|"Real-Time Assessment"| RiskEngine
    Backend <-->|"Persist & Query Records"| DB
    AgentCore -->|"Ingest Telemetry & Compliance (HTTPS)"| Backend
```

### 🔄 Architectural Data & Enforcement Flow

1. **Continuous Telemetry & Compliance Auditing:**
   - The endpoint daemon continuously streams low-overhead telemetry (file modifications, USB attachments, process creation, clipboard hooks, and network bandwidth via `psutil`).
   - Concurrently, the **CIS Compliance Auditor** inspects local host configurations against critical security controls.

2. **Automated User Enforcement & Self-Healing:**
   - When policy deviations are detected (e.g., firewall disabled, missing screen lock timeout, or unrestricted USB ports), the **Automated Policy Enforcer** triggers native system remediation (`netsh`, Windows Registry policies, and `manage-bde`).
   - The agent records both pre- and post-enforcement states and tags the remediation in the outgoing `COMPLIANCE_STATUS` event.

3. **Ingestion & Risk Scoring:**
   - The **FastAPI Backend** validates and ingests telemetry batches.
   - The **Hybrid Risk Engine** combines unsupervised ML (`IsolationForest`) with heuristic rules. Compliance failures act as risk multipliers that escalate the endpoint's overall Threat Level (e.g., from `LOW` to `HIGH` or `CRITICAL`).

4. **Live SOC Visibility:**
   - The **React Dashboard** renders real-time threat gauges, telemetry sparklines, active process counts, and the **CIS Compliance Enforcement Panel**, detailing individual control statuses (`PASS`, `FAIL`, `ENFORCED`) and calculated compliance percentages.

---

## 🛡️ CIS Compliance Benchmarks & Active Enforcement

Dikoryx actively inspects and self-heals key operating system controls:

| Security Control | Benchmark Standard | Audit Mechanism | Automated Enforcement Action |
| :--- | :--- | :--- | :--- |
| **Windows Firewall** | CIS Controls v8 (Profile Protection) | `netsh advfirewall show allprofiles` | Automatically enables all firewall profiles (`set allprofiles state on`) |
| **Screen Lock & Inactivity** | CIS Benchmark (Lockout Timeout) | Registry: `HKCU\Control Panel\Desktop` (`ScreenSaveTimeOut`) | Configures 300s timeout & forces `ScreenSaverIsSecure=1` |
| **Antivirus Protection** | CIS Endpoint Defense (AV Service) | PowerShell `Get-MpComputerStatus` / `AMServiceEnabled` | Validates active Windows Defender engine status |
| **Disk Encryption** | CIS Data Protection (Storage At Rest) | `manage-bde -status` (BitLocker Protection) | Audits volume protection status across mounted volumes |
| **USB Storage Lockdown** | CIS Removable Media Policy | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR` | Enforces policy lockdown by disabling mass storage drivers (`Start=4`) |

> **Self-Healing Loop:** If a local user or malware alters system security settings, the agent detects the drift on its next cycle, re-applies policy enforcement, and notifies the backend dashboard immediately.

---

## 🧩 Tech Stack

| Layer | Technologies & Tools |
|---|---|
| **Frontend** | React 18, Vite, Lucide Icons, Recharts, Custom High-Contrast Cyber Theme |
| **Backend** | FastAPI, Uvicorn, SQLAlchemy, Pydantic, Passlib, Argon2-cffi |
| **Compliance & Enforcement** | Windows Security APIs, Netsh, Registry (`reg`), Manage-BDE, PowerShell Host APIs |
| **Database** | PostgreSQL (Neon / AWS RDS / Self-hosted) or SQLite |
| **Endpoint Agent** | Python 3.11+, `psutil`, `requests`, `pyyaml`, Windows Telemetry Collectors |
| **Machine Learning** | scikit-learn (`IsolationForest`), Rule-Based Behavioral Threat Engines |

---

## 🚀 Quick Start Guide

### 1️⃣ Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your PostgreSQL DATABASE_URL if using cloud DB

# Start backend server
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```
Interactive OpenAPI documentation will be accessible at: `http://127.0.0.1:8000/docs`

### 2️⃣ Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install packages
npm install

# Configure environment variables
cp .env.example .env
# Set VITE_BACKEND_URL=http://127.0.0.1:8000 (or production backend URL)

# Launch development dashboard
npm run dev
```
Open your browser at: `http://localhost:5173` and log in with `admin` / `admin`.

### 3️⃣ Endpoint Agent Setup

```bash
# In the project root:
pip install -r agent/requirements.txt

# Run the agent daemon (runs telemetry + compliance monitor + enforcement)
python -m agent.agent
```

---

## ⚙️ Agent Configuration & Policy Controls

Agent behavior and policy enforcement can be adjusted via `agent/config.yaml` or inline configuration:

```yaml
agent:
  interval_sec: 10          # Telemetry reporting interval in seconds
  server_url: "http://127.0.0.1:8000"

compliance:
  interval_sec: 300         # Compliance audit cadence (5 minutes)
  enforce: true             # Set to true to enable automated self-healing remediation
  max_screen_timeout_sec: 300
```

---

## 🔒 Production Readiness & Security Guidelines

Before deploying Dikoryx into a production enterprise environment, implement the following operational safeguards:

### 1. Hardened Authentication & Credential Management
* **Production Credentials:** Replace or disable the hardcoded `admin`/`admin` fallback in [`backend/api/auth.py`](backend/api/auth.py) for sensitive environments, and enforce strong password complexity policies.
* **Database Hashing:** Passwords must always be hashed with Argon2 or bcrypt before persistence. Never store unhashed passwords in database records.

### 2. Enforce Agent Authentication (`REQUIRE_AGENT_AUTH`)
* By default, `REQUIRE_AGENT_AUTH=false` is set for rapid local testing.
* In production, set `REQUIRE_AGENT_AUTH=true` in `backend/.env`. Every endpoint agent must then be registered to an organization and supply a cryptographically secure `Bearer <api_key>` in the `Authorization` header.

### 3. Strict CORS Origin Configuration
* In [`backend/main.py`](backend/main.py), restrict `allow_origins=["*"]` to your actual frontend domain:
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["https://dikoryx.vercel.app"],
      allow_credentials=True,
      allow_methods=["GET", "POST", "OPTIONS"],
      allow_headers=["*"],
  )
  ```

### 4. Database Over TLS / SSL
* Always enforce TLS connection strings when using cloud databases (e.g., Neon, AWS RDS, Supabase):
  `DATABASE_URL=postgresql://user:pass@host/dbname?sslmode=require&channel_binding=require`

### 5. Secret Protection & Git Hygiene
* Keep `.env`, local SQLite database files (`*.db`), runtime agent state files (`agent/state.json`, `agent_identity.json`), and log files strictly ignored in [`.gitignore`](.gitignore).
* Use cloud provider secret injection (Vercel Environment Variables, AWS Secrets Manager, GitHub Secrets) during deployment pipelines.

---

## 📁 Repository Structure

```
dikoryx/
├── agent/                          # Endpoint telemetry & enforcement daemon
│   ├── collectors/                 # Specialized telemetry collectors
│   │   └── windows/                # Windows OS collectors
│   │       ├── compliance.py       # CIS Compliance & Policy Enforcement collector
│   │       ├── file_ops.py         # File creation, deletion, modification monitor
│   │       ├── usb.py              # Removable drive insertion & file inventory
│   │       ├── process.py          # Process creation & thread analyzer
│   │       └── clipboard.py        # Clipboard hook & exfiltration detector
│   ├── agent.py                    # Main agent orchestration & heartbeat loop
│   ├── compliance_monitor.py       # Continuous baseline evaluation & compliance scoring
│   ├── vpn_api.py                  # Public IP & VPN/proxy network telemetry
│   └── requirements.txt            # Agent dependencies (psutil, requests, pyyaml)
│
├── backend/                        # FastAPI application
│   ├── api/                        # REST API routers
│   │   ├── auth.py                 # Argon2 authentication & session tokens
│   │   ├── agents.py               # Agent registration & health monitoring
│   │   ├── systems.py              # Endpoint overview & system metrics
│   │   └── telemetry.py            # High-throughput telemetry & compliance ingestion
│   ├── database.py                 # SQLAlchemy models and schema definitions
│   ├── risk_engine.py              # Hybrid ML & behavioral risk scoring engine
│   ├── requirements.txt            # Backend dependencies
│   └── main.py                     # Application entrypoint & middleware
│
├── frontend/                       # React 18 + Vite cyber dashboard
│   ├── src/
│   │   ├── components/             # Reusable UI components
│   │   │   ├── SystemDetails.jsx   # Threat vector, sparklines & CIS compliance view
│   │   │   ├── SystemDetails.css   # Cyberpunk styling & animated compliance badges
│   │   │   ├── CyberGauge.jsx      # SVG threat rating gauge
│   │   │   └── StatRow.jsx         # Metric visualization rows
│   │   ├── Pages/                  # Primary views (Dashboard, AgentSelect, Login)
│   │   └── App.jsx                 # Application router & session state
│   └── package.json
│
├── docs/
│   ├── screenshots/                # Showcase UI images (dashboard, agent_select, login)
│   ├── architecture.png            # High-resolution System Architecture & Data Flow diagram
│   ├── er_diagram.png              # Complete Relational ER Schema diagram
│   └── ARCHITECTURE.md             # In-depth architectural blueprint & data dictionary
│
├── .gitignore                      # Production exclusion rules
├── .vercelignore                   # Vercel deployment exclusions
└── README.md                       # Comprehensive project documentation
```

---

<div align="center">

*Built for the threats that don't come through the front door — and the policies that keep the endpoint secure.*

</div>
