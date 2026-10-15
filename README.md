<div align="center">

# 🛡️ Dikoryx
### **Next-Gen Insider Threat Detection & Behavioral Telemetry Platform**

*Watching for the threats that come from inside the walls.*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61DAFB.svg)](https://reactjs.org/)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%20%7C%20SQLite-336791.svg)](https://www.postgresql.org/)
[![Auth](https://img.shields.io/badge/Auth-Argon2-orange.svg)](https://en.wikipedia.org/wiki/Argon2)

</div>

---

## 📸 Dashboard & UI Showcase

<div align="center">

### Real-Time Threat Vector & Network Telemetry Dashboard
![Dikoryx Dashboard](docs/screenshots/dashboard.png)

<br/>

| Monitored Endpoints View | Authentication Portal |
| :---: | :---: |
| ![Active Agents](docs/screenshots/agent_select.png) | ![Login Portal](docs/screenshots/login.png) |

</div>

---

## 🔑 Default Credentials (Instant Access)

For evaluation, demonstrations, and test deployments, Dikoryx is pre-configured with the following default administrator credentials:

| Role | Username | Password | Access Level |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin` | Full System & Endpoint Telemetry Access |

> **Note:** Additional accounts can be registered dynamically via the `POST /api/v1/signup` API endpoint. All database passwords are cryptographically hashed using **Argon2**.

---

## 🌐 What is Dikoryx?

Most security software guards the perimeter — firewalls, proxies, and external intrusion detection. Dikoryx focuses on what occurs **within the endpoint**:
- Disgruntled employees exfiltrating confidential files to USB drives.
- Compromised developer machines transmitting high-volume outbound telemetry through covert tunnels or VPNs.
- Rapid deletion or mass modification of sensitive directories.
- Abnormal process execution patterns and unauthorized clipboard activity.

Dikoryx couples a lightweight endpoint agent with a FastAPI backend and a cyber-themed React dashboard to evaluate behavioral risk scores in real time.

---

## 🏗️ Architecture

```mermaid
flowchart TD
    subgraph AnalystLayer ["Analysis & Monitoring"]
        Analyst["🧑‍💻 Security Analyst<br/>(Web Browser)"]
    end

    subgraph PresentationLayer ["Frontend Layer"]
        Frontend["💻 React 18 + Vite Dashboard<br/>Cyberpunk UI • Live Telemetry • Threat Matrix"]
    end

    subgraph BackendLayer ["Backend Services"]
        Backend["⚙️ FastAPI Application<br/>Ingest Endpoints • Auth • Agent Management"]
        RiskEngine["🧠 Hybrid Risk Engine<br/>Rule Heuristics + IsolationForest ML"]
    end

    subgraph DataLayer ["Data Storage"]
        DB[("🗄️ PostgreSQL / SQLite<br/>Users • Events • Logs • Systems")]
    end

    subgraph AgentLayer ["Endpoint Telemetry"]
        Agent["🖥️ Endpoint Agent (Python Daemon)<br/>USB • File Activity • Network Bandwidth • Processes • VPN"]
    end

    Analyst <-->|"HTTPS / Web GUI"| Frontend
    Frontend <-->|"REST API (JSON)"| Backend
    Backend <-->|"Real-Time Evaluation"| RiskEngine
    Backend <-->|"Persists & Reads Events"| DB
    Agent -->|"Ingest Telemetry (HTTPS / Bearer Auth)"| Backend
```

**Architecture Data Flow:**
1. **Endpoint Agent:** Collects system metrics (USB transfers, file writes/deletions, network volume, active processes, and public IP/VPN status) and batches telemetry to the FastAPI backend over HTTPS.
2. **Backend & Risk Engine:** Ingests raw telemetry, executes rule-based heuristics and the scikit-learn `IsolationForest` anomaly detector, calculates threat scores, and saves records to PostgreSQL / SQLite.
3. **Frontend Dashboard:** Polls the backend API in real time and renders interactive visual analytics, threat gauges, and network volume sparklines for security analysts.

---

## 🧩 Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, Vite, Lucide Icons, Recharts, Custom Cyber Theme |
| **Backend** | FastAPI, Uvicorn, SQLAlchemy, Pydantic, Passlib, Argon2-cffi |
| **Database** | PostgreSQL (Neon / AWS RDS / Self-hosted) or SQLite |
| **Endpoint Agent** | Python 3, `psutil`, `requests`, `pyyaml`, Windows/Linux telemetry collectors |
| **Machine Learning** | scikit-learn (`IsolationForest`), Rule-Based Behavioral Engines |

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

# Run the agent daemon
python -m agent.agent
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
├── agent/                  # Endpoint telemetry daemon
│   ├── collectors/         # Specialized Windows & Linux collectors
│   │   └── windows/        # USB, File, Network (psutil), Process, Clipboard
│   ├── agent.py            # Main agent heartbeat and transmission loop
│   ├── vpn_api.py          # Public IP & VPN/proxy heuristic analyzer
│   └── requirements.txt    # Agent dependencies
│
├── backend/                # FastAPI application
│   ├── api/                # Auth, Agents, Systems, Telemetry routes
│   ├── database.py         # SQLAlchemy models and schema definitions
│   ├── risk_engine.py      # Behavioral rule and anomaly scoring engine
│   ├── requirements.txt    # Backend dependencies
│   └── main.py             # Application entrypoint & middleware
│
├── frontend/               # React 18 + Vite cyber dashboard
│   ├── src/
│   │   ├── components/     # SystemDetails, CyberGauge, StatRow, Charts
│   │   ├── Pages/          # Dashboard, AgentSelect
│   │   └── App.jsx         # App router and session management
│   └── package.json
│
├── docs/
│   └── screenshots/        # High-resolution UI screenshots
│
├── .gitignore              # Production exclusion rules
├── .vercelignore           # Vercel deployment exclusions
└── README.md               # Project documentation
```

---

<div align="center">

*Built for the threats that don't come through the front door.*

</div>
