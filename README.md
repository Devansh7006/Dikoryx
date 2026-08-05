# Dikoryx

Enterprise Insider Threat Detection, Data Loss Prevention (DLP), and Compliance Monitoring Platform.

## Overview

Dikoryx is a security platform designed to detect insider threats, monitor endpoint activity, enforce compliance policies, and prevent data exfiltration.

The platform consists of:

* **Agent** – Lightweight endpoint agent deployed on monitored systems.
* **Backend** – FastAPI-based API and risk analysis engine.
* **Frontend** – React dashboard for analysts and administrators.
* **Risk Engine** – Rule-based and anomaly-based threat scoring.
* **DLP Engine** – Sensitive data detection and exfiltration monitoring.
* **Compliance Engine** – Endpoint compliance assessment and enforcement.

---

## Key Features

### Insider Threat Detection

* User behavior monitoring
* USB activity monitoring
* File activity monitoring
* Process activity monitoring
* Risk scoring engine
* Event correlation

### Data Loss Prevention (DLP)

* Sensitive file detection
* Data exfiltration monitoring
* Large file transfer detection
* USB copy monitoring
* Policy-based alerting

### Compliance Monitoring

* Firewall status monitoring
* Security configuration assessment
* Endpoint compliance evaluation
* Compliance enforcement actions

### SaaS Multi-Tenant Architecture

* Organization management
* Enrollment tokens
* Agent registration
* Agent API keys
* Authenticated telemetry ingestion

---

## Architecture

```text
+-------------------+
|  Security Analyst |
+---------+---------+
          |
          v
+-------------------+
|     Frontend      |
|   React Dashboard |
+---------+---------+
          |
          v
+-------------------+
|      Backend      |
| FastAPI + Risk AI |
+---------+---------+
          |
          v
+-------------------+
|    PostgreSQL     |
+---------+---------+
          ^
          |
+---------+---------+
|       Agent       |
| Endpoint Monitor  |
+-------------------+
```

---

## Technology Stack

### Backend

* FastAPI
* SQLAlchemy
* PostgreSQL
* Pydantic
* Uvicorn

### Agent

* Python
* Requests
* Watchdog
* Windows APIs
* Retry Framework

### Frontend

* React
* Vite
* JavaScript

### Testing

* Pytest
* Ruff
* Mypy
* Coverage

---

## Security Model

### Organization Enrollment

1. Administrator creates an organization.
2. System generates an enrollment token.
3. Endpoint agent registers using the token.
4. Backend issues:

   * Agent ID
   * API Key
5. Agent uses API Key for authenticated telemetry submission.

---

## Repository Structure

```text
dikoryx/
│
├── agent/
│   ├── collectors/
│   ├── tests/
│   └── ...
│
├── backend/
│   ├── api/
│   ├── tests/
│   └── ...
│
├── frontend/
│   └── ...
│
├── docs/
│
├── .github/
│   └── workflows/
│
└── README.md
```

---

## Testing

### Backend

```bash
pytest backend/tests
```

### Agent

```bash
pytest agent/tests
```

### Coverage

```bash
pytest backend/tests --cov=backend
pytest agent/tests --cov=agent
```

---

## Quality Assurance

### Ruff

```bash
ruff check .
```

### Mypy

```bash
mypy backend
mypy agent
```

---

## Running the Platform

### Backend

```bash
uvicorn backend.main:app --reload --port 8000
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Agent

Configure:

```yaml
backend_url: http://127.0.0.1:8000
organization_id: ...
api_key: ...
```

Run:

```bash
python -m agent.agent
```

---

## Current Status

### Completed

* Insider Threat Detection Engine
* DLP Engine
* Compliance Engine
* Organization Management
* Agent Registration
* API Key Authentication
* Automated Testing
* Type Checking
* Static Analysis

### Planned

* Windows Service Deployment
* MSI Installer
* Advanced UEBA
* Enhanced DLP Policies
* GitHub Actions CI/CD
* Load Testing Framework
* Multi-Tenant Dashboard Enhancements

---

## License

This project is currently under active development.
