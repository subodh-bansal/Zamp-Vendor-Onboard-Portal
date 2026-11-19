# Zamp.ai Vendor Onboarding & Compliance Portal

A FastAPI + SQLite + Server-Sent Events (SSE) supplier onboarding and compliance review portal with separate **Vendor** and **Admin / Compliance** workflows, automated document & rule evaluation (`R1`–`R14`), masked banking details, tamper-evident hash-chained audit logs, and CSV/JSON reporting.

## Quick Start

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 8000