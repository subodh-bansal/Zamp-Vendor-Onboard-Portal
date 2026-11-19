import json
import sqlite3
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

import app as app_module
import db as db_module
import samples as samples_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = tmp_path / "test_zamp.db"
    test_samples_dir = tmp_path / "sample_docs"
    monkeypatch.setattr(db_module, "DB_PATH", str(test_db))
    monkeypatch.setattr(samples_module, "SAMPLE_DOCS_DIR", str(test_samples_dir))
    monkeypatch.setattr(samples_module, "SCENARIO_ASSETS", {})
    app_module.SESSIONS.clear()
    app_module.VENDOR_DRAFTS.clear()
    app_module.PENDING_RUNS.clear()

    db_module.init_db()
    samples_module.generate_sample_documents()
    return TestClient(app_module.app, follow_redirects=False)


def login(client: TestClient, login_url: str, email: str, password: str):
    res = client.post(login_url, data={"email": email, "password": password})
    assert res.status_code == 302
    return res


def test_auth_and_role_guards(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/api/admin/vendors").status_code == 401
    assert client.get("/api/vendor/status").status_code == 401

    login(client, "/login/vendor", "contact@novacircuits.in", "Vendor@123")
    assert client.get("/api/vendor/status").status_code == 200
    assert client.get("/admin/dashboard").status_code == 403
    assert client.get("/api/admin/vendors").status_code == 403


def test_register_and_vendor_flow(client):
    res = client.post(
        "/register",
        data={
            "company_name": "Kaveri Sensors Pvt Ltd",
            "contact_name": "Arjun Rao",
            "email": "arjun@kaverisensors.in",
            "password": "Password@123",
        },
    )
    assert res.status_code == 302
    assert res.headers["location"] == "/vendor/home"

    home = client.get("/vendor/home")
    assert home.status_code == 200
    assert "Kaveri Sensors Pvt Ltd" in home.text


def test_application_submit_and_sse_stream(client):
    login(client, "/login/vendor", "contact@novacircuits.in", "Vendor@123")
    samples_module.generate_sample_documents()
    assets = samples_module.SCENARIO_ASSETS["nova"]

    files = {}
    for key in ["gst_cert", "pan_card", "cancelled_cheque"]:
        fpath = Path(samples_module.SAMPLE_DOCS_DIR) / assets[key]
        files[key] = (assets[key], fpath.read_bytes(), "image/png")

    submit_res = client.post(
        "/api/vendor/application/submit",
        data={
            "vendor_name": "Nova Precision Circuits Pvt Ltd",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "email": "contact@novacircuits.in",
            "contact_name": "Rohan Kulkarni",
            "phone": "+91 98201 44120",
            "address_state": "Maharashtra",
            "city": "Pune",
            "pin": "411028",
            "gstin": "27AABCN4412P1Z5",
            "pan": "AABCN4412P",
            "bank_name": "HDFC Bank",
            "bank_account": "50200088192011",
            "ifsc": "HDFC0001234",
            "account_holder": "Nova Precision Circuits Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "billing@novacircuits.in",
            "category": "Electronics",
            "description": "Precision PCB assembly",
            "lead_time_days": "7",
        },
        files=files,
    )
    assert submit_res.status_code == 200
    run_id = submit_res.json()["run_id"]

    with client.stream("GET", f"/api/stream/{run_id}?view=vendor") as stream_res:
        assert stream_res.status_code == 200
        chunks = [line for line in stream_res.iter_lines() if line.startswith("data: ")]
        assert any('"type": "done"' in c for c in chunks)
        for c in chunks:
            assert "risk_score" not in c


def test_admin_override_rbac_and_audit_chain(client):
    login(client, "/login/admin", "priya.nair@zamp.ai", "Admin@123")
    vendors_json = client.get("/api/admin/vendors").json()["vendors"]
    assert len(vendors_json) >= 8
    for v in vendors_json:
        if v.get("bank_account"):
            assert "*" in v["bank_account"]

    pending_apps = client.get("/api/admin/applications?status=pending&substate=awaiting_review").json()["applications"]
    assert len(pending_apps) >= 1
    target_app_id = pending_apps[0]["id"]

    bad_override = client.post(
        f"/api/admin/applications/{target_app_id}/override",
        json={"to_status": "approved", "remark": "short"},
    )
    assert bad_override.status_code == 422

    analyst_override = client.post(
        f"/api/admin/applications/{target_app_id}/override",
        json={"to_status": "approved", "remark": "Verified compliance documents manually after review."},
    )
    assert analyst_override.status_code in {200, 403}

    audit_page = client.get("/admin/audit")
    assert audit_page.status_code == 200
    assert "Chain verified" in audit_page.text


def test_reports_export_and_demo_reset(client):
    login(client, "/login/admin", "vikram.menon@zamp.ai", "Compliance@123")

    csv_res = client.get("/api/admin/reports/export?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "vendor_id" in csv_res.text

    json_res = client.get("/api/admin/reports/export?format=json")
    assert json_res.status_code == 200
    assert "vendors" in json_res.json()

    reset_res = client.post("/api/demo/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["ok"] is True