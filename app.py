import os
import io
import csv
import json
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timezone
from fastapi import FastAPI, Request, Response, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from db import (
    init_db,
    get_db,
    add_audit_log,
    verify_audit_chain,
    compute_risk_tier,
    mask_bank_account,
    compute_vendor_performance,
    DB_PATH,
)
from samples import (
    generate_sample_documents,
    build_scenario_zip_bytes,
    get_scenarios_list,
    SAMPLE_DOCS_DIR,
    SCENARIO_ASSETS,
)
from engine import (
    stream_pipeline_stages,
    RULES_CATALOG,
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    MAX_FILE_BYTES,
)

app = FastAPI(title="Zamp.ai Vendor Portal")

os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
os.makedirs("static/img", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs(SAMPLE_DOCS_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

SESSIONS: dict[str, str] = {}
VENDOR_DRAFTS: dict[str, dict] = {}
PENDING_RUNS: dict[str, dict] = {}


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    generate_sample_documents()


def send_email_stub(to_email: str, subject: str, body: str) -> None:
    # plug SMTP here
    print(f"[SIMULATED EMAIL] To: {to_email} | Subject: {subject}")


def record_notification(
    conn,
    vendor_id: str,
    application_id: str | None,
    to_email: str,
    subject: str,
    body: str,
    outcome: str,
    check_ids: list[str] | None = None,
    actor: str = "rules:decision",
    role: str = "system",
) -> dict:
    ts = time.time()
    notif_id = f"NTF-{uuid.uuid4().hex[:8].upper()}"
    cids = check_ids or []
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO notifications (
            id, vendor_id, application_id, ts, subject, body, outcome, check_ids, delivery, read
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'simulated', 0)
        """,
        (notif_id, vendor_id, application_id, ts, subject, body, outcome, json.dumps(cids)),
    )
    add_audit_log(
        conn,
        vendor_id,
        application_id,
        actor,
        role,
        "NOTIFY",
        "notification",
        None,
        outcome,
        f"Sent {outcome} notification ({notif_id}) to {to_email}: {subject}",
    )
    send_email_stub(to_email, subject, body)
    return {
        "id": notif_id,
        "vendor_id": vendor_id,
        "application_id": application_id,
        "ts": ts,
        "subject": subject,
        "body": body,
        "outcome": outcome,
        "check_ids": cids,
        "delivery": "simulated",
        "read": 0,
    }


def get_session_user(request: Request) -> dict | None:
    token = request.cookies.get("zamp_session")
    if not token or token not in SESSIONS:
        return None
    user_id = SESSIONS[token]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, role, display_name, vendor_id FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def require_user(request: Request) -> dict:
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_admin(request: Request) -> dict:
    user = require_user(request)
    if user["role"] not in {"analyst", "compliance"}:
        raise HTTPException(status_code=403, detail="Admin or compliance access required.")
    return user


def require_vendor(request: Request) -> dict:
    user = require_user(request)
    if user["role"] != "vendor":
        raise HTTPException(status_code=403, detail="Vendor account required.")
    return user


def get_unread_count(user: dict | None) -> int:
    if not user:
        return 0
    conn = get_db()
    cursor = conn.cursor()
    if user["role"] == "vendor" and user.get("vendor_id"):
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM notifications WHERE vendor_id = ? AND read = 0",
            (user["vendor_id"],),
        )
    else:
        cursor.execute(
            "SELECT COUNT(*) AS cnt FROM vendors WHERE status = 'pending' AND substate = 'awaiting_review'"
        )
    cnt = cursor.fetchone()["cnt"]
    conn.close()
    return int(cnt)


def render_page(request: Request, template_name: str, context: dict | None = None, status_code: int = 200):
    user = get_session_user(request)
    ctx = {
        "request": request,
        "current_user": user,
        "unread_count": get_unread_count(user),
        "active_nav": "",
    }
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, template_name, ctx, status_code=status_code)


@app.exception_handler(401)
def unauthorized_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=401, content={"detail": exc.detail or "Unauthorized."})
    if request.url.path.startswith("/admin"):
        return RedirectResponse(url="/login/admin", status_code=302)
    return RedirectResponse(url="/login/vendor", status_code=302)


@app.exception_handler(403)
def forbidden_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=403, content={"detail": exc.detail or "Forbidden."})
    return render_page(
        request,
        "errors/error.html",
        {"status_code": 403, "title": "Not allowed", "message": exc.detail or "You do not have permission for this action."},
        status_code=403,
    )


@app.exception_handler(404)
def not_found_handler(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"detail": exc.detail or "Not found."})
    return render_page(
        request,
        "errors/error.html",
        {"status_code": 404, "title": "Not found", "message": "Requested resource was not found."},
        status_code=404,
    )


@app.exception_handler(500)
def server_error_handler(request: Request, exc: Exception):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})
    return render_page(
        request,
        "errors/error.html",
        {"status_code": 500, "title": "Internal server error", "message": "An unexpected error occurred while processing your request."},
        status_code=500,
    )


@app.get("/healthz")
def healthz():
    return {"ok": True}


# --- Public & Auth Routes ---

@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    user = get_session_user(request)
    if user:
        if user["role"] == "vendor":
            return RedirectResponse(url="/vendor/home", status_code=302)
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    return render_page(request, "auth/landing.html")


@app.get("/login/vendor", response_class=HTMLResponse)
def login_vendor_page(request: Request):
    return render_page(request, "auth/login_vendor.html")


@app.post("/login/vendor")
def login_vendor_submit(request: Request, email: str = Form(""), password: str = Form("")):
    clean_email = email.strip().lower()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE lower(email) = ?", (clean_email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return render_page(
            request,
            "auth/login_vendor.html",
            {"error": f"No vendor account found for '{clean_email}'.", "email": clean_email},
            status_code=401,
        )
    user = dict(row)
    if user["role"] != "vendor":
        return render_page(
            request,
            "auth/login_vendor.html",
            {"error": "That email belongs to a staff account. Please use Admin login.", "email": clean_email},
            status_code=401,
        )
    if user["password"] != password:
        return render_page(
            request,
            "auth/login_vendor.html",
            {"error": "Wrong password for that email.", "email": clean_email},
            status_code=401,
        )

    token = secrets.token_hex(24)
    SESSIONS[token] = user["id"]
    resp = RedirectResponse(url="/vendor/home", status_code=302)
    resp.set_cookie("zamp_session", token, httponly=True, samesite="lax")
    return resp


@app.get("/login/admin", response_class=HTMLResponse)
def login_admin_page(request: Request):
    return render_page(request, "auth/login_admin.html")


@app.post("/login/admin")
def login_admin_submit(request: Request, email: str = Form(""), password: str = Form("")):
    clean_email = email.strip().lower()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE lower(email) = ?", (clean_email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return render_page(
            request,
            "auth/login_admin.html",
            {"error": f"No staff account found for '{clean_email}'.", "email": clean_email},
            status_code=401,
        )
    user = dict(row)
    if user["role"] not in {"analyst", "compliance"}:
        return render_page(
            request,
            "auth/login_admin.html",
            {"error": "That email belongs to a vendor account. Please use Vendor login.", "email": clean_email},
            status_code=401,
        )
    if user["password"] != password:
        return render_page(
            request,
            "auth/login_admin.html",
            {"error": "Wrong password for that email.", "email": clean_email},
            status_code=401,
        )

    token = secrets.token_hex(24)
    SESSIONS[token] = user["id"]
    resp = RedirectResponse(url="/admin/dashboard", status_code=302)
    resp.set_cookie("zamp_session", token, httponly=True, samesite="lax")
    return resp


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return render_page(request, "auth/register.html")


@app.post("/register")
def register_submit(
    request: Request,
    company_name: str = Form(""),
    contact_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
):
    c_name = company_name.strip()
    p_name = contact_name.strip()
    clean_email = email.strip().lower()

    if not c_name or not p_name or not clean_email or len(password) < 6:
        return render_page(
            request,
            "auth/register.html",
            {
                "error": "Please fill all fields and use a password of at least 6 characters.",
                "company_name": c_name,
                "contact_name": p_name,
                "email": clean_email,
            },
            status_code=400,
        )

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE lower(email) = ?", (clean_email,))
    if cursor.fetchone():
        conn.close()
        return render_page(
            request,
            "auth/register.html",
            {
                "error": "An account with that email already exists. Please sign in.",
                "company_name": c_name,
                "contact_name": p_name,
                "email": clean_email,
            },
            status_code=400,
        )

    cursor.execute("SELECT vendor_id FROM vendors")
    max_num = 8
    for r in cursor.fetchall():
        vid_str = r["vendor_id"]
        if vid_str.startswith("V-") and vid_str[2:].isdigit():
            max_num = max(max_num, int(vid_str[2:]))
    new_vid = f"V-{max_num + 1:04d}"
    new_uid = f"U-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()

    contact_json = json.dumps({"primary_name": p_name, "email": clean_email, "designation": "", "phone": ""})
    cursor.execute(
        """
        INSERT INTO vendors (
            vendor_id, name, email, contact, status, substate, risk_score, risk_tier,
            escalated, on_portal_since, created_ts, updated_ts
        ) VALUES (?, ?, ?, ?, 'not_started', NULL, 0, 'Low', 0, ?, ?, ?)
        """,
        (new_vid, c_name, clean_email, contact_json, time.strftime("%Y-%m-%d"), now, now),
    )

    cursor.execute(
        "INSERT INTO users (id, email, password, role, display_name, vendor_id) VALUES (?, ?, ?, 'vendor', ?, ?)",
        (new_uid, clean_email, password, c_name, new_vid),
    )

    add_audit_log(
        conn,
        new_vid,
        None,
        c_name,
        "vendor",
        "REGISTER",
        "vendor_account",
        None,
        "not_started",
        f"Registered new vendor account for {c_name} ({clean_email})",
    )
    conn.commit()
    conn.close()

    token = secrets.token_hex(24)
    SESSIONS[token] = new_uid
    resp = RedirectResponse(url="/vendor/home", status_code=302)
    resp.set_cookie("zamp_session", token, httponly=True, samesite="lax")
    return resp


@app.post("/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("zamp_session")
    if token and token in SESSIONS:
        del SESSIONS[token]
    response.delete_cookie("zamp_session")
    return {"ok": True}


# --- Vendor Portal HTML Pages ---

@app.get("/vendor/home", response_class=HTMLResponse)
def vendor_home(request: Request):
    user = require_vendor(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (user["vendor_id"],))
    v_row = cursor.fetchone()
    vendor = dict(v_row) if v_row else {"vendor_id": user["vendor_id"], "name": user["display_name"], "status": "not_started"}

    cursor.execute(
        "SELECT * FROM notifications WHERE vendor_id = ? ORDER BY ts DESC LIMIT 3",
        (user["vendor_id"],),
    )
    recent_msgs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    st = vendor.get("status") or "not_started"
    sub = vendor.get("substate") or ""

    if st == "approved":
        meaning = "Your supplier onboarding is approved. You can view orders and track your profile."
        next_label = "View purchase orders"
        next_url = "/vendor/orders"
    elif st == "rejected":
        meaning = "Your latest onboarding application was not approved. View status details for next steps."
        next_label = "View status & details"
        next_url = "/vendor/application/status"
    elif st == "pending" and sub == "awaiting_vendor":
        meaning = "We need a few updates or documents from you before moving forward."
        next_label = "Fix required items"
        next_url = "/vendor/application/status"
    elif st == "pending":
        meaning = "Your submission is currently under review by our compliance/procurement team."
        next_label = "View application status"
        next_url = "/vendor/application/status"
    elif st == "draft":
        meaning = "You have a saved application draft ready to finish and submit."
        next_label = "Continue application"
        next_url = "/vendor/application"
    else:
        meaning = "Start your 6-step supplier onboarding application to get verified."
        next_label = "Start onboarding"
        next_url = "/vendor/application"

    checklist = [
        {"label": "1. Company details", "done": bool(vendor.get("name") and vendor.get("state"))},
        {"label": "2. Contact details", "done": bool(vendor.get("email"))},
        {"label": "3. Tax & banking details", "done": bool(vendor.get("gstin") and vendor.get("pan") and vendor.get("bank_account"))},
        {"label": "4. Products & services", "done": bool(vendor.get("category"))},
        {"label": "5. Documents & review", "done": st in {"pending", "approved", "rejected"}},
    ]

    return render_page(
        request,
        "vendor/home.html",
        {
            "active_nav": "home",
            "vendor": vendor,
            "status_meaning": meaning,
            "next_action_label": next_label,
            "next_action_url": next_url,
            "checklist": checklist,
            "recent_messages": recent_msgs,
        },
    )


@app.get("/vendor/application", response_class=HTMLResponse)
def vendor_application_page(request: Request, demo: int = 0):
    require_vendor(request)
    show_demo = bool(demo == 1 or os.environ.get("DEMO_MODE", "1") == "1")
    return render_page(
        request,
        "vendor/application.html",
        {"active_nav": "application", "demo_mode": show_demo},
    )


@app.get("/vendor/application/processing/{run_id}", response_class=HTMLResponse)
def vendor_processing_page(request: Request, run_id: str):
    require_vendor(request)
    return render_page(
        request,
        "vendor/processing.html",
        {"active_nav": "application", "run_id": run_id},
    )


def _step_for_check(chk: dict) -> int:
    rid = chk.get("rule_id") or ""
    cid = chk.get("id") or ""
    if rid == "R2" or "doc" in cid or "read" in cid:
        return 5
    if rid in {"R5", "R6", "R8", "R9", "R13", "R14"} or any(k in cid for k in ["gstin", "pan", "ifsc", "bank", "state"]):
        return 3
    if "contact" in cid or "email" in cid:
        return 2
    if "vendor_name" in cid or "name" in rid or "R10" in rid:
        return 1
    return 1


@app.get("/vendor/application/status", response_class=HTMLResponse)
def vendor_status_page(request: Request):
    user = require_vendor(request)
    vid = user["vendor_id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vid,))
    v_row = cursor.fetchone()
    vendor = dict(v_row) if v_row else {"vendor_id": vid, "status": "not_started"}

    cursor.execute("SELECT * FROM applications WHERE vendor_id = ? ORDER BY round DESC", (vid,))
    app_rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    fix_items: list[dict] = []
    rejection_summary = ""
    rounds_history: list[dict] = []

    for r in app_rows:
        parsed = json.loads(r["data"])
        dec = parsed.get("decision") or {}
        r_checks = dec.get("checks") or []
        if r["status"] == "rejected":
            v_summary = "Application was not approved."
        elif r["status"] == "approved":
            v_summary = "Application approved."
        elif r["substate"] == "awaiting_vendor":
            fix_c = [c for c in r_checks if c.get("status") == "fix"]
            v_summary = f"{len(fix_c)} item(s) to update before review."
        else:
            v_summary = "Submitted for review."

        rounds_history.append(
            {
                "id": r["id"],
                "round": r["round"],
                "status": r["status"],
                "substate": r["substate"],
                "vendor_summary": v_summary,
            }
        )

    if app_rows:
        latest = app_rows[0]
        latest_dec = (json.loads(latest["data"]).get("decision") or {})
        latest_checks = latest_dec.get("checks") or []
        for c in latest_checks:
            if c.get("status") == "fix":
                fix_items.append(
                    {
                        "label": c.get("label") or "Update required",
                        "vendor_msg": c.get("vendor_msg") or "Please review and update this field or document.",
                        "target_step": _step_for_check(c),
                    }
                )
        if latest["status"] == "rejected":
            if any(c.get("rule_id") == "R12" and c.get("status") == "fail" for c in latest_checks):
                rejection_summary = "We're unable to onboard your company at this time."
            elif any(c.get("rule_id") == "R7" and c.get("status") == "fail" for c in latest_checks):
                rejection_summary = "Your uploaded GST certificate and PAN card show conflicting tax identity details."
            else:
                rejection_summary = "We're unable to onboard your company at this time."

    st = vendor.get("status") or "not_started"
    sub = vendor.get("substate") or ""
    if st == "approved":
        explanation = "Your application is approved and your supplier account is active."
    elif st == "rejected":
        explanation = "Your latest application was not approved. You may start a new application if needed."
    elif st == "pending" and sub == "awaiting_vendor":
        explanation = "Some items need your attention before we can proceed with your application."
    elif st == "pending":
        explanation = "Your application is under review. We will notify you as soon as there is an update."
    else:
        explanation = "No active submission yet."

    return render_page(
        request,
        "vendor/status.html",
        {
            "active_nav": "application",
            "vendor": vendor,
            "status_explanation": explanation,
            "fix_items": fix_items,
            "rejection_summary": rejection_summary,
            "rounds_history": rounds_history,
            "can_start_new": st == "rejected",
        },
    )


@app.post("/api/vendor/new-application")
def api_vendor_new_application(request: Request):
    user = require_vendor(request)
    vid = user["vendor_id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM vendors WHERE vendor_id = ?", (vid,))
    row = cursor.fetchone()
    prev_status = row["status"] if row else None
    cursor.execute(
        "UPDATE vendors SET status = 'draft', substate = NULL, updated_ts = ? WHERE vendor_id = ?",
        (time.time(), vid),
    )
    add_audit_log(
        conn,
        vid,
        None,
        user["display_name"],
        "vendor",
        "NEW_APPLICATION",
        "application",
        prev_status,
        "draft",
        "Started a new onboarding application after prior outcome.",
    )
    conn.commit()
    conn.close()
    VENDOR_DRAFTS[vid] = {}
    return {"ok": True, "status": "draft"}


@app.get("/vendor/documents", response_class=HTMLResponse)
def vendor_documents_page(request: Request):
    user = require_vendor(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, doc_type, filename, readable_status, expiry_date, uploaded_ts FROM documents WHERE vendor_id = ? ORDER BY uploaded_ts DESC",
        (user["vendor_id"],),
    )
    docs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_page(request, "vendor/documents.html", {"active_nav": "documents", "docs": docs})


@app.get("/vendor/messages", response_class=HTMLResponse)
def vendor_messages_page(request: Request):
    user = require_vendor(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM notifications WHERE vendor_id = ? ORDER BY ts DESC",
        (user["vendor_id"],),
    )
    msgs = [dict(r) for r in cursor.fetchall()]
    cursor.execute("UPDATE notifications SET read = 1 WHERE vendor_id = ?", (user["vendor_id"],))
    conn.commit()
    conn.close()
    return render_page(request, "vendor/messages.html", {"active_nav": "messages", "messages": msgs})


@app.get("/vendor/orders", response_class=HTMLResponse)
def vendor_orders_page(request: Request):
    user = require_vendor(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (user["vendor_id"],))
    v_row = cursor.fetchone()
    vendor = dict(v_row) if v_row else {"status": "not_started"}
    orders = []
    if vendor.get("status") == "approved":
        cursor.execute("SELECT * FROM orders WHERE vendor_id = ? ORDER BY created DESC", (user["vendor_id"],))
        orders = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return render_page(request, "vendor/orders.html", {"active_nav": "orders", "vendor": vendor, "orders": orders})


@app.get("/vendor/profile", response_class=HTMLResponse)
def vendor_profile_get(request: Request):
    user = require_vendor(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (user["vendor_id"],))
    v_row = cursor.fetchone()
    conn.close()
    vendor = dict(v_row) if v_row else {}
    return render_page(request, "vendor/profile.html", {"active_nav": "profile", "vendor": vendor})


@app.post("/vendor/profile")
def vendor_profile_post(
    request: Request,
    name: str = Form(""),
    trading_name: str = Form(""),
    bank_name: str = Form(""),
    bank_account: str = Form(""),
    ifsc: str = Form(""),
    invoice_email: str = Form(""),
    new_password: str = Form(""),
):
    user = require_vendor(request)
    vid = user["vendor_id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE vendors
        SET name = COALESCE(NULLIF(?, ''), name),
            trading_name = ?,
            bank_name = ?,
            bank_account = COALESCE(NULLIF(?, ''), bank_account),
            ifsc = COALESCE(NULLIF(?, ''), ifsc),
            invoice_email = ?,
            updated_ts = ?
        WHERE vendor_id = ?
        """,
        (name.strip(), trading_name.strip(), bank_name.strip(), bank_account.strip(), ifsc.strip().upper(), invoice_email.strip(), time.time(), vid),
    )
    if new_password and len(new_password.strip()) >= 6:
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password.strip(), user["id"]))
    add_audit_log(
        conn,
        vid,
        None,
        user["display_name"],
        "vendor",
        "UPDATE_PROFILE",
        "vendor",
        None,
        None,
        "Updated vendor profile details.",
    )
    conn.commit()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vid,))
    vendor = dict(cursor.fetchone())
    conn.close()
    return render_page(
        request,
        "vendor/profile.html",
        {"active_nav": "profile", "vendor": vendor, "saved_msg": "Your profile details have been saved."},
    )


# --- Admin Portal HTML Pages ---

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard_page(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM applications ORDER BY ts ASC")
    apps = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM vendors")
    vendors = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 8")
    recent_activity = [dict(r) for r in cursor.fetchall()]
    conn.close()

    vendor_map = {v["vendor_id"]: v for v in vendors}
    open_reviews = [a for a in apps if a["status"] == "pending" and a["substate"] == "awaiting_review"]
    awaiting_vendor = [a for a in apps if a["status"] == "pending" and a["substate"] == "awaiting_vendor"]
    approved_apps = [a for a in apps if a["status"] == "approved"]
    rejected_apps = [a for a in apps if a["status"] == "rejected"]

    decided_count = len(approved_apps) + len(rejected_apps)
    rejection_rate = round((len(rejected_apps) / decided_count) * 100, 1) if decided_count else 0.0
    high_risk_count = len([v for v in vendors if (v.get("risk_score") or 0) >= 50 or v.get("risk_tier") == "High"])

    attention_items = []
    for a in open_reviews:
        v = vendor_map.get(a["vendor_id"]) or {}
        attention_items.append(
            {
                "id": a["id"],
                "vendor_id": a["vendor_id"],
                "vendor_name": v.get("name") or a["vendor_id"],
                "round": a["round"],
                "status": a["status"],
                "substate": a["substate"],
                "risk_score": a["risk_score"],
                "risk_tier": a["risk_tier"] or compute_risk_tier(a["risk_score"] or 0),
            }
        )

    kpis = {
        "open_reviews": len(open_reviews),
        "awaiting_vendor": len(awaiting_vendor),
        "approved_this_month": len(approved_apps),
        "rejection_rate": rejection_rate,
        "avg_decision_hours": 1.4,
        "high_risk_count": high_risk_count,
    }

    status_counts = {
        "approved": len(approved_apps),
        "awaiting_review": len(open_reviews),
        "awaiting_vendor": len(awaiting_vendor),
        "rejected": len(rejected_apps),
    }

    tier_counts = {"Low": 0, "Medium": 0, "High": 0}
    for v in vendors:
        t = v.get("risk_tier") or compute_risk_tier(v.get("risk_score") or 0)
        tier_counts[t] = tier_counts.get(t, 0) + 1

    return render_page(
        request,
        "admin/dashboard.html",
        {
            "active_nav": "dashboard",
            "kpis": kpis,
            "attention_items": attention_items,
            "status_counts": status_counts,
            "tier_counts": tier_counts,
            "recent_activity": recent_activity,
        },
    )


@app.get("/admin/applications", response_class=HTMLResponse)
def admin_applications_page(request: Request, tab: str = "all", tier: str = "", q: str = ""):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications ORDER BY ts DESC")
    app_rows = [dict(r) for r in cursor.fetchall()]
    cursor.execute("SELECT * FROM vendors")
    vendors = {v["vendor_id"]: dict(v) for v in cursor.fetchall()}
    conn.close()

    q_clean = (q or "").strip().lower()
    items = []
    for a in app_rows:
        v = vendors.get(a["vendor_id"]) or {}
        sub_data = (json.loads(a["data"]).get("submission") or {})
        v_name = sub_data.get("vendor_name") or v.get("name") or a["vendor_id"]
        gstin_val = (sub_data.get("gstin") or v.get("gstin") or "").lower()
        pan_val = (sub_data.get("pan") or v.get("pan") or "").lower()

        if tab == "needs_review" and not (a["status"] == "pending" and a["substate"] == "awaiting_review"):
            continue
        if tab == "awaiting_vendor" and not (a["status"] == "pending" and a["substate"] == "awaiting_vendor"):
            continue
        if tab == "approved" and a["status"] != "approved":
            continue
        if tab == "rejected" and a["status"] != "rejected":
            continue

        a_tier = a["risk_tier"] or compute_risk_tier(a["risk_score"] or 0)
        if tier and a_tier.lower() != tier.lower():
            continue

        if q_clean:
            hay = f"{a['id']} {a['vendor_id']} {v_name} {gstin_val} {pan_val}".lower()
            if q_clean not in hay:
                continue

        dt_str = datetime.fromtimestamp(a["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        items.append(
            {
                "id": a["id"],
                "vendor_id": a["vendor_id"],
                "vendor_name": v_name,
                "submitted_display": dt_str,
                "round": a["round"],
                "status": a["status"],
                "substate": a["substate"],
                "risk_score": a["risk_score"] or 0,
                "risk_tier": a_tier,
                "escalated": int(a.get("escalated") or 0),
            }
        )

    return render_page(
        request,
        "admin/applications.html",
        {
            "active_nav": "applications",
            "applications": items,
            "active_tab": tab,
            "tier": tier,
            "q": q,
        },
    )


@app.get("/admin/applications/{app_id}", response_class=HTMLResponse)
def admin_application_detail_page(request: Request, app_id: str):
    user = require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
    a_row = cursor.fetchone()
    if not a_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Application not found.")

    app_obj = dict(a_row)
    parsed = json.loads(app_obj["data"])
    submission = parsed.get("submission") or {}
    decision = parsed.get("decision") or {}
    stages_list = parsed.get("stages") or []

    cursor.execute("SELECT * FROM checks WHERE application_id = ?", (app_id,))
    checks = [dict(r) for r in cursor.fetchall()]
    if not checks:
        checks = decision.get("checks") or []

    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (app_obj["vendor_id"],))
    v_row = cursor.fetchone()
    vendor = dict(v_row) if v_row else {"vendor_id": app_obj["vendor_id"], "name": submission.get("vendor_name") or app_obj["vendor_id"]}

    cursor.execute(
        "SELECT * FROM notifications WHERE vendor_id = ? AND (application_id = ? OR application_id IS NULL) ORDER BY ts DESC",
        (app_obj["vendor_id"], app_id),
    )
    notifications = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT id, doc_type, filename, readable_status FROM documents WHERE application_id = ?", (app_id,))
    documents = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM audit_logs WHERE application_id = ? ORDER BY id ASC", (app_id,))
    audit_rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    has_fail = any(c.get("status") == "fail" for c in checks)
    has_review = any(c.get("status") == "review" for c in checks)
    is_pending = app_obj["status"] == "pending"

    can_reject = bool(is_pending and not has_fail)
    if not is_pending:
        can_approve = False
        override_blocked_reason = f"Application is already '{app_obj['status']}'."
    elif has_fail:
        can_approve = False
        override_blocked_reason = "Hard-failed ('fail') checks cannot be overridden."
    elif has_review and user["role"] != "compliance":
        can_approve = False
        override_blocked_reason = "Procurement Analysts cannot approve cases with open 'review' items; Compliance Officer approval is required."
    else:
        can_approve = True
        override_blocked_reason = None

    recs = []
    for c in checks:
        if c.get("recommendation") and c.get("recommendation") not in recs:
            recs.append(c["recommendation"])

    bank_acct_raw = submission.get("bank_account") or vendor.get("bank_account") or ""

    return render_page(
        request,
        "admin/application_detail.html",
        {
            "active_nav": "applications",
            "application": app_obj,
            "submission": submission,
            "vendor": vendor,
            "checks": checks,
            "decision_reason": decision.get("reason") or f"Status: {app_obj['status']}",
            "notifications": notifications,
            "documents": documents,
            "audit_rows": audit_rows,
            "stages_json": stages_list,
            "bank_account_masked": mask_bank_account(bank_acct_raw),
            "can_approve": can_approve,
            "can_reject": can_reject,
            "override_blocked_reason": override_blocked_reason,
            "recommendations": recs,
        },
    )


@app.post("/api/admin/applications/{app_id}/override")
async def api_admin_override(request: Request, app_id: str):
    user = require_admin(request)
    body = await request.json()
    to_status = (body.get("to_status") or "").strip().lower()
    remark = (body.get("remark") or "").strip()

    if len(remark) < 10:
        raise HTTPException(status_code=422, detail="A remark of at least 10 characters is required for overrides.")
    if to_status not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="to_status must be 'approved' or 'rejected'.")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
    a_row = cursor.fetchone()
    if not a_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Application not found.")

    app_obj = dict(a_row)
    if app_obj["status"] != "pending":
        conn.close()
        raise HTTPException(status_code=409, detail="Only pending applications can be overridden.")

    cursor.execute("SELECT * FROM checks WHERE application_id = ?", (app_id,))
    checks = [dict(r) for r in cursor.fetchall()]

    has_fail = any(c.get("status") == "fail" for c in checks)
    has_review = any(c.get("status") == "review" for c in checks)

    if has_fail:
        conn.close()
        raise HTTPException(status_code=403, detail="Cannot override an application that failed a hard rule.")

    if to_status == "approved" and has_review and user["role"] != "compliance":
        conn.close()
        raise HTTPException(status_code=403, detail="Only a Compliance Officer can approve applications with open review items.")

    vid = app_obj["vendor_id"]
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vid,))
    v_row = cursor.fetchone()
    vendor = dict(v_row) if v_row else {}
    from_status = vendor.get("status") or app_obj["status"]

    parsed = json.loads(app_obj["data"])
    submission = parsed.get("submission") or {}
    now = time.time()

    cursor.execute(
        "UPDATE applications SET status = ?, substate = NULL WHERE id = ?",
        (to_status, app_id),
    )

    if to_status == "approved":
        cursor.execute(
            """
            UPDATE vendors
            SET name = COALESCE(NULLIF(?, ''), name),
                gstin = COALESCE(NULLIF(?, ''), gstin),
                pan = COALESCE(NULLIF(?, ''), pan),
                state = COALESCE(NULLIF(?, ''), state),
                bank_name = COALESCE(NULLIF(?, ''), bank_name),
                bank_account = COALESCE(NULLIF(?, ''), bank_account),
                ifsc = COALESCE(NULLIF(?, ''), ifsc),
                account_holder = COALESCE(NULLIF(?, ''), account_holder),
                category = COALESCE(NULLIF(?, ''), category),
                status = 'approved',
                substate = NULL,
                escalated = 0,
                updated_ts = ?
            WHERE vendor_id = ?
            """,
            (
                submission.get("vendor_name"),
                submission.get("gstin"),
                submission.get("pan"),
                submission.get("address_state"),
                submission.get("bank_name"),
                submission.get("bank_account"),
                submission.get("ifsc"),
                submission.get("account_holder"),
                submission.get("category"),
                now,
                vid,
            ),
        )
    else:
        if vendor.get("status") != "approved":
            cursor.execute(
                "UPDATE vendors SET status = 'rejected', substate = NULL, updated_ts = ? WHERE vendor_id = ?",
                (now, vid),
            )

    add_audit_log(
        conn,
        vid,
        app_id,
        user["display_name"],
        user["role"],
        "OVERRIDE",
        "application",
        from_status,
        to_status,
        remark,
    )

    to_email = submission.get("email") or vendor.get("email") or "vendor@example.com"
    v_name = submission.get("vendor_name") or vendor.get("name") or vid
    if to_status == "approved":
        subj = f"Onboarding approved — Application {app_id}"
        body = f"Hello {v_name},\n\nYour onboarding application ({app_id}) has been approved following review."
    else:
        subj = f"Onboarding update — Application {app_id}"
        body = f"Hello {v_name},\n\nWe're unable to approve your onboarding application ({app_id}) at this time."

    record_notification(
        conn,
        vid,
        app_id,
        to_email,
        subj,
        body,
        to_status,
        [],
        actor=user["display_name"],
        role=user["role"],
    )

    conn.commit()
    conn.close()
    return {"ok": True, "application_id": app_id, "to_status": to_status}


@app.get("/admin/vendors", response_class=HTMLResponse)
def admin_vendors_page(request: Request, q: str = "", category: str = "", status: str = "", tier: str = ""):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors ORDER BY vendor_id ASC")
    rows = [dict(r) for r in cursor.fetchall()]

    categories = sorted({(r.get("category") or "").strip() for r in rows if (r.get("category") or "").strip()})
    q_clean = (q or "").strip().lower()
    enriched = []

    for v in rows:
        if category and (v.get("category") or "").lower() != category.lower():
            continue
        if status and (v.get("status") or "").lower() != status.lower():
            continue
        v_tier = v.get("risk_tier") or compute_risk_tier(v.get("risk_score") or 0)
        if tier and v_tier.lower() != tier.lower():
            continue
        if q_clean and q_clean not in f"{v['vendor_id']} {v.get('name') or ''}".lower():
            continue

        perf = compute_vendor_performance(conn, v["vendor_id"])
        enriched.append(
            {
                **v,
                "risk_tier": v_tier,
                "bank_account_masked": mask_bank_account(v.get("bank_account")),
                "orders_count": perf["metrics"]["closed_deals"]["value"] + len(perf["open_orders"]),
                "closed_deals": perf["metrics"]["closed_deals"]["value"],
                "on_time_pct": perf["metrics"]["on_time_shipping"]["value"],
            }
        )

    conn.close()
    return render_page(
        request,
        "admin/vendors.html",
        {
            "active_nav": "vendors",
            "vendors": enriched,
            "categories": categories,
            "q": q,
            "category": category,
            "status": status,
            "tier": tier,
        },
    )


@app.get("/admin/vendors/{vendor_id}", response_class=HTMLResponse)
def admin_vendor_detail_page(request: Request, vendor_id: str, tab: str = "overview"):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,))
    v_row = cursor.fetchone()
    if not v_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Vendor not found.")

    vendor = dict(v_row)
    contact = json.loads(vendor["contact"]) if vendor.get("contact") else {}
    perf = compute_vendor_performance(conn, vendor_id)

    cursor.execute("SELECT * FROM orders WHERE vendor_id = ? ORDER BY created DESC", (vendor_id,))
    orders = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM applications WHERE vendor_id = ? ORDER BY round DESC", (vendor_id,))
    app_history = []
    for r in cursor.fetchall():
        row_d = dict(r)
        parsed = json.loads(row_d["data"])
        dec = parsed.get("decision") or {}
        app_history.append(
            {
                **row_d,
                "risk_tier": row_d.get("risk_tier") or compute_risk_tier(row_d.get("risk_score") or 0),
                "reason": dec.get("reason") or "",
            }
        )

    cursor.execute("SELECT id, doc_type, filename, readable_status, expiry_date FROM documents WHERE vendor_id = ?", (vendor_id,))
    documents = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM notifications WHERE vendor_id = ? ORDER BY ts DESC", (vendor_id,))
    messages = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM audit_logs WHERE vendor_id = ? ORDER BY id DESC", (vendor_id,))
    audit_rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return render_page(
        request,
        "admin/vendor_detail.html",
        {
            "active_nav": "vendors",
            "vendor": vendor,
            "contact": contact,
            "bank_account_masked": mask_bank_account(vendor.get("bank_account")),
            "active_tab": tab,
            "perf": perf,
            "orders": orders,
            "app_history": app_history,
            "documents": documents,
            "messages": messages,
            "audit_rows": audit_rows,
        },
    )


@app.get("/admin/messages", response_class=HTMLResponse)
def admin_messages_page(request: Request, outcome: str = ""):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT vendor_id, name FROM vendors")
    v_names = {r["vendor_id"]: r["name"] for r in cursor.fetchall()}

    if outcome:
        cursor.execute("SELECT * FROM notifications WHERE outcome = ? ORDER BY ts DESC", (outcome,))
    else:
        cursor.execute("SELECT * FROM notifications ORDER BY ts DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    for r in rows:
        r["vendor_name"] = v_names.get(r["vendor_id"]) or r["vendor_id"]

    return render_page(
        request,
        "admin/messages.html",
        {"active_nav": "messages", "messages": rows, "outcome": outcome},
    )


@app.get("/admin/audit", response_class=HTMLResponse)
def admin_audit_page(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
    logs = [dict(r) for r in cursor.fetchall()]
    chain_status = verify_audit_chain(conn)
    conn.close()
    return render_page(
        request,
        "admin/audit.html",
        {"active_nav": "audit", "logs": logs, "chain_status": chain_status},
    )


@app.get("/admin/reports", response_class=HTMLResponse)
def admin_reports_page(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors ORDER BY vendor_id ASC")
    vendors = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_vendors = len(vendors)
    approved_vendors = len([v for v in vendors if v.get("status") == "approved"])
    pending_vendors = len([v for v in vendors if v.get("status") == "pending"])
    high_risk_vendors = len([v for v in vendors if (v.get("risk_score") or 0) >= 50 or v.get("risk_tier") == "High"])

    by_cat: dict[str, list[dict]] = {}
    for v in vendors:
        cat = (v.get("category") or "General").strip()
        by_cat.setdefault(cat, []).append(v)

    category_breakdown = []
    for cat, items in sorted(by_cat.items()):
        avg_r = round(sum((x.get("risk_score") or 0) for x in items) / max(1, len(items)), 1)
        app_c = len([x for x in items if x.get("status") == "approved"])
        category_breakdown.append(
            {"category": cat, "count": len(items), "approved": app_c, "avg_risk": avg_r}
        )

    return render_page(
        request,
        "admin/reports.html",
        {
            "active_nav": "reports",
            "summary": {
                "total_vendors": total_vendors,
                "approved_vendors": approved_vendors,
                "pending_vendors": pending_vendors,
                "high_risk_vendors": high_risk_vendors,
            },
            "category_breakdown": category_breakdown,
        },
    )


@app.get("/api/admin/reports/export")
def api_admin_reports_export(request: Request, format: str = "csv"):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors ORDER BY vendor_id ASC")
    vendors = [dict(r) for r in cursor.fetchall()]
    conn.close()

    export_rows = []
    for v in vendors:
        export_rows.append(
            {
                "vendor_id": v["vendor_id"],
                "name": v.get("name") or "",
                "category": v.get("category") or "",
                "state": v.get("state") or "",
                "gstin": v.get("gstin") or "",
                "pan": v.get("pan") or "",
                "bank_account_masked": mask_bank_account(v.get("bank_account")),
                "status": v.get("status") or "",
                "substate": v.get("substate") or "",
                "risk_score": v.get("risk_score") or 0,
                "risk_tier": v.get("risk_tier") or compute_risk_tier(v.get("risk_score") or 0),
            }
        )

    fmt = (format or "csv").strip().lower()
    if fmt == "json":
        return JSONResponse(
            content={"vendors": export_rows},
            headers={"Content-Disposition": 'attachment; filename="zamp_vendors_report.json"'},
        )

    buf = io.StringIO()
    fieldnames = [
        "vendor_id",
        "name",
        "category",
        "state",
        "gstin",
        "pan",
        "bank_account_masked",
        "status",
        "substate",
        "risk_score",
        "risk_tier",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(export_rows)

    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="zamp_vendors_report.csv"'},
    )


@app.get("/admin/rules", response_class=HTMLResponse)
def admin_rules_page(request: Request):
    require_admin(request)
    info = api_rules()
    return render_page(
        request,
        "admin/rules.html",
        {
            "active_nav": "rules",
            "rules": info["rules"],
            "tiers": info["tiers"],
            "decision_order": info["decision_order"],
            "name_thresholds": info["name_similarity_thresholds"],
            "watchlist": info["watchlist"],
        },
    )


@app.get("/admin/demo", response_class=HTMLResponse)
def admin_demo_page(request: Request):
    require_admin(request)
    if not SCENARIO_ASSETS:
        generate_sample_documents()
    return render_page(
        request,
        "admin/demo.html",
        {"active_nav": "demo", "scenarios": get_scenarios_list()},
    )


@app.post("/api/demo/reset")
def api_demo_reset(request: Request):
    require_admin(request)
    SESSIONS.clear()
    VENDOR_DRAFTS.clear()
    PENDING_RUNS.clear()
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()
    generate_sample_documents()
    return {"ok": True, "message": "Database reset to clean seeded state."}


# --- Admin JSON APIs ---

@app.get("/api/admin/applications")
def api_admin_applications(request: Request, status: str = "", substate: str = "", tier: str = "", q: str = ""):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications ORDER BY ts DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    out = []
    for r in rows:
        if status and r["status"] != status:
            continue
        if substate and (r["substate"] or "") != substate:
            continue
        r_tier = r["risk_tier"] or compute_risk_tier(r["risk_score"] or 0)
        if tier and r_tier.lower() != tier.lower():
            continue
        if q and q.lower() not in f"{r['id']} {r['vendor_id']} {r['data']}".lower():
            continue
        out.append({**r, "risk_tier": r_tier})
    return {"applications": out}


@app.get("/api/admin/applications/{app_id}")
def api_admin_application_detail(request: Request, app_id: str):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM applications WHERE id = ?", (app_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Application not found.")
    app_obj = dict(row)
    cursor.execute("SELECT * FROM checks WHERE application_id = ?", (app_id,))
    checks = [dict(r) for r in cursor.fetchall()]
    cursor.execute(
        "SELECT * FROM notifications WHERE vendor_id = ? AND (application_id = ? OR application_id IS NULL) ORDER BY ts DESC",
        (app_obj["vendor_id"], app_id),
    )
    notifs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"application": app_obj, "checks": checks, "notifications": notifs}


@app.get("/api/admin/vendors")
def api_admin_vendors(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors ORDER BY vendor_id ASC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    masked_list = []
    for v in rows:
        item = dict(v)
        item["bank_account"] = mask_bank_account(v.get("bank_account"))
        masked_list.append(item)
    return {"vendors": masked_list}


@app.get("/api/admin/vendors/{vendor_id}")
def api_admin_vendor_detail(request: Request, vendor_id: str):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vendor_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Vendor not found.")
    v = dict(row)
    v["bank_account"] = mask_bank_account(v.get("bank_account"))
    return {"vendor": v}


@app.get("/api/admin/vendors/{vendor_id}/orders")
def api_admin_vendor_orders(request: Request, vendor_id: str):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE vendor_id = ? ORDER BY created DESC", (vendor_id,))
    orders = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"orders": orders}


@app.get("/api/admin/vendors/{vendor_id}/performance")
def api_admin_vendor_performance(request: Request, vendor_id: str):
    require_admin(request)
    conn = get_db()
    perf = compute_vendor_performance(conn, vendor_id)
    conn.close()
    return perf


@app.get("/api/admin/messages")
def api_admin_messages(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM notifications ORDER BY ts DESC")
    msgs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"messages": msgs}


@app.get("/api/admin/audit")
def api_admin_audit(request: Request):
    require_admin(request)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
    logs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {"audit_logs": logs}


# --- Demo sample endpoints ---

@app.get("/api/demo/scenarios")
def api_demo_scenarios():
    if not SCENARIO_ASSETS:
        generate_sample_documents()
    return {"scenarios": get_scenarios_list()}


@app.get("/api/demo/sample/{scenario}/{doc_type}.png")
def api_demo_sample_png(scenario: str, doc_type: str):
    if not SCENARIO_ASSETS:
        generate_sample_documents()
    s_map = SCENARIO_ASSETS.get(scenario)
    if not s_map or not s_map.get(doc_type):
        raise HTTPException(status_code=404, detail="Sample document not found.")
    fpath = os.path.join(SAMPLE_DOCS_DIR, s_map[doc_type])
    if not os.path.exists(fpath):
        generate_sample_documents()
    return FileResponse(fpath, media_type="image/png", filename=s_map[doc_type])


@app.get("/api/demo/sample/{scenario}.zip")
def api_demo_sample_zip(scenario: str):
    if not SCENARIO_ASSETS:
        generate_sample_documents()
    if scenario not in SCENARIO_ASSETS:
        raise HTTPException(status_code=404, detail="Unknown demo scenario.")
    raw_zip = build_scenario_zip_bytes(scenario)
    return Response(
        content=raw_zip,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{scenario}_sample_docs.zip"'},
    )


# --- Vendor application draft, upload, submit, and SSE stream ---

@app.get("/api/vendor/application")
def api_get_vendor_application(request: Request):
    user = require_vendor(request)
    vid = user["vendor_id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (vid,))
    v_row = cursor.fetchone()
    cursor.execute("SELECT * FROM applications WHERE vendor_id = ? ORDER BY round DESC LIMIT 1", (vid,))
    app_row = cursor.fetchone()
    conn.close()

    draft = VENDOR_DRAFTS.get(vid, {})
    latest_sub = {}
    latest_checks = []
    if app_row:
        parsed = json.loads(app_row["data"])
        latest_sub = parsed.get("submission") or {}
        latest_checks = (parsed.get("decision") or {}).get("checks") or []

    return {
        "vendor": dict(v_row) if v_row else {},
        "draft": draft,
        "latest_submission": latest_sub,
        "latest_checks": latest_checks,
    }


@app.put("/api/vendor/application")
async def api_put_vendor_application(request: Request):
    user = require_vendor(request)
    vid = user["vendor_id"]
    body = await request.json()
    current = VENDOR_DRAFTS.get(vid, {})
    current.update(body)
    VENDOR_DRAFTS[vid] = current
    return {"ok": True, "draft": current}


@app.post("/api/vendor/application/submit")
async def api_submit_application(
    request: Request,
    vendor_name: str = Form(""),
    trading_name: str = Form(""),
    company_type: str = Form("Private Ltd"),
    registration_date: str = Form("2019-04-12"),
    email: str = Form(""),
    contact_name: str = Form(""),
    phone: str = Form(""),
    address_state: str = Form(""),
    city: str = Form(""),
    pin: str = Form(""),
    gstin: str = Form(""),
    pan: str = Form(""),
    bank_name: str = Form(""),
    bank_account: str = Form(""),
    ifsc: str = Form(""),
    account_holder: str = Form(""),
    payment_terms: str = Form("Net 30"),
    payment_method: str = Form("Bank transfer"),
    invoice_email: str = Form(""),
    category: str = Form("General"),
    description: str = Form(""),
    lead_time_days: str = Form("7"),
    reviewer_note: str = Form(""),
    target_vendor_id: str = Form(""),
    gst_cert: UploadFile | None = File(None),
    pan_card: UploadFile | None = File(None),
    cancelled_cheque: UploadFile | None = File(None),
):
    init_db()
    if not SCENARIO_ASSETS:
        generate_sample_documents()

    session_user = get_session_user(request)
    conn = get_db()
    cursor = conn.cursor()

    clean_name = (vendor_name or "").strip()
    clean_email = (email or (session_user["email"] if session_user else "") or "").strip()
    clean_gstin = (gstin or "").strip().upper()
    clean_pan = (pan or "").strip().upper()
    clean_state = (address_state or "").strip()
    clean_acct = (bank_account or "").strip()
    clean_ifsc = (ifsc or "").strip().upper()
    clean_holder = (account_holder or "").strip()
    clean_cat = (category or "General").strip() or "General"
    clean_note = (reviewer_note or "").strip()

    matched_vendor = None
    explicit_vid = (target_vendor_id or "").strip()
    if explicit_vid:
        cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (explicit_vid,))
        r = cursor.fetchone()
        if r:
            matched_vendor = dict(r)
    elif session_user and session_user.get("role") == "vendor" and session_user.get("vendor_id"):
        cursor.execute("SELECT * FROM vendors WHERE vendor_id = ?", (session_user["vendor_id"],))
        r = cursor.fetchone()
        if r:
            matched_vendor = dict(r)
            if not clean_name:
                clean_name = matched_vendor.get("name") or ""

    if not matched_vendor:
        cursor.execute(
            """
            SELECT * FROM vendors
            WHERE (email != '' AND lower(email) = lower(?))
               OR (gstin != '' AND upper(gstin) = upper(?))
               OR (pan != '' AND upper(pan) = upper(?))
            ORDER BY created_ts ASC LIMIT 1
            """,
            (clean_email, clean_gstin, clean_pan),
        )
        r = cursor.fetchone()
        if r:
            matched_vendor = dict(r)

    round_no = 1
    prior_docs: dict[str, dict] = {}
    prior_name_near_match = False

    if matched_vendor:
        vid = matched_vendor["vendor_id"]
        cursor.execute("SELECT * FROM applications WHERE vendor_id = ? ORDER BY round DESC LIMIT 1", (vid,))
        prev_app = cursor.fetchone()
        if prev_app:
            prev_data = json.loads(prev_app["data"])
            prior_docs = (prev_data.get("decision") or {}).get("merged_docs") or {}
            prior_name_near_match = bool((prev_data.get("decision") or {}).get("name_near_match_detected"))
            if matched_vendor["status"] == "pending":
                round_no = int(prev_app["round"]) + 1
            else:
                round_no = 1
    else:
        cursor.execute("SELECT vendor_id FROM vendors")
        max_num = 8
        for row in cursor.fetchall():
            v_str = row["vendor_id"]
            if v_str.startswith("V-") and v_str[2:].isdigit():
                max_num = max(max_num, int(v_str[2:]))
        vid = f"V-{max_num + 1:04d}"

    uploaded_meta: list[dict] = []
    for doc_type, upload_file in [
        ("gst_cert", gst_cert),
        ("pan_card", pan_card),
        ("cancelled_cheque", cancelled_cheque),
    ]:
        if upload_file is None or not upload_file.filename:
            continue
        content = await upload_file.read()
        fname = upload_file.filename
        ext = os.path.splitext(fname)[1].lower()
        ctype = (upload_file.content_type or "").lower()
        sha = hashlib.sha256(content).hexdigest()

        if len(content) > MAX_FILE_BYTES:
            uploaded_meta.append(
                {
                    "doc_type": doc_type,
                    "filename": fname,
                    "sha256": sha,
                    "valid_upload": False,
                    "error_detail": f"File '{fname}' exceeds 5 MB limit.",
                    "vendor_msg": f"'{fname}' is over 5 MB. Please upload a file up to 5 MB.",
                    "content": content,
                }
            )
            continue

        if ext not in ALLOWED_EXTENSIONS and ctype not in ALLOWED_MIME_TYPES:
            uploaded_meta.append(
                {
                    "doc_type": doc_type,
                    "filename": fname,
                    "sha256": sha,
                    "valid_upload": False,
                    "error_detail": f"Invalid file type '{fname}' ({ctype}).",
                    "vendor_msg": f"Unsupported file type for '{fname}'. Please upload PDF, JPG, or PNG up to 5 MB.",
                    "content": content,
                }
            )
            continue

        uploaded_meta.append(
            {
                "doc_type": doc_type,
                "filename": fname,
                "sha256": sha,
                "valid_upload": True,
                "content": content,
            }
        )

    submission = {
        "vendor_name": clean_name,
        "trading_name": trading_name.strip(),
        "company_type": company_type.strip() or "Private Ltd",
        "registration_date": registration_date.strip() or "2019-04-12",
        "email": clean_email,
        "contact": {"primary_name": contact_name.strip(), "email": clean_email, "phone": phone.strip()},
        "address": {"city": city.strip(), "state": clean_state, "pin": pin.strip(), "country": "India"},
        "address_state": clean_state,
        "gstin": clean_gstin,
        "pan": clean_pan,
        "bank_name": bank_name.strip(),
        "bank_account": clean_acct,
        "ifsc": clean_ifsc,
        "account_holder": clean_holder,
        "payment_terms": payment_terms.strip() or "Net 30",
        "payment_method": payment_method.strip() or "Bank transfer",
        "invoice_email": invoice_email.strip() or clean_email,
        "category": clean_cat,
        "description": description.strip(),
        "lead_time_days": lead_time_days.strip() or "7",
        "reviewer_note": clean_note,
    }

    run_id = f"RUN-{uuid.uuid4().hex[:10].upper()}"
    PENDING_RUNS[run_id] = {
        "run_id": run_id,
        "vendor_id": vid,
        "round_no": round_no,
        "submission": submission,
        "uploaded_meta": uploaded_meta,
        "prior_docs": prior_docs,
        "matched_vendor": matched_vendor,
        "prior_name_near_match": prior_name_near_match,
        "actor_name": session_user["display_name"] if session_user else (clean_name or "Vendor"),
        "actor_role": session_user["role"] if session_user else "vendor",
    }

    conn.close()
    return {"run_id": run_id, "vendor_id": vid, "round": round_no}


def _persist_completed_run(ctx: dict, decision: dict, stages_history: list[dict]) -> str:
    conn = get_db()
    cursor = conn.cursor()

    run_id = ctx["run_id"]
    vid = ctx["vendor_id"]
    round_no = ctx["round_no"]
    submission = ctx["submission"]
    uploaded_meta = ctx["uploaded_meta"]
    matched_vendor = ctx["matched_vendor"]

    now = time.time()
    app_id = f"A-{uuid.uuid4().hex[:6].upper()}"
    status_val = decision["status"]
    substate_val = decision["substate"]
    risk_score = int(decision["risk_score"])
    risk_tier = decision["risk_tier"]
    escalated_flag = int(decision.get("escalated") or 0)
    checks = decision.get("checks") or []
    merged_docs = decision.get("merged_docs") or {}

    app_data = {
        "run_id": run_id,
        "submission": submission,
        "stages": stages_history,
        "decision": {
            "status": status_val,
            "substate": substate_val,
            "risk_score": risk_score,
            "risk_tier": risk_tier,
            "escalated": escalated_flag,
            "reason": decision.get("reason") or "",
            "checks": checks,
            "merged_docs": merged_docs,
            "name_near_match_detected": bool(decision.get("name_near_match_detected")),
        },
    }

    cursor.execute(
        """
        INSERT INTO applications (
            id, vendor_id, round, ts, status, substate, risk_score, risk_tier, data, escalated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (app_id, vid, round_no, now, status_val, substate_val, risk_score, risk_tier, json.dumps(app_data), escalated_flag),
    )

    for chk in checks:
        cursor.execute(
            """
            INSERT INTO checks (
                id, application_id, stage, rule_id, label, status, points, detail, vendor_msg, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"CHK-{uuid.uuid4().hex[:8].upper()}",
                app_id,
                chk.get("stage") or "general",
                chk.get("rule_id") or "R0",
                chk.get("label") or "",
                chk.get("status") or "pass",
                int(chk.get("points") or 0),
                chk.get("detail") or "",
                chk.get("vendor_msg"),
                chk.get("recommendation"),
            ),
        )

    for doc in uploaded_meta:
        dt = doc["doc_type"]
        readable_label = "Read" if doc.get("valid_upload") and dt in merged_docs else ("Needs manual check" if doc.get("valid_upload") else "Couldn't read")
        cursor.execute(
            """
            INSERT INTO documents (
                id, vendor_id, application_id, doc_type, filename, sha256,
                extraction, readable_status, content, uploaded_ts, expiry_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"DOC-{uuid.uuid4().hex[:8].upper()}",
                vid,
                app_id,
                dt,
                doc["filename"],
                doc["sha256"],
                json.dumps(merged_docs.get(dt) or {}),
                readable_label,
                doc.get("content") or b"",
                now,
                None,
            ),
        )

    from_status = matched_vendor["status"] if matched_vendor else None

    if matched_vendor:
        if matched_vendor["status"] == "approved":
            cursor.execute(
                "UPDATE vendors SET risk_score = ?, risk_tier = ?, updated_ts = ? WHERE vendor_id = ?",
                (risk_score, risk_tier, now, vid),
            )
        else:
            cursor.execute(
                """
                UPDATE vendors
                SET name = ?, trading_name = ?, email = ?, gstin = ?, pan = ?,
                    company_type = ?, registration_date = ?, address = ?, state = ?,
                    contact = ?, bank_name = ?, bank_account = ?, ifsc = ?,
                    account_holder = ?, payment_terms = ?, payment_method = ?,
                    invoice_email = ?, category = ?, description = ?,
                    status = ?, substate = ?, risk_score = ?, risk_tier = ?,
                    escalated = ?, updated_ts = ?
                WHERE vendor_id = ?
                """,
                (
                    submission["vendor_name"] or matched_vendor["name"],
                    submission["trading_name"] or matched_vendor["trading_name"],
                    submission["email"] or matched_vendor["email"],
                    submission["gstin"] or matched_vendor["gstin"],
                    submission["pan"] or matched_vendor["pan"],
                    submission["company_type"],
                    submission["registration_date"],
                    json.dumps(submission["address"]),
                    submission["address_state"] or matched_vendor["state"],
                    json.dumps(submission["contact"]),
                    submission["bank_name"],
                    submission["bank_account"],
                    submission["ifsc"],
                    submission["account_holder"],
                    submission["payment_terms"],
                    submission["payment_method"],
                    submission["invoice_email"],
                    submission["category"],
                    submission["description"],
                    status_val,
                    substate_val,
                    risk_score,
                    risk_tier,
                    escalated_flag,
                    now,
                    vid,
                ),
            )
    else:
        cursor.execute(
            """
            INSERT INTO vendors (
                vendor_id, name, trading_name, email, gstin, pan, company_type,
                registration_date, address, state, contact, bank_name, bank_account,
                ifsc, account_holder, payment_terms, payment_method, invoice_email,
                category, description, employees, annual_revenue, on_portal_since,
                status, substate, risk_score, risk_tier, escalated, created_ts, updated_ts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 25, 15000000, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vid,
                submission["vendor_name"],
                submission["trading_name"],
                submission["email"],
                submission["gstin"],
                submission["pan"],
                submission["company_type"],
                submission["registration_date"],
                json.dumps(submission["address"]),
                submission["address_state"],
                json.dumps(submission["contact"]),
                submission["bank_name"],
                submission["bank_account"],
                submission["ifsc"],
                submission["account_holder"],
                submission["payment_terms"],
                submission["payment_method"],
                submission["invoice_email"],
                submission["category"],
                submission["description"],
                time.strftime("%Y-%m-%d"),
                status_val,
                substate_val,
                risk_score,
                risk_tier,
                escalated_flag,
                now,
                now,
            ),
        )

    for st in stages_history:
        st_name = st.get("stage") or "stage"
        st_checks = st.get("checks") or []
        flagged = [c for c in st_checks if c.get("status") != "pass"]
        summary = (
            "; ".join([f"{c['rule_id']} {c['label']} -> {c['status']} (+{c.get('points', 0)} pts)" for c in flagged])
            if flagged
            else f"Stage {st_name} completed with all checks passing."
        )
        add_audit_log(
            conn,
            vid,
            app_id,
            f"rules:{st_name}",
            "system",
            "RULE_STAGE",
            st_name,
            from_status,
            status_val,
            summary,
        )

    add_audit_log(
        conn,
        vid,
        app_id,
        "rules:decision",
        "system",
        "DECISION",
        "application",
        from_status,
        status_val,
        f"Round {round_no}: risk_score={risk_score} ({risk_tier}). {decision.get('reason') or ''}",
    )

    v_display = submission["vendor_name"] or vid
    to_addr = submission["email"] or (matched_vendor["email"] if matched_vendor else "vendor@example.com")

    record_notification(
        conn,
        vid,
        app_id,
        to_addr,
        f"Submission received — Application {app_id} (Round {round_no})",
        f"Hello {v_display},\n\nWe have received your onboarding submission (Reference: {vid}, Application: {app_id}, Round {round_no}) and run our automated compliance checks.",
        "received",
        [],
        actor="rules:intake",
        role="system",
    )

    flagged_ids = [c["id"] for c in checks if c.get("status") in {"fix", "review", "fail"}]
    if status_val == "approved":
        subj = f"Approved — Zamp.ai Vendor Onboarding ({vid})"
        body = f"Hello {v_display},\n\nCongratulations! Your onboarding application ({app_id}) has been approved."
        outcome = "approved"
    elif status_val == "rejected":
        subj = f"Application update — Zamp.ai Vendor Onboarding ({vid})"
        r7_fail = next((c for c in checks if c.get("rule_id") == "R7" and c.get("status") == "fail"), None)
        r12_fail = next((c for c in checks if c.get("rule_id") == "R12" and c.get("status") == "fail"), None)
        if r12_fail:
            reason_msg = "We're unable to onboard your company at this time."
        elif r7_fail:
            reason_msg = "Your uploaded GST certificate and PAN card show conflicting tax identity details."
        else:
            reason_msg = "We're unable to onboard your company at this time."
        body = f"Hello {v_display},\n\n{reason_msg}\n\nYou can view your application status at /vendor/application/status."
        outcome = "rejected"
    elif substate_val == "awaiting_vendor":
        subj = f"Action needed: items to fix — Application {app_id}"
        fix_msgs = [c["vendor_msg"] for c in checks if c.get("status") == "fix" and c.get("vendor_msg")]
        item_lines = "\n".join([f"• {m}" for m in fix_msgs]) if fix_msgs else "• Please review your submitted information."
        body = (
            f"Hello {v_display},\n\n"
            f"Your application ({app_id}) needs a few updates before we can proceed:\n{item_lines}\n\n"
            f"Update and resubmit at /vendor/application"
        )
        outcome = "awaiting_vendor"
    else:
        subj = f"Application under review — Application {app_id}"
        body = (
            f"Hello {v_display},\n\n"
            f"Your application ({app_id}) is currently under review by our team.\n"
            f"Track progress at /vendor/application/status"
        )
        outcome = "awaiting_review"

    record_notification(
        conn,
        vid,
        app_id,
        to_addr,
        subj,
        body,
        outcome,
        flagged_ids,
        actor="rules:decision",
        role="system",
    )

    conn.commit()
    conn.close()
    return app_id


def _sanitize_vendor_check(chk: dict) -> dict:
    return {
        "id": chk.get("id"),
        "stage": chk.get("stage"),
        "rule_id": chk.get("rule_id"),
        "label": chk.get("label"),
        "status": chk.get("status"),
        "vendor_msg": chk.get("vendor_msg"),
    }


@app.get("/api/stream/{run_id}")
def api_stream_run(run_id: str, view: str = "full"):
    ctx = PENDING_RUNS.get(run_id)
    if not ctx:
        raise HTTPException(status_code=404, detail="Run not found or already streamed.")

    def event_generator():
        stages_history: list[dict] = []
        final_decision: dict | None = None

        for ev in stream_pipeline_stages(
            submission=ctx["submission"],
            uploaded_docs=ctx["uploaded_meta"],
            prior_docs=ctx["prior_docs"],
            matched_vendor=ctx["matched_vendor"],
            round_no=ctx["round_no"],
            prior_name_near_match=ctx["prior_name_near_match"],
            delay_seconds=0.35,
        ):
            ev_type = ev.get("type")
            stage_name = ev.get("stage")
            if ev_type == "start":
                if view == "vendor":
                    payload = {"type": "start", "stage": stage_name, "label": ev.get("vendor_label")}
                else:
                    payload = {"type": "start", "stage": stage_name}
                yield f"data: {json.dumps(payload)}\n\n"
            elif ev_type == "stage":
                checks_list = ev.get("checks") or []
                stages_history.append({"stage": stage_name, "checks": checks_list})
                if ev.get("decision"):
                    final_decision = ev["decision"]
                if view == "vendor":
                    safe_checks = [_sanitize_vendor_check(c) for c in checks_list]
                    payload = {"type": "stage", "stage": stage_name, "label": ev.get("vendor_label"), "checks": safe_checks}
                else:
                    payload = {"type": "stage", "stage": stage_name, "checks": checks_list}
                yield f"data: {json.dumps(payload)}\n\n"

        if final_decision is None:
            final_decision = {
                "status": "pending",
                "substate": "awaiting_review",
                "risk_score": 20,
                "risk_tier": "Medium",
                "escalated": 0,
                "reason": "Completed pipeline evaluation.",
                "checks": [],
                "merged_docs": {},
                "name_near_match_detected": False,
            }

        app_id = _persist_completed_run(ctx, final_decision, stages_history)
        PENDING_RUNS.pop(run_id, None)

        if view == "vendor":
            fix_list = [
                {
                    "id": c["id"],
                    "label": c["label"],
                    "vendor_msg": c.get("vendor_msg") or "Please review and update this item.",
                }
                for c in (final_decision.get("checks") or [])
                if c.get("status") == "fix"
            ]
            done_payload = {
                "type": "done",
                "run_id": run_id,
                "application_id": app_id,
                "vendor_id": ctx["vendor_id"],
                "round": ctx["round_no"],
                "status": final_decision["status"],
                "substate": final_decision["substate"],
                "fix_items": fix_list,
                "decision": {
                    "status": final_decision["status"],
                    "substate": final_decision["substate"],
                    "fix_items": fix_list,
                },
            }
        else:
            done_payload = {
                "type": "done",
                "run_id": run_id,
                "application_id": app_id,
                "vendor_id": ctx["vendor_id"],
                "round": ctx["round_no"],
                "decision": final_decision,
            }
        yield f"data: {json.dumps(done_payload)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/rules")
def api_rules():
    return {
        "rules": RULES_CATALOG,
        "tiers": [
            {"tier": "Low", "min": 0, "max": 19},
            {"tier": "Medium", "min": 20, "max": 49},
            {"tier": "High", "min": 50, "max": 100},
        ],
        "decision_order": [
            "1. Any check with status 'fail' -> rejected",
            "2. Else any check with status 'fix' -> pending / awaiting_vendor",
            "3. Else any check with status 'review' -> pending / awaiting_review",
            "4. Else -> approved",
        ],
        "name_similarity_thresholds": {
            "pass_min": 0.92,
            "near_match_min": 0.75,
            "drop_words": ["pvt", "private", "ltd", "limited", "llp", "co", "company", "inc"],
        },
        "watchlist": ["Global Shell Trading FZE"],
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("app:app", host="0.0.0.0", port=port)