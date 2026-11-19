import os
import json
import time
import random
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = os.environ.get("DB_PATH", "zamp_portal.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def add_audit_log(
    conn: sqlite3.Connection,
    vendor_id: str | None,
    application_id: str | None,
    actor: str,
    role: str,
    action: str,
    target: str,
    from_status: str | None,
    to_status: str | None,
    remark: str,
) -> dict:
    cursor = conn.cursor()
    cursor.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    prev_hash = row["hash"] if row and row["hash"] else "GENESIS"

    ts = datetime.now(timezone.utc).isoformat()
    clean_remark = (remark or "").strip() or "System action recorded"

    entry_without_hash = {
        "vendor_id": vendor_id,
        "application_id": application_id,
        "ts": ts,
        "actor": actor,
        "role": role,
        "action": action,
        "target": target,
        "from_status": from_status,
        "to_status": to_status,
        "remark": clean_remark,
        "prev_hash": prev_hash,
    }
    digest = hashlib.sha256(
        (prev_hash + canonical_json(entry_without_hash)).encode("utf-8")
    ).hexdigest()

    cursor.execute(
        """
        INSERT INTO audit_logs (
            vendor_id, application_id, ts, actor, role, action, target,
            from_status, to_status, remark, prev_hash, hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            vendor_id,
            application_id,
            ts,
            actor,
            role,
            action,
            target,
            from_status,
            to_status,
            clean_remark,
            prev_hash,
            digest,
        ),
    )
    entry_without_hash["hash"] = digest
    return entry_without_hash


def verify_audit_chain(conn: sqlite3.Connection) -> dict:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY id ASC")
    rows = cursor.fetchall()
    expected_prev = "GENESIS"
    for row in rows:
        item = dict(row)
        actual_prev = item.get("prev_hash") or "GENESIS"
        if actual_prev != expected_prev:
            return {"ok": False, "broken_at": item["id"], "count": len(rows)}
        entry_without_hash = {
            "vendor_id": item["vendor_id"],
            "application_id": item["application_id"],
            "ts": item["ts"],
            "actor": item["actor"],
            "role": item["role"],
            "action": item["action"],
            "target": item["target"],
            "from_status": item["from_status"],
            "to_status": item["to_status"],
            "remark": item["remark"],
            "prev_hash": actual_prev,
        }
        computed = hashlib.sha256(
            (actual_prev + canonical_json(entry_without_hash)).encode("utf-8")
        ).hexdigest()
        if computed != item["hash"]:
            return {"ok": False, "broken_at": item["id"], "count": len(rows)}
        expected_prev = item["hash"]
    return {"ok": True, "broken_at": None, "count": len(rows)}


def compute_risk_tier(score: int) -> str:
    if score <= 19:
        return "Low"
    if score <= 49:
        return "Medium"
    return "High"


def mask_bank_account(acct: str | None) -> str:
    if not acct:
        return "—"
    s = str(acct).strip()
    if len(s) <= 4:
        return "••••"
    return ("•" * (len(s) - 4)) + s[-4:]


def init_db() -> None:
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT NOT NULL,
            vendor_id TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS vendors (
            vendor_id TEXT PRIMARY KEY,
            name TEXT,
            trading_name TEXT,
            email TEXT,
            gstin TEXT,
            pan TEXT,
            company_type TEXT,
            registration_date TEXT,
            address TEXT,
            state TEXT,
            contact TEXT,
            bank_name TEXT,
            bank_account TEXT,
            ifsc TEXT,
            account_holder TEXT,
            payment_terms TEXT,
            payment_method TEXT,
            invoice_email TEXT,
            category TEXT,
            description TEXT,
            employees INTEGER,
            annual_revenue INTEGER,
            on_portal_since TEXT,
            status TEXT,
            substate TEXT,
            risk_score INTEGER,
            risk_tier TEXT,
            escalated INTEGER DEFAULT 0,
            created_ts REAL,
            updated_ts REAL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS applications (
            id TEXT PRIMARY KEY,
            vendor_id TEXT NOT NULL,
            round INTEGER NOT NULL,
            ts REAL NOT NULL,
            status TEXT NOT NULL,
            substate TEXT,
            risk_score INTEGER DEFAULT 0,
            risk_tier TEXT DEFAULT 'Low',
            data TEXT NOT NULL,
            escalated INTEGER DEFAULT 0
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS checks (
            id TEXT PRIMARY KEY,
            application_id TEXT NOT NULL,
            stage TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            label TEXT NOT NULL,
            status TEXT NOT NULL,
            points INTEGER DEFAULT 0,
            detail TEXT,
            vendor_msg TEXT,
            recommendation TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            vendor_id TEXT NOT NULL,
            application_id TEXT,
            doc_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            extraction TEXT,
            readable_status TEXT NOT NULL,
            content BLOB,
            uploaded_ts REAL NOT NULL,
            expiry_date TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            vendor_id TEXT NOT NULL,
            application_id TEXT,
            ts REAL NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            outcome TEXT NOT NULL,
            check_ids TEXT,
            delivery TEXT DEFAULT 'simulated',
            read INTEGER DEFAULT 0
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id TEXT PRIMARY KEY,
            vendor_id TEXT NOT NULL,
            created TEXT NOT NULL,
            expected_delivery TEXT NOT NULL,
            delivered_date TEXT,
            status TEXT NOT NULL,
            total_inr INTEGER NOT NULL,
            defect INTEGER DEFAULT 0,
            t_confirm_days REAL DEFAULT 1.0,
            t_ship_days REAL DEFAULT 3.0,
            t_invoice_days REAL DEFAULT 1.5
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT,
            application_id TEXT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            role TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            remark TEXT NOT NULL,
            prev_hash TEXT,
            hash TEXT
        )
        """
    )

    cursor.execute("SELECT COUNT(*) AS cnt FROM users")
    if cursor.fetchone()["cnt"] == 0:
        seed_all(conn)

    conn.commit()
    conn.close()


def seed_all(conn: sqlite3.Connection) -> None:
    now = time.time()
    today = datetime.now(timezone.utc).date()
    cursor = conn.cursor()

    add_audit_log(
        conn,
        None,
        None,
        "system-seed",
        "system",
        "INIT",
        "ledger",
        None,
        None,
        "Initialized Zamp.ai tamper-evident audit ledger",
    )

    # Seed Admin + Vendor users
    users = [
        ("U-ADM-1", "ravi@zamp.demo", "analyst123", "analyst", "Ravi Menon", None),
        ("U-ADM-2", "anita@zamp.demo", "compliance123", "compliance", "Anita Rao", None),
        ("U-VND-1", "apex@demo.in", "vendor123", "vendor", "Apex Components", "V-0001"),
        ("U-VND-2", "zenith@demo.in", "vendor123", "vendor", "Zenith Packaging", "V-0002"),
    ]
    cursor.executemany(
        "INSERT INTO users (id, email, password, role, display_name, vendor_id) VALUES (?, ?, ?, ?, ?, ?)",
        users,
    )

    # 8 approved vendors with realistic profiles & varied performance profiles
    vendor_specs = [
        {
            "vendor_id": "V-0001",
            "name": "Apex Components Pvt Ltd",
            "trading_name": "Apex Precision",
            "email": "apex@demo.in",
            "gstin": "07AAACA1111A1Z2",
            "pan": "AAACA1111A",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "address": {"street": "Plot 44, Okhla Phase II", "city": "New Delhi", "state": "Delhi", "pin": "110020", "country": "India"},
            "state": "Delhi",
            "contact": {"primary_name": "Vikram Sethi", "designation": "VP Operations", "email": "apex@demo.in", "phone": "+91 98111 22334"},
            "bank_name": "HDFC Bank",
            "bank_account": "50100123456789",
            "ifsc": "HDFC0001234",
            "account_holder": "Apex Components Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "billing@apex.in",
            "category": "Industrial components",
            "description": "CNC machined fasteners, assemblies, and precision industrial hardware.",
            "employees": 145,
            "annual_revenue": 84000000,
            "on_portal_since": "2023-03-15",
            "risk_score": 0,
            "risk_tier": "Low",
            "perf_profile": "excellent",
            "order_count": 34,
        },
        {
            "vendor_id": "V-0002",
            "name": "Zenith Packaging Pvt Ltd",
            "trading_name": "Zenith Pack",
            "email": "zenith@demo.in",
            "gstin": "27AAACZ2222B1Z5",
            "pan": "AAACZ2222B",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "address": {"street": "12 MIDC Industrial Area", "city": "Pune", "state": "Maharashtra", "pin": "411019", "country": "India"},
            "state": "Maharashtra",
            "contact": {"primary_name": "Meera Nair", "designation": "Key Account Manager", "email": "zenith@demo.in", "phone": "+91 98220 44556"},
            "bank_name": "ICICI Bank",
            "bank_account": "00040511223344",
            "ifsc": "ICIC0000004",
            "account_holder": "Zenith Packaging Pvt Ltd",
            "payment_terms": "Net 45",
            "payment_method": "Bank transfer",
            "invoice_email": "accounts@zenithpack.in",
            "category": "Packaging",
            "description": "Corrugated cartons, export-grade pallet wraps, and molded inserts.",
            "employees": 92,
            "annual_revenue": 52000000,
            "on_portal_since": "2023-07-01",
            "risk_score": 0,
            "risk_tier": "Low",
            "perf_profile": "good",
            "order_count": 28,
        },
        {
            "vendor_id": "V-0003",
            "name": "Kaveri Logistics LLP",
            "trading_name": "Kaveri Freight",
            "email": "ops@kaverilogistics.in",
            "gstin": "29AAACK3333C1Z8",
            "pan": "AAACK3333C",
            "company_type": "LLP",
            "registration_date": "2019-04-12",
            "address": {"street": "88 Peenya 2nd Stage", "city": "Bengaluru", "state": "Karnataka", "pin": "560058", "country": "India"},
            "state": "Karnataka",
            "contact": {"primary_name": "Suresh Gowda", "designation": "Fleet Director", "email": "ops@kaverilogistics.in", "phone": "+91 98450 77889"},
            "bank_name": "State Bank of India",
            "bank_account": "30987654321098",
            "ifsc": "SBIN0004321",
            "account_holder": "Kaveri Logistics LLP",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "invoices@kaverilogistics.in",
            "category": "Logistics",
            "description": "Inter-state cold chain and linehaul surface freight services.",
            "employees": 210,
            "annual_revenue": 115000000,
            "on_portal_since": "2023-09-10",
            "risk_score": 15,
            "risk_tier": "Low",
            "perf_profile": "mediocre",
            "order_count": 32,
        },
        {
            "vendor_id": "V-0004",
            "name": "Haryana Metals & Alloys Ltd",
            "trading_name": "HMA Steel",
            "email": "sales@hmasteel.in",
            "gstin": "06AAACH4444D1Z1",
            "pan": "AAACH4444D",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "address": {"street": "Sector 24 Faridabad", "city": "Faridabad", "state": "Haryana", "pin": "121005", "country": "India"},
            "state": "Haryana",
            "contact": {"primary_name": "Rajesh Jindal", "designation": "Managing Partner", "email": "sales@hmasteel.in", "phone": "+91 98102 66778"},
            "bank_name": "Axis Bank",
            "bank_account": "91802003344556",
            "ifsc": "UTIB0000123",
            "account_holder": "Haryana Metals & Alloys Ltd",
            "payment_terms": "Net 60",
            "payment_method": "Bank transfer",
            "invoice_email": "billing@hmasteel.in",
            "category": "Raw metals",
            "description": "Cold-rolled steel sheets, aluminium extrusions, and brass billets.",
            "employees": 180,
            "annual_revenue": 160000000,
            "on_portal_since": "2024-01-12",
            "risk_score": 0,
            "risk_tier": "Low",
            "perf_profile": "excellent",
            "order_count": 26,
        },
        {
            "vendor_id": "V-0005",
            "name": "Surya Electronics Pvt Ltd",
            "trading_name": "Surya Circuits",
            "email": "orders@suryaelec.in",
            "gstin": "33AAACS5555E1Z4",
            "pan": "AAACS5555E",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "address": {"street": "Guindy Industrial Estate", "city": "Chennai", "state": "Tamil Nadu", "pin": "600032", "country": "India"},
            "state": "Tamil Nadu",
            "contact": {"primary_name": "Karthik Subramanian", "designation": "Head of Sales", "email": "orders@suryaelec.in", "phone": "+91 98401 33445"},
            "bank_name": "Kotak Mahindra Bank",
            "bank_account": "74125896301234",
            "ifsc": "KKBK0000462",
            "account_holder": "Surya Electronics Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "ap@suryaelec.in",
            "category": "Electronics",
            "description": "PCB assemblies, industrial sensors, and harness wiring.",
            "employees": 115,
            "annual_revenue": 73000000,
            "on_portal_since": "2024-02-20",
            "risk_score": 20,
            "risk_tier": "Medium",
            "perf_profile": "low_compliance",
            "order_count": 24,
        },
        {
            "vendor_id": "V-0006",
            "name": "Sabarmati Textiles Ltd",
            "trading_name": "Sabarmati Weaves",
            "email": "supply@sabarmatitex.in",
            "gstin": "24AAACS6666F1Z7",
            "pan": "AAACS6666F",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "address": {"street": "Naroda GIDC Phase I", "city": "Ahmedabad", "state": "Gujarat", "pin": "382330", "country": "India"},
            "state": "Gujarat",
            "contact": {"primary_name": "Neha Shah", "designation": "Export Lead", "email": "supply@sabarmatitex.in", "phone": "+91 98250 11992"},
            "bank_name": "HDFC Bank",
            "bank_account": "50200991122334",
            "ifsc": "HDFC0000567",
            "account_holder": "Sabarmati Textiles Ltd",
            "payment_terms": "Net 45",
            "payment_method": "Bank transfer",
            "invoice_email": "finance@sabarmatitex.in",
            "category": "Textiles",
            "description": "Technical fabrics, industrial canvas, and protective workwear.",
            "employees": 260,
            "annual_revenue": 140000000,
            "on_portal_since": "2023-11-05",
            "risk_score": 0,
            "risk_tier": "Low",
            "perf_profile": "good",
            "order_count": 30,
        },
        {
            "vendor_id": "V-0007",
            "name": "Gomti Office Supplies Co",
            "trading_name": "Gomti Workplace",
            "email": "desk@gomtisupplies.in",
            "gstin": "09AAACG7777G1Z9",
            "pan": "AAACG7777G",
            "company_type": "Partnership",
            "registration_date": "2019-04-12",
            "address": {"street": "19 Vibhuti Khand", "city": "Lucknow", "state": "Uttar Pradesh", "pin": "226010", "country": "India"},
            "state": "Uttar Pradesh",
            "contact": {"primary_name": "Alok Srivastava", "designation": "Partner", "email": "desk@gomtisupplies.in", "phone": "+91 94150 88776"},
            "bank_name": "Bank of Baroda",
            "bank_account": "29010200011223",
            "ifsc": "BARB0GOMTIX",
            "account_holder": "Gomti Office Supplies Co",
            "payment_terms": "Net 30",
            "payment_method": "UPI",
            "invoice_email": "billing@gomtisupplies.in",
            "category": "Office supplies",
            "description": "Ergonomic furniture, stationery, and facility consumables.",
            "employees": 42,
            "annual_revenue": 24000000,
            "on_portal_since": "2024-04-01",
            "risk_score": 0,
            "risk_tier": "Low",
            "perf_profile": "good",
            "order_count": 22,
        },
        {
            "vendor_id": "V-0008",
            "name": "Indraprastha Print & Label Pvt Ltd",
            "trading_name": "IP Print",
            "email": "print@ipprint.in",
            "gstin": "07AAACI8888H1Z2",
            "pan": "AAACI8888H",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "address": {"street": "B-14 Naraina Industrial Area", "city": "New Delhi", "state": "Delhi", "pin": "110028", "country": "India"},
            "state": "Delhi",
            "contact": {"primary_name": "Pooja Malhotra", "designation": "Client Servicing", "email": "print@ipprint.in", "phone": "+91 98114 55667"},
            "bank_name": "Yes Bank",
            "bank_account": "001483700001234",
            "ifsc": "YESB0000014",
            "account_holder": "Indraprastha Print & Label Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "accounts@ipprint.in",
            "category": "Printing",
            "description": "Barcode labels, security holograms, and compliance manuals.",
            "employees": 68,
            "annual_revenue": 39000000,
            "on_portal_since": "2024-05-18",
            "risk_score": 0,
            "risk_tier": "Low",
            "perf_profile": "excellent",
            "order_count": 25,
        },
    ]

    rng = random.Random(42)
    order_seq = 1001

    for idx, v in enumerate(vendor_specs):
        vid = v["vendor_id"]
        cursor.execute(
            """
            INSERT INTO vendors (
                vendor_id, name, trading_name, email, gstin, pan, company_type,
                registration_date, address, state, contact, bank_name, bank_account,
                ifsc, account_holder, payment_terms, payment_method, invoice_email,
                category, description, employees, annual_revenue, on_portal_since,
                status, substate, risk_score, risk_tier, escalated, created_ts, updated_ts
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', NULL, ?, ?, 0, ?, ?)
            """,
            (
                vid,
                v["name"],
                v["trading_name"],
                v["email"],
                v["gstin"],
                v["pan"],
                v["company_type"],
                v["registration_date"],
                json.dumps(v["address"]),
                v["state"],
                json.dumps(v["contact"]),
                v["bank_name"],
                v["bank_account"],
                v["ifsc"],
                v["account_holder"],
                v["payment_terms"],
                v["payment_method"],
                v["invoice_email"],
                v["category"],
                v["description"],
                v["employees"],
                v["annual_revenue"],
                v["on_portal_since"],
                v["risk_score"],
                v["risk_tier"],
                now - (8 - idx) * 86400 * 15,
                now - (8 - idx) * 86400 * 5,
            ),
        )

        # Seed compliance documents (with expiry dates so compliance rate is computed cleanly)
        future_exp = (today + timedelta(days=365)).isoformat()
        past_exp = (today - timedelta(days=20)).isoformat()
        doc_types = [
            ("gst_cert", "gst_registration.pdf", future_exp),
            ("pan_card", "pan_card.pdf", future_exp),
            ("cancelled_cheque", "cancelled_cheque.png", future_exp),
            ("insurance_cert", "liability_insurance.pdf", past_exp if v["perf_profile"] == "low_compliance" else future_exp),
            ("safety_cert", "iso_compliance.pdf", past_exp if v["perf_profile"] == "low_compliance" else future_exp),
        ]
        for d_idx, (dt, fname, exp_dt) in enumerate(doc_types):
            cursor.execute(
                """
                INSERT INTO documents (
                    id, vendor_id, application_id, doc_type, filename, sha256,
                    extraction, readable_status, content, uploaded_ts, expiry_date
                ) VALUES (?, ?, NULL, ?, ?, ?, ?, 'Read', ?, ?, ?)
                """,
                (
                    f"DOC-{vid}-{d_idx+1}",
                    vid,
                    dt,
                    fname,
                    hashlib.sha256(f"{vid}:{dt}".encode()).hexdigest(),
                    json.dumps({"verified": True}),
                    b"",
                    now - 86400 * 30,
                    exp_dt,
                ),
            )

        # Seed 22-34 historical orders spread over past 350 days
        prof = v["perf_profile"]
        n_orders = v["order_count"]
        for o_i in range(n_orders):
            oid = f"PO-{order_seq}"
            order_seq += 1
            days_ago = int((o_i / n_orders) * 340) + rng.randint(1, 10)
            created_dt = today - timedelta(days=days_ago)
            lead_target = rng.choice([7, 10, 14])
            expected_dt = created_dt + timedelta(days=lead_target)

            if o_i < 2:
                # 2 recent open orders
                status = "Processing" if o_i == 0 else "Ready to ship"
                delivered_str = None
                defect = 0
            elif o_i == 2 and prof == "mediocre":
                status = "Delayed"
                delivered_str = None
                defect = 0
            elif o_i == n_orders - 1 and prof in {"mediocre", "low_compliance"}:
                status = "Cancelled"
                delivered_str = None
                defect = 0
            else:
                status = "Delivered"
                if prof == "excellent":
                    delay = rng.choice([-2, -1, 0, 0, 0, 1]) if rng.random() < 0.08 else rng.choice([-2, -1, 0])
                    defect = 1 if rng.random() < 0.03 else 0
                elif prof == "good":
                    delay = rng.choice([1, 2]) if rng.random() < 0.16 else rng.choice([-1, 0, 0])
                    defect = 1 if rng.random() < 0.07 else 0
                elif prof == "mediocre":
                    delay = rng.choice([2, 4, 6]) if rng.random() < 0.42 else rng.choice([0, 1])
                    defect = 1 if rng.random() < 0.18 else 0
                else:
                    delay = rng.choice([1, 3]) if rng.random() < 0.22 else 0
                    defect = 1 if rng.random() < 0.10 else 0

                deliv_dt = expected_dt + timedelta(days=delay)
                if deliv_dt > today:
                    deliv_dt = today
                delivered_str = deliv_dt.isoformat()

            total_inr = rng.randint(45000, 480000)
            t_confirm = round(rng.uniform(0.5, 2.2), 1)
            t_ship = round(rng.uniform(2.0, 6.5), 1)
            t_inv = round(rng.uniform(0.5, 3.0), 1)

            cursor.execute(
                """
                INSERT INTO orders (
                    id, vendor_id, created, expected_delivery, delivered_date,
                    status, total_inr, defect, t_confirm_days, t_ship_days, t_invoice_days
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    oid,
                    vid,
                    created_dt.isoformat(),
                    expected_dt.isoformat(),
                    delivered_str,
                    status,
                    total_inr,
                    defect,
                    t_confirm,
                    t_ship,
                    t_inv,
                ),
            )

        # Seed a baseline approved application & welcome notification
        app_id = f"A-{idx+1:04d}"
        seed_app_data = {
            "submission": {
                "vendor_name": v["name"],
                "trading_name": v["trading_name"],
                "company_type": v["company_type"],
                "registration_date": v["registration_date"],
                "email": v["email"],
                "state": v["state"],
                "address": v["address"],
                "contact": v["contact"],
                "gstin": v["gstin"],
                "pan": v["pan"],
                "bank_name": v["bank_name"],
                "bank_account": v["bank_account"],
                "ifsc": v["ifsc"],
                "account_holder": v["account_holder"],
                "payment_terms": v["payment_terms"],
                "payment_method": v["payment_method"],
                "invoice_email": v["invoice_email"],
                "category": v["category"],
                "description": v["description"],
            },
            "decision": {
                "status": "approved",
                "substate": None,
                "risk_score": v["risk_score"],
                "risk_tier": v["risk_tier"],
                "reason": "Approved automatically: all onboarding checks passed.",
            },
        }
        cursor.execute(
            """
            INSERT INTO applications (
                id, vendor_id, round, ts, status, substate, risk_score, risk_tier, data, escalated
            ) VALUES (?, ?, 1, ?, 'approved', NULL, ?, ?, ?, 0)
            """,
            (
                app_id,
                vid,
                now - (8 - idx) * 86400 * 14,
                v["risk_score"],
                v["risk_tier"],
                json.dumps(seed_app_data),
            ),
        )

        cursor.execute(
            """
            INSERT INTO notifications (
                id, vendor_id, application_id, ts, subject, body, outcome, check_ids, delivery, read
            ) VALUES (?, ?, ?, ?, ?, ?, 'approved', '[]', 'simulated', 1)
            """,
            (
                f"NTF-SEED-{idx+1}",
                vid,
                app_id,
                now - (8 - idx) * 86400 * 14,
                f"Welcome to Zamp.ai Vendor Portal — {v['name']}",
                f"Hello {v['name']},\n\nYour onboarding application ({app_id}) is approved. You can now receive purchase orders and track performance on Zamp.ai.",
            ),
        )

        add_audit_log(
            conn,
            vid,
            app_id,
            "system-seed",
            "system",
            "SEED_VENDOR",
            "vendor",
            None,
            "approved",
            f"Seeded approved supplier {v['name']} ({vid}) with {n_orders} historical orders",
        )

    conn.commit()


def compute_vendor_performance(conn: sqlite3.Connection, vendor_id: str) -> dict:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE vendor_id = ? ORDER BY created DESC", (vendor_id,))
    orders = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT expiry_date FROM documents WHERE vendor_id = ?", (vendor_id,))
    docs = [dict(r) for r in cursor.fetchall()]

    today = datetime.now(timezone.utc).date()
    cutoff_90 = today - timedelta(days=90)
    cutoff_180 = today - timedelta(days=180)

    def calc_window(order_list: list[dict]) -> dict:
        total = len(order_list)
        delivered = [o for o in order_list if o["status"] == "Delivered" and o["delivered_date"]]
        delayed = [o for o in order_list if o["status"] == "Delayed"]
        cancelled = [o for o in order_list if o["status"] == "Cancelled"]

        closed_deals = len(delivered)
        on_time_count = 0
        perfect_count = 0
        defect_count = 0
        lead_days_list = []

        for o in delivered:
            c_dt = datetime.strptime(o["created"], "%Y-%m-%d").date()
            e_dt = datetime.strptime(o["expected_delivery"], "%Y-%m-%d").date()
            d_dt = datetime.strptime(o["delivered_date"], "%Y-%m-%d").date()
            is_on_time = d_dt <= e_dt
            has_defect = int(o.get("defect") or 0) == 1
            if is_on_time:
                on_time_count += 1
            if has_defect:
                defect_count += 1
            if is_on_time and not has_defect:
                perfect_count += 1
            lead_days_list.append(max(1, (d_dt - c_dt).days))

        perfect_rate = round((perfect_count / closed_deals) * 100, 1) if closed_deals else 100.0
        defect_rate = round((defect_count / closed_deals) * 100, 1) if closed_deals else 0.0
        backorder_rate = round((len(delayed) / total) * 100, 1) if total else 0.0
        availability = round(((total - len(cancelled)) / total) * 100, 1) if total else 100.0
        on_time_rate = round((on_time_count / closed_deals) * 100, 1) if closed_deals else 100.0
        avg_lead = round(sum(lead_days_list) / len(lead_days_list), 1) if lead_days_list else 0.0

        return {
            "total_orders": total,
            "closed_deals": closed_deals,
            "perfect_order_rate": perfect_rate,
            "defect_rate": defect_rate,
            "back_order_rate": backorder_rate,
            "supplier_availability": availability,
            "on_time_shipping": on_time_rate,
            "avg_lead_time": avg_lead,
        }

    overall = calc_window(orders)

    recent_orders = [
        o for o in orders if datetime.strptime(o["created"], "%Y-%m-%d").date() >= cutoff_90
    ]
    prev_orders = [
        o
        for o in orders
        if cutoff_180 <= datetime.strptime(o["created"], "%Y-%m-%d").date() < cutoff_90
    ]
    recent_m = calc_window(recent_orders)
    prev_m = calc_window(prev_orders) if prev_orders else recent_m

    valid_docs = 0
    for d in docs:
        exp = d.get("expiry_date")
        if not exp:
            valid_docs += 1
        else:
            try:
                if datetime.strptime(exp, "%Y-%m-%d").date() >= today:
                    valid_docs += 1
            except Exception:
                valid_docs += 1
    compliance_rate = round((valid_docs / len(docs)) * 100, 1) if docs else 100.0

    def trend_dir(curr: float, prev: float, lower_is_better: bool = False) -> str:
        if abs(curr - prev) < 0.2:
            return "flat"
        improved = (curr < prev) if lower_is_better else (curr > prev)
        return "up" if improved else "down"

    avg_confirm = round(sum(o["t_confirm_days"] for o in orders) / len(orders), 1) if orders else 1.0
    avg_ship = round(sum(o["t_ship_days"] for o in orders) / len(orders), 1) if orders else 3.0
    avg_inv = round(sum(o["t_invoice_days"] for o in orders) / len(orders), 1) if orders else 1.5

    return {
        "metrics": {
            "closed_deals": {"value": overall["closed_deals"], "unit": "", "trend": trend_dir(recent_m["closed_deals"], prev_m["closed_deals"])},
            "perfect_order_rate": {"value": overall["perfect_order_rate"], "unit": "%", "trend": trend_dir(recent_m["perfect_order_rate"], prev_m["perfect_order_rate"])},
            "defect_rate": {"value": overall["defect_rate"], "unit": "%", "trend": trend_dir(recent_m["defect_rate"], prev_m["defect_rate"], lower_is_better=True)},
            "back_order_rate": {"value": overall["back_order_rate"], "unit": "%", "trend": trend_dir(recent_m["back_order_rate"], prev_m["back_order_rate"], lower_is_better=True)},
            "supplier_availability": {"value": overall["supplier_availability"], "unit": "%", "trend": trend_dir(recent_m["supplier_availability"], prev_m["supplier_availability"])},
            "on_time_shipping": {"value": overall["on_time_shipping"], "unit": "%", "trend": trend_dir(recent_m["on_time_shipping"], prev_m["on_time_shipping"])},
            "avg_lead_time": {"value": overall["avg_lead_time"], "unit": " days", "trend": trend_dir(recent_m["avg_lead_time"], prev_m["avg_lead_time"], lower_is_better=True)},
            "avg_compliance_rate": {"value": compliance_rate, "unit": "%", "trend": "up" if compliance_rate >= 90 else "down"},
        },
        "cycle_days": {
            "placement_to_confirm": avg_confirm,
            "confirm_to_ship": avg_ship,
            "ship_to_invoice": avg_inv,
            "total": round(avg_confirm + avg_ship + avg_inv, 1),
        },
        "recent_deals": [o for o in orders if o["status"] == "Delivered"][:5],
        "open_orders": [o for o in orders if o["status"] in {"Processing", "Ready to ship", "Delayed"}][:6],
    }