import os
import io
import zipfile
import hashlib
from datetime import datetime, timedelta, timezone
from PIL import Image, ImageDraw, ImageFont

SAMPLE_DOCS_DIR = "sample_docs"
SAMPLE_DOC_REGISTRY: dict[str, dict] = {}
SCENARIO_ASSETS: dict[str, dict[str, str]] = {}


def _load_fonts():
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "arial.ttf",
    ]
    title_font = None
    body_font = None
    for path in candidates:
        if os.path.exists(path):
            try:
                title_font = ImageFont.truetype(path, 22)
                body_font = ImageFont.truetype(path, 15)
                break
            except Exception:
                continue
    if title_font is None:
        title_font = ImageFont.load_default()
    if body_font is None:
        body_font = ImageFont.load_default()
    return title_font, body_font


def _build_card_png(filename: str, doc_type: str, title: str, lines: list[str], fields: dict, readable: bool = True, blurry: bool = False) -> str:
    os.makedirs(SAMPLE_DOCS_DIR, exist_ok=True)
    path = os.path.join(SAMPLE_DOCS_DIR, filename)
    bg_color = (250, 251, 253) if not blurry else (196, 198, 202)
    fg_color = (24, 29, 43) if not blurry else (152, 154, 158)
    border_color = (75, 63, 209) if not blurry else (140, 140, 140)

    img = Image.new("RGB", (820, 500), color=bg_color)
    draw = ImageDraw.Draw(img)
    title_font, body_font = _load_fonts()

    draw.rectangle([20, 20, 800, 480], outline=border_color, width=2)
    draw.rectangle([20, 20, 800, 74], fill=border_color)
    draw.text((40, 38), title, fill=(255, 255, 255), font=title_font)

    y = 104
    for line in lines:
        draw.text((42, y), line, fill=fg_color, font=body_font)
        y += 36

    if blurry:
        tiny = img.resize((150, 90))
        img = tiny.resize((820, 500))

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    raw = buf.getvalue()
    with open(path, "wb") as f:
        f.write(raw)

    sha = hashlib.sha256(raw).hexdigest()
    SAMPLE_DOC_REGISTRY[sha] = {
        "doc_type": doc_type,
        "fields": fields,
        "readable": readable,
        "filename": filename,
    }
    return filename


def generate_sample_documents() -> None:
    SAMPLE_DOC_REGISTRY.clear()
    SCENARIO_ASSETS.clear()
    os.makedirs(SAMPLE_DOCS_DIR, exist_ok=True)

    today = datetime.now(timezone.utc).date()
    recent_reg_date = (today - timedelta(days=60)).isoformat()

    # 1. Nova Fabrics
    SCENARIO_ASSETS["nova"] = {
        "gst_cert": _build_card_png(
            "nova_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Nova Fabrics Pvt Ltd",
                "GSTIN: 07AABCN2345K1Z6",
                "State: Delhi",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Nova Fabrics Pvt Ltd", "gstin": "07AABCN2345K1Z6", "state": "Delhi", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "nova_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Nova Fabrics Pvt Ltd",
                "PAN: AABCN2345K",
            ],
            {"name": "Nova Fabrics Pvt Ltd", "pan": "AABCN2345K"},
        ),
        "cancelled_cheque": _build_card_png(
            "nova_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Nova Fabrics Pvt Ltd",
                "Account No: 009876543210",
                "IFSC: HDFC0005678",
            ],
            {"account_holder": "Nova Fabrics Pvt Ltd", "account_no": "009876543210", "ifsc": "HDFC0005678"},
        ),
    }

    # 2. Sharma Traders (cheque holder near-match: Sharma Trading Co)
    SCENARIO_ASSETS["sharma"] = {
        "gst_cert": _build_card_png(
            "sharma_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Sharma Traders Pvt Ltd",
                "GSTIN: 24AABCS4321Q1Z8",
                "State: Gujarat",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Sharma Traders Pvt Ltd", "gstin": "24AABCS4321Q1Z8", "state": "Gujarat", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "sharma_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Sharma Traders Pvt Ltd",
                "PAN: AABCS4321Q",
            ],
            {"name": "Sharma Traders Pvt Ltd", "pan": "AABCS4321Q"},
        ),
        "cancelled_cheque": _build_card_png(
            "sharma_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Sharma Trading Co",
                "Account No: 112233445566",
                "IFSC: SBIN0001122",
            ],
            {"account_holder": "Sharma Trading Co", "account_no": "112233445566", "ifsc": "SBIN0001122"},
        ),
    }

    # 3. Meridian Logistics (3a: docs match GSTIN 27AABCS9999M1Z3 while typed PAN is BBBCS5678M -> R6 fix)
    SCENARIO_ASSETS["meridian"] = {
        "gst_cert": _build_card_png(
            "meridian_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Meridian Logistics LLP",
                "GSTIN: 27AABCS9999M1Z3",
                "State: Maharashtra",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Meridian Logistics LLP", "gstin": "27AABCS9999M1Z3", "state": "Maharashtra", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "meridian_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Meridian Logistics LLP",
                "PAN: AABCS9999M",
            ],
            {"name": "Meridian Logistics LLP", "pan": "AABCS9999M"},
        ),
        "cancelled_cheque": _build_card_png(
            "meridian_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Meridian Logistics LLP",
                "Account No: 778899001122",
                "IFSC: ICIC0002233",
            ],
            {"account_holder": "Meridian Logistics LLP", "account_no": "778899001122", "ifsc": "ICIC0002233"},
        ),
    }

    # 3b. Variant 3b: GST cert and PAN card contradict each other (R7 fail)
    SCENARIO_ASSETS["meridian_3b"] = {
        "gst_cert": _build_card_png(
            "meridian_3b_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Meridian Logistics LLP",
                "GSTIN: 27AABCS9999M1Z3",
                "State: Maharashtra",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Meridian Logistics LLP", "gstin": "27AABCS9999M1Z3", "state": "Maharashtra", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "meridian_3b_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Meridian Logistics LLP",
                "PAN: BBBCS5678M",
            ],
            {"name": "Meridian Logistics LLP", "pan": "BBBCS5678M"},
        ),
        "cancelled_cheque": _build_card_png(
            "meridian_3b_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Meridian Logistics LLP",
                "Account No: 778899001122",
                "IFSC: ICIC0002233",
            ],
            {"account_holder": "Meridian Logistics LLP", "account_no": "778899001122", "ifsc": "ICIC0002233"},
        ),
    }

    # 4. Apex Components re-application (new bank account)
    SCENARIO_ASSETS["apex_change"] = {
        "gst_cert": _build_card_png(
            "apex_change_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Apex Components Pvt Ltd",
                "GSTIN: 07AAACA1111A1Z2",
                "State: Delhi",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Apex Components Pvt Ltd", "gstin": "07AAACA1111A1Z2", "state": "Delhi", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "apex_change_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Apex Components Pvt Ltd",
                "PAN: AAACA1111A",
            ],
            {"name": "Apex Components Pvt Ltd", "pan": "AAACA1111A"},
        ),
        "cancelled_cheque": _build_card_png(
            "apex_change_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Apex Components Pvt Ltd",
                "Account No: 60200998877665",
                "IFSC: ICIC0004321",
            ],
            {"account_holder": "Apex Components Pvt Ltd", "account_no": "60200998877665", "ifsc": "ICIC0004321"},
        ),
    }

    # 5. Kiran Packaging
    SCENARIO_ASSETS["kiran"] = {
        "gst_cert": _build_card_png(
            "kiran_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Kiran Packaging Pvt Ltd",
                "GSTIN: 29AABCK7777L1Z1",
                "State: Karnataka",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Kiran Packaging Pvt Ltd", "gstin": "29AABCK7777L1Z1", "state": "Karnataka", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "kiran_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Kiran Packaging Pvt Ltd",
                "PAN: AABCK7777L",
            ],
            {"name": "Kiran Packaging Pvt Ltd", "pan": "AABCK7777L"},
        ),
        "cancelled_cheque": _build_card_png(
            "kiran_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Kiran Packaging Pvt Ltd",
                "Account No: 445566778899",
                "IFSC: KKBK0000456",
            ],
            {"account_holder": "Kiran Packaging Pvt Ltd", "account_no": "445566778899", "ifsc": "KKBK0000456"},
        ),
    }

    # 6. Global Shell Trading FZE (sanctions hit)
    SCENARIO_ASSETS["global_shell"] = {
        "gst_cert": _build_card_png(
            "shell_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Global Shell Trading FZE",
                "GSTIN: 07AABCG1234H1Z4",
                "State: Delhi",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Global Shell Trading FZE", "gstin": "07AABCG1234H1Z4", "state": "Delhi", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "shell_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Global Shell Trading FZE",
                "PAN: AABCG1234H",
            ],
            {"name": "Global Shell Trading FZE", "pan": "AABCG1234H"},
        ),
        "cancelled_cheque": _build_card_png(
            "shell_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Global Shell Trading FZE",
                "Account No: 998877665544",
                "IFSC: YESB0000123",
            ],
            {"account_holder": "Global Shell Trading FZE", "account_no": "998877665544", "ifsc": "YESB0000123"},
        ),
    }

    # 7. Orbit Metals (blurry cheque initially, clear cheque on retry)
    SCENARIO_ASSETS["orbit"] = {
        "gst_cert": _build_card_png(
            "orbit_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Orbit Metals Pvt Ltd",
                "GSTIN: 07AABCO1234L1Z5",
                "State: Delhi",
                "Date of Registration: 2019-04-12",
            ],
            {"legal_name": "Orbit Metals Pvt Ltd", "gstin": "07AABCO1234L1Z5", "state": "Delhi", "registration_date": "2019-04-12"},
        ),
        "pan_card": _build_card_png(
            "orbit_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Orbit Metals Pvt Ltd",
                "PAN: AABCO1234L",
            ],
            {"name": "Orbit Metals Pvt Ltd", "pan": "AABCO1234L"},
        ),
        "cancelled_cheque": _build_card_png(
            "orbit_cheque_blurry.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Orbit Metals Pvt Ltd",
                "Account No: 889900112233",
                "IFSC: HDFC0009988",
            ],
            {"account_holder": "Orbit Metals Pvt Ltd", "account_no": "889900112233", "ifsc": "HDFC0009988"},
            readable=False,
            blurry=True,
        ),
        "clear_cheque": _build_card_png(
            "orbit_cheque_clear.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Orbit Metals Pvt Ltd",
                "Account No: 889900112233",
                "IFSC: HDFC0009988",
            ],
            {"account_holder": "Orbit Metals Pvt Ltd", "account_no": "889900112233", "ifsc": "HDFC0009988"},
            readable=True,
            blurry=False,
        ),
    }

    # 8. Brightline Tech (registered ~60 days ago)
    SCENARIO_ASSETS["brightline"] = {
        "gst_cert": _build_card_png(
            "brightline_gst.png",
            "gst_cert",
            "GST REGISTRATION CERTIFICATE",
            [
                "Legal Name of Business: Brightline Tech Pvt Ltd",
                "GSTIN: 29AABCB5555D1Z9",
                "State: Karnataka",
                f"Date of Registration: {recent_reg_date}",
            ],
            {"legal_name": "Brightline Tech Pvt Ltd", "gstin": "29AABCB5555D1Z9", "state": "Karnataka", "registration_date": recent_reg_date},
        ),
        "pan_card": _build_card_png(
            "brightline_pan.png",
            "pan_card",
            "PERMANENT ACCOUNT NUMBER CARD",
            [
                "Name: Brightline Tech Pvt Ltd",
                "PAN: AABCB5555D",
            ],
            {"name": "Brightline Tech Pvt Ltd", "pan": "AABCB5555D"},
        ),
        "cancelled_cheque": _build_card_png(
            "brightline_cheque.png",
            "cancelled_cheque",
            "CANCELLED CHEQUE",
            [
                "Account Holder: Brightline Tech Pvt Ltd",
                "Account No: 223344556677",
                "IFSC: KKBK0000789",
            ],
            {"account_holder": "Brightline Tech Pvt Ltd", "account_no": "223344556677", "ifsc": "KKBK0000789"},
        ),
    }


def build_scenario_zip_bytes(scenario: str) -> bytes:
    if not SCENARIO_ASSETS:
        generate_sample_documents()
    asset_map = SCENARIO_ASSETS.get(scenario)
    if not asset_map:
        return b""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for doc_type, fname in asset_map.items():
            fpath = os.path.join(SAMPLE_DOCS_DIR, fname)
            if os.path.exists(fpath):
                zf.write(fpath, arcname=f"{doc_type}_{fname}")
    return buf.getvalue()


def get_scenarios_list() -> list[dict]:
    today = datetime.now(timezone.utc).date()
    recent_reg_date = (today - timedelta(days=60)).isoformat()
    return [
        {
            "key": "nova",
            "label": "1. Nova Fabrics (Approved)",
            "vendor_name": "Nova Fabrics Pvt Ltd",
            "trading_name": "Nova Weaves",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "email": "ap@novafabrics.in",
            "contact_name": "Rohan Gupta",
            "phone": "+91 98100 11223",
            "state": "Delhi",
            "city": "New Delhi",
            "pin": "110001",
            "gstin": "07AABCN2345K1Z6",
            "pan": "AABCN2345K",
            "bank_name": "HDFC Bank",
            "bank_account": "009876543210",
            "ifsc": "HDFC0005678",
            "account_holder": "Nova Fabrics Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "invoices@novafabrics.in",
            "category": "Textiles",
            "description": "Industrial textiles and woven technical fabrics.",
            "lead_time_days": 8,
            "docs": {"gst_cert": "nova_gst.png", "pan_card": "nova_pan.png", "cancelled_cheque": "nova_cheque.png"},
        },
        {
            "key": "sharma",
            "label": "2. Sharma Traders (Name fix -> review)",
            "vendor_name": "Sharma Traders Pvt Ltd",
            "trading_name": "Sharma Trading",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "email": "sharma@traders.in",
            "contact_name": "Deepak Sharma",
            "phone": "+91 98251 22334",
            "state": "Gujarat",
            "city": "Ahmedabad",
            "pin": "380001",
            "gstin": "24AABCS4321Q1Z8",
            "pan": "AABCS4321Q",
            "bank_name": "State Bank of India",
            "bank_account": "112233445566",
            "ifsc": "SBIN0001122",
            "account_holder": "Sharma Trading Co",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "billing@sharmatraders.in",
            "category": "Raw metals",
            "description": "Commercial steel and alloy trading.",
            "lead_time_days": 10,
            "docs": {"gst_cert": "sharma_gst.png", "pan_card": "sharma_pan.png", "cancelled_cheque": "sharma_cheque.png"},
        },
        {
            "key": "meridian",
            "label": "3. Meridian Logistics (GST/PAN typo -> fix)",
            "vendor_name": "Meridian Logistics LLP",
            "trading_name": "Meridian Transit",
            "company_type": "LLP",
            "registration_date": "2019-04-12",
            "email": "contact@meridian.com",
            "contact_name": "Nikhil Joshi",
            "phone": "+91 98200 55667",
            "state": "Maharashtra",
            "city": "Mumbai",
            "pin": "400001",
            "gstin": "27AABCS9999M1Z3",
            "pan": "BBBCS5678M",
            "bank_name": "ICICI Bank",
            "bank_account": "778899001122",
            "ifsc": "ICIC0002233",
            "account_holder": "Meridian Logistics LLP",
            "payment_terms": "Net 45",
            "payment_method": "Bank transfer",
            "invoice_email": "ap@meridian.com",
            "category": "Logistics",
            "description": "National supply chain and warehousing.",
            "lead_time_days": 5,
            "docs": {"gst_cert": "meridian_gst.png", "pan_card": "meridian_pan.png", "cancelled_cheque": "meridian_cheque.png"},
        },
        {
            "key": "apex_change",
            "label": "4. Apex Components (Bank change -> review)",
            "vendor_name": "Apex Components Pvt Ltd",
            "trading_name": "Apex Precision",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "email": "apex@demo.in",
            "contact_name": "Vikram Sethi",
            "phone": "+91 98111 22334",
            "state": "Delhi",
            "city": "New Delhi",
            "pin": "110020",
            "gstin": "07AAACA1111A1Z2",
            "pan": "AAACA1111A",
            "bank_name": "ICICI Bank",
            "bank_account": "60200998877665",
            "ifsc": "ICIC0004321",
            "account_holder": "Apex Components Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "billing@apex.in",
            "category": "Industrial components",
            "description": "Precision components and machined assemblies.",
            "lead_time_days": 7,
            "docs": {"gst_cert": "apex_change_gst.png", "pan_card": "apex_change_pan.png", "cancelled_cheque": "apex_change_cheque.png"},
        },
        {
            "key": "kiran",
            "label": "5. Kiran Packaging (Missing cheque -> fix)",
            "vendor_name": "Kiran Packaging Pvt Ltd",
            "trading_name": "Kiran Pack",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "email": "ops@kiranpack.in",
            "contact_name": "Kiran Rao",
            "phone": "+91 98451 99887",
            "state": "Karnataka",
            "city": "Bengaluru",
            "pin": "560001",
            "gstin": "29AABCK7777L1Z1",
            "pan": "AABCK7777L",
            "bank_name": "Kotak Mahindra Bank",
            "bank_account": "445566778899",
            "ifsc": "KKBK0000456",
            "account_holder": "Kiran Packaging Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "accounts@kiranpack.in",
            "category": "Packaging",
            "description": "Protective cartons and industrial packaging.",
            "lead_time_days": 9,
            "docs": {"gst_cert": "kiran_gst.png", "pan_card": "kiran_pan.png", "cancelled_cheque": None},
        },
        {
            "key": "global_shell",
            "label": "6. Global Shell Trading (Rejected)",
            "vendor_name": "Global Shell Trading FZE",
            "trading_name": "Global Shell",
            "company_type": "Other",
            "registration_date": "2019-04-12",
            "email": "shell@fze.com",
            "contact_name": "Alex Vance",
            "phone": "+91 99000 11122",
            "state": "Delhi",
            "city": "New Delhi",
            "pin": "110002",
            "gstin": "07AABCG1234H1Z4",
            "pan": "AABCG1234H",
            "bank_name": "Yes Bank",
            "bank_account": "998877665544",
            "ifsc": "YESB0000123",
            "account_holder": "Global Shell Trading FZE",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "finance@shellfze.com",
            "category": "General",
            "description": "General trading supplier.",
            "lead_time_days": 14,
            "docs": {"gst_cert": "shell_gst.png", "pan_card": "shell_pan.png", "cancelled_cheque": "shell_cheque.png"},
        },
        {
            "key": "orbit",
            "label": "7. Orbit Metals (Blurry cheque -> fix)",
            "vendor_name": "Orbit Metals Pvt Ltd",
            "trading_name": "Orbit Alloys",
            "company_type": "Private Ltd",
            "registration_date": "2019-04-12",
            "email": "ops@orbit.in",
            "contact_name": "Ananya Verma",
            "phone": "+91 98118 44332",
            "state": "Delhi",
            "city": "New Delhi",
            "pin": "110019",
            "gstin": "07AABCO1234L1Z5",
            "pan": "AABCO1234L",
            "bank_name": "HDFC Bank",
            "bank_account": "889900112233",
            "ifsc": "HDFC0009988",
            "account_holder": "Orbit Metals Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "billing@orbit.in",
            "category": "Raw metals",
            "description": "Non-ferrous metal ingots and strips.",
            "lead_time_days": 8,
            "docs": {"gst_cert": "orbit_gst.png", "pan_card": "orbit_pan.png", "cancelled_cheque": "orbit_cheque_blurry.png"},
        },
        {
            "key": "brightline",
            "label": "8. Brightline Tech (New entity -> review)",
            "vendor_name": "Brightline Tech Pvt Ltd",
            "trading_name": "Brightline",
            "company_type": "Private Ltd",
            "registration_date": recent_reg_date,
            "email": "hello@brightline.in",
            "contact_name": "Siddharth Rao",
            "phone": "+91 98801 77665",
            "state": "Karnataka",
            "city": "Bengaluru",
            "pin": "560102",
            "gstin": "29AABCB5555D1Z9",
            "pan": "AABCB5555D",
            "bank_name": "Kotak Mahindra Bank",
            "bank_account": "223344556677",
            "ifsc": "KKBK0000789",
            "account_holder": "Brightline Tech Pvt Ltd",
            "payment_terms": "Net 30",
            "payment_method": "Bank transfer",
            "invoice_email": "accounts@brightline.in",
            "category": "Electronics",
            "description": "Embedded controllers and industrial telemetry.",
            "lead_time_days": 12,
            "docs": {"gst_cert": "brightline_gst.png", "pan_card": "brightline_pan.png", "cancelled_cheque": "brightline_cheque.png"},
        },
    ]