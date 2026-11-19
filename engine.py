import re
import time
import difflib
from datetime import datetime, timezone

from db import get_db, compute_risk_tier
from samples import SAMPLE_DOC_REGISTRY

GSTIN_REGEX = r"^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$"
PAN_REGEX = r"^[A-Z]{5}\d{4}[A-Z]$"
IFSC_REGEX = r"^[A-Z]{4}0[A-Z0-9]{6}$"
BANK_ACCT_REGEX = r"^[0-9]{6,22}$"

STATE_CODE_MAP = {
    "07": "Delhi",
    "06": "Haryana",
    "09": "Uttar Pradesh",
    "24": "Gujarat",
    "27": "Maharashtra",
    "29": "Karnataka",
    "33": "Tamil Nadu",
}

SANCTIONS_WATCHLIST = ["global shell trading fze"]

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
ALLOWED_MIME_TYPES = {"application/pdf", "image/png", "image/jpeg"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB

# Single source of truth for rules displayed on /admin/rules and executed by the engine
RULES_CATALOG = [
    {"id": "R1", "name": "Required fields", "what_it_checks": "Checks that required company, contact, tax, and banking fields are non-empty.", "default_status": "fix", "points": 10, "cap_note": "10 each (cap 30)"},
    {"id": "R2", "name": "Required documents", "what_it_checks": "Checks that GST certificate, PAN card, and cancelled cheque are uploaded or carried over.", "default_status": "fix", "points": 10, "cap_note": "10 each (cap 30)"},
    {"id": "R3", "name": "Document legibility", "what_it_checks": "Flags known unreadable/blurry scans so the vendor can re-upload a clear copy.", "default_status": "fix", "points": 10, "cap_note": "10 per unreadable file"},
    {"id": "R4", "name": "Document not auto-readable", "what_it_checks": "Unrecognised files in this demo build are never faked as passed; routed for manual check.", "default_status": "review", "points": 15, "cap_note": "15 per unrecognised file"},
    {"id": "R5", "name": "Format: GSTIN / PAN / IFSC / bank account", "what_it_checks": "Validates standard format and length for GSTIN, PAN, IFSC, and bank account number.", "default_status": "fix", "points": 10, "cap_note": "10 per invalid field"},
    {"id": "R6", "name": "GSTIN contains PAN (form)", "what_it_checks": "Checks whether characters [2:12] of submitted GSTIN match typed PAN; treats mismatch as a likely typo.", "default_status": "fix", "points": 10, "cap_note": "10"},
    {"id": "R7", "name": "Document identity consistency", "what_it_checks": "Hard stop if GST certificate's embedded PAN contradicts the uploaded PAN card's PAN.", "default_status": "fail", "points": 40, "cap_note": "40"},
    {"id": "R8", "name": "GST state vs address state", "what_it_checks": "Verifies that the GSTIN state code matches the vendor's registered state.", "default_status": "fix", "points": 10, "cap_note": "10"},
    {"id": "R9", "name": "Documents match the form", "what_it_checks": "Compares extracted GSTIN, PAN, bank account, and IFSC against submitted form values.", "default_status": "fix", "points": 10, "cap_note": "10 per mismatch"},
    {"id": "R10", "name": "Name consistency", "what_it_checks": "Compares normalized legal name against each readable document (>=0.92 pass; 0.75-0.92 round 1 fix, note -> review; <0.75 fix in rounds 1-2, review in round 3+).", "default_status": "fix / review", "points": 10, "cap_note": "10 (fix) or 20 (review)"},
    {"id": "R11", "name": "Documents contradict each other on name", "what_it_checks": "Flags when GST registration legal name and PAN card name have similarity below 0.75.", "default_status": "review", "points": 25, "cap_note": "25"},
    {"id": "R12", "name": "Sanctions / watchlist", "what_it_checks": "Screens legal name and account holder against the restricted watchlist.", "default_status": "fail", "points": 100, "cap_note": "100"},
    {"id": "R13", "name": "Bank details changed for existing vendor", "what_it_checks": "Flags bank account changes on an existing vendor for out-of-band verification.", "default_status": "review", "points": 25, "cap_note": "25"},
    {"id": "R14", "name": "Bank account shared with different vendor", "what_it_checks": "Flags when a bank account is already associated with another vendor record.", "default_status": "review", "points": 30, "cap_note": "30"},
    {"id": "R15", "name": "Newly registered entity", "what_it_checks": "Flags entities whose GST registration date is less than 180 days ago.", "default_status": "review", "points": 15, "cap_note": "15"},
    {"id": "R16", "name": "Repeated failed rounds", "what_it_checks": "Marks application as escalated if round >= 3 and fix items remain open.", "default_status": "escalate", "points": 15, "cap_note": "15 (flag)"},
]


def normalize_name(name: str) -> str:
    lower = (name or "").lower()
    cleaned = re.sub(r"[^\w\s]", " ", lower)
    drop_words = {"pvt", "private", "ltd", "limited", "llp", "co", "company", "inc"}
    tokens = [w for w in cleaned.split() if w not in drop_words]
    return " ".join(tokens)


def name_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, normalize_name(a), normalize_name(b)).ratio()


def _make_check(
    check_id: str,
    stage: str,
    rule_id: str,
    label: str,
    status: str,
    points: int,
    detail: str,
    vendor_msg: str | None = None,
    recommendation: str | None = None,
) -> dict:
    return {
        "id": check_id,
        "stage": stage,
        "rule_id": rule_id,
        "label": label,
        "status": status,
        "points": points,
        "detail": detail,
        "vendor_msg": vendor_msg,
        "recommendation": recommendation,
    }


def stream_pipeline_stages(
    submission: dict,
    uploaded_docs: list[dict],
    prior_docs: dict[str, dict],
    matched_vendor: dict | None,
    round_no: int,
    prior_name_near_match: bool = False,
    delay_seconds: float = 0.55,
):
    all_checks: list[dict] = []
    merged_docs: dict[str, dict] = {k: dict(v) for k, v in (prior_docs or {}).items()}
    doc_auto_read: dict[str, bool] = {}

    # Stage 1: Intake
    yield {"type": "start", "stage": "intake", "vendor_label": "Receiving your submission"}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    intake_checks: list[dict] = []
    required_fields = [
        ("vendor_name", "Legal name"),
        ("email", "Email address"),
        ("address_state", "State"),
        ("gstin", "GSTIN"),
        ("pan", "PAN"),
        ("bank_account", "Bank account number"),
        ("ifsc", "IFSC code"),
        ("account_holder", "Account holder name"),
    ]
    missing_field_pts = 0
    for key, label in required_fields:
        val = (submission.get(key) or "").strip()
        if not val:
            pts = 10 if missing_field_pts < 30 else 0
            missing_field_pts += 10
            intake_checks.append(
                _make_check(
                    f"intake_{key}",
                    "intake",
                    "R1",
                    f"Required field: {label}",
                    "fix",
                    pts,
                    f"Field '{key}' was left empty.",
                    f"Please enter your {label.lower()}.",
                    "Confirm vendor fills all required fields.",
                )
            )
        else:
            intake_checks.append(
                _make_check(
                    f"intake_{key}",
                    "intake",
                    "R1",
                    f"Required field: {label}",
                    "pass",
                    0,
                    f"Field '{key}' provided.",
                )
            )

    uploaded_valid_types = {d["doc_type"] for d in uploaded_docs if d.get("valid_upload")}
    missing_doc_pts = 0
    for dt in ["gst_cert", "pan_card", "cancelled_cheque"]:
        nice_dt = dt.replace("_", " ")
        if dt in uploaded_valid_types:
            intake_checks.append(
                _make_check(
                    f"intake_doc_{dt}",
                    "intake",
                    "R2",
                    f"Document: {nice_dt}",
                    "pass",
                    0,
                    f"Uploaded {nice_dt} in round {round_no}.",
                )
            )
        elif dt in merged_docs:
            intake_checks.append(
                _make_check(
                    f"intake_doc_{dt}",
                    "intake",
                    "R2",
                    f"Document: {nice_dt}",
                    "pass",
                    0,
                    f"Reused prior {nice_dt} from earlier round.",
                )
            )
        else:
            pts = 10 if missing_doc_pts < 30 else 0
            missing_doc_pts += 10
            intake_checks.append(
                _make_check(
                    f"intake_doc_{dt}",
                    "intake",
                    "R2",
                    f"Document: {nice_dt}",
                    "fix",
                    pts,
                    f"Missing required document '{nice_dt}'.",
                    f"Please upload your {nice_dt} (PDF, JPG, or PNG up to 5 MB).",
                    "Wait for vendor to upload the missing document.",
                )
            )

    all_checks.extend(intake_checks)
    yield {"type": "stage", "stage": "intake", "vendor_label": "Receiving your submission", "checks": intake_checks}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    # Stage 2: Document reading
    yield {"type": "start", "stage": "reading", "vendor_label": "Reading your documents"}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    reading_checks: list[dict] = []
    for doc in uploaded_docs:
        dt = doc["doc_type"]
        nice_dt = dt.replace("_", " ")
        fname = doc.get("filename") or nice_dt

        if not doc.get("valid_upload"):
            doc_auto_read[dt] = False
            reading_checks.append(
                _make_check(
                    f"read_bad_file_{dt}",
                    "reading",
                    "R3",
                    f"Upload check: {fname}",
                    "fix",
                    10,
                    doc.get("error_detail") or f"Invalid file '{fname}'.",
                    doc.get("vendor_msg") or "Please upload a PDF, JPG, or PNG file up to 5 MB.",
                    "Vendor must upload a valid file type under 5 MB.",
                )
            )
            continue

        sha = doc["sha256"]
        if sha in SAMPLE_DOC_REGISTRY:
            entry = SAMPLE_DOC_REGISTRY[sha]
            if entry.get("readable"):
                merged_docs[dt] = dict(entry.get("fields") or {})
                doc_auto_read[dt] = True
                reading_checks.append(
                    _make_check(
                        f"read_ok_{dt}",
                        "reading",
                        "R3",
                        f"Read {nice_dt}",
                        "pass",
                        0,
                        f"Extracted fields from {fname}: {entry.get('fields')}",
                    )
                )
            else:
                merged_docs.pop(dt, None)
                doc_auto_read[dt] = False
                msg = (
                    "We couldn't read your cancelled cheque. Please upload a clearer, well-lit photo or PDF."
                    if dt == "cancelled_cheque"
                    else f"We couldn't read your {nice_dt}. Please upload a clearer, well-lit photo or PDF."
                )
                reading_checks.append(
                    _make_check(
                        f"read_unreadable_{dt}",
                        "reading",
                        "R3",
                        f"Read {nice_dt}",
                        "fix",
                        10,
                        f"Unreadable document scan in '{fname}'.",
                        msg,
                        "Open the document and verify its fields manually.",
                    )
                )
        else:
            doc_auto_read[dt] = False
            reading_checks.append(
                _make_check(
                    f"read_unknown_{dt}",
                    "reading",
                    "R4",
                    f"Read {nice_dt}",
                    "review",
                    15,
                    f"Unrecognised file '{fname}' ({sha[:10]}...); auto-read skipped in demo build.",
                    None,
                    "Open the document and verify its fields manually.",
                )
            )

    all_checks.extend(reading_checks)
    yield {"type": "stage", "stage": "reading", "vendor_label": "Reading your documents", "checks": reading_checks}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    # Stage 3: Format
    yield {"type": "start", "stage": "format", "vendor_label": "Checking your details"}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    format_checks: list[dict] = []
    gstin = (submission.get("gstin") or "").strip().upper()
    pan = (submission.get("pan") or "").strip().upper()
    ifsc = (submission.get("ifsc") or "").strip().upper()
    bank_acct = (submission.get("bank_account") or "").strip()

    if gstin and re.match(GSTIN_REGEX, gstin):
        format_checks.append(_make_check("fmt_gstin", "format", "R5", "GSTIN format", "pass", 0, f"GSTIN '{gstin}' matches format."))
    else:
        format_checks.append(
            _make_check(
                "fmt_gstin",
                "format",
                "R5",
                "GSTIN format",
                "fix",
                10,
                f"GSTIN '{gstin}' failed format check (length {len(gstin)}).",
                f"GSTIN must be 15 characters, you entered {len(gstin)}.",
                "Ask vendor to enter a valid 15-character GSTIN.",
            )
        )

    if pan and re.match(PAN_REGEX, pan):
        format_checks.append(_make_check("fmt_pan", "format", "R5", "PAN format", "pass", 0, f"PAN '{pan}' matches format."))
    else:
        format_checks.append(
            _make_check(
                "fmt_pan",
                "format",
                "R5",
                "PAN format",
                "fix",
                10,
                f"PAN '{pan}' failed format check (length {len(pan)}).",
                f"PAN must be 10 characters, you entered {len(pan)}.",
                "Ask vendor to enter a valid 10-character PAN.",
            )
        )

    if ifsc and re.match(IFSC_REGEX, ifsc):
        format_checks.append(_make_check("fmt_ifsc", "format", "R5", "IFSC format", "pass", 0, f"IFSC '{ifsc}' matches format."))
    else:
        format_checks.append(
            _make_check(
                "fmt_ifsc",
                "format",
                "R5",
                "IFSC format",
                "fix",
                10,
                f"IFSC '{ifsc}' failed format check (length {len(ifsc)}).",
                f"IFSC must be 11 characters, you entered {len(ifsc)}.",
                "Ask vendor to enter a valid 11-character IFSC code.",
            )
        )

    if bank_acct and re.match(BANK_ACCT_REGEX, bank_acct):
        format_checks.append(_make_check("fmt_bank_acct", "format", "R5", "Bank account format", "pass", 0, "Bank account number format valid."))
    else:
        format_checks.append(
            _make_check(
                "fmt_bank_acct",
                "format",
                "R5",
                "Bank account format",
                "fix",
                10,
                f"Bank account '{bank_acct}' is not a valid 6-22 digit number.",
                "Bank account number should contain 6 to 22 digits without spaces.",
                "Ask vendor to check bank account digits.",
            )
        )

    all_checks.extend(format_checks)
    yield {"type": "stage", "stage": "format", "vendor_label": "Checking your details", "checks": format_checks}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    # Stage 4: Cross-check
    yield {"type": "start", "stage": "crosscheck", "vendor_label": "Checking your details"}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    xref_checks: list[dict] = []

    # R6: Form GSTIN [2:12] vs form PAN -> fix first (likely typo)
    if len(gstin) >= 12 and pan:
        embedded_pan = gstin[2:12]
        if embedded_pan == pan:
            xref_checks.append(
                _make_check(
                    "xref_form_gstin_pan",
                    "crosscheck",
                    "R6",
                    "Form GSTIN vs PAN",
                    "pass",
                    0,
                    f"GSTIN embedded PAN '{embedded_pan}' matches submitted PAN '{pan}'.",
                )
            )
        else:
            xref_checks.append(
                _make_check(
                    "xref_form_gstin_pan",
                    "crosscheck",
                    "R6",
                    "Form GSTIN vs PAN",
                    "fix",
                    10,
                    f"Form GSTIN '{gstin}' embeds '{embedded_pan}', while typed PAN is '{pan}'.",
                    "Your GSTIN and PAN don't match; please re-check both.",
                    "Confirm whether the vendor made a typing error in GSTIN or PAN.",
                )
            )

    # R7: Document identity consistency: GST cert embedded PAN vs PAN card PAN -> fail (40)
    gst_fields = merged_docs.get("gst_cert") or {}
    pan_fields = merged_docs.get("pan_card") or {}
    chq_fields = merged_docs.get("cancelled_cheque") or {}

    gst_can_xref = ("gst_cert" in merged_docs) and (doc_auto_read.get("gst_cert", True))
    pan_can_xref = ("pan_card" in merged_docs) and (doc_auto_read.get("pan_card", True))
    chq_can_xref = ("cancelled_cheque" in merged_docs) and (doc_auto_read.get("cancelled_cheque", True))

    doc_gst_val = (gst_fields.get("gstin") or "").strip().upper()
    doc_pan_val = (pan_fields.get("pan") or "").strip().upper()

    if gst_can_xref and pan_can_xref and len(doc_gst_val) >= 12 and doc_pan_val:
        doc_embedded_pan = doc_gst_val[2:12]
        if doc_embedded_pan != doc_pan_val:
            xref_checks.append(
                _make_check(
                    "xref_doc_identity_conflict",
                    "crosscheck",
                    "R7",
                    "Document PAN vs GST PAN",
                    "fail",
                    40,
                    f"GST certificate embeds PAN '{doc_embedded_pan}' but PAN card states '{doc_pan_val}'.",
                    "Your uploaded GST certificate and PAN card show conflicting PAN numbers.",
                    "Reject application due to contradictory tax identity documents.",
                )
            )
        else:
            xref_checks.append(
                _make_check(
                    "xref_doc_identity_conflict",
                    "crosscheck",
                    "R7",
                    "Document PAN vs GST PAN",
                    "pass",
                    0,
                    f"GST certificate embedded PAN '{doc_embedded_pan}' matches PAN card '{doc_pan_val}'.",
                )
            )

    # R8: GST state code vs address state -> fix (10)
    state_code = gstin[:2] if len(gstin) >= 2 else ""
    mapped_state = STATE_CODE_MAP.get(state_code)
    addr_state = (submission.get("address_state") or "").strip()
    if state_code and addr_state:
        if mapped_state and mapped_state.lower() == addr_state.lower():
            xref_checks.append(
                _make_check(
                    "xref_state_match",
                    "crosscheck",
                    "R8",
                    "GST state vs address state",
                    "pass",
                    0,
                    f"GST code '{state_code}' ({mapped_state}) matches state '{addr_state}'.",
                )
            )
        else:
            xref_checks.append(
                _make_check(
                    "xref_state_match",
                    "crosscheck",
                    "R8",
                    "GST state vs address state",
                    "fix",
                    10,
                    f"GST prefix '{state_code}' ({mapped_state or 'unknown'}) does not match address state '{addr_state}'.",
                    f"Your GSTIN state ({mapped_state or state_code}) does not match your address state ({addr_state}). Please check both.",
                    "Verify vendor's registered address state and GSTIN.",
                )
            )

    # R9: Document values vs form values -> fix (10)
    if gst_can_xref and doc_gst_val and gstin and doc_gst_val != gstin:
        xref_checks.append(
            _make_check(
                "xref_doc_vs_form_gstin",
                "crosscheck",
                "R9",
                "GST cert vs form GSTIN",
                "fix",
                10,
                f"GST cert has '{doc_gst_val}', form has '{gstin}'.",
                f"GSTIN on your GST certificate ({doc_gst_val}) differs from your form ({gstin}).",
                "Ask vendor to align GSTIN with their GST certificate.",
            )
        )

    if pan_can_xref and doc_pan_val and pan and doc_pan_val != pan:
        xref_checks.append(
            _make_check(
                "xref_doc_vs_form_pan",
                "crosscheck",
                "R9",
                "PAN card vs form PAN",
                "fix",
                10,
                f"PAN card has '{doc_pan_val}', form has '{pan}'.",
                f"PAN on your PAN card ({doc_pan_val}) differs from your form ({pan}).",
                "Ask vendor to align PAN with their PAN card.",
            )
        )

    doc_acct_val = (chq_fields.get("account_no") or "").strip()
    if chq_can_xref and doc_acct_val and bank_acct and doc_acct_val != bank_acct:
        xref_checks.append(
            _make_check(
                "xref_doc_vs_form_acct",
                "crosscheck",
                "R9",
                "Cheque vs form account",
                "fix",
                10,
                f"Cheque shows account '{doc_acct_val}', form shows '{bank_acct}'.",
                f"Bank account on your cancelled cheque ({doc_acct_val}) differs from your form ({bank_acct}).",
                "Ask vendor to verify bank account number against cheque.",
            )
        )

    doc_ifsc_val = (chq_fields.get("ifsc") or "").strip().upper()
    if chq_can_xref and doc_ifsc_val and ifsc and doc_ifsc_val != ifsc:
        xref_checks.append(
            _make_check(
                "xref_doc_vs_form_ifsc",
                "crosscheck",
                "R9",
                "Cheque vs form IFSC",
                "fix",
                10,
                f"Cheque shows IFSC '{doc_ifsc_val}', form shows '{ifsc}'.",
                f"IFSC on your cancelled cheque ({doc_ifsc_val}) differs from your form ({ifsc}).",
                "Ask vendor to verify IFSC code against cheque.",
            )
        )

    # R10: Name consistency (form legal name vs each readable doc)
    form_name = (submission.get("vendor_name") or "").strip()
    doc_name_pairs: list[tuple[str, str]] = []
    if gst_can_xref and gst_fields.get("legal_name"):
        doc_name_pairs.append(("GST certificate", gst_fields["legal_name"]))
    if pan_can_xref and pan_fields.get("name"):
        doc_name_pairs.append(("PAN card", pan_fields["name"]))
    if chq_can_xref and chq_fields.get("account_holder"):
        doc_name_pairs.append(("Cancelled cheque", chq_fields["account_holder"]))

    name_near_match_now = False
    vendor_note = (submission.get("reviewer_note") or "").strip()

    if form_name and doc_name_pairs:
        scored = [(src, dname, name_similarity(form_name, dname)) for src, dname in doc_name_pairs]
        weak_src, weak_name, weak_score = min(scored, key=lambda x: x[2])
        score_text = "; ".join([f"{s}='{n}' ({sc:.2f})" for s, n, sc in scored])

        if weak_score >= 0.92:
            xref_checks.append(
                _make_check(
                    "xref_name_consistency",
                    "crosscheck",
                    "R10",
                    "Name consistency",
                    "pass",
                    0,
                    f"Matches legal name '{form_name}' ({score_text}).",
                )
            )
        elif weak_score >= 0.75:
            name_near_match_now = True
            if round_no > 1 and (bool(vendor_note) or prior_name_near_match):
                xref_checks.append(
                    _make_check(
                        "xref_name_consistency",
                        "crosscheck",
                        "R10",
                        "Name consistency (near-match review)",
                        "review",
                        20,
                        f"Near-match ({weak_score:.2f}) persists after resubmission note '{vendor_note or 'provided'}': {score_text}.",
                        None,
                        "Compare the vendor's note and documents; approve if it is the same legal entity.",
                    )
                )
            else:
                xref_checks.append(
                    _make_check(
                        "xref_name_consistency",
                        "crosscheck",
                        "R10",
                        "Name consistency (near-match)",
                        "fix",
                        10,
                        f"Similarity {weak_score:.2f} on {weak_src}: {score_text}.",
                        f"The name on your {weak_src.lower()} is '{weak_name}' but your legal name is '{form_name}'. Please upload a document in your legal name, or explain the difference in the note.",
                        "Compare the vendor's note and documents; approve if it is the same legal entity.",
                    )
                )
        else:
            # < 0.75 -> fix in rounds 1-2, review from round 3+
            if round_no >= 3:
                xref_checks.append(
                    _make_check(
                        "xref_name_consistency",
                        "crosscheck",
                        "R10",
                        "Name consistency (round 3+ review)",
                        "review",
                        20,
                        f"Name difference ({weak_score:.2f}) reached round {round_no}: {score_text}.",
                        None,
                        "Compare the vendor's note and documents; approve if it is the same legal entity.",
                    )
                )
            else:
                xref_checks.append(
                    _make_check(
                        "xref_name_consistency",
                        "crosscheck",
                        "R10",
                        "Name consistency",
                        "fix",
                        10,
                        f"Similarity {weak_score:.2f} on {weak_src}: {score_text}.",
                        f"Names on your documents differ from your legal name '{form_name}' (score {weak_score:.2f}). Please upload matching documents or add a note.",
                        "Compare the vendor's note and documents; approve if it is the same legal entity.",
                    )
                )

    # R11: Documents contradict each other on name (< 0.75 between GST legal name and PAN name) -> review (25)
    if gst_can_xref and pan_can_xref and gst_fields.get("legal_name") and pan_fields.get("name"):
        g_name = gst_fields["legal_name"]
        p_name = pan_fields["name"]
        doc_pair_sim = name_similarity(g_name, p_name)
        if doc_pair_sim < 0.75:
            xref_checks.append(
                _make_check(
                    "xref_doc_name_conflict",
                    "crosscheck",
                    "R11",
                    "GST vs PAN document name",
                    "review",
                    25,
                    f"GST legal name '{g_name}' vs PAN name '{p_name}' similarity is {doc_pair_sim:.2f} (<0.75).",
                    None,
                    "Compare the vendor's note and documents; approve if it is the same legal entity.",
                )
            )

    all_checks.extend(xref_checks)
    yield {"type": "stage", "stage": "crosscheck", "vendor_label": "Checking your details", "checks": xref_checks}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    # Stage 5: Risk
    yield {"type": "start", "stage": "risk", "vendor_label": "Checking your details"}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    risk_checks: list[dict] = []
    holder_name = (submission.get("account_holder") or "").strip()

    # R12: Sanctions / watchlist -> fail (100)
    sanctions_hit = any(
        w in form_name.lower() or w in holder_name.lower() for w in SANCTIONS_WATCHLIST
    )
    if sanctions_hit:
        risk_checks.append(
            _make_check(
                "risk_sanctions_match",
                "risk",
                "R12",
                "Watchlist screening",
                "fail",
                100,
                "Matched restricted entity on watchlist.",
                "We're unable to onboard your company at this time.",
                "Keep rejected; do not disclose watchlist details to vendor.",
            )
        )
    else:
        risk_checks.append(
            _make_check(
                "risk_sanctions_match",
                "risk",
                "R12",
                "Watchlist screening",
                "pass",
                0,
                "No watchlist match found.",
            )
        )

    conn = get_db()
    cursor = conn.cursor()

    # R13: Bank details changed for an existing vendor -> review (25)
    if matched_vendor and (matched_vendor.get("bank_account") or "").strip():
        existing_acct = (matched_vendor.get("bank_account") or "").strip()
        if bank_acct and existing_acct != bank_acct:
            risk_checks.append(
                _make_check(
                    "risk_bank_change",
                    "risk",
                    "R13",
                    "Existing vendor bank change",
                    "review",
                    25,
                    f"Existing vendor {matched_vendor['vendor_id']} bank account changed from '{existing_acct}' to '{bank_acct}'.",
                    None,
                    "Call the vendor on the number already on file (not the one in this submission) to confirm the new account, then approve or reject.",
                )
            )

    # R14: Bank account shared with a different vendor -> review (30)
    if bank_acct:
        other_vid = matched_vendor["vendor_id"] if matched_vendor else ""
        cursor.execute(
            "SELECT vendor_id, name FROM vendors WHERE bank_account = ? AND vendor_id != ?",
            (bank_acct, other_vid),
        )
        shared = cursor.fetchone()
        if shared:
            risk_checks.append(
                _make_check(
                    "risk_shared_bank",
                    "risk",
                    "R14",
                    "Shared bank account",
                    "review",
                    30,
                    f"Bank account '{bank_acct}' is already used by vendor {shared['vendor_id']} ({shared['name']}).",
                    None,
                    "Check the other vendor on this account; reject if the link isn't disclosed.",
                )
            )

    conn.close()

    # R15: Newly registered entity (< 180 days) -> review (15)
    reg_date_str = (submission.get("registration_date") or gst_fields.get("registration_date") or "").strip()
    if reg_date_str:
        try:
            reg_dt = datetime.strptime(reg_date_str, "%Y-%m-%d").date()
            age_days = (datetime.now(timezone.utc).date() - reg_dt).days
            if age_days < 180:
                risk_checks.append(
                    _make_check(
                        "risk_new_entity",
                        "risk",
                        "R15",
                        "Business age (< 180 days)",
                        "review",
                        15,
                        f"Entity registered {age_days} days ago ({reg_date_str}), under 180-day threshold.",
                        None,
                        "Check incorporation date; request references if the order value is high.",
                    )
                )
        except Exception:
            pass

    all_checks.extend(risk_checks)
    yield {"type": "stage", "stage": "risk", "vendor_label": "Checking your details", "checks": risk_checks}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    # Stage 6: Decision & notification
    yield {"type": "start", "stage": "decision", "vendor_label": "Preparing your result"}
    if delay_seconds > 0:
        time.sleep(delay_seconds)

    has_fail = any(c["status"] == "fail" for c in all_checks)
    has_fix = any(c["status"] == "fix" for c in all_checks)
    has_review = any(c["status"] == "review" for c in all_checks)

    if has_fail:
        status_out = "rejected"
        substate_out = None
        fail_labels = [c["label"] for c in all_checks if c["status"] == "fail"]
        reason_text = f"Rejected because check failed: {', '.join(fail_labels)}."
    elif has_fix:
        status_out = "pending"
        substate_out = "awaiting_vendor"
        fix_count = len([c for c in all_checks if c["status"] == "fix"])
        reason_text = f"Pending awaiting vendor because {fix_count} fix item(s) are open."
    elif has_review:
        status_out = "pending"
        substate_out = "awaiting_review"
        rev_labels = [c["label"] for c in all_checks if c["status"] == "review"]
        reason_text = f"Pending awaiting human review for: {', '.join(rev_labels)}."
    else:
        status_out = "approved"
        substate_out = None
        reason_text = "Approved automatically: all checks passed."

    escalated_flag = 1 if (round_no >= 3 and has_fix) else 0
    if escalated_flag:
        r16_check = _make_check(
            "risk_escalated_rounds",
            "decision",
            "R16",
            "Repeated rounds escalation",
            "review",
            15,
            f"Escalated at round {round_no} with open fix items.",
            None,
            "Review repeated vendor submissions and guide or decide manually.",
        )
        all_checks.append(r16_check)

    total_points = sum(int(c.get("points") or 0) for c in all_checks)
    risk_score = min(100, total_points)
    risk_tier = compute_risk_tier(risk_score)

    decision_obj = {
        "status": status_out,
        "substate": substate_out,
        "risk_score": risk_score,
        "risk_tier": risk_tier,
        "escalated": escalated_flag,
        "reason": reason_text,
        "checks": all_checks,
        "merged_docs": merged_docs,
        "name_near_match_detected": name_near_match_now,
    }

    yield {
        "type": "stage",
        "stage": "decision",
        "vendor_label": "Preparing your result",
        "checks": [r16_check] if escalated_flag else [],
        "decision": decision_obj,
    }