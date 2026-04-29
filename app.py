"""
e-Sevai Intelligent Middleware - Main Flask Application
"""
import json
import os
from datetime import datetime, timezone

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory, session
from functools import wraps
from werkzeug.utils import secure_filename

from Config import Config
from utils.helpers import generate_id, allowed_file, timestamp_now, ensure_dirs
from modules.ocr_engine import extract_text_from_file
from modules.data_extractor import extract_fields
from modules.validator import validate
from modules.sla_engine import start_sla_timer, check_sla, complete_sla_step
from modules.audit_logger import append_audit, get_audit_trail, verify_chain_integrity

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config["SECRET_KEY"]


# ── Auth decorators ──────────────────────────────────────────────────────────

def login_required(f):
    """Protect government/official routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please log in to access the Official Portal.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


ensure_dirs(
    app.config["UPLOAD_FOLDER"],
    app.config["EXTRACTED_FOLDER"],
    os.path.dirname(app.config["DB_PATH"]),
)


# ── DB helpers ───────────────────────────────────────────────────────────────

def load_db():
    path = app.config["DB_PATH"]
    if not os.path.exists(path):
        return {"applications": {}, "audit_chain": []}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return {"applications": {}, "audit_chain": []}


def save_db(data):
    with open(app.config["DB_PATH"], "w") as f:
        json.dump(data, f, indent=2)


# ── Citizen routes ───────────────────────────────────────────────────────────

@app.route("/")
def home():
    """Citizen landing page / submission portal."""
    return render_template("upload.html", services=Config.SERVICES)


@app.route("/apply", methods=["POST"])
def apply():
    """Handle citizen application submission."""

    # Assign a persistent citizen session ID on first submission
    if not session.get("citizen_id"):
        session["citizen_id"] = generate_id()

    citizen_id = session["citizen_id"]

    # Form fields
    form_data = {
        "name":    request.form.get("name", "").strip(),
        "dob":     request.form.get("dob", "").strip(),
        "aadhaar": request.form.get("aadhaar", "").strip(),
        "service": request.form.get("service", "").strip(),
        "address": request.form.get("address", "").strip(),
        "data":    request.form.get("data", "").strip(),
    }

    files = request.files.getlist("document")
    if not files or all(f.filename == "" for f in files):
        flash("Please upload at least one document.", "error")
        return redirect(url_for("home"))

    app_id = generate_id()
    documents_metadata = []
    combined_raw_text = ""
    aggregated_extracted = {}

    for file in files:
        if not file or file.filename == "":
            continue

        if not allowed_file(file.filename, app.config["ALLOWED_EXTENSIONS"]):
            flash(f"Invalid file type for {file.filename}. Skipped.", "warning")
            continue

        # Save file
        filename = secure_filename(f"{app_id}_{file.filename}")
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        # OCR
        raw_text = extract_text_from_file(filepath)
        extracted = extract_fields(raw_text)

        # Aggregate
        combined_raw_text += f"\n--- DOCUMENT: {file.filename} ---\n{raw_text}\n"
        for k, v in extracted.items():
            if v and not aggregated_extracted.get(k):
                aggregated_extracted[k] = v

        documents_metadata.append({
            "filename": filename,
            "original_name": file.filename,
            "fields_found": list(extracted.keys())
        })

    # Validate
    report = validate(form_data, aggregated_extracted, combined_raw_text)

    # Save extracted data
    ext_path = os.path.join(app.config["EXTRACTED_FOLDER"], f"{app_id}.json")
    with open(ext_path, "w") as f:
        json.dump({
            "combined_raw_text": combined_raw_text,
            "aggregated_extracted": aggregated_extracted,
            "documents": documents_metadata
        }, f, indent=2)

    # All new applications start as "Pending" regardless of AI result
    status = "Pending"

    # Build application record
    application = {
        "id":           app_id,
        "citizen_id":   citizen_id,
        "service":      form_data["service"],
        "form_data":    form_data,
        "extracted":    aggregated_extracted,
        "validation":   report,
        "risk":         report["risk"],
        "status":       status,
        "submitted_at": timestamp_now(),
        "documents":    documents_metadata,
        "sla":          {},
    }

    db = load_db()
    db["applications"][app_id] = application
    save_db(db)

    # Audit
    append_audit(app.config["DB_PATH"], app_id, "citizen", "submitted",
                 {"service": form_data["service"], "document_count": len(documents_metadata)})
    append_audit(app.config["DB_PATH"], app_id, "system", "ocr_complete",
                 {"aggregate_fields": list(aggregated_extracted.keys())})
    append_audit(app.config["DB_PATH"], app_id, "system", "validation_complete",
                 {"risk": report["risk"], "summary": report["summary"]})

    # Start SLA
    start_sla_timer(app.config["DB_PATH"], app_id, "officer_review",
                    app.config["SLA_LIMITS"]["officer_review"])

    return redirect(url_for("success", app_id=app_id, service=form_data["service"]))


@app.route("/success/<app_id>")
def success(app_id):
    service = request.args.get("service", "Service")
    return render_template("success.html", app_id=app_id, service=service)


@app.route("/application_check")
def application_check():
    """Citizen view: show only their own submitted applications."""
    citizen_id = session.get("citizen_id")
    db = load_db()
    all_apps = list(db["applications"].values())

    if citizen_id:
        apps = [a for a in all_apps if a.get("citizen_id") == citizen_id]
        # Sort newest first
        apps.sort(key=lambda x: x.get("submitted_at", ""), reverse=True)
    else:
        apps = []

    return render_template("application_check.html", apps=apps)


# ── Government / Official routes ─────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role     = request.form.get("role", "gov")

        if role == "gov":
            if username == "admin" and password == "admin123":
                session["logged_in"] = True
                session["role"] = "gov"
                flash("Logged in successfully as Government Official.", "success")
                return redirect(url_for("official_dashboard"))
            else:
                flash("Invalid official credentials.", "error")
        else:
            # Citizen login: just set a citizen_id session so they can track apps
            if not session.get("citizen_id"):
                session["citizen_id"] = generate_id()
            session["role"] = "citizen"
            flash("Signed in as Citizen. You can now track your applications.", "success")
            return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/official/dashboard")
@login_required
def official_dashboard():
    db = load_db()
    apps = list(db["applications"].values())
    apps.sort(key=lambda x: x.get("submitted_at", ""), reverse=True)
    stats = {
        "total":    len(apps),
        "pending":  sum(1 for a in apps if a.get("status") == "Pending"),
        "approved": sum(1 for a in apps if a.get("status") == "Approved"),
        "rejected": sum(1 for a in apps if a.get("status") == "Rejected"),
        "flagged":  sum(1 for a in apps if a.get("risk") in ("high", "medium")),
    }
    return render_template("index.html", applications=apps, stats=stats)


@app.route("/official/review/<app_id>", methods=["GET"])
@login_required
def result(app_id):
    db = load_db()
    application = db["applications"].get(app_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("official_dashboard"))
    audit = get_audit_trail(app.config["DB_PATH"], app_id)
    sla   = check_sla(app.config["DB_PATH"], app_id, "officer_review")
    return render_template("result.html", app=application, audit=audit, sla=sla)


@app.route("/update_status/<app_id>/<new_status>")
@login_required
def update_status(app_id, new_status):
    """Government officer approves or rejects an application from the dashboard."""
    if new_status not in ("Approved", "Rejected"):
        flash("Invalid status value.", "error")
        return redirect(url_for("official_dashboard"))

    db = load_db()
    application = db["applications"].get(app_id)
    if not application:
        flash("Application not found.", "error")
        return redirect(url_for("official_dashboard"))

    application["status"] = new_status
    db["applications"][app_id] = application
    save_db(db)

    append_audit(app.config["DB_PATH"], app_id, "officer", new_status.lower(),
                 {"new_status": new_status})

    flash(f"Application {app_id[:8]}... marked as {new_status}.", "success")
    return redirect(url_for("official_dashboard"))


@app.route("/official/action/<app_id>", methods=["POST"])
@login_required
def officer_action(app_id):
    db = load_db()
    application = db["applications"].get(app_id)
    if not application:
        return jsonify({"error": "Not found"}), 404

    action  = request.form.get("action")
    reason  = request.form.get("reason", "")
    officer = request.form.get("officer", "Officer")

    if action == "approve":
        application["status"] = "Approved"
        complete_sla_step(app.config["DB_PATH"], app_id, "officer_review")
    elif action == "reject":
        application["status"] = "Rejected"
        complete_sla_step(app.config["DB_PATH"], app_id, "officer_review")
    elif action == "escalate":
        application["status"] = "Escalated to Senior Officer"

    db["applications"][app_id] = application
    save_db(db)

    append_audit(app.config["DB_PATH"], app_id, officer, action,
                 {"reason": reason, "new_status": application["status"]})

    return redirect(url_for("result", app_id=app_id))


# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/raw/<app_id>")
def raw_data(app_id):
    db = load_db()
    application = db["applications"].get(app_id)
    if not application:
        return jsonify({"error": "Application not found"}), 404
    return jsonify({
        "app_id":            app_id,
        "service":           application.get("service"),
        "extracted_data":    application.get("extracted", {}),
        "validation_report": application.get("validation", {}),
        "form_data":         application.get("form_data", {})
    })


@app.route("/api/applications")
def api_applications():
    db = load_db()
    return jsonify(list(db["applications"].values()))


@app.route("/api/audit/<app_id>")
def api_audit(app_id):
    trail = get_audit_trail(app.config["DB_PATH"], app_id)
    return jsonify(trail)


@app.route("/api/chain/verify")
def api_verify_chain():
    ok, msg = verify_chain_integrity(app.config["DB_PATH"])
    return jsonify({"valid": ok, "message": msg})


@app.route("/uploads/<filename>")
def serve_upload(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    app.run(debug=True, port=5000)