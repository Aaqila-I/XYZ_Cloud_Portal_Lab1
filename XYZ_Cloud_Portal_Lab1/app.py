"""
XYZ Cloud Portal - Lab 1 (Baseline Portal)
- Branch-based login (US/UK/CA)
- Branch-isolated file upload/list/download
- Server-side audit-style logging (no passwords/cookies/contents)

Lab 2 will add TLS/PKI. This code is structured to easily enable HTTPS by running:
    flask run --cert=... --key=...
or app.run(ssl_context=(cert, key))
"""
from __future__ import annotations

import os
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Tuple

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, abort
)
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename


# -----------------------------
# App configuration
# -----------------------------
APP_NAME = "XYZ Cloud Portal"
BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"

ALLOWED_EXTENSIONS = { "pdf", "docx", "pptx", "xlsx", "txt", "csv", "jpg", "jpeg", "png" }
MAX_UPLOAD_MB = 10

app = Flask(__name__)
# Use an environment variable for repeatable sessions on lab PCs, otherwise a random key
app.config["SECRET_KEY"] = os.environ.get("XYZ_SECRET_KEY", os.urandom(24))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024


# -----------------------------
# Logging (audit-style)
# -----------------------------
def setup_logger() -> logging.Logger:
    logger = logging.getLogger("xyz_audit")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # Optional file log for evidence collection
    fh = logging.FileHandler(BASE_DIR / "logs" / "audit.log", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger

audit = setup_logger()


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def audit_event(event: str, username: str | None = None, branch: str | None = None,
                filename: str | None = None, success: bool | None = None,
                details: str | None = None) -> None:
    parts = [f"event={event}", f"ts={utc_ts()}"]
    if username:
        parts.append(f"user={username}")
    if branch:
        parts.append(f"branch={branch}")
    if filename:
        parts.append(f"file={filename}")
    if success is not None:
        parts.append(f"success={success}")
    if details:
        parts.append(f"details={details}")
    audit.info(" | ".join(parts))


# -----------------------------
# Hardcoded users (Lab 1)
# -----------------------------
# NOTE: Password hashes are generated using werkzeug.security.generate_password_hash(...)
# We share the plaintext passwords in the lab sheet, but we DO NOT store plaintext in code.
USERS: Dict[str, Dict[str, Any]] = {
    "us.alex": {
        "branch": "US",
        "password_hash": "scrypt:32768:8:1$hgFzHinWXX16HLLW$021e80efa3cf49537f089064c844b86f73549c152763e67ad36cffa42bb4384829439cba899f2ebc3ff84e274c6cfea94c39990f15292c60d6d42742c80eb911"
    },
    "uk.sana": {
        "branch": "UK",
        "password_hash": "scrypt:32768:8:1$12Opasi5Tz9kfqs0$1091ab2f327337cf850067830c68e9b98497a9371d72105298371595d266129ec8946ba4f7639ad94ba2902f576a8194bdd1c554cd67fc905967d2d96a112d75"
    },
    "ca.mike": {
        "branch": "CA",
        "password_hash": "scrypt:32768:8:1$PvIGS94d7ejkVJS6$f5e342918f9ec849d726eb21ce4e7cc7f08b5259b87f47583062f98ff990a5271dc47d4bcb1703ad3389c77f3379b456d63568572c3d713cda1a46ce9b0f217d"
    }
}

# These passwords are shared in the lab sheet:
# us.alex  -> Password123!
# uk.sana  -> Password123!
# ca.mike  -> Password123!


# -----------------------------
# Helper functions
# -----------------------------
def is_logged_in() -> bool:
    return "user" in session and "branch" in session


def current_user() -> Tuple[str, str]:
    return session.get("user", ""), session.get("branch", "")


def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower().strip()
    return ext in ALLOWED_EXTENSIONS


def branch_storage_dir(branch: str) -> Path:
    # Only allow expected branch names
    if branch not in {"US", "UK", "CA"}:
        raise ValueError("Invalid branch")
    d = STORAGE_DIR / branch
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_branch_files(branch: str) -> list[str]:
    d = branch_storage_dir(branch)
    files = []
    for p in d.iterdir():
        if p.is_file():
            files.append(p.name)
    files.sort(key=str.lower)
    return files


# -----------------------------
# Routes
# -----------------------------
@app.route("/", methods=["GET"])
def index():
    if is_logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")

        user = USERS.get(username)
        if not user:
            audit_event("login", username=username, success=False, details="unknown_user")
            flash("Invalid username or password.", "danger")
            return render_template("login.html", app_name=APP_NAME)

        if check_password_hash(user["password_hash"], password):
            session.clear()
            session["user"] = username
            session["branch"] = user["branch"]
            session["login_time"] = utc_ts()

            audit_event("login", username=username, branch=user["branch"], success=True)
            return redirect(url_for("dashboard"))

        audit_event("login", username=username, branch=user.get("branch"), success=False, details="bad_password")
        flash("Invalid username or password.", "danger")
        return render_template("login.html", app_name=APP_NAME)

    return render_template("login.html", app_name=APP_NAME)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    username, branch = current_user()
    files = list_branch_files(branch)

    return render_template(
        "dashboard.html",
        app_name=APP_NAME,
        username=username,
        branch=branch,
        files=files,
        allowed_exts=", ".join(sorted(ALLOWED_EXTENSIONS)),
        max_mb=MAX_UPLOAD_MB
    )


@app.route("/upload", methods=["POST"])
def upload():
    if not is_logged_in():
        return redirect(url_for("login"))

    username, branch = current_user()

    if "file" not in request.files:
        flash("No file part in the request.", "warning")
        return redirect(url_for("dashboard"))

    f = request.files["file"]
    if f.filename == "":
        flash("No file selected.", "warning")
        return redirect(url_for("dashboard"))

    original_name = f.filename
    safe_name = secure_filename(original_name)

    # Basic safe checks (Lab 1 baseline)
    if not safe_name:
        flash("Invalid filename.", "danger")
        return redirect(url_for("dashboard"))

    if not allowed_file(safe_name):
        flash("File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), "danger")
        return redirect(url_for("dashboard"))

    dest_dir = branch_storage_dir(branch)
    dest_path = dest_dir / safe_name

    # Prevent overwriting without telling the user
    if dest_path.exists():
        flash("A file with this name already exists in your branch. Rename and try again.", "warning")
        return redirect(url_for("dashboard"))

    f.save(dest_path)
    audit_event("upload", username=username, branch=branch, filename=safe_name, success=True)
    flash(f"Uploaded: {safe_name}", "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<filename>", methods=["GET"])
def download(filename: str):
    if not is_logged_in():
        return redirect(url_for("login"))

    username, branch = current_user()

    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        abort(400)

    # Only allow download within the logged-in user's branch directory
    d = branch_storage_dir(branch)
    file_path = d / safe_name
    if not file_path.exists() or not file_path.is_file():
        abort(404)

    audit_event("download", username=username, branch=branch, filename=safe_name, success=True)
    return send_from_directory(d, safe_name, as_attachment=True)


@app.route("/logout", methods=["POST"])
def logout():
    if is_logged_in():
        username, branch = current_user()
        audit_event("logout", username=username, branch=branch, success=True)
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# -----------------------------
# Friendly error pages
# -----------------------------
@app.errorhandler(413)
def too_large(_e):
    flash(f"File too large. Max upload size is {MAX_UPLOAD_MB} MB.", "danger")
    return redirect(url_for("dashboard")), 413


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", app_name=APP_NAME, code=404, message="Not Found"), 404


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", app_name=APP_NAME, code=400, message="Bad Request"), 400


# -----------------------------
# Main entry point
# -----------------------------
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5443,
        ssl_context=(
            "certs/server/server.crt",
            "certs/server/server.key"
        ),
        debug=True
    )
   
           