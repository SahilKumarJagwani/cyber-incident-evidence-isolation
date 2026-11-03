from flask import Flask, Request, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, date, timezone, timedelta
from zoneinfo import ZoneInfo
import uuid
import os
import hashlib
import secrets
from flask_wtf.csrf import CSRFProtect
import subprocess
import zipfile
import tempfile
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from database import get_db_connection, current_user_is_admin
from sandbox_link import SandboxError, send_evidence_to_sandbox, delete_evidence_from_sandbox, release_evidence_in_sandbox
import threading
import json
import urllib.error
import urllib.parse
import urllib.request
from io import BytesIO


class InMemoryUploadRequest(Request):
    
    # Keep uploaded files in RAM only.
    
    def _get_file_stream(self, total_content_length, content_type,
                         filename=None, content_length=None):
        return BytesIO()


app = Flask(__name__)
app.request_class = InMemoryUploadRequest


csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

sandbox_export_lock = threading.Lock()

@app.template_filter("ist")
def convert_to_ist(value):
    if not value:
        return ""

    dt = datetime.fromisoformat(str(value))

    # Assume naive database timestamps are in UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # Convert UTC to Indian Standard Time (UTC+5:30)
    ist = timezone(timedelta(hours=5, minutes=30))
    ist_time = dt.astimezone(ist)

    return ist_time.strftime("%Y-%m-%d %H:%M:%S")


# Load the session secret from the environment.
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is not set."
    )

# Maximum upload size: 2 MB
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False  # Local HTTP development only
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


# Evidence storage directory
UPLOAD_FOLDER = os.path.join("uploads", "evidence")

SANDBOX_EXPORT_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "sandbox_exports"
)
os.makedirs(SANDBOX_EXPORT_FOLDER, exist_ok=True)


# VirtualBox control for the isolated evidence-review VM
VBOXMANAGE_PATH = r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
SANDBOX_VM_NAME = "CyberEvidenceSandbox"



# Allowed evidence file extensions
ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "pdf",
    "txt",
    "eml"
}

# Create evidence folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def start_evidence_sandbox():
    """Start only the isolated evidence-review VM."""

    result = subprocess.run(
        [
            VBOXMANAGE_PATH,
            "showvminfo",
            SANDBOX_VM_NAME,
            "--machinereadable",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    vm_info = result.stdout

    if 'VMState="running"' in vm_info:
        return "already_running"

    if 'VMState="paused"' in vm_info:
        raise RuntimeError("Sandbox VM is paused. Resume it manually.")

    if 'VMState="saved"' in vm_info:
        raise RuntimeError("Sandbox VM has a saved state. Resume it manually.")

    if 'VMState="poweroff"' not in vm_info:
        raise RuntimeError("Sandbox VM is not in a supported state.")

    subprocess.run(
        [
            VBOXMANAGE_PATH,
            "startvm",
            SANDBOX_VM_NAME,
            "--type",
            "gui",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    return "started"


def attach_evidence_iso(iso_path):
    """Attach the generated ISO to the sandbox VM's IDE optical drive."""

    iso_path = os.path.abspath(iso_path)

    if not os.path.isfile(iso_path):
        raise FileNotFoundError("Evidence ISO not found.")

    # Confirm the target VM is running before changing its optical drive.
    result = subprocess.run(
        [
            VBOXMANAGE_PATH,
            "showvminfo",
            SANDBOX_VM_NAME,
            "--machinereadable",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    if 'VMState="running"' not in result.stdout:
        raise RuntimeError(
            "CyberEvidenceSandbox must be running before ISO attachment."
        )

    # Replace only IDE secondary device 0 (IDE-1-0).
    subprocess.run(
        [
            VBOXMANAGE_PATH,
            "storageattach",
            SANDBOX_VM_NAME,
            "--storagectl",
            "IDE",
            "--port",
            "1",
            "--device",
            "0",
            "--type",
            " dvddrive".strip(),
            "--medium",
            iso_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    return iso_path


def replace_sandbox_iso_and_restart(iso_path):
    """Replace the evidence ISO while the sandbox VM is powered off."""

    iso_path = os.path.abspath(iso_path)

    if not os.path.isfile(iso_path):
        raise FileNotFoundError("Evidence ISO not found.")

    # Check the state of the specifically named evidence-review VM.
    result = subprocess.run(
        [
            VBOXMANAGE_PATH,
            "showvminfo",
            SANDBOX_VM_NAME,
            "--machinereadable",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    vm_info = result.stdout

    if 'VMState="running"' in vm_info:
        raise RuntimeError(
            "Sandbox is running. Shut it down cleanly inside Ubuntu, "
            "then retry ISO replacement."
        )

    if 'VMState="paused"' in vm_info:
        raise RuntimeError("Sandbox is paused. Resume and shut it down manually.")

    if 'VMState="saved"' in vm_info:
        raise RuntimeError("Sandbox has a saved state. Resume and shut it down manually.")

    if 'VMState="poweroff"' not in vm_info:
        raise RuntimeError("Sandbox VM is not in a supported state.")

    # Replace only the sandbox VM's IDE optical drive.
    subprocess.run(
        [
            VBOXMANAGE_PATH,
            "storageattach",
            SANDBOX_VM_NAME,
            "--storagectl", "IDE",
            "--port", "1",
            "--device", "0",
            "--type", "dvddrive",
            "--medium", iso_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    # Start the isolated evidence-review VM.
    subprocess.run(
        [
            VBOXMANAGE_PATH,
            "startvm",
            SANDBOX_VM_NAME,
            "--type", "gui",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )

    return "restarted_with_new_iso"



def create_evidence_zip(export_path, evidence_filename, expected_hash):
    """Create a ZIP containing one verified evidence file and its manifest."""

    import uuid

    actual_hash = calculate_sha256(export_path)

    if actual_hash.lower() != expected_hash.lower():
        raise RuntimeError("Evidence hash mismatch; ZIP creation blocked.")

    # Give this export its own unique filenames.
    export_id = uuid.uuid4().hex

    zip_path = os.path.join(
        SANDBOX_EXPORT_FOLDER,
        f"evidence_transfer_{export_id}.zip",
    )
    manifest_path = os.path.join(
        SANDBOX_EXPORT_FOLDER,
        f"SHA256SUMS_{export_id}.txt",
    )

    try:
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as manifest:
            manifest.write(f"{actual_hash}  {evidence_filename}\n")

        with zipfile.ZipFile(
            zip_path,
            mode="w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            archive.write(export_path, arcname=evidence_filename)
            archive.write(manifest_path, arcname="SHA256SUMS.txt")

        # Verify the ZIP before using it.
        with zipfile.ZipFile(zip_path, "r") as archive:
            if archive.namelist().count(evidence_filename) != 1:
                raise RuntimeError(
                    "ZIP does not contain exactly one evidence file."
                )

            packaged_hash = hashlib.sha256(
                archive.read(evidence_filename)
            ).hexdigest()

            if packaged_hash.lower() != expected_hash.lower():
                raise RuntimeError("Packaged evidence hash mismatch.")

        return zip_path

    except Exception:
        # If ZIP creation or verification fails, remove this export's files.
        for temporary_file in (zip_path, manifest_path):
            try:
                if os.path.isfile(temporary_file):
                    os.remove(temporary_file)
            except OSError:
                app.logger.exception(
                    "Could not remove failed ZIP export file: %s",
                    temporary_file,
                )
        raise





@app.route("/my-case/<int:incident_id>")
def view_case(incident_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    try:
        incident = connection.execute("""
            SELECT *
            FROM incidents
            WHERE id = ? AND user_id = ?
        """, (incident_id, session["user_id"])).fetchone()

        if incident is None:
            return "Case not found or access denied.", 404

        # Get evidence for this incident
        evidence = connection.execute("""
            SELECT
                id,
                original_filename,
                file_type,
                file_size,
                file_hash,
                uploaded_at
            FROM evidence
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

        # Get administrator updates
        updates = connection.execute("""
            SELECT
                status,
                message,
                created_at
            FROM case_updates
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

        return render_template(
            "view_case.html",
            incident=incident,
            evidence=evidence,
            updates=updates
        )

    finally:
        connection.close()



def has_valid_evidence_signature(data, extension):
    """Validate file signature / text encoding on in-memory bytes."""

    header = data[:16]

    signatures = {
        "png": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
        "jpg": lambda d: d.startswith(b"\xff\xd8\xff"),
        "jpeg": lambda d: d.startswith(b"\xff\xd8\xff"),
        "pdf": lambda d: d.startswith(b"%PDF-"),
    }

    if extension in signatures:
        return signatures[extension](header)

    if extension in ("txt", "eml"):
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            return False

        if len(text) > 1024 * 1024:
            return False

        if any(ord(c) < 32 and c not in "\r\n\t\f" for c in text):
            return False

        if extension == "eml":
            return "\n" in text and ":" in text.split("\n", 1)[0]

        return True

    return False



# HELPER FUNCTIONS

def allowed_file(filename):
    """
    Check whether the uploaded file has an allowed extension.
    """

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def has_valid_file_signature(file_path, extension):
    """Validate basic file signatures or text encoding for evidence."""

    with open(file_path, "rb") as evidence:
        header = evidence.read(16)

    signatures = {
        "png": lambda data: data.startswith(b"\x89PNG\r\n\x1a\n"),
        "jpg": lambda data: data.startswith(b"\xff\xd8\xff"),
        "jpeg": lambda data: data.startswith(b"\xff\xd8\xff"),
        "pdf": lambda data: data.startswith(b"%PDF-"),
    }

    if extension in signatures:
        return signatures[extension](header)

    if extension in ("txt", "eml"):
        try:
            with open(file_path, "r", encoding="utf-8-sig") as evidence:
                text = evidence.read(1024 * 1024 + 1)

            # Reject binary-like control characters.
            if any(
                ord(char) < 32 and char not in "\r\n\t\f"
                for char in text
            ):
                return False

            # Avoid accepting a text file larger than the validation limit
            # without inspecting its full contents.
            if len(text) > 1024 * 1024:
                return False

            if extension == "eml":
                return (
                    "\n" in text
                    and ":" in text.split("\n", 1)[0]
                )

            return True

        except (UnicodeDecodeError, OSError):
            return False

    return False


def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            data = file.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# HOME 

@app.route("/")
def home():

    return render_template("home.html")


# REGISTER

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        college_id = request.form.get("college_id", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not all([name, college_id, email, password]):
            return "All registration fields are required.", 400

        # Limit input lengths
        if len(name) > 100 or len(college_id) > 50 or len(email) > 254:
            return "One or more fields are too long.", 400

        # Basic email-format validation
        if (
            "@" not in email
            or email.startswith("@")
            or email.endswith("@")
            or email.count("@") != 1
        ):
            return "Please enter a valid email address.", 400

        # Require a minimum password length
        if len(password) < 12:
            return "Password must be at least 12 characters long.", 400

        # Prevent excessively long passwords
        if len(password) > 128:
            return "Password must not exceed 128 characters.", 400

        password_hash = generate_password_hash(password)

        connection = get_db_connection()

        try:

            connection.execute("""
                INSERT INTO users
                (name, college_id, email, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                college_id,
                email,
                password_hash,
                "student"
            ))

            connection.commit()

        except connection.IntegrityError:

            connection.close()

            return "College ID or Email already registered."

        connection.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# LOGIN

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not email or not password:
            return "Email and password are required.", 400

        connection = get_db_connection()

        user = connection.execute("""
            SELECT *
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):
            # Remove pre-authentication session data before login.
            session.clear()

            session.permanent = True

            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]

            # Redirect users based on their role
            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("dashboard"))

        return "Invalid email or password."

    return render_template("login.html")


# DASHBOARD

@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:

        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        name=session["name"],
        role=session["role"]
    )


# REPORT INCIDENT

@app.route("/report-incident", methods=["GET", "POST"])
def report_incident():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        # Validate the one-time submission token
        submitted_token = request.form.get("submission_token")
        session_token = session.get("submission_token")

        if not submitted_token or submitted_token != session_token:
            return """
                <h3>Form already submitted or expired.</h3>
                <a href="/report-incident">Submit a new report</a>
            """, 400

        # Consume the token so a repeated request is rejected
        session.pop("submission_token", None)

        
        # Read and normalize submitted fields
        incident_type = request.form.get("incident_type", "").strip()
        description = request.form.get("description", "").strip()
        incident_date = request.form.get("incident_date", "").strip()
        location = request.form.get("location", "").strip()

        # Allowed incident types must match the HTML form
        allowed_incident_types = {
            "Phishing",
            "Malware",
            "Account Compromise",
            "Suspicious Website",
            "Data Leakage",
            "Other",
        }

        if incident_type not in allowed_incident_types:
            return "Please select a valid incident type.", 400

        if not description or len(description) < 10:
            return "Description must be at least 10 characters long.", 400

        if len(description) > 5000:
            return "Description must not exceed 5000 characters.", 400

        if len(location) > 200:
            return "Location must not exceed 200 characters.", 400

        # Validate the date format and ensure it is not in the future
        try:
            parsed_date = date.fromisoformat(incident_date)
        except ValueError:
            return "Please enter a valid incident date.", 400

        if parsed_date.isoformat() != incident_date:
            return "Date must use YYYY-MM-DD format.", 400

        if parsed_date < date(1900, 1, 1):
            return "Incident date must be on or after 1900-01-01.", 400

        if parsed_date > date.today():
            return "Incident date cannot be in the future.", 400

  
        
        clicked_link = (
            1 if request.form.get("clicked_link") == "yes" else 0
        )

        credentials_entered = (
            1 if request.form.get("credentials_entered") == "yes" else 0
        )

        if clicked_link and credentials_entered:
            priority = "HIGH"
        elif clicked_link:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        connection = get_db_connection()
        sandbox_vault_id = None

        try:
            temporary_case_id = "TEMP-" + str(uuid.uuid4())

            cursor = connection.execute("""
                INSERT INTO incidents (
                    case_id, user_id, incident_type,
                    description, incident_date, location,
                    clicked_link, credentials_entered,
                    priority, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                temporary_case_id,
                session["user_id"],
                incident_type,
                description,
                incident_date,
                location,
                clicked_link,
                credentials_entered,
                priority,
                "SUBMITTED"
            ))

            incident_id = cursor.lastrowid
            case_id = f"CYB-{datetime.now().year}-{incident_id:05d}"

            connection.execute("""
                UPDATE incidents
                SET case_id = ?
                WHERE id = ?
            """, (case_id, incident_id))

            evidence_file = request.files.get("evidence")

            if evidence_file and evidence_file.filename:
                original_filename = secure_filename(
                    evidence_file.filename
                )

                if not allowed_file(original_filename):
                    connection.rollback()
                    return (
                        "Invalid file type. Allowed types: "
                        "PNG, JPG, JPEG, PDF, TXT, EML.",
                        400
                    )

                extension = original_filename.rsplit(".", 1)[1].lower()

                # The upload lives in memory only (see InMemoryUploadRequest).
                evidence_bytes = evidence_file.read()
                file_size = len(evidence_bytes)

                if file_size == 0:
                    connection.rollback()
                    return "Evidence file is empty.", 400

                if not has_valid_evidence_signature(evidence_bytes, extension):
                    connection.rollback()
                    return (
                        "The file content does not match its extension.",
                        400
                    )

                file_hash = hashlib.sha256(evidence_bytes).hexdigest()
                vault_id = uuid.uuid4().hex

                try:
                    send_evidence_to_sandbox(
                        vault_id,
                        evidence_bytes,
                        original_filename,
                        file_hash
                    )
                except SandboxError:
                    app.logger.exception("Evidence delivery to sandbox failed")
                    connection.rollback()
                    return (
                        "Evidence could not be delivered to the isolated "
                        "analysis system, so this report was not saved. "
                        "Please try again later.",
                        503
                    )
                finally:
                    # Drop the in-memory copy as soon as possible.
                    evidence_bytes = None

                sandbox_vault_id = vault_id

                # stored_filename now holds the sandbox vault ID. The file
                # itself is never stored on this machine.
                connection.execute("""
                    INSERT INTO evidence (
                        incident_id, original_filename,
                        stored_filename, file_type,
                        file_size, file_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    incident_id,
                    original_filename,
                    vault_id,
                    extension,
                    file_size,
                    file_hash
                ))

            connection.commit()

        except Exception:
            connection.rollback()

            # Remove the sandbox copy if the database transaction failed
            if sandbox_vault_id:
                try:
                    delete_evidence_from_sandbox(sandbox_vault_id)
                except SandboxError:
                    app.logger.exception(
                        "Could not remove orphaned sandbox evidence: %s",
                        sandbox_vault_id,
                    )

            raise

        finally:
            connection.close()

        return redirect(url_for(
            "incident_success",
            case_id=case_id
        ))

    # Generate a fresh token for each new form page
    session["submission_token"] = secrets.token_urlsafe(32)

    return render_template(
    "report_incident.html",
    today=date.today().isoformat()
    )

@app.route("/incident-success/<case_id>")
def incident_success(case_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    try:
        incident = connection.execute("""
            SELECT case_id, priority
            FROM incidents
            WHERE case_id = ? AND user_id = ?
        """, (
            case_id,
            session["user_id"]
        )).fetchone()

        if incident is None:
            return "Case not found.", 404

        return render_template(
            "incident_success.html",
            case_id=incident["case_id"],
            priority=incident["priority"]
        )

    finally:
        connection.close()

# MY REPORTS 

@app.route("/my-reports")
def my_reports():

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    incidents = connection.execute("""
        SELECT
            id,
            case_id,
            incident_type,
            priority,
            status,
            incident_date,
            created_at
        FROM incidents
        WHERE user_id = ?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()

    connection.close()

    return render_template(
        "my_reports.html",
        incidents=incidents
    )


# CASE DETAILS 

@app.route("/case/<int:incident_id>")
def case_details(incident_id):

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    connection = get_db_connection()

    # Get the case
    incident = connection.execute("""
        SELECT *
        FROM incidents
        WHERE id = ?
        AND user_id = ?
    """, (
        incident_id,
        session["user_id"]
    )).fetchone()

    # If the case doesn't belong to this user
    if incident is None:

        connection.close()

        return "Case not found or access denied.", 404

    # Get evidence belonging to this case
    evidence = connection.execute("""
    SELECT
    id,
    original_filename,
    file_type,
    file_size,
    file_hash,
    uploaded_at 
    FROM evidence
    WHERE incident_id = ?
    ORDER BY id DESC
    """, (incident_id,)).fetchall()

    # Get case updates
    updates = connection.execute("""
        SELECT
            status,
            message,
            created_at
        FROM case_updates
        WHERE incident_id = ?
        ORDER BY id DESC
    """, (incident_id,)).fetchall()

    connection.close()

    return render_template(
        "case_details.html",
        incident=incident,
        evidence=evidence,
        updates=updates
    )

# FILE TOO LARGE

@app.errorhandler(413)
def file_too_large(error):

    return (
        "File is too large. "
        "Maximum allowed size is 2 MB.",
        413
    )



# ADMIN DASHBOARD

@app.route("/admin")
def admin_dashboard():

    # User must be logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Only admins are allowed
    if not current_user_is_admin(session.get("user_id")):
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()

    # Get all incidents with reporter information
    incidents = connection.execute("""
        SELECT
            incidents.id,
            incidents.case_id,
            incidents.incident_type,
            incidents.priority,
            incidents.status,
            incidents.incident_date,
            incidents.created_at,
            users.name AS reporter_name,
            users.email AS reporter_email
        FROM incidents
        JOIN users
        ON incidents.user_id = users.id
        ORDER BY incidents.id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "admin_dashboard.html",
        incidents=incidents
    )



# ADMIN CASE REVIEW

@app.route("/admin/case/<int:incident_id>", methods=["GET", "POST"])
def admin_case(incident_id):

    # Login check
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Admin permission check
    if not current_user_is_admin(session.get("user_id")):
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()

    try:
        # Get incident and reporter details
        incident = connection.execute("""
            SELECT
                incidents.*,
                users.name AS reporter_name,
                users.email AS reporter_email
            FROM incidents
            JOIN users ON incidents.user_id = users.id
            WHERE incidents.id = ?
        """, (incident_id,)).fetchone()

        if incident is None:
            return "Incident not found.", 404

        # Handle submitted forms
        if request.method == "POST":
            action = request.form.get("action", "")

            # Add a private investigation note
            if action == "add_note":
                note = request.form.get("note", "").strip()

                if not note:
                    return "Investigation note cannot be empty.", 400

                connection.execute("""
                    INSERT INTO internal_notes
                        (incident_id, admin_id, note)
                    VALUES (?, ?, ?)
                """, (
                    incident_id,
                    session["user_id"],
                    note
                ))

                connection.execute("""
                    INSERT INTO audit_logs
                        (user_id, incident_id, action)
                    VALUES (?, ?, ?)
                """, (
                    session["user_id"],
                    incident_id,
                    "Added an internal investigation note"
                ))

                connection.commit()

                return redirect(url_for(
                    "admin_case",
                    incident_id=incident_id
                ))

            # Update case priority, status, assignment, and public message
            
            # Add a public case update without changing case details
            elif action == "add_public_update":
                message = request.form.get("message", "").strip()

                if not message:
                    return "Public update cannot be empty.", 400

                connection.execute("""
                    INSERT INTO case_updates
                        (incident_id, admin_id, status, message)
                    VALUES (?, ?, ?, ?)
                """, (
                    incident_id,
                    session["user_id"],
                    incident["status"],
                    message
                ))

                connection.execute("""
                    INSERT INTO audit_logs
                        (user_id, incident_id, action)
                    VALUES (?, ?, ?)
                """, (
                    session["user_id"],
                    incident_id,
                    "Added a public case update"
                ))

                connection.commit()

                return redirect(url_for(
                    "admin_case",
                    incident_id=incident_id
                ))
            elif action == "update_case":
                priority = request.form.get("priority")
                status = request.form.get("status")
                assigned_to = request.form.get("assigned_to") or None
                message = request.form.get("message", "").strip()

                allowed_priorities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                allowed_statuses = [
                    "SUBMITTED",
                    "ACKNOWLEDGED",
                    "INVESTIGATING",
                    "ACTION REQUIRED",
                    "RESOLVED",
                    "CLOSED"
                ]

                if priority not in allowed_priorities:
                    return "Invalid priority.", 400

                if status not in allowed_statuses:
                    return "Invalid status.", 400

                # Ensure an assigned user is actually an administrator
                if assigned_to is not None:
                    admin = connection.execute("""
                        SELECT id
                        FROM users
                        WHERE id = ? AND role = 'admin'
                    """, (assigned_to,)).fetchone()

                    if admin is None:
                        return "Invalid administrator assignment.", 400

                connection.execute("""
                    UPDATE incidents
                    SET priority = ?,
                        status = ?,
                        assigned_to = ?
                    WHERE id = ?
                """, (
                    priority,
                    status,
                    assigned_to,
                    incident_id
                ))

                # Save a public update only when a message is provided
                if message:
                    connection.execute("""
                        INSERT INTO case_updates
                            (incident_id, admin_id, status, message)
                        VALUES (?, ?, ?, ?)
                    """, (
                        incident_id,
                        session["user_id"],
                        status,
                        message
                    ))

                connection.execute("""
                    INSERT INTO audit_logs
                        (user_id, incident_id, action)
                    VALUES (?, ?, ?)
                """, (
                    session["user_id"],
                    incident_id,
                    "Updated incident case"
                ))

                connection.commit()

                return redirect(url_for(
                    "admin_case",
                    incident_id=incident_id
                ))

            else:
                return "Invalid form action.", 400

        # Load evidence
        evidence = connection.execute("""
        SELECT
        id,
        original_filename,
        file_type,
        file_size,
        file_hash,
        uploaded_at
        FROM evidence
        WHERE incident_id = ?
        ORDER BY id DESC
        """, (incident_id,)).fetchall()

        # Load public case updates
        updates = connection.execute("""
            SELECT
                case_updates.status,
                case_updates.message,
                case_updates.created_at,
                users.name AS admin_name
            FROM case_updates
            JOIN users ON case_updates.admin_id = users.id
            WHERE case_updates.incident_id = ?
            ORDER BY case_updates.id DESC
        """, (incident_id,)).fetchall()

        # Load private investigation notes
        notes = connection.execute("""
            SELECT
                internal_notes.note,
                internal_notes.created_at,
                users.name AS admin_name
            FROM internal_notes
            JOIN users ON internal_notes.admin_id = users.id
            WHERE internal_notes.incident_id = ?
            ORDER BY internal_notes.id DESC
        """, (incident_id,)).fetchall()

        # Load administrator list for assignment
        admins = connection.execute("""
            SELECT id, name, email
            FROM users
            WHERE role = 'admin'
            ORDER BY name
        """).fetchall()

        return render_template(
            "admin_case.html",
            incident=incident,
            evidence=evidence,
            updates=updates,
            notes=notes,
            admins=admins
        )

    finally:
        connection.close()


@app.route("/admin/evidence/<int:evidence_id>")
def admin_view_evidence(evidence_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not current_user_is_admin(session.get("user_id")):
        return "Access denied. Admin privileges required.", 403

    # Evidence is held only inside the sandbox VM; it is deliberately not
    # downloadable to this system.
    return (
        "Evidence is stored only in the isolated sandbox and cannot be "
        "downloaded to this system. Use Prepare for Sandbox instead.",
        410
    )


@app.route("/admin/evidence/<int:evidence_id>/prepare-export", methods=["POST"])
def admin_prepare_evidence_export(evidence_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    if not current_user_is_admin(session.get("user_id")):
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()

    try:
        evidence = connection.execute("""
            SELECT incident_id, stored_filename, original_filename, file_hash
            FROM evidence
            WHERE id = ?
        """, (evidence_id,)).fetchone()
    finally:
        connection.close()

    if evidence is None:
        return "Evidence not found.", 404

    vault_id = evidence["stored_filename"]

    # Old records (uuid + extension) were stored on this machine before the
    # sandbox vault existed. They cannot be released from the VM.
    if "." in vault_id:
        return (
            "This evidence was uploaded before the sandbox vault was "
            "introduced and is not in the sandbox. Ask the reporter to "
            "resubmit it.",
            410
        )

    try:
        result = release_evidence_in_sandbox(vault_id, evidence["file_hash"])
    except SandboxError:
        app.logger.exception("Sandbox release failed")
        return (
            "The sandbox could not release this evidence. Check that the "
            "VM is running and see the Flask terminal logs.",
            502
        )

    return (
        f"Case {evidence['incident_id']}: Evidence {evidence_id} verified "
        f"inside the sandbox. Status: {result.get('status')}. "
        f"Location in VM: {result.get('path')}"
    ), 200

# ADMIN AUDIT LOGS

@app.route("/admin/audit-logs")
def admin_audit_logs():

    # Login check
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Admin access check
    if not current_user_is_admin(session.get("user_id")):
        return "Access denied. Admin privileges required.", 403

    connection = get_db_connection()

    logs = connection.execute("""
        SELECT
            audit_logs.id,
            audit_logs.action,
            audit_logs.timestamp,
            audit_logs.incident_id,
            users.name AS user_name,
            incidents.case_id
        FROM audit_logs
        LEFT JOIN users
            ON audit_logs.user_id = users.id
        LEFT JOIN incidents
            ON audit_logs.incident_id = incidents.id
        ORDER BY audit_logs.id DESC
    """).fetchall()

    connection.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )
  


# LOGOUT 

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# RUN APPLICATION

if __name__ == "__main__":
    app.run(debug=False)