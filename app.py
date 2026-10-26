from dotenv import load_dotenv
load_dotenv()  
import os
import re
import secrets
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from smtplib import SMTP, SMTP_SSL, SMTPException
from email.message import EmailMessage
from urllib.parse import quote_plus, unquote
from uuid import uuid4

from bson import ObjectId
from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

ROOT = Path(__file__).resolve().parent
FRONTEND_DIST = ROOT / "FictionFlix-Codex-Setup-FIXED" / "dist"
UPLOAD_FOLDER = Path(os.environ.get("UPLOAD_FOLDER", ROOT / "uploads"))

app = Flask(__name__, static_folder="img", static_url_path="/img")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
is_production = os.environ.get("APP_ENV") == "production"
secret_key = os.environ.get("FLASK_SECRET_KEY")
if is_production and not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY must be set when APP_ENV=production.")

app.config.update(
    SECRET_KEY=secret_key or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=is_production,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
)

def normalize_mongodb_uri(uri):
    if not uri or "://" not in uri:
        return uri
    prefix, rest = uri.split("://", 1)
    if prefix not in {"mongodb", "mongodb+srv"} or "@" not in rest:
        return uri

    user_info, separator, host_and_options = rest.rpartition("@")
    if not separator or ":" not in user_info:
        return uri

    username, password = user_info.split(":", 1)
    encoded_username = quote_plus(unquote(username))
    encoded_password = quote_plus(unquote(password))
    return f"{prefix}://{encoded_username}:{encoded_password}@{host_and_options}"


MONGO_URI = normalize_mongodb_uri(os.environ.get("MONGO_URI"))
app.config["MONGO_URI"] = MONGO_URI
USE_MONGODB = bool(MONGO_URI)
DATABASE_PATH = os.environ.get("DATABASE_PATH", str(ROOT / "fictionflix.sqlite3"))
if USE_MONGODB:
    client = MongoClient(app.config["MONGO_URI"], serverSelectionTimeoutMS=5000)
    db = client["fictionflix_db"]
    users_collection = db["users"]
else:
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                preferred_language TEXT NOT NULL DEFAULT 'hi',
                content_preference TEXT NOT NULL DEFAULT 'horror-mystery',
                profile_image TEXT NOT NULL DEFAULT '',
                email_verified INTEGER NOT NULL DEFAULT 1
            )
        """)
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(users)").fetchall()
        }
        if "role" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'"
            )
        if "preferred_language" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN preferred_language TEXT NOT NULL DEFAULT 'hi'"
            )
        if "content_preference" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN content_preference TEXT NOT NULL DEFAULT 'horror-mystery'"
            )
        if "profile_image" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN profile_image TEXT NOT NULL DEFAULT ''"
            )
        if "email_verified" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"
            )
        connection.commit()

with closing(sqlite3.connect(DATABASE_PATH)) as connection:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS content (
            collection TEXT NOT NULL,
            id TEXT NOT NULL,
            data TEXT NOT NULL,
            PRIMARY KEY (collection, id)
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS user_library (
            user_id TEXT NOT NULL,
            story_id TEXT NOT NULL,
            title TEXT NOT NULL,
            poster TEXT NOT NULL DEFAULT '',
            genre TEXT NOT NULL DEFAULT '',
            mode TEXT NOT NULL DEFAULT '',
            beat INTEGER NOT NULL DEFAULT 1,
            saved INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, story_id)
        )
    """)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS user_library_updated_idx ON user_library (user_id, updated_at DESC)"
    )
    connection.commit()

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_PASSWORD_LENGTH = 128
ROLE_CHOICES = frozenset({"user", "member", "team", "owner", "admin"})
IMAGE_TYPES = {
    "image/avif": "avif",
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
}
password_reset_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
email_verification_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"status": "error", "message": "The submitted content is too large."}), 413


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(allowed_roles):
    allowed_roles = frozenset(allowed_roles)

    def decorate(view):
        @wraps(view)
        def wrapped_view(*args, **kwargs):
            if "user_id" not in session:
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            try:
                role = get_current_role()
            except (PyMongoError, sqlite3.Error, ValueError):
                return database_error()
            if role is None:
                session.clear()
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            session["role"] = role
            if role not in allowed_roles:
                return jsonify({
                    "status": "error",
                    "message": "This account does not have permission to access this resource.",
                }), 403
            return view(*args, **kwargs)

        return wrapped_view

    return decorate


def studio_required(view):
    return role_required({"owner", "team", "admin"})(view)


def owner_required(view):
    return role_required({"owner", "admin"})(view)


def auth_payload():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return None, (jsonify({"status": "error", "message": "Invalid request."}), 400)
    return payload, None


def validate_identity(name, email):
    name = name.strip() if isinstance(name, str) else ""
    email = email.strip().lower() if isinstance(email, str) else ""
    if not name or len(name) > 80:
        return None, None, "Name must be between 1 and 80 characters."
    if len(email) > 254 or not EMAIL_PATTERN.fullmatch(email):
        return None, None, "Enter a valid email address."
    return name, email, None


def database_error():
    app.logger.exception("Database operation failed")
    return jsonify({"status": "error", "message": "Database is unavailable. Please try again."}), 503


def public_user(name, email, user_id, role, profile_image=""):
    if not isinstance(role, str) or role not in ROLE_CHOICES:
        role = "user"
    return {
        "id": str(user_id),
        "name": name,
        "email": email,
        "role": role,
        "profileImage": profile_image,
    }


def configured_owner_email():
    return os.environ.get("OWNER_EMAIL", "").strip().lower()


def dashboard_path_for_role(role):
    return {
        "member": "/dashboard/member",
        "team": "/dashboard/team",
        "owner": "/dashboard/owner",
        "admin": "/dashboard/admin",
    }.get(role, "/")


def valid_owner_setup_token(token):
    expected = os.environ.get("OWNER_SETUP_TOKEN", "")
    return (
        bool(expected)
        and isinstance(token, str)
        and secrets.compare_digest(token, expected)
    )


def set_user_session(user):
    session.clear()
    session.permanent = True
    session["user_id"] = str(user["id"])
    session["user"] = {
        "name": user["name"],
        "email": user["email"],
        "profile_image": user.get("profileImage", ""),
    }
    session["role"] = user.get("role", "user")


def get_current_role():
    user_id = session.get("user_id")
    if not user_id:
        return None
    if USE_MONGODB:
        user = users_collection.find_one({"_id": ObjectId(user_id)}, {"role": 1})
        role = user.get("role", "user") if user else None
        return role if isinstance(role, str) and role in ROLE_CHOICES else "user"
    with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
        row = connection.execute("SELECT role FROM users WHERE id = ?", (int(user_id),)).fetchone()
    role = row[0] if row else None
    return role if isinstance(role, str) and role in ROLE_CHOICES else "user"


def content_rows(collection, published_only=False):
    with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
        rows = connection.execute(
            "SELECT data FROM content WHERE collection = ? ORDER BY rowid",
            (collection,),
        ).fetchall()
    items = [json.loads(row[0]) for row in rows]
    if published_only and collection == "shows":
        items = [item for item in items if item.get("status") == "Published"]
    if published_only and collection == "categories":
        items = [item for item in items if item.get("active") is not False]
    return items


def send_email_message(message):
    mail_server = os.environ.get("MAIL_SERVER")
    sender = os.environ.get("MAIL_DEFAULT_SENDER")
    if not mail_server or not sender:
        raise RuntimeError("Email delivery is not configured.")

    port = int(os.environ.get("MAIL_PORT", "587"))
    if os.environ.get("MAIL_USE_SSL", "").lower() == "true":
        with SMTP_SSL(mail_server, port, timeout=10) as smtp:
            username = os.environ.get("MAIL_USERNAME")
            if username:
                smtp.login(username, os.environ["MAIL_PASSWORD"])
            smtp.send_message(message)
    else:
        with SMTP(mail_server, port, timeout=10) as smtp:
            if os.environ.get("MAIL_USE_TLS", "true").lower() == "true":
                smtp.starttls()
            username = os.environ.get("MAIL_USERNAME")
            if username:
                smtp.login(username, os.environ["MAIL_PASSWORD"])
            smtp.send_message(message)


def public_base_url():
    return (
        os.environ.get("PUBLIC_URL")
        or os.environ.get("RENDER_EXTERNAL_URL")
        or request.url_root.rstrip("/")
    )


def send_password_reset_email(email, token):
    sender = os.environ.get("MAIL_DEFAULT_SENDER")
    message = EmailMessage()
    message["Subject"] = "Reset your FictionFlix password"
    message["From"] = sender or ""
    message["To"] = email
    message.set_content(
        "Use this link within one hour to reset your FictionFlix password:\n"
        f"{public_base_url()}/reset-password?token={token}"
    )
    send_email_message(message)


def send_account_verification_email(name, email, token):
    sender = os.environ.get("MAIL_DEFAULT_SENDER")
    message = EmailMessage()
    message["Subject"] = "Verify your FictionFlix email"
    message["From"] = sender or ""
    message["To"] = email
    message.set_content(
        f"Hi {name},\n\n"
        "Verify your email address within 24 hours to activate your FictionFlix account:\n"
        f"{public_base_url()}/api/auth/verify-email?token={token}\n\n"
        "If you did not create this account, you can ignore this email."
    )
    send_email_message(message)


@app.route("/")
def home():
    if (FRONTEND_DIST / "index.html").is_file():
        return send_from_directory(FRONTEND_DIST, "index.html")
    if "user_id" in session:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))


@app.route("/assets/<path:filename>")
def frontend_assets(filename):
    return send_from_directory(FRONTEND_DIST / "assets", filename)


@app.route("/manifest.webmanifest")
@app.route("/sw.js")
def frontend_public_files():
    filename = request.path.rsplit("/", 1)[-1]
    return send_from_directory(FRONTEND_DIST, filename)


@app.route("/uploads/<path:filename>")
def uploaded_artwork(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route("/login")
def login():
    if "user_id" in session:
        try:
            role = get_current_role()
        except (PyMongoError, sqlite3.Error, ValueError):
            return database_error()
        if role is None:
            session.clear()
            return render_template("Login.html")
        return redirect(dashboard_path_for_role(role))
    return render_template("Login.html")


@app.route("/profile")
@app.route("/User.html")
@login_required
def profile():
    return render_template("User.html", user=session["user"])


@app.route("/api/auth/signup", methods=["POST"])
def signup():
    payload, error = auth_payload()
    if error:
        return error

    name, email, validation_error = validate_identity(
        payload.get("name"), payload.get("email")
    )
    password = payload.get("password")
    if validation_error:
        return jsonify({"status": "error", "message": validation_error}), 400
    if not isinstance(password, str) or not 8 <= len(password) <= MAX_PASSWORD_LENGTH:
        return jsonify({
            "status": "error",
            "message": f"Password must be between 8 and {MAX_PASSWORD_LENGTH} characters.",
        }), 400

    role = "user"
    if email == configured_owner_email():
        if not valid_owner_setup_token(payload.get("ownerSetupToken")):
            return jsonify({
                "status": "error",
                "message": "A valid owner setup token is required for this account.",
            }), 403
        try:
            if USE_MONGODB:
                owner_exists = users_collection.count_documents({"role": "owner"}) > 0
            else:
                with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                    owner_exists = connection.execute(
                        "SELECT 1 FROM users WHERE role = 'owner' LIMIT 1"
                    ).fetchone() is not None
        except (PyMongoError, sqlite3.Error):
            return database_error()
        if owner_exists:
            return jsonify({"status": "error", "message": "The FictionFlix owner account is already set up."}), 409
        role = "owner"
    password_hash = generate_password_hash(password)
    try:
        if USE_MONGODB:
            users_collection.create_index("email", unique=True)
            result = users_collection.insert_one({
                "name": name,
                "email": email,
                "password_hash": password_hash,
                "created_at": datetime.now(timezone.utc),
                "role": role,
                "email_verified": False,
            })
            user_id = str(result.inserted_id)
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute(
                    "INSERT INTO users (name, email, password_hash, created_at, role, email_verified) VALUES (?, ?, ?, ?, ?, 0)",
                    (name, email, password_hash, datetime.now(timezone.utc).isoformat(), role),
                )
                user_id = str(cursor.lastrowid)
                connection.commit()
    except (DuplicateKeyError, sqlite3.IntegrityError):
        return jsonify({"status": "error", "message": "An account with this email already exists."}), 409
    except (PyMongoError, sqlite3.Error):
        return database_error()

    token = email_verification_serializer.dumps(
        {"user_id": user_id, "email": email},
        salt="fictionflix-email-verification",
    )
    try:
        send_account_verification_email(name, email, token)
    except RuntimeError as error:
        app.logger.warning("Verification email is unavailable: %s", error)
        return jsonify({
            "status": "error",
            "message": "Account created, but email delivery is not configured. Contact the site owner to enable verification emails.",
            "code": "verification_email_unavailable",
        }), 503
    except (OSError, SMTPException, KeyError, ValueError):
        app.logger.exception("Account verification email could not be sent")
        return jsonify({
            "status": "error",
            "message": "Account created, but the verification email could not be sent. Try resending the verification email.",
            "code": "verification_email_failed",
        }), 503

    return jsonify({
        "status": "success",
        "message": "Account created. Check your email for a verification link before signing in.",
    }), 201


@app.route("/api/auth/verify-email", methods=["GET", "POST"])
def verify_email():
    if request.method == "GET":
        token = request.args.get("token")
    else:
        payload, error = auth_payload()
        if error:
            return error
        token = payload.get("token")
    if not isinstance(token, str):
        if request.method == "GET":
            return redirect(url_for("login", verification="invalid"))
        return jsonify({"status": "error", "message": "A valid verification link is required."}), 400
    try:
        identity = email_verification_serializer.loads(
            token,
            salt="fictionflix-email-verification",
            max_age=24 * 60 * 60,
        )
        user_id = identity.get("user_id")
        email = identity.get("email")
        if not isinstance(user_id, str) or not isinstance(email, str):
            raise BadSignature("Invalid verification identity.")
        if USE_MONGODB:
            result = users_collection.update_one(
                {"_id": ObjectId(user_id), "email": email, "email_verified": False},
                {"$set": {"email_verified": True}},
            )
            verified = result.modified_count == 1
            existing = users_collection.find_one(
                {"_id": ObjectId(user_id), "email": email},
                {"email_verified": 1},
            )
            already_verified = bool(existing and existing.get("email_verified", True))
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute(
                    "UPDATE users SET email_verified = 1 WHERE id = ? AND email = ? AND email_verified = 0",
                    (int(user_id), email),
                )
                verified = cursor.rowcount == 1
                existing = connection.execute(
                    "SELECT email_verified FROM users WHERE id = ? AND email = ?",
                    (int(user_id), email),
                ).fetchone()
                already_verified = bool(existing and existing[0])
                connection.commit()
    except (BadSignature, SignatureExpired, ValueError, TypeError):
        if request.method == "GET":
            return redirect(url_for("login", verification="invalid"))
        return jsonify({"status": "error", "message": "This verification link is invalid or expired."}), 400
    except (PyMongoError, sqlite3.Error):
        return database_error()
    if not verified and not already_verified:
        if request.method == "GET":
            return redirect(url_for("login", verification="invalid"))
        return jsonify({"status": "error", "message": "This account could not be verified."}), 404
    if request.method == "GET":
        return redirect(url_for("login", verification="success"))
    return jsonify({"status": "success", "message": "Email verified. You can now sign in."})


@app.route("/api/auth/verify-email/resend", methods=["POST"])
def resend_verification_email():
    payload, error = auth_payload()
    if error:
        return error
    email = payload.get("email")
    email = email.strip().lower() if isinstance(email, str) else ""
    if not EMAIL_PATTERN.fullmatch(email):
        return jsonify({"status": "error", "message": "Enter a valid email address."}), 400
    try:
        if USE_MONGODB:
            user = users_collection.find_one(
                {"email": email, "email_verified": False},
                {"_id": 1, "name": 1, "email": 1},
            )
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                connection.row_factory = sqlite3.Row
                user = connection.execute(
                    "SELECT id, name, email FROM users WHERE email = ? AND email_verified = 0",
                    (email,),
                ).fetchone()
                user = dict(user) if user else None
        if user:
            user_id = str(user["_id"] if USE_MONGODB else user["id"])
            token = email_verification_serializer.dumps(
                {"user_id": user_id, "email": email},
                salt="fictionflix-email-verification",
            )
            send_account_verification_email(user["name"], email, token)
    except (PyMongoError, sqlite3.Error):
        return database_error()
    except RuntimeError as error:
        app.logger.warning("Verification email is unavailable: %s", error)
        return jsonify({"status": "error", "message": "Email delivery is not configured. Contact the site owner."}), 503
    except (OSError, SMTPException, KeyError, ValueError):
        app.logger.exception("Verification email could not be resent")
        return jsonify({"status": "error", "message": "Could not send a verification email. Please try again later."}), 503
    return jsonify({
        "status": "success",
        "message": "If an unverified account exists for that email, a verification link has been sent.",
    })


@app.route("/api/auth/login", methods=["POST"])
def authenticate():
    payload, error = auth_payload()
    if error:
        return error

    email = payload.get("email")
    password = payload.get("password")
    email = email.strip().lower() if isinstance(email, str) else ""
    if not isinstance(password, str) or not email or len(password) > MAX_PASSWORD_LENGTH:
        return jsonify({"status": "error", "message": "Email or password is incorrect."}), 401

    try:
        if USE_MONGODB:
            user = users_collection.find_one({"email": email})
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    "SELECT id, name, email, password_hash, role, profile_image, email_verified FROM users WHERE email = ?",
                    (email,),
                ).fetchone()
                user = dict(row) if row else None
    except (PyMongoError, sqlite3.Error):
        return database_error()

    if not user or not user.get("password_hash") or not check_password_hash(user["password_hash"], password):
        return jsonify({"status": "error", "message": "Email or password is incorrect."}), 401
    if not user.get("email_verified", True):
        return jsonify({
            "status": "error",
            "message": "Please verify your email address before signing in.",
            "code": "email_not_verified",
        }), 403

    user_id = str(user["_id"] if USE_MONGODB else user["id"])
    role = user.get("role", "user")
    if not isinstance(role, str) or role not in ROLE_CHOICES:
        role = "user"
    public_profile = public_user(
        user["name"], user["email"], user_id, role, user.get("profile_image", "")
    )
    set_user_session(public_profile)
    return jsonify({"status": "success", "user": public_profile})


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "success"})


@app.route("/api/auth/me")
def current_user():
    user = session.get("user")
    if not user:
        return jsonify({"status": "error", "message": "Authentication required."}), 401
    try:
        role = get_current_role()
    except (PyMongoError, sqlite3.Error, ValueError):
        return database_error()
    if role is None:
        session.clear()
        return jsonify({"status": "error", "message": "Authentication required."}), 401
    session["role"] = role
    return jsonify({
        "status": "success",
        "user": {**user, "id": session["user_id"], "role": role},
    })


@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    payload, error = auth_payload()
    if error:
        return error

    name, email, validation_error = validate_identity(
        payload.get("name"), payload.get("email")
    )
    if validation_error:
        return jsonify({"status": "error", "message": validation_error}), 400

    try:
        if USE_MONGODB:
            result = users_collection.update_one(
                {"_id": ObjectId(session["user_id"])},
                {"$set": {"name": name, "email": email}},
            )
            user_found = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute(
                    "UPDATE users SET name = ?, email = ? WHERE id = ?",
                    (name, email, int(session["user_id"])),
                )
                user_found = cursor.rowcount == 1
                connection.commit()
    except (DuplicateKeyError, sqlite3.IntegrityError):
        return jsonify({"status": "error", "message": "An account with this email already exists."}), 409
    except (PyMongoError, sqlite3.Error, ValueError):
        return database_error()

    if not user_found:
        session.clear()
        return jsonify({"status": "error", "message": "Authentication required."}), 401

    session["user"] = {
        "name": name,
        "email": email,
        "profile_image": session["user"].get("profile_image", ""),
    }
    return jsonify({"status": "success", "user": session["user"]})


@app.route("/api/user/profile-image", methods=["POST"])
@login_required
def update_profile_image():
    image = request.files.get("file")
    if not image:
        return jsonify({"status": "error", "message": "Choose a profile picture."}), 400
    extension = IMAGE_TYPES.get(image.mimetype)
    if not extension:
        return jsonify({"status": "error", "message": "Use a PNG, JPG, WebP, or AVIF image."}), 400
    image.stream.seek(0, os.SEEK_END)
    image_size = image.stream.tell()
    image.stream.seek(0)
    if image_size == 0:
        return jsonify({"status": "error", "message": "Choose a non-empty profile picture."}), 400
    if image_size > 8 * 1024 * 1024:
        return jsonify({"status": "error", "message": "Profile pictures must be 8 MB or smaller."}), 413

    filename = f"profile-{uuid4().hex}.{extension}"
    saved_path = UPLOAD_FOLDER / filename
    try:
        UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        image.save(saved_path)
        profile_image = f"/uploads/{filename}"
        if USE_MONGODB:
            result = users_collection.update_one(
                {"_id": ObjectId(session["user_id"])},
                {"$set": {"profile_image": profile_image}},
            )
            user_found = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute(
                    "UPDATE users SET profile_image = ? WHERE id = ?",
                    (profile_image, int(session["user_id"])),
                )
                user_found = cursor.rowcount == 1
                connection.commit()
    except (PyMongoError, sqlite3.Error, ValueError):
        try:
            saved_path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Could not remove an uncommitted profile picture")
        return database_error()
    except OSError:
        try:
            saved_path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Could not remove a failed profile picture upload")
        app.logger.exception("Profile picture upload failed")
        return jsonify({"status": "error", "message": "Could not save the profile picture."}), 503

    if not user_found:
        try:
            saved_path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Could not remove an uncommitted profile picture")
        session.clear()
        return jsonify({"status": "error", "message": "Authentication required."}), 401

    previous_image = session.get("user", {}).get("profile_image", "")
    session["user"]["profile_image"] = profile_image
    if previous_image.startswith("/uploads/profile-"):
        previous_filename = previous_image.rsplit("/", 1)[-1]
        if re.fullmatch(r"profile-[0-9a-f]{32}\.(?:avif|jpg|png|webp)", previous_filename):
            try:
                (UPLOAD_FOLDER / previous_filename).unlink(missing_ok=True)
            except OSError:
                app.logger.exception("Could not remove the previous profile picture")
    return jsonify({"status": "success", "profileImage": profile_image})


@app.route("/api/user/preferences")
@login_required
def user_preferences():
    try:
        if USE_MONGODB:
            user = users_collection.find_one(
                {"_id": ObjectId(session["user_id"])},
                {"preferred_language": 1, "content_preference": 1},
            )
            if not user:
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            preferences = {
                "preferredLanguage": user.get("preferred_language", "hi"),
                "contentPreference": user.get("content_preference", "horror-mystery"),
            }
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                row = connection.execute(
                    "SELECT preferred_language, content_preference FROM users WHERE id = ?",
                    (int(session["user_id"]),),
                ).fetchone()
            if not row:
                session.clear()
                return jsonify({"status": "error", "message": "Authentication required."}), 401
            preferences = {"preferredLanguage": row[0], "contentPreference": row[1]}
    except (PyMongoError, sqlite3.Error, ValueError):
        return database_error()
    return jsonify({"status": "success", **preferences})


@app.route("/api/user/preferences", methods=["PUT"])
@login_required
def update_user_preferences():
    payload, error = auth_payload()
    if error:
        return error
    language = payload.get("preferredLanguage")
    preference = payload.get("contentPreference")
    if language not in {"hi", "en", "bn"} or preference not in {
        "horror-mystery",
        "micro-vertical-drama",
    }:
        return jsonify({"status": "error", "message": "Choose a supported language and content preference."}), 400
    try:
        if USE_MONGODB:
            result = users_collection.update_one(
                {"_id": ObjectId(session["user_id"])},
                {"$set": {
                    "preferred_language": language,
                    "content_preference": preference,
                }},
            )
            found = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute(
                    "UPDATE users SET preferred_language = ?, content_preference = ? WHERE id = ?",
                    (language, preference, int(session["user_id"])),
                )
                found = cursor.rowcount == 1
                connection.commit()
    except (PyMongoError, sqlite3.Error, ValueError):
        return database_error()
    if not found:
        session.clear()
        return jsonify({"status": "error", "message": "Authentication required."}), 401
    return jsonify({
        "status": "success",
        "preferredLanguage": language,
        "contentPreference": preference,
    })


@app.route("/api/user/library")
@login_required
def user_library():
    try:
        with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT story_id, title, poster, genre, mode, beat, saved, updated_at
                FROM user_library WHERE user_id = ? ORDER BY updated_at DESC
                """,
                (session["user_id"],),
            ).fetchall()
    except sqlite3.Error:
        return database_error()
    items = [{
        "storyId": row["story_id"],
        "title": row["title"],
        "poster": row["poster"],
        "genre": row["genre"],
        "mode": row["mode"],
        "beat": row["beat"],
        "saved": bool(row["saved"]),
        "updatedAt": row["updated_at"],
    } for row in rows]
    return jsonify({"status": "success", "items": items})


@app.route("/api/user/library/<story_id>", methods=["PUT", "DELETE"])
@login_required
def update_library_item(story_id):
    if not story_id or len(story_id) > 128:
        return jsonify({"status": "error", "message": "Choose a valid story."}), 400
    if request.method == "DELETE":
        try:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                connection.execute(
                    "DELETE FROM user_library WHERE user_id = ? AND story_id = ?",
                    (session["user_id"], story_id),
                )
                connection.commit()
        except sqlite3.Error:
            return database_error()
        return jsonify({"status": "success"})

    payload, error = auth_payload()
    if error:
        return error
    title = payload.get("title")
    poster = payload.get("poster", "")
    genre = payload.get("genre", "")
    saved = payload.get("saved")
    mode = payload.get("mode")
    beat = payload.get("beat")
    if not isinstance(title, str) or not title.strip() or len(title) > 200:
        return jsonify({"status": "error", "message": "A valid story title is required."}), 400
    if not isinstance(poster, str) or len(poster) > 2048 or not isinstance(genre, str) or len(genre) > 160:
        return jsonify({"status": "error", "message": "Story artwork or genre is invalid."}), 400
    if saved is not None and not isinstance(saved, bool):
        return jsonify({"status": "error", "message": "Saved status must be true or false."}), 400
    if mode is not None and mode not in {"", "book", "audio", "video"}:
        return jsonify({"status": "error", "message": "Choose a valid story format."}), 400
    if beat is not None and (not isinstance(beat, int) or isinstance(beat, bool) or not 1 <= beat <= 100000):
        return jsonify({"status": "error", "message": "Choose a valid StoryBeat."}), 400

    try:
        with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
            connection.row_factory = sqlite3.Row
            existing = connection.execute(
                "SELECT title, poster, genre, mode, beat, saved FROM user_library WHERE user_id = ? AND story_id = ?",
                (session["user_id"], story_id),
            ).fetchone()
            item = {
                "title": title.strip(),
                "poster": poster,
                "genre": genre,
                "mode": mode if mode is not None else existing["mode"] if existing else "",
                "beat": beat if beat is not None else existing["beat"] if existing else 1,
                "saved": int(saved if saved is not None else existing["saved"] if existing else False),
            }
            if not item["saved"] and not item["mode"]:
                connection.execute(
                    "DELETE FROM user_library WHERE user_id = ? AND story_id = ?",
                    (session["user_id"], story_id),
                )
                connection.commit()
                return jsonify({"status": "success", "item": None})
            updated_at = datetime.now(timezone.utc).isoformat()
            connection.execute(
                """
                INSERT INTO user_library
                    (user_id, story_id, title, poster, genre, mode, beat, saved, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id, story_id) DO UPDATE SET
                    title = excluded.title,
                    poster = excluded.poster,
                    genre = excluded.genre,
                    mode = excluded.mode,
                    beat = excluded.beat,
                    saved = excluded.saved,
                    updated_at = excluded.updated_at
                """,
                (
                    session["user_id"], story_id, item["title"], item["poster"],
                    item["genre"], item["mode"], item["beat"], item["saved"], updated_at,
                ),
            )
            connection.commit()
    except sqlite3.Error:
        return database_error()
    return jsonify({
        "status": "success",
        "item": {
            "storyId": story_id,
            **item,
            "saved": bool(item["saved"]),
            "updatedAt": updated_at,
        },
    })


@app.route("/api/studio/access")
def studio_access():
    if "user_id" not in session:
        return jsonify({"status": "success", "allowed": False, "user": None})
    try:
        role = get_current_role()
    except (PyMongoError, sqlite3.Error, ValueError):
        return database_error()
    if role is None:
        session.clear()
        return jsonify({"status": "success", "allowed": False, "user": None})
    session["role"] = role
    return jsonify({
        "status": "success",
        "allowed": role in {"owner", "team", "admin"},
        "user": {
            **session.get("user", {}),
            "id": session["user_id"],
            "role": role,
        },
    })


def dashboard_data(dashboard):
    user = session.get("user", {})
    return jsonify({
        "status": "success",
        "dashboard": dashboard,
        "user": {
            **user,
            "id": session["user_id"],
            "role": session["role"],
        },
    })


@app.route("/api/dashboard/member")
@role_required({"member", "owner", "admin"})
def member_dashboard():
    return dashboard_data("member")


@app.route("/api/dashboard/team")
@role_required({"team", "owner", "admin"})
def team_dashboard():
    return dashboard_data("team")


@app.route("/api/dashboard/owner")
@role_required({"owner", "admin"})
def owner_dashboard():
    return dashboard_data("owner")


@app.route("/api/dashboard/admin")
@role_required({"admin"})
def admin_dashboard():
    return dashboard_data("admin")


@app.route("/api/studio/users")
@owner_required
def studio_users():
    try:
        if USE_MONGODB:
            users = [
                public_user(user.get("name", ""), user["email"], user["_id"], user.get("role", "user"))
                for user in users_collection.find({}, {"name": 1, "email": 1, "role": 1})
            ]
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                connection.row_factory = sqlite3.Row
                rows = connection.execute("SELECT id, name, email, role FROM users ORDER BY created_at").fetchall()
                users = [public_user(row["name"], row["email"], row["id"], row["role"]) for row in rows]
    except (PyMongoError, sqlite3.Error):
        return database_error()
    return jsonify({"status": "success", "users": users})


@app.route("/api/studio/roles", methods=["PUT"])
@owner_required
def update_user_role():
    payload, error = auth_payload()
    if error:
        return error
    email = payload.get("email")
    role = payload.get("role")
    if not isinstance(email, str) or not isinstance(role, str) or role not in {"user", "member", "team", "admin"}:
        return jsonify({"status": "error", "message": "Choose a valid email and role."}), 400
    email = email.strip().lower()
    try:
        if USE_MONGODB:
            result = users_collection.update_one({"email": email}, {"$set": {"role": role}})
            found = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute("UPDATE users SET role = ? WHERE email = ?", (role, email))
                found = cursor.rowcount == 1
                connection.commit()
    except (PyMongoError, sqlite3.Error):
        return database_error()
    if not found:
        return jsonify({"status": "error", "message": "No account was found for that email."}), 404
    return jsonify({"status": "success"})


@app.route("/api/admin/update-role", methods=["PUT"])
@role_required({"admin"})
def admin_update_role():
    payload, error = auth_payload()
    if error:
        return error
    email = payload.get("email")
    role = payload.get("role")
    if not isinstance(email, str) or not isinstance(role, str) or role not in ROLE_CHOICES:
        return jsonify({"status": "error", "message": "Choose a valid email and role."}), 400
    email = email.strip().lower()
    try:
        if USE_MONGODB:
            result = users_collection.update_one({"email": email}, {"$set": {"role": role}})
            found = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute(
                    "UPDATE users SET role = ? WHERE email = ?",
                    (role, email),
                )
                found = cursor.rowcount == 1
                connection.commit()
    except (PyMongoError, sqlite3.Error):
        return database_error()
    if not found:
        return jsonify({"status": "error", "message": "No account was found for that email."}), 404
    return jsonify({"status": "success"})


@app.route("/api/studio/bootstrap-owner", methods=["POST"])
@login_required
def bootstrap_owner():
    payload, error = auth_payload()
    if error:
        return error
    email = session.get("user", {}).get("email", "").strip().lower()
    if email != configured_owner_email() or not valid_owner_setup_token(payload.get("token")):
        return jsonify({"status": "error", "message": "Owner email and setup token do not match."}), 403
    try:
        if USE_MONGODB:
            owner_exists = users_collection.count_documents({"role": "owner"}) > 0
            if owner_exists:
                return jsonify({"status": "error", "message": "The FictionFlix owner account is already set up."}), 409
            result = users_collection.update_one(
                {"_id": ObjectId(session["user_id"]), "email": email, "role": {"$ne": "owner"}},
                {"$set": {"role": "owner"}},
            )
            found = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                owner_exists = connection.execute(
                    "SELECT 1 FROM users WHERE role = 'owner' LIMIT 1"
                ).fetchone() is not None
                if owner_exists:
                    connection.rollback()
                    return jsonify({"status": "error", "message": "The FictionFlix owner account is already set up."}), 409
                cursor = connection.execute(
                    "UPDATE users SET role = 'owner' WHERE id = ? AND email = ? AND role != 'owner'",
                    (int(session["user_id"]), email),
                )
                found = cursor.rowcount == 1
                connection.commit()
    except (PyMongoError, sqlite3.Error, ValueError):
        return database_error()
    if not found:
        return jsonify({"status": "error", "message": "No eligible owner account was found."}), 404
    session["role"] = "owner"
    user = session["user"]
    return jsonify({
        "status": "success",
        "user": public_user(user["name"], user["email"], session["user_id"], "owner"),
    })


@app.route("/api/content/public")
def public_content():
    try:
        return jsonify({
            "status": "success",
            "stories": content_rows("shows", published_only=True),
            "categories": content_rows("categories", published_only=True),
        })
    except (sqlite3.Error, json.JSONDecodeError):
        return database_error()


@app.route("/api/content/managed")
@studio_required
def managed_content():
    try:
        return jsonify({
            "status": "success",
            "shows": content_rows("shows"),
            "categories": content_rows("categories"),
        })
    except (sqlite3.Error, json.JSONDecodeError):
        return database_error()


@app.route("/api/content/managed/<collection>", methods=["PUT"])
@studio_required
def replace_managed_content(collection):
    if collection not in {"shows", "categories"}:
        abort(404)
    payload, error = auth_payload()
    if error:
        return error
    items = payload.get("items")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        return jsonify({"status": "error", "message": "Content must be a list of objects."}), 400
    if any(
        not isinstance(item.get("id"), (str, int)) or isinstance(item.get("id"), bool)
        for item in items
    ):
        return jsonify({"status": "error", "message": "Every content item needs an ID."}), 400
    try:
        with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
            connection.execute("BEGIN")
            connection.execute("DELETE FROM content WHERE collection = ?", (collection,))
            connection.executemany(
                "INSERT INTO content (collection, id, data) VALUES (?, ?, ?)",
                [(collection, str(item["id"]), json.dumps(item, ensure_ascii=False)) for item in items],
            )
            connection.commit()
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "Content IDs must be unique."}), 409
    except sqlite3.Error:
        return database_error()
    return jsonify({"status": "success", "count": len(items)})


@app.route("/api/studio/uploads", methods=["POST"])
@studio_required
def upload_artwork():
    image = request.files.get("file")
    kind = request.form.get("kind")
    if not image or kind not in {"poster", "hero"}:
        return jsonify({"status": "error", "message": "Choose an image and artwork type."}), 400
    extension = IMAGE_TYPES.get(image.mimetype)
    if not extension:
        return jsonify({"status": "error", "message": "Use a PNG, JPG, WebP, or AVIF image."}), 400
    image.stream.seek(0, os.SEEK_END)
    image_size = image.stream.tell()
    image.stream.seek(0)
    if image_size > 8 * 1024 * 1024:
        return jsonify({"status": "error", "message": "Images must be 8 MB or smaller."}), 413
    try:
        UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        filename = f"{kind}-{uuid4().hex}.{extension}"
        image.save(UPLOAD_FOLDER / filename)
    except OSError:
        app.logger.exception("Artwork upload failed")
        return jsonify({"status": "error", "message": "Could not save artwork."}), 503
    return jsonify({"status": "success", "url": f"/uploads/{filename}"}), 201


@app.route("/api/auth/reset-password", methods=["POST"])
def request_password_reset():
    payload, error = auth_payload()
    if error:
        return error
    email = payload.get("email")
    email = email.strip().lower() if isinstance(email, str) else ""
    if not EMAIL_PATTERN.fullmatch(email):
        return jsonify({"status": "error", "message": "Enter a valid email address."}), 400
    try:
        if USE_MONGODB:
            user = users_collection.find_one({"email": email}, {"email": 1})
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                user = connection.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = password_reset_serializer.dumps(email, salt="fictionflix-password-reset")
            send_password_reset_email(email, token)
    except (PyMongoError, sqlite3.Error):
        return database_error()
    except RuntimeError as error:
        app.logger.warning("Password reset email is unavailable: %s", error)
        return jsonify({"status": "error", "message": "Password reset email is not configured. Contact the site owner."}), 503
    except (OSError, KeyError, ValueError):
        app.logger.exception("Password reset email could not be sent")
        return jsonify({"status": "error", "message": "Could not send a password reset email. Please try again later."}), 503
    return jsonify({"status": "success", "message": "If the account exists, a reset link has been sent."})


@app.route("/api/auth/reset-password/confirm", methods=["POST"])
def confirm_password_reset():
    payload, error = auth_payload()
    if error:
        return error
    token = payload.get("token")
    password = payload.get("password")
    if not isinstance(token, str) or not isinstance(password, str) or not 8 <= len(password) <= MAX_PASSWORD_LENGTH:
        return jsonify({"status": "error", "message": "Use a valid reset link and a password between 8 and 128 characters."}), 400
    try:
        email = password_reset_serializer.loads(
            token,
            salt="fictionflix-password-reset",
            max_age=3600,
        )
    except (BadSignature, SignatureExpired):
        return jsonify({"status": "error", "message": "This password reset link is invalid or expired."}), 400
    try:
        password_hash = generate_password_hash(password)
        if USE_MONGODB:
            result = users_collection.update_one({"email": email}, {"$set": {"password_hash": password_hash}})
            updated = result.matched_count == 1
        else:
            with closing(sqlite3.connect(DATABASE_PATH, timeout=10)) as connection:
                cursor = connection.execute("UPDATE users SET password_hash = ? WHERE email = ?", (password_hash, email))
                updated = cursor.rowcount == 1
                connection.commit()
    except (PyMongoError, sqlite3.Error):
        return database_error()
    if not updated:
        return jsonify({"status": "error", "message": "This account no longer exists."}), 404
    return jsonify({"status": "success"})


@app.route("/<path:frontend_path>")
def frontend_routes(frontend_path):
    if frontend_path.startswith("api/"):
        abort(404)
    if (FRONTEND_DIST / "index.html").is_file():
        return send_from_directory(FRONTEND_DIST, "index.html")
    abort(404)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
