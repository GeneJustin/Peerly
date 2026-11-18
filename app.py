import os
import re
from datetime import datetime, timezone
from functools import wraps
from types import SimpleNamespace

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from supabase import create_client, Client
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")

app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di environment variables")

app.config.update(
    SESSION_TYPE="filesystem",
    SESSION_FILE_DIR="/tmp/flask_session",
    SESSION_PERMANENT=True,
    SESSION_USE_SIGNER=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)

Session(app)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_PUBLISHABLE_KEY = os.getenv("SUPABASE_PUBLISHABLE_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not all([SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY]):
    raise RuntimeError("SUPABASE_URL dan SUPABASE_SERVICE_ROLE_KEY wajib diisi di .env")

USERNAME_RE = re.compile(r"^[a-z0-9_.]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DUMMY_HASH = generate_password_hash("peerly-dummy-password")

PUBLIC_PAGES = {"login", "register"}
PROTECTED_PAGES = {
    "dashboard", "profil", "cari-siswa", "cari-tutor",
    "materi", "notifikasi", "poin", "progress", "sesi",
}


def db_client() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


def json_error(message, status=400):
    return jsonify({"error": str(message)}), status


def get_profile(user_id):
    result = db_client().table("profiles").select("*").eq("id", user_id).maybe_single().execute()
    data = result.data if result else None
    if data:
        data.pop("password_hash", None)
    return data


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    try:
        profile = get_profile(user_id)
    except Exception:
        return None
    if not profile:
        session.clear()
        return None
    return SimpleNamespace(**profile)


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return json_error("Sesi login tidak ditemukan atau sudah kedaluwarsa. Silakan masuk kembali.", 401)
        return fn(user, *args, **kwargs)
    return wrapper


def start_session(user_id):
    session.clear()
    session["user_id"] = user_id
    session.permanent = True


@app.after_request
def no_store(response):
    if request.path == "/" or request.path.startswith(("/pages/", "/api/")):
        response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/api/config")
def public_config():
    return jsonify({
        "supabaseUrl": SUPABASE_URL,
        "supabasePublishableKey": SUPABASE_PUBLISHABLE_KEY
    })


@app.get("/")
def home():
    if current_user():
        return redirect(url_for("page", page="dashboard"))
    return render_template("index.html")


@app.get("/index.html")
def index_alias():
    return redirect(url_for("home"))


@app.get("/pages/<page>")
def page(page):
    if page.endswith(".html"):
        return redirect(url_for("page", page=page[:-5]))

    if page not in PUBLIC_PAGES | PROTECTED_PAGES:
        return "Halaman tidak ditemukan", 404

    user = current_user()
    if page in PUBLIC_PAGES and user:
        return redirect(url_for("page", page="dashboard"))
    if page in PROTECTED_PAGES and not user:
        return redirect(url_for("page", page="login"))
    return render_template(f"pages/{page}.html")



@app.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    role = data.get("role")

    if not name or not username or not email or not password:
        return json_error("Nama, username, email, dan password wajib diisi.")
    if not USERNAME_RE.match(username):
        return json_error("Username 3-30 karakter, hanya huruf kecil, angka, titik, dan underscore.")
    if not EMAIL_RE.match(email) or len(email) > 254:
        return json_error("Format email tidak valid.")
    if len(password) < 6:
        return json_error("Password minimal 6 karakter.")
    if role not in ("siswa", "tutor"):
        return json_error("Role harus siswa atau tutor.")

    try:
        db = db_client()

        if db.table("profiles").select("id").eq("username", username).limit(1).execute().data:
            return json_error("Username sudah dipakai. Silakan pilih yang lain.", 409)
        if db.table("profiles").select("id").eq("email", email).limit(1).execute().data:
            return json_error("Email sudah terdaftar. Silakan masuk.", 409)

        row = {
            "full_name": name,
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": role,
        }
        try:
            inserted = db.table("profiles").insert(row).execute().data
        except Exception as exc:
            msg = str(exc).lower()
            if "duplicate" in msg or "23505" in msg:
                if "email" in msg:
                    return json_error("Email sudah terdaftar. Silakan masuk.", 409)
                return json_error("Username sudah dipakai. Silakan pilih yang lain.", 409)
            raise

        profile = inserted[0]
        profile.pop("password_hash", None)

        start_session(profile["id"])
        return jsonify({"user": profile, "logged_in": True}), 201
    except Exception as exc:
        return json_error("Registrasi gagal: " + str(exc), 500)


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip().lower()
    password = data.get("password") or ""
    if not identifier or not password:
        return json_error("Email/username dan password wajib diisi.")

    column = "email" if "@" in identifier else "username"

    try:
        result = db_client().table("profiles").select("*").eq(column, identifier).limit(1).execute()
        row = result.data[0] if result.data else None
    except Exception as exc:
        return json_error("Gagal menghubungi database: " + str(exc), 500)

    stored_hash = (row or {}).get("password_hash") or DUMMY_HASH
    valid = check_password_hash(stored_hash, password)
    if not row or not row.get("password_hash") or not valid:
        return json_error("Email/username atau password salah.", 401)

    row.pop("password_hash", None)
    start_session(row["id"])
    return jsonify({"user": row, "logged_in": True})


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"success": True})


@app.get("/api/auth/me")
@login_required
def me(user):
    profile = get_profile(user.id)
    if not profile:
        return json_error("Profil Peerly tidak ditemukan.", 404)
    return jsonify({"user": profile})



def parse_ts(value):
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def is_upcoming(s):
    ts = parse_ts(s.get("scheduled_at"))
    return s.get("status") == "confirmed" and ts is not None and ts > datetime.now(timezone.utc)


def lookup_names(db, table, column, ids):
    ids = list({i for i in ids if i})
    if not ids:
        return {}
    rows = db.table(table).select(f"id,{column}").in_("id", ids).execute().data or []
    return {r["id"]: r[column] for r in rows}


@app.get("/api/dashboard")
@login_required
def dashboard_data(user):
    try:
        db = db_client()
        profile = get_profile(user.id)
        if not profile:
            return json_error("Profil belum tersedia.", 404)

        role = profile.get("role")

        if role == "siswa":
            sessions = db.table("sessions").select("id,status,scheduled_at,duration_min,mode,topik,subject_id,tutor_id").eq("siswa_id", user.id).order("scheduled_at", desc=False).execute().data or []
            progress = db.table("learning_progress").select("id,subject_id,mastery,created_at,topik").eq("siswa_id", user.id).order("created_at", desc=True).execute().data or []

            subject_map = lookup_names(db, "subjects", "name", [r.get("subject_id") for r in sessions + progress])
            tutor_map = lookup_names(db, "profiles", "full_name", [s.get("tutor_id") for s in sessions])
            for s in sessions:
                s["mata_pelajaran"] = subject_map.get(s.get("subject_id"), "Mata pelajaran")
                s["tutor_name"] = tutor_map.get(s.get("tutor_id"), "Tutor")

            grouped = {}
            for row in progress:
                if row.get("subject_id"):
                    grouped.setdefault(row["subject_id"], []).append(float(row.get("mastery") or 0))
            progress_summary = [
                {
                    "mata_pelajaran": subject_map.get(sid, "Mata pelajaran"),
                    "avg_mastery": round(sum(vals) / len(vals), 1),
                    "entries": len(vals),
                }
                for sid, vals in grouped.items()
            ]

            return jsonify({
                "user": profile,
                "stats": {
                    "completed": sum(s.get("status") == "completed" for s in sessions),
                    "pending": sum(s.get("status") == "pending" for s in sessions),
                    "tracked_subjects": len(progress_summary),
                    "avg_mastery": round(sum(x["avg_mastery"] for x in progress_summary) / len(progress_summary), 1) if progress_summary else None,
                },
                "upcoming": [s for s in sessions if is_upcoming(s)][:3],
                "progress": progress_summary,
            })

        sessions = db.table("sessions").select("id,status,scheduled_at,duration_min,mode,topik,subject_id,siswa_id").eq("tutor_id", user.id).order("scheduled_at", desc=False).execute().data or []
        subject_map = lookup_names(db, "subjects", "name", [s.get("subject_id") for s in sessions])
        siswa_map = lookup_names(db, "profiles", "full_name", [s.get("siswa_id") for s in sessions])
        for s in sessions:
            s["mata_pelajaran"] = subject_map.get(s.get("subject_id"), "Mata pelajaran")
            s["siswa_name"] = siswa_map.get(s.get("siswa_id"), "Siswa")

        points_rows = db.table("tutor_points_summary").select("points,hours_taught,tier").eq("tutor_id", user.id).execute().data or []
        point_data = points_rows[0] if points_rows else {"points": 0, "hours_taught": 0, "tier": "Starter"}
        feedback = db.table("feedbacks").select("rating").eq("to_user_id", user.id).execute().data or []
        ratings = [int(x["rating"]) for x in feedback if x.get("rating") is not None]
        hours = float(point_data.get("hours_taught") or 0)
        tier_steps = [(5, "Bronze"), (20, "Silver"), (50, "Gold"), (100, "Platinum")]
        next_tier = next(({"name": name, "need": round(max(0, threshold - hours), 1), "threshold": threshold} for threshold, name in tier_steps if hours < threshold), {"name": "Max", "need": 0, "threshold": 100})
        pending = [s for s in sessions if s.get("status") == "pending"]

        return jsonify({
            "user": profile,
            "stats": {
                "points": int(point_data.get("points") or 0),
                "hours_taught": hours,
                "completed": sum(s.get("status") == "completed" for s in sessions),
                "rating": round(sum(ratings) / len(ratings), 1) if ratings else None,
                "rating_count": len(ratings),
                "tier": point_data.get("tier", "Starter"),
            },
            "pending_count": len(pending),
            "pending_sessions": pending[:3],
            "upcoming": [s for s in sessions if is_upcoming(s)][:3],
            "next_tier": next_tier,
        })
    except Exception as exc:
        return json_error("Gagal memuat dashboard: " + str(exc), 500)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG") == "1")
