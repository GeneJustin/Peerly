import os
import re
from datetime import datetime, timezone
from functools import wraps
from types import SimpleNamespace
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from supabase import create_client, Client
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")

app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur di environment variables")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
)

SUPABASE_URL = os.getenv("SUPABASE_URL")
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
# Halaman yang hanya boleh dibuka role tertentu.
ROLE_PAGES = {"cari-siswa": "tutor", "cari-tutor": "siswa", "progress": "siswa"}

# Tabel bank materi & kolom penulisnya (ubah di sini jika nama di database berbeda).
MATERIAL_TABLE = "materials"
MATERIAL_AUTHOR = "created_by"

LEVELS = ("SD", "SMP", "SMA")
MODES = ("online", "offline", "both")
LEARNING_STYLES = ("visual", "auditori", "kinestetik", "campuran")

# Tabel profil khusus role & kolom kuncinya (ubah di sini jika nama di database berbeda).
ROLE_TABLES = {"siswa": "student_profiles", "tutor": "tutor_profiles"}
ROLE_KEY = "user_id"
# siswa "learn" mata pelajaran, tutor "teach" mata pelajaran (tabel user_subjects).
ROLE_INTEREST = {"siswa": "learn", "tutor": "teach"}


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

    required_role = ROLE_PAGES.get(page)
    if required_role and user.role != required_role:
        return redirect(url_for("page", page="dashboard"))

    return render_template(f"pages/{page}.html")


# ---------------------------------------------------------------- Auth

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

        # Pengganti trigger handle_new_user(): siapkan baris profil khusus role.
        # Jika gagal, baris ini tetap dibuat saat pengguna menyimpan profil (PUT /api/profile).
        try:
            db.table(ROLE_TABLES[role]).upsert({ROLE_KEY: profile["id"]}, on_conflict=ROLE_KEY).execute()
        except Exception as exc:
            app.logger.warning("Gagal membuat baris %s: %s", ROLE_TABLES[role], exc)

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


# ---------------------------------------------------------------- Helper umum

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


def fetch_in(db, table, select, column, ids, extra=None):
    """Select ... where column in (ids), dipecah per 100 id agar URL tidak terlalu panjang."""
    ids = list({i for i in ids if i})
    rows = []
    for i in range(0, len(ids), 100):
        query = db.table(table).select(select).in_(column, ids[i:i + 100])
        if extra:
            query = extra(query)
        rows.extend(query.execute().data or [])
    return rows


def clean_text(value, max_len):
    if not isinstance(value, str):
        return None
    return value.strip()[:max_len] or None


# ---------------------------------------------------------------- Dashboard

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


# ---------------------------------------------------------------- Mata pelajaran & profil

@app.get("/api/subjects")
@login_required
def list_subjects(user):
    try:
        rows = db_client().table("subjects").select("id,name").order("name").execute().data or []
        return jsonify({"subjects": rows})
    except Exception as exc:
        return json_error("Gagal memuat mata pelajaran: " + str(exc), 500)


def load_full_profile(db, user_id):
    profile = get_profile(user_id)
    if not profile:
        return None
    role = profile.get("role")

    rows = db.table(ROLE_TABLES[role]).select("*").eq(ROLE_KEY, user_id).limit(1).execute().data or []
    extra = rows[0] if rows else {}

    subj = db.table("user_subjects").select("subject_id").eq("user_id", user_id).eq("interest", ROLE_INTEREST[role]).execute().data or []
    profile["subject_ids"] = [r["subject_id"] for r in subj]

    if role == "siswa":
        profile["jenjang"] = extra.get("jenjang")
        profile["kelas"] = extra.get("kelas")
    else:
        profile["teaching_levels"] = extra.get("teaching_levels") or []
        profile["experience_description"] = extra.get("experience_description")
        profile["verified"] = bool(extra.get("verified"))
    return profile


@app.get("/api/profile")
@login_required
def get_my_profile(user):
    try:
        profile = load_full_profile(db_client(), user.id)
        if not profile:
            return json_error("Profil Peerly tidak ditemukan.", 404)
        return jsonify({"profile": profile})
    except Exception as exc:
        return json_error("Gagal memuat profil: " + str(exc), 500)


@app.put("/api/profile")
@login_required
def update_my_profile(user):
    data = request.get_json(silent=True) or {}
    role = user.role

    mode = (data.get("mode_preference") or "").strip()
    if mode and mode not in MODES:
        return json_error("Preferensi mode tidak valid.")
    style = (data.get("gaya_belajar") or "").strip()
    if style and style not in LEARNING_STYLES:
        return json_error("Gaya belajar tidak valid.")

    base = {
        "phone": clean_text(data.get("phone"), 30),
        "location": clean_text(data.get("location"), 100),
        "bio": clean_text(data.get("bio"), 1000),
        "mode_preference": mode or None,
        "gaya_belajar": style or None,
        "availability": clean_text(data.get("availability"), 500),
    }

    if role == "siswa":
        jenjang = (data.get("jenjang") or "").strip()
        if jenjang and jenjang not in LEVELS:
            return json_error("Jenjang tidak valid.")
        role_row = {
            ROLE_KEY: user.id,
            "jenjang": jenjang or None,
            "kelas": clean_text(data.get("kelas"), 50),
        }
    else:
        levels = data.get("teaching_levels") or []
        if not isinstance(levels, list) or any(level not in LEVELS for level in levels):
            return json_error("Jenjang mengajar tidak valid.")
        role_row = {
            ROLE_KEY: user.id,
            "teaching_levels": [lv for lv in LEVELS if lv in levels],
            "experience_description": clean_text(data.get("experience_description"), 1000),
        }

    raw_ids = data.get("subject_ids") or []
    if not isinstance(raw_ids, list) or len(raw_ids) > 50:
        return json_error("Daftar mata pelajaran tidak valid.")

    try:
        db = db_client()

        valid = {str(r["id"]): r["id"] for r in db.table("subjects").select("id").execute().data or []}
        wanted = {str(i) for i in raw_ids if str(i) in valid}

        interest = ROLE_INTEREST[role]
        current_rows = db.table("user_subjects").select("subject_id").eq("user_id", user.id).eq("interest", interest).execute().data or []
        existing = {str(r["subject_id"]): r["subject_id"] for r in current_rows}

        to_add = [valid[s] for s in wanted - set(existing)]
        to_remove = [existing[s] for s in set(existing) - wanted]

        db.table("profiles").update(base).eq("id", user.id).execute()
        db.table(ROLE_TABLES[role]).upsert(role_row, on_conflict=ROLE_KEY).execute()
        if to_remove:
            db.table("user_subjects").delete().eq("user_id", user.id).eq("interest", interest).in_("subject_id", to_remove).execute()
        if to_add:
            db.table("user_subjects").insert([
                {"user_id": user.id, "subject_id": sid, "interest": interest} for sid in to_add
            ]).execute()

        return jsonify({"profile": load_full_profile(db, user.id)})
    except Exception as exc:
        return json_error("Gagal menyimpan profil: " + str(exc), 500)


# ---------------------------------------------------------------- Cari tutor (siswa)

@app.get("/api/tutors")
@login_required
def list_tutors(user):
    if user.role != "siswa":
        return json_error("Hanya siswa yang dapat mencari tutor.", 403)
    try:
        db = db_client()

        tutors = db.table("profiles").select("id,full_name,bio,location,mode_preference,availability").eq("role", "tutor").limit(500).execute().data or []
        ids = [t["id"] for t in tutors]

        tutor_rows = {
            r[ROLE_KEY]: r for r in fetch_in(
                db, ROLE_TABLES["tutor"], f"{ROLE_KEY},verified,experience_description,teaching_levels", ROLE_KEY, ids
            )
        }

        subjects_by_tutor = {}
        for r in fetch_in(db, "user_subjects", "user_id,subject_id,subjects(id,name)", "user_id", ids, lambda q: q.eq("interest", "teach")):
            subj = r.get("subjects")
            if subj:
                subjects_by_tutor.setdefault(r["user_id"], []).append({"id": subj["id"], "name": subj["name"]})

        ratings = {}
        for r in fetch_in(db, "feedbacks", "to_user_id,rating", "to_user_id", ids):
            if r.get("rating") is not None:
                ratings.setdefault(r["to_user_id"], []).append(float(r["rating"]))

        points = {r["tutor_id"]: r for r in fetch_in(db, "tutor_points_summary", "tutor_id,points,hours_taught,tier", "tutor_id", ids)}

        result = []
        for t in tutors:
            tid = t["id"]
            # Hanya tutor yang sudah melengkapi profil & punya mata pelajaran.
            if tid not in tutor_rows or not subjects_by_tutor.get(tid):
                continue
            extra = tutor_rows[tid]
            rs = ratings.get(tid, [])
            pt = points.get(tid, {})
            result.append({
                "id": tid,
                "full_name": t.get("full_name"),
                "bio": t.get("bio"),
                "location": t.get("location"),
                "mode_preference": t.get("mode_preference"),
                "availability": t.get("availability"),
                "verified": bool(extra.get("verified")),
                "experience_description": extra.get("experience_description"),
                "teaching_levels": extra.get("teaching_levels") or [],
                "subjects": subjects_by_tutor[tid],
                "rating": round(sum(rs) / len(rs), 1) if rs else None,
                "rating_count": len(rs),
                "hours_taught": float(pt.get("hours_taught") or 0),
                "points": int(pt.get("points") or 0),
                "tier": pt.get("tier", "Starter"),
            })

        me_row = db.table(ROLE_TABLES["siswa"]).select("jenjang,kelas").eq(ROLE_KEY, user.id).limit(1).execute().data or []
        learn = db.table("user_subjects").select("subject_id").eq("user_id", user.id).eq("interest", "learn").execute().data or []

        return jsonify({
            "tutors": result,
            "me": {
                "jenjang": me_row[0].get("jenjang") if me_row else None,
                "subject_ids": [r["subject_id"] for r in learn],
            },
        })
    except Exception as exc:
        return json_error("Gagal memuat tutor: " + str(exc), 500)


@app.post("/api/sessions")
@login_required
def create_session(user):
    if user.role != "siswa":
        return json_error("Hanya siswa yang dapat mengajukan sesi.", 403)

    data = request.get_json(silent=True) or {}
    tutor_id = data.get("tutor_id")
    subject_id = data.get("subject_id")
    jenjang = (data.get("jenjang") or "").strip()
    mode = (data.get("mode") or "").strip()
    scheduled = parse_ts(data.get("scheduled_at"))
    try:
        duration = int(data.get("duration_min"))
    except (TypeError, ValueError):
        return json_error("Durasi tidak valid.")

    if not tutor_id or not subject_id:
        return json_error("Tutor dan mata pelajaran wajib dipilih.")
    if jenjang not in LEVELS:
        return json_error("Jenjang tidak valid.")
    if mode not in ("online", "offline"):
        return json_error("Mode sesi harus online atau offline.")
    if not 30 <= duration <= 180:
        return json_error("Durasi sesi 30-180 menit.")
    if scheduled is None or scheduled <= datetime.now(timezone.utc):
        return json_error("Jadwal sesi harus berada di masa mendatang.")

    try:
        db = db_client()

        if not db.table("profiles").select("id").eq("id", tutor_id).eq("role", "tutor").limit(1).execute().data:
            return json_error("Tutor tidak ditemukan.", 404)

        teach = db.table("user_subjects").select("subject_id").eq("user_id", tutor_id).eq("interest", "teach").execute().data or []
        if str(subject_id) not in {str(r["subject_id"]) for r in teach}:
            return json_error("Tutor tidak mengajar mata pelajaran tersebut.")

        tp = db.table(ROLE_TABLES["tutor"]).select("teaching_levels").eq(ROLE_KEY, tutor_id).limit(1).execute().data or []
        levels = (tp[0].get("teaching_levels") if tp else None) or []
        if levels and jenjang not in levels:
            return json_error("Tutor belum mengajar jenjang tersebut.")

        row = {
            "siswa_id": user.id,
            "tutor_id": tutor_id,
            "subject_id": subject_id,
            "jenjang": jenjang,
            "topik": clean_text(data.get("topik"), 200),
            "scheduled_at": scheduled.isoformat(),
            "duration_min": duration,
            "mode": mode,
            "location_or_link": clean_text(data.get("location_or_link"), 300),
            "notes": clean_text(data.get("notes"), 1000),
        }
        inserted = db.table("sessions").insert(row).execute().data
        return jsonify({"session": inserted[0] if inserted else row}), 201
    except Exception as exc:
        return json_error("Gagal mengirim permintaan sesi: " + str(exc), 500)


# ---------------------------------------------------------------- Cari siswa (tutor)

@app.get("/api/students")
@login_required
def list_students(user):
    if user.role != "tutor":
        return json_error("Hanya tutor yang dapat mencari siswa.", 403)
    try:
        db = db_client()

        my_levels = set(
            ((db.table(ROLE_TABLES["tutor"]).select("teaching_levels").eq(ROLE_KEY, user.id).limit(1).execute().data or [{}])[0].get("teaching_levels")) or []
        )
        my_subjects = {
            str(r["subject_id"]) for r in
            db.table("user_subjects").select("subject_id").eq("user_id", user.id).eq("interest", "teach").execute().data or []
        }
        my_mode = getattr(user, "mode_preference", None)
        my_loc = (getattr(user, "location", None) or "").strip().lower()

        students = db.table("profiles").select("id,full_name,bio,location,mode_preference,availability,gaya_belajar").eq("role", "siswa").limit(500).execute().data or []
        ids = [s["id"] for s in students]

        student_rows = {r[ROLE_KEY]: r for r in fetch_in(db, ROLE_TABLES["siswa"], f"{ROLE_KEY},jenjang,kelas", ROLE_KEY, ids)}

        subjects_by_student = {}
        for r in fetch_in(db, "user_subjects", "user_id,subject_id,subjects(id,name)", "user_id", ids, lambda q: q.eq("interest", "learn")):
            subj = r.get("subjects")
            if subj:
                subjects_by_student.setdefault(r["user_id"], []).append({"id": subj["id"], "name": subj["name"]})

        result = []
        for s in students:
            sid = s["id"]
            extra = student_rows.get(sid, {})
            subjects = subjects_by_student.get(sid, [])

            score = 0
            overlap = [x for x in subjects if str(x["id"]) in my_subjects]
            if overlap:
                score += 40 + min(len(overlap) - 1, 2) * 5
            if extra.get("jenjang") and extra["jenjang"] in my_levels:
                score += 20
            s_mode = s.get("mode_preference")
            if s_mode and my_mode and (s_mode == my_mode or "both" in (s_mode, my_mode)):
                score += 10
            s_loc = (s.get("location") or "").strip().lower()
            if s_loc and my_loc and (s_loc in my_loc or my_loc in s_loc):
                score += 10

            result.append({
                "id": sid,
                "name": s.get("full_name"),
                "bio": s.get("bio"),
                "lokasi": s.get("location"),
                "mode_preference": s_mode,
                "availability": s.get("availability"),
                "gaya_belajar": s.get("gaya_belajar"),
                "jenjang": extra.get("jenjang"),
                "kelas": extra.get("kelas"),
                "subjects": subjects,
                "_score": score,
            })

        result.sort(key=lambda x: (-x["_score"], (x["name"] or "").lower()))
        return jsonify({"students": result})
    except Exception as exc:
        return json_error("Gagal memuat siswa: " + str(exc), 500)


# ---------------------------------------------------------------- Bank materi

def is_http_url(value):
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


@app.get("/api/materi")
@login_required
def list_materi(user):
    subject_id = request.args.get("subject_id") or None
    jenjang = request.args.get("jenjang") or None
    q = (request.args.get("q") or "").strip().lower()
    if jenjang and jenjang not in LEVELS:
        return json_error("Jenjang tidak valid.")

    try:
        db = db_client()
        query = db.table(MATERIAL_TABLE).select("id,title,description,subject_id,jenjang,created_at")
        if subject_id:
            query = query.eq("subject_id", subject_id)
        if jenjang:
            query = query.eq("jenjang", jenjang)
        rows = query.order("created_at", desc=True).limit(300).execute().data or []

        # Pencarian teks dilakukan di sini agar input tidak masuk ke sintaks filter PostgREST.
        if q:
            rows = [r for r in rows if q in (r.get("title") or "").lower() or q in (r.get("description") or "").lower()]

        subject_map = lookup_names(db, "subjects", "name", [r.get("subject_id") for r in rows])
        for r in rows:
            r["mata_pelajaran"] = subject_map.get(r.get("subject_id"), "-")
        return jsonify({"materi": rows})
    except Exception as exc:
        return json_error("Gagal memuat materi: " + str(exc), 500)


@app.get("/api/materi/<material_id>")
@login_required
def get_materi(user, material_id):
    try:
        db = db_client()
        rows = db.table(MATERIAL_TABLE).select("*").eq("id", material_id).limit(1).execute().data or []
        if not rows:
            return json_error("Materi tidak ditemukan.", 404)
        m = rows[0]
        subject_map = lookup_names(db, "subjects", "name", [m.get("subject_id")])
        author_map = lookup_names(db, "profiles", "full_name", [m.get(MATERIAL_AUTHOR)])
        return jsonify({"materi": {
            "id": m["id"],
            "title": m.get("title"),
            "description": m.get("description"),
            "content": m.get("content"),
            "url": m.get("url"),
            "jenjang": m.get("jenjang"),
            "mata_pelajaran": subject_map.get(m.get("subject_id"), "-"),
            "author_name": author_map.get(m.get(MATERIAL_AUTHOR)),
            "created_at": m.get("created_at"),
        }})
    except Exception as exc:
        return json_error("Gagal memuat materi: " + str(exc), 500)


@app.post("/api/materi")
@login_required
def create_materi(user):
    if user.role != "tutor":
        return json_error("Hanya tutor yang dapat menambah materi.", 403)

    data = request.get_json(silent=True) or {}
    title = clean_text(data.get("title"), 200)
    subject_id = data.get("subject_id")
    jenjang = (data.get("jenjang") or "").strip()
    url = clean_text(data.get("url"), 500)

    if not title:
        return json_error("Judul wajib diisi.")
    if not subject_id:
        return json_error("Mata pelajaran wajib dipilih.")
    if jenjang not in LEVELS:
        return json_error("Jenjang tidak valid.")
    if url and not is_http_url(url):
        return json_error("Link harus diawali http:// atau https://")

    try:
        db = db_client()
        if not db.table("subjects").select("id").eq("id", subject_id).limit(1).execute().data:
            return json_error("Mata pelajaran tidak ditemukan.", 404)

        row = {
            "title": title,
            "description": clean_text(data.get("description"), 500),
            "subject_id": subject_id,
            "jenjang": jenjang,
            "content": clean_text(data.get("content"), 20000),
            "url": url,
            MATERIAL_AUTHOR: user.id,
        }
        inserted = db.table(MATERIAL_TABLE).insert(row).execute().data
        return jsonify({"materi": inserted[0] if inserted else row}), 201
    except Exception as exc:
        return json_error("Gagal menyimpan materi: " + str(exc), 500)


# ---------------------------------------------------------------- Progress belajar (siswa)

@app.get("/api/progress")
@login_required
def my_progress(user):
    if user.role != "siswa":
        return json_error("Hanya siswa yang memiliki progress belajar.", 403)
    try:
        db = db_client()
        rows = db.table("learning_progress").select("*").eq("siswa_id", user.id).order("created_at", desc=True).limit(200).execute().data or []

        subject_map = lookup_names(db, "subjects", "name", [r.get("subject_id") for r in rows])
        tutor_map = lookup_names(db, "profiles", "full_name", [r.get("tutor_id") for r in rows])

        progress = []
        grouped = {}
        for r in rows:
            try:
                mastery = max(0, min(5, int(r.get("mastery") or 0)))
            except (TypeError, ValueError):
                mastery = 0
            name = subject_map.get(r.get("subject_id"), "Mata pelajaran")
            if r.get("subject_id"):
                grouped.setdefault(r["subject_id"], []).append(mastery)
            progress.append({
                "id": r.get("id"),
                "created_at": r.get("created_at"),
                "mata_pelajaran": name,
                "topik": r.get("topik") or "-",
                "mastery": mastery,
                "tutor_name": tutor_map.get(r.get("tutor_id")),
                # Mendukung nama kolom "catatan" maupun "notes".
                "catatan": r.get("catatan") or r.get("notes"),
            })

        summary = [
            {
                "mata_pelajaran": subject_map.get(sid, "Mata pelajaran"),
                "avg_mastery": round(sum(vals) / len(vals), 1),
                "entries": len(vals),
            }
            for sid, vals in grouped.items()
        ]

        done = db.table("sessions").select("id").eq("siswa_id", user.id).eq("status", "completed").execute().data or []
        return jsonify({"progress": progress, "summary": summary, "total_sesi_selesai": len(done)})
    except Exception as exc:
        return json_error("Gagal memuat progress: " + str(exc), 500)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG") == "1")
