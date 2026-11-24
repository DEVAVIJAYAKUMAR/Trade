"""Nivesh Practice backend (FastAPI).

- Accounts: register / login with PBKDF2 hashed passwords, bearer-token sessions
- Data: each account's practice state (portfolio, orders, F&O lab, chart drawings) is saved on the server
- Storage: SQLite by default. Set DATABASE_URL (Postgres) to keep data permanently on free hosts.
- Serves the app from index.html or indexc.html in the same folder.

Run:  uvicorn main:app --host 0.0.0.0 --port $PORT
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
import zlib
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

PG_URL = os.getenv("DATABASE_URL", "")
SQLITE_PATH = os.getenv("DB_PATH", "nivesh.db")
SESSION_DAYS = 90
MAX_FIELD = 2_000_000  # bytes per saved field
HERE = Path(__file__).resolve().parent


# ------------------------------------------------------------------ database
def _conn():
    if PG_URL:
        import psycopg
        return psycopg.connect(PG_URL)
    return sqlite3.connect(SQLITE_PATH)


def run(sql, args=(), fetch=False):
    c = _conn()
    try:
        cur = c.cursor()
        cur.execute(sql.replace("?", "%s") if PG_URL else sql, args)
        rows = cur.fetchall() if fetch else None
        c.commit()
        return rows
    finally:
        c.close()


def init_db():
    run("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, name TEXT, salt TEXT, pw TEXT, created BIGINT)")
    run("CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, email TEXT, created BIGINT)")
    run("CREATE TABLE IF NOT EXISTS profiles(email TEXT PRIMARY KEY, phone TEXT, city TEXT, experience TEXT, risk TEXT, goal TEXT, color TEXT, updated BIGINT)")
    run("CREATE TABLE IF NOT EXISTS userdata(email TEXT PRIMARY KEY, state TEXT, lab TEXT, draw TEXT, updated BIGINT)")


# ------------------------------------------------------------------ auth logic
EMAIL_RE = re.compile(r"^\S+@\S+\.\S+$")
_fails = {}  # email -> [timestamps]


def _hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def _tok_hash(t):
    return hashlib.sha256(t.encode()).hexdigest()


def _new_session(email):
    token = secrets.token_urlsafe(32)
    run("INSERT INTO sessions(th, email, created) VALUES(?,?,?)", (_tok_hash(token), email, int(time.time())))
    return token


def register_user(name, email, password):
    email = (email or "").strip().lower()
    name = (name or "").strip()[:60]
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "Enter a valid email address.")
    if len(password or "") < 6:
        raise HTTPException(400, "Password must be at least 6 characters.")
    if not name:
        raise HTTPException(400, "Enter your name.")
    if run("SELECT 1 FROM users WHERE email=?", (email,), fetch=True):
        raise HTTPException(409, "This email is already registered. Please login.")
    salt = secrets.token_hex(16)
    run("INSERT INTO users(email, name, salt, pw, created) VALUES(?,?,?,?,?)",
        (email, name, salt, _hash_pw(password, salt), int(time.time())))
    return {"token": _new_session(email), "name": name}


def login_user(email, password):
    email = (email or "").strip().lower()
    now = time.time()
    recent = [t for t in _fails.get(email, []) if now - t < 600]
    if len(recent) >= 8:
        raise HTTPException(429, "Too many attempts. Try again in 10 minutes.")
    rows = run("SELECT name, salt, pw FROM users WHERE email=?", (email,), fetch=True)
    if not rows or not hmac.compare_digest(rows[0][2], _hash_pw(password or "", rows[0][1])):
        _fails[email] = recent + [now]
        raise HTTPException(401, "Email or password is incorrect.")
    _fails.pop(email, None)
    return {"token": _new_session(email), "name": rows[0][0]}


def email_for_token(authorization):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Login required.")
    th = _tok_hash(authorization[7:].strip())
    rows = run("SELECT email, created FROM sessions WHERE th=?", (th,), fetch=True)
    if not rows or time.time() - rows[0][1] > SESSION_DAYS * 86400:
        raise HTTPException(401, "Session expired. Please login again.")
    return rows[0][0]


def get_data(email):
    rows = run("SELECT state, lab, draw FROM userdata WHERE email=?", (email,), fetch=True)
    if not rows:
        return {"state": None, "lab": None, "draw": None}
    return {"state": rows[0][0], "lab": rows[0][1], "draw": rows[0][2]}


def put_data(email, state=None, lab=None, draw=None):
    for v in (state, lab, draw):
        if v is not None and len(v) > MAX_FIELD:
            raise HTTPException(413, "Data too large.")
    cur = get_data(email)
    new = {"state": state if state is not None else cur["state"],
           "lab": lab if lab is not None else cur["lab"],
           "draw": draw if draw is not None else cur["draw"]}
    run("INSERT INTO userdata(email, state, lab, draw, updated) VALUES(?,?,?,?,?) "
        "ON CONFLICT(email) DO UPDATE SET state=excluded.state, lab=excluded.lab, "
        "draw=excluded.draw, updated=excluded.updated",
        (email, new["state"], new["lab"], new["draw"], int(time.time())))
    return {"ok": True}


# ------------------------------------------------------------------ profile
EXP_OK = {"", "Beginner", "Intermediate", "Advanced"}
RISK_OK = {"", "Low", "Moderate", "High"}
GOAL_OK = {"", "Learn the basics", "Practice options", "Build long-term wealth", "Test strategies"}
COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def get_profile(email):
    u = run("SELECT name, created FROM users WHERE email=?", (email,), fetch=True)
    if not u:
        raise HTTPException(404, "Account not found.")
    p = run("SELECT phone, city, experience, risk, goal, color FROM profiles WHERE email=?", (email,), fetch=True)
    p = p[0] if p else ("", "", "", "", "", "#3A47D5")
    return {"name": u[0][0], "email": email, "created": u[0][1], "phone": p[0] or "", "city": p[1] or "",
            "experience": p[2] or "", "risk": p[3] or "", "goal": p[4] or "", "color": p[5] or "#3A47D5"}


def put_profile(email, b):
    name = (b.name or "").strip()[:60]
    phone = (b.phone or "").strip()[:20]
    city = (b.city or "").strip()[:40]
    if not name:
        raise HTTPException(400, "Enter your name.")
    if phone and not re.match(r"^[0-9+()\-\s]{6,20}$", phone):
        raise HTTPException(400, "Enter a valid phone number.")
    if b.experience not in EXP_OK or b.risk not in RISK_OK or b.goal not in GOAL_OK:
        raise HTTPException(400, "Invalid option selected.")
    if not COLOR_RE.match(b.color or ""):
        raise HTTPException(400, "Invalid avatar colour.")
    run("UPDATE users SET name=? WHERE email=?", (name, email))
    run("INSERT INTO profiles(email, phone, city, experience, risk, goal, color, updated) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(email) DO UPDATE SET phone=excluded.phone, city=excluded.city, experience=excluded.experience, "
        "risk=excluded.risk, goal=excluded.goal, color=excluded.color, updated=excluded.updated",
        (email, phone, city, b.experience, b.risk, b.goal, b.color, int(time.time())))
    return get_profile(email)


def change_password(email, current, new):
    if len(new or "") < 6:
        raise HTTPException(400, "New password must be at least 6 characters.")
    rows = run("SELECT salt, pw FROM users WHERE email=?", (email,), fetch=True)
    if not rows or not hmac.compare_digest(rows[0][1], _hash_pw(current or "", rows[0][0])):
        raise HTTPException(401, "Current password is incorrect.")
    salt = secrets.token_hex(16)
    run("UPDATE users SET salt=?, pw=? WHERE email=?", (salt, _hash_pw(new, salt), email))
    run("DELETE FROM sessions WHERE email=?", (email,))  # sign out every other device
    return {"token": _new_session(email)}


# ------------------------------------------------------------------ PWA assets
def make_png(n):
    bg, fg = (0, 179, 134), (255, 255, 255)
    px = [[bg] * n for _ in range(n)]
    pts = [(.20, .70), (.40, .45), (.55, .60), (.80, .30)]
    r = max(2, int(n * .035))
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        steps = int(n * 1.2)
        for i in range(steps + 1):
            cx, cy = int((x0 + (x1 - x0) * i / steps) * n), int((y0 + (y1 - y0) * i / steps) * n)
            for y in range(cy - r, cy + r + 1):
                for x in range(cx - r, cx + r + 1):
                    if 0 <= x < n and 0 <= y < n and (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                        px[y][x] = fg
    raw = b"".join(b"\x00" + b"".join(bytes(p) for p in row) for row in px)

    def ch(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)

    return (b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 2, 0, 0, 0))
            + ch(b"IDAT", zlib.compress(raw, 9)) + ch(b"IEND", b""))


ICON192, ICON512 = make_png(192), make_png(512)
MANIFEST = """{"name":"Nivesh Practice","short_name":"Nivesh","start_url":"/","scope":"/","display":"standalone",
"background_color":"#ffffff","theme_color":"#00b386",
"icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png","purpose":"any maskable"},
{"src":"/icon-512.png","sizes":"512x512","type":"image/png","purpose":"any maskable"}]}"""
SW_JS = """self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{});"""


# ------------------------------------------------------------------ API
class RegisterIn(BaseModel):
    name: str = ""
    email: str
    password: str


class LoginIn(BaseModel):
    name: str = ""
    email: str
    password: str


class DataIn(BaseModel):
    state: Optional[str] = None
    lab: Optional[str] = None
    draw: Optional[str] = None


class ProfileIn(BaseModel):
    name: str = ""
    phone: str = ""
    city: str = ""
    experience: str = ""
    risk: str = ""
    goal: str = ""
    color: str = "#3A47D5"


class PasswordIn(BaseModel):
    current: str
    new: str


app = FastAPI(title="Nivesh Practice")
init_db()


@app.get("/api/health")
def health():
    return {"ok": True, "db": "postgres" if PG_URL else "sqlite"}


@app.post("/api/register")
def api_register(b: RegisterIn):
    return register_user(b.name, b.email, b.password)


@app.post("/api/login")
def api_login(b: LoginIn):
    return login_user(b.email, b.password)


@app.get("/api/data")
def api_get(authorization: Optional[str] = Header(None)):
    return get_data(email_for_token(authorization))


@app.put("/api/data")
def api_put(b: DataIn, authorization: Optional[str] = Header(None)):
    return put_data(email_for_token(authorization), b.state, b.lab, b.draw)


@app.get("/api/profile")
def api_profile(authorization: Optional[str] = Header(None)):
    return get_profile(email_for_token(authorization))


@app.put("/api/profile")
def api_profile_put(b: ProfileIn, authorization: Optional[str] = Header(None)):
    return put_profile(email_for_token(authorization), b)


@app.post("/api/profile/password")
def api_profile_pw(b: PasswordIn, authorization: Optional[str] = Header(None)):
    return change_password(email_for_token(authorization), b.current, b.new)


@app.get("/")
def index():
    # Accept either filename so the deployed app works with the current
    # GitHub file name (indexc.html) or the conventional name (index.html).
    candidates = (HERE / "index.html", HERE / "indexc.html")
    html_file = next((path for path in candidates if path.is_file()), None)
    if html_file is None:
        raise HTTPException(
            status_code=500,
            detail="App HTML file not found. Add index.html or indexc.html beside main.py.",
        )
    return FileResponse(html_file, headers={"Cache-Control": "no-cache"})


@app.get("/manifest.webmanifest")
def manifest():
    return Response(MANIFEST, media_type="application/manifest+json")


@app.get("/sw.js")
def sw():
    return Response(SW_JS, media_type="application/javascript")


@app.get("/icon-192.png")
def icon192():
    return Response(ICON192, media_type="image/png")


@app.get("/icon-512.png")
def icon512():
    return Response(ICON512, media_type="image/png")
