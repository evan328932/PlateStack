import os, re, time, hmac, hashlib, secrets, sqlite3
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory, g

app = Flask(__name__, static_folder="public")

# ── Config ──────────────────────────────────────────────────────────────────────
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ADMIN_CODE    = os.environ.get("ADMIN_CODE", "")
DB_PATH       = os.environ.get("DB_PATH", "liftlab.db")
WAITLIST_FILE = "waitlist.txt"

# ── Rate limiting ───────────────────────────────────────────────────────────────
RATE_LIMIT  = 20
RATE_WINDOW = 3600
request_log: dict = defaultdict(list)

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    cutoff = now - RATE_WINDOW
    request_log[ip] = [t for t in request_log[ip] if t > cutoff]
    if len(request_log[ip]) >= RATE_LIMIT:
        return True
    request_log[ip].append(now)
    return False

def get_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

# ── Database ────────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                email    TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token   TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS workout_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL,
                exercise     TEXT NOT NULL,
                weight       REAL NOT NULL,
                reps         INTEGER NOT NULL,
                estimated1rm INTEGER NOT NULL,
                unit         TEXT NOT NULL DEFAULT 'lbs',
                note         TEXT,
                date         TEXT NOT NULL,
                created      INTEGER NOT NULL DEFAULT (strftime('%s','now')),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS waitlist (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                email   TEXT UNIQUE NOT NULL,
                created INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
        """)
        db.commit()

init_db()

# ── Auth helpers ────────────────────────────────────────────────────────────────
def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 200_000)
    return salt + ':' + h.hex()

def check_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split(':', 1)
        expected = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 200_000)
        return hmac.compare_digest(expected.hex(), h)
    except Exception:
        return False

def make_token() -> str:
    return secrets.token_urlsafe(32)

def get_user_from_token(token: str):
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT u.id, u.email FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token=? AND s.created > strftime('%s','now') - 2592000",  # 30 days
        (token,)
    ).fetchone()
    return dict(row) if row else None

def get_auth_user():
    token = request.headers.get("X-Auth-Token", "") or request.cookies.get("ll_token", "")
    return get_user_from_token(token)

# ── Input helpers ───────────────────────────────────────────────────────────────
def sanitize(value, max_len=500):
    text = str(value).strip()[:max_len]
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    text = re.sub(r'<[^>]*>', '', text)
    return text

def is_safe(s: str) -> bool:
    bad = ["ignore previous","ignore all","disregard","forget your instructions",
           "new instructions","system prompt","you are now","act as",
           "pretend you","jailbreak","<script","javascript:"]
    low = s.lower()
    return not any(b in low for b in bad)

def verify_admin(code: str) -> bool:
    if not ADMIN_CODE or not code:
        return False
    return hmac.compare_digest(
        hashlib.sha256(code.encode()).digest(),
        hashlib.sha256(ADMIN_CODE.encode()).digest()
    )

# ── Anthropic helper ────────────────────────────────────────────────────────────
def call_claude(system_prompt, user_msg, max_tokens=1400,
                model="claude-sonnet-4-20250514", cache_system=False):
    if cache_system:
        system_content = [{"type":"text","text":system_prompt,"cache_control":{"type":"ephemeral"}}]
    else:
        system_content = system_prompt
    headers = {"x-api-key":ANTHROPIC_KEY,"anthropic-version":"2023-06-01","content-type":"application/json"}
    if cache_system:
        headers["anthropic-beta"] = "prompt-caching-2024-07-31"
    response = requests.post(
        "https://api.anthropic.com/v1/messages", headers=headers,
        json={"model":model,"max_tokens":max_tokens,"system":system_content,
              "messages":[{"role":"user","content":user_msg}]}, timeout=35)
    result = response.json()
    if "error" in result:
        raise Exception(result["error"].get("message","API error"))
    return "".join(b.get("text","") for b in result.get("content",[]))

# ── Plan template ───────────────────────────────────────────────────────────────
PLAN_SYSTEM = """You are an expert strength and conditioning coach. Fill in the training plan template below using the athlete's data. Be specific — always use exact weights, sets, reps, and percentages of their actual 1RM. Use markdown: ## for section headers, - for bullets. No preamble. No closing remarks. Fill every section."""

def build_plan_prompt(profile, experience, days, split, goal, unit, lifts_text):
    return f"""ATHLETE DATA:
Profile: {profile}
Experience: {experience}
Schedule: {days} days/week, {split}
Goal: {goal}
Unit: {unit}
Lifts: {lifts_text}

FILL THIS TEMPLATE:

## Where You're At
[2-3 sentences: current strength level vs goal, honest assessment]

## Weekly Program ({days}-Day {split})
[List each training day. For each exercise: sets x reps @ % of 1RM (actual weight in {unit}). Be exact.]

## 4-Week Milestone
[What numbers to hit at week 4]

## 8-Week Milestone
[What numbers to hit at week 8]

## 12-Week Milestone
[What numbers to hit at week 12]

## Key Tips
[2-3 tips specific to this athlete's numbers and situation]"""

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("public", "index.html")

# ── Auth routes ─────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many requests."}), 429
    data = request.get_json(silent=True) or {}
    email = sanitize(data.get("email",""), 200).lower()
    pw    = str(data.get("password",""))
    if not email or "@" not in email or "." not in email:
        return jsonify({"error":"Please enter a valid email address."}), 400
    if len(pw) < 6:
        return jsonify({"error":"Password must be at least 6 characters."}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (email,password) VALUES (?,?)", (email, hash_password(pw)))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"An account with that email already exists."}), 409
    user_id = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    token = make_token()
    db.execute("INSERT INTO sessions (token,user_id) VALUES (?,?)", (token, user_id))
    db.commit()
    return jsonify({"ok":True,"token":token,"email":email}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many requests."}), 429
    data = request.get_json(silent=True) or {}
    email = sanitize(data.get("email",""), 200).lower()
    pw    = str(data.get("password",""))
    db = get_db()
    row = db.execute("SELECT id,password FROM users WHERE email=?", (email,)).fetchone()
    if not row or not check_password(pw, row["password"]):
        return jsonify({"error":"Incorrect email or password."}), 401
    token = make_token()
    db.execute("INSERT INTO sessions (token,user_id) VALUES (?,?)", (token, row["id"]))
    db.commit()
    return jsonify({"ok":True,"token":token,"email":email}), 200

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    token = request.headers.get("X-Auth-Token","")
    if token:
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token=?", (token,))
        db.commit()
    return jsonify({"ok":True}), 200

@app.route("/api/auth/me", methods=["GET"])
def me():
    user = get_auth_user()
    if not user:
        return jsonify({"user":None}), 200
    return jsonify({"user":user}), 200

# ── Workout log routes ──────────────────────────────────────────────────────────
@app.route("/api/log", methods=["GET"])
def get_log():
    user = get_auth_user()
    if not user:
        return jsonify({"error":"Not logged in."}), 401
    db = get_db()
    rows = db.execute(
        "SELECT id,exercise,weight,reps,estimated1rm,unit,note,date FROM workout_log "
        "WHERE user_id=? ORDER BY date DESC, created DESC LIMIT 500",
        (user["id"],)
    ).fetchall()
    return jsonify({"log": [dict(r) for r in rows]}), 200

@app.route("/api/log", methods=["POST"])
def add_log():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many requests."}), 429
    user = get_auth_user()
    if not user:
        return jsonify({"error":"Not logged in."}), 401
    data = request.get_json(silent=True) or {}
    exercise = sanitize(data.get("exercise",""), 100)
    weight   = float(data.get("weight", 0))
    reps     = int(data.get("reps", 0))
    e1rm     = int(data.get("estimated1rm", 0))
    unit_val = data.get("unit","lbs")
    note     = sanitize(data.get("note",""), 500)
    date_val = sanitize(data.get("date",""), 20)
    if not exercise or weight <= 0 or reps <= 0:
        return jsonify({"error":"Invalid entry."}), 400
    if unit_val not in ("lbs","kg"):
        unit_val = "lbs"
    db = get_db()
    db.execute(
        "INSERT INTO workout_log (user_id,exercise,weight,reps,estimated1rm,unit,note,date) VALUES (?,?,?,?,?,?,?,?)",
        (user["id"], exercise, weight, reps, e1rm, unit_val, note, date_val)
    )
    db.commit()
    new_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    return jsonify({"ok":True,"id":new_id}), 201

@app.route("/api/log/<int:entry_id>", methods=["DELETE"])
def delete_log(entry_id):
    user = get_auth_user()
    if not user:
        return jsonify({"error":"Not logged in."}), 401
    db = get_db()
    db.execute("DELETE FROM workout_log WHERE id=? AND user_id=?", (entry_id, user["id"]))
    db.commit()
    return jsonify({"ok":True}), 200

@app.route("/api/log/<int:entry_id>", methods=["PATCH"])
def update_log(entry_id):
    user = get_auth_user()
    if not user:
        return jsonify({"error":"Not logged in."}), 401
    data = request.get_json(silent=True) or {}
    note = sanitize(data.get("note",""), 500)
    date_val = sanitize(data.get("date",""), 20)
    db = get_db()
    db.execute("UPDATE workout_log SET note=?,date=? WHERE id=? AND user_id=?",
               (note, date_val, entry_id, user["id"]))
    db.commit()
    return jsonify({"ok":True}), 200

# ── AI plan route ───────────────────────────────────────────────────────────────
@app.route("/api/plan", methods=["POST"])
def plan():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many requests. Please wait an hour and try again."}), 429
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error":"Invalid request."}), 400
    admin  = verify_admin(str(data.get("adminCode","")))
    lifts  = data.get("lifts",[])
    unit   = data.get("unit","lbs")
    goal   = sanitize(data.get("goal",""),400)
    exp    = sanitize(data.get("experience","beginner"),50)
    days   = sanitize(str(data.get("days","3")),5)
    split  = sanitize(data.get("split","Full body"),100)
    age    = sanitize(str(data.get("age","")),3) if data.get("age") else None
    bw     = sanitize(str(data.get("bodyweight","")),20) if data.get("bodyweight") else None
    sex    = sanitize(str(data.get("sex","")),10) if data.get("sex") else None
    height = sanitize(str(data.get("height","")),20) if data.get("height") else None
    if unit not in ("lbs","kg"): unit="lbs"
    if exp not in ("beginner","intermediate","advanced"): exp="beginner"
    for field in [goal, split]:
        if not is_safe(field):
            return jsonify({"error":"Invalid input detected."}), 400
    if not isinstance(lifts,list) or not lifts:
        return jsonify({"error":"No lifts provided."}), 400
    if len(lifts) > 20:
        return jsonify({"error":"Maximum 20 lifts allowed."}), 400
    clean_lifts = []
    for l in lifts:
        try:
            name   = str(l.get("name",""))[:50].strip()
            weight = float(l.get("weight",0))
            reps   = int(l.get("reps",0))
            max_v  = int(l.get("max",0))
            if name and 0 < weight < 5000 and 0 < reps <= 50 and is_safe(name):
                clean_lifts.append({"name":name,"weight":weight,"reps":reps,"max":max_v})
        except Exception:
            continue
    if not clean_lifts:
        return jsonify({"error":"No valid lifts provided."}), 400
    parts = []
    if age: parts.append(f"Age {age}")
    if bw: parts.append(f"BW {bw}")
    if height: parts.append(f"Height {height}")
    if sex: parts.append(sex.capitalize())
    profile = ", ".join(parts) if parts else "Not specified"
    lifts_text = "\n".join([f"- {l['name']}: {l['weight']}{unit} x {l['reps']} reps → 1RM ~{l['max']}{unit}" for l in clean_lifts])
    try:
        plan_text = call_claude(PLAN_SYSTEM, build_plan_prompt(profile,exp,days,split,goal,unit,lifts_text), max_tokens=1400, cache_system=True)
        return jsonify({"plan":plan_text,"admin":admin})
    except requests.exceptions.Timeout:
        return jsonify({"error":"Request timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ── Q&A route ───────────────────────────────────────────────────────────────────
@app.route("/api/question", methods=["POST"])
def question():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many requests."}), 429
    data = request.get_json(silent=True)
    if not data: return jsonify({"error":"Invalid request."}), 400
    plan_text = sanitize(data.get("plan",""), 3000)
    q         = sanitize(data.get("question",""), 300)
    if not plan_text or not q: return jsonify({"error":"Missing plan or question."}), 400
    if not is_safe(q): return jsonify({"error":"Invalid input detected."}), 400
    qa_system = "You are an expert strength coach answering a follow-up question about a training plan. Be concise and specific — 2-4 sentences or a short bullet list. Never restate the full plan."
    try:
        answer = call_claude(qa_system, f"Training plan:\n{plan_text}\n\nQuestion: {q}", max_tokens=350, model="claude-haiku-4-5-20251001", cache_system=True)
        return jsonify({"answer":answer})
    except requests.exceptions.Timeout:
        return jsonify({"error":"Request timed out."}), 504
    except Exception as e:
        return jsonify({"error":str(e)}), 500

# ── Waitlist route ──────────────────────────────────────────────────────────────
@app.route("/api/waitlist", methods=["POST"])
def waitlist():
    data = request.get_json(silent=True) or {}
    email = sanitize(str(data.get("email","")), 200).lower()
    if not email or "@" not in email or "." not in email:
        return jsonify({"ok":False,"error":"Invalid email"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO waitlist (email) VALUES (?)", (email,))
        db.commit()
    except sqlite3.IntegrityError:
        pass  # already on list, that's fine
    try:
        with open(WAITLIST_FILE,"a") as f:
            f.write(f"{email}\n")
    except Exception:
        pass
    return jsonify({"ok":True}), 200

# ── Admin routes ────────────────────────────────────────────────────────────────
@app.route("/api/verify-admin", methods=["POST"])
def verify_admin_route():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error":"Too many requests."}), 429
    data = request.get_json(silent=True) or {}
    code = sanitize(str(data.get("code","")), 100)
    return jsonify({"valid":verify_admin(code)}), 200

@app.route("/api/emails", methods=["GET"])
def view_emails():
    code = request.args.get("code","")
    if not verify_admin(code):
        return "Unauthorized", 403
    db = get_db()
    waitlist_rows = db.execute("SELECT email, datetime(created,'unixepoch') as ts FROM waitlist ORDER BY created DESC").fetchall()
    user_rows     = db.execute("SELECT email, datetime(created,'unixepoch') as ts FROM users ORDER BY created DESC").fetchall()
    fmt = request.args.get("format","html")
    if fmt == "json":
        return jsonify({"waitlist":[dict(r) for r in waitlist_rows],"accounts":[dict(r) for r in user_rows]})
    def tbl(rows, title):
        if not rows: return f"<h2>{title}</h2><p style='color:#999'>None yet.</p>"
        trs = "".join(f"<tr><td>{i+1}</td><td>{r['email']}</td><td style='color:#999'>{r['ts']}</td></tr>" for i,r in enumerate(rows))
        return f"<h2>{title} ({len(rows)})</h2><table><thead><tr><th>#</th><th>Email</th><th>Date</th></tr></thead><tbody>{trs}</tbody></table>"
    return f"""<!DOCTYPE html><html><head><title>LiftLab Admin</title>
<style>body{{font-family:system-ui;padding:2rem;max-width:700px;margin:0 auto;background:#f9f9f9}}
h1{{font-size:22px;margin-bottom:0.25rem}}h2{{font-size:16px;margin:2rem 0 0.5rem}}
table{{width:100%;border-collapse:collapse;font-size:14px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{text-align:left;padding:10px 14px;background:#f0f0f0;border-bottom:2px solid #ddd}}
td{{padding:9px 14px;border-bottom:1px solid #eee}}a{{font-size:13px;color:#888;margin-top:1.5rem;display:inline-block}}
</style></head><body>
<h1>🏋️ LiftLab Admin</h1>
{tbl(user_rows,"Accounts")}{tbl(waitlist_rows,"Waitlist")}
<a href="?code={code}&format=json">View as JSON</a>
</body></html>"""

if __name__ == "__main__":
    app.run(debug=False)
