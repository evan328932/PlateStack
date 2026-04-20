import os, re, time, hmac, hashlib, secrets, sqlite3
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory, g

app = Flask(__name__, static_folder="public")

@app.after_request
def add_security_headers(resp):
    """Standard security headers applied to every response."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Only HSTS on HTTPS responses
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ADMIN_CODE    = os.environ.get("ADMIN_CODE", "")
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "")  # set in Railway env vars
DB_PATH       = os.environ.get("DB_PATH", "platestack.db")
WAITLIST_FILE = "waitlist.txt"
ANON_PLAN_LIMIT = 2    # no account
USER_PLAN_LIMIT = 4    # free account

RATE_LIMIT  = 30
RATE_WINDOW = 3600
AUTH_RATE_LIMIT  = 20
AUTH_RATE_WINDOW = 600

request_log: dict = defaultdict(list)
auth_log: dict    = defaultdict(list)

def is_rate_limited(ip):
    now=time.time(); cutoff=now-RATE_WINDOW
    request_log[ip]=[t for t in request_log[ip] if t>cutoff]
    if len(request_log[ip])>=RATE_LIMIT: return True
    request_log[ip].append(now); return False

def is_auth_rate_limited(ip):
    now=time.time(); cutoff=now-AUTH_RATE_WINDOW
    auth_log[ip]=[t for t in auth_log[ip] if t>cutoff]
    if len(auth_log[ip])>=AUTH_RATE_LIMIT: return True
    auth_log[ip].append(now); return False

def get_ip():
    fwd=request.headers.get("X-Forwarded-For","")
    # Use the LAST entry — that's the one Railway's proxy added, which can't be spoofed
    # The first entry can be forged by the client
    if fwd:
        parts=[p.strip() for p in fwd.split(",") if p.strip()]
        return parts[-1] if parts else (request.remote_addr or "unknown")
    return request.remote_addr or "unknown"

def get_db():
    if 'db' not in g:
        g.db=sqlite3.connect(DB_PATH); g.db.row_factory=sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db=g.pop('db',None)
    if db: db.close()

def init_db():
    with app.app_context():
        db=get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')),FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS workout_log(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,exercise TEXT NOT NULL,weight REAL NOT NULL,reps INTEGER NOT NULL,estimated1rm INTEGER NOT NULL,unit TEXT NOT NULL DEFAULT 'lbs',note TEXT,date TEXT NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')),FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS saved_plans(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,title TEXT NOT NULL,plan_text TEXT NOT NULL,lifts_json TEXT,created INTEGER NOT NULL DEFAULT(strftime('%s','now')),FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE TABLE IF NOT EXISTS plan_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,plan_id INTEGER NOT NULL,user_id INTEGER NOT NULL,week INTEGER NOT NULL,day INTEGER NOT NULL,exercise TEXT NOT NULL,exercise_order INTEGER NOT NULL DEFAULT 0,set_number INTEGER NOT NULL,prescribed_weight REAL,prescribed_reps INTEGER,actual_weight REAL,actual_reps INTEGER,rpe INTEGER,unit TEXT NOT NULL DEFAULT 'lbs',completed INTEGER NOT NULL DEFAULT 0,completed_at INTEGER,created INTEGER NOT NULL DEFAULT(strftime('%s','now')),FOREIGN KEY(plan_id) REFERENCES saved_plans(id),FOREIGN KEY(user_id) REFERENCES users(id));
            CREATE INDEX IF NOT EXISTS idx_plan_sessions_lookup ON plan_sessions(user_id,plan_id,week,day);
            CREATE TABLE IF NOT EXISTS ip_plan_usage(ip TEXT PRIMARY KEY,count INTEGER NOT NULL DEFAULT 0,updated INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE TABLE IF NOT EXISTS waitlist(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE TABLE IF NOT EXISTS page_visits(id INTEGER PRIMARY KEY AUTOINCREMENT,date TEXT NOT NULL,ip_hash TEXT NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE INDEX IF NOT EXISTS idx_visits_date ON page_visits(date);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_visits_unique ON page_visits(date,ip_hash);
        """)
        # Idempotent column adds for existing DBs (SQLite has no IF NOT EXISTS on ALTER)
        def _add_col(tbl,col,decl):
            try: db.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {decl}")
            except sqlite3.OperationalError: pass  # already exists
        _add_col("users","is_premium","INTEGER NOT NULL DEFAULT 1")  # defaulting everyone premium for launch; flip to 0 when paid tier ships
        _add_col("saved_plans","is_active","INTEGER NOT NULL DEFAULT 0")
        _add_col("saved_plans","structured_plan","TEXT")
        _add_col("saved_plans","days_per_week","INTEGER NOT NULL DEFAULT 0")
        _add_col("saved_plans","unit","TEXT NOT NULL DEFAULT 'lbs'")
        db.commit()

init_db()

def hash_password(pw):
    salt=secrets.token_hex(16); h=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt.encode(),200_000)
    return salt+':'+h.hex()

def check_password(pw,stored):
    try:
        salt,h=stored.split(':',1); expected=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt.encode(),200_000)
        return hmac.compare_digest(expected.hex(),h)
    except: return False

def make_token(): return secrets.token_urlsafe(32)

def get_user_from_token(token):
    if not token: return None
    db=get_db()
    row=db.execute("SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created>strftime('%s','now')-2592000",(token,)).fetchone()
    return dict(row) if row else None

def get_auth_user():
    token=request.headers.get("X-Auth-Token","") or request.cookies.get("ll_token","")
    return get_user_from_token(token)

def is_premium_user(user):
    """Check if user has premium features. Right now everyone is premium=1 by default.
    When paid tier launches: flip the default on the users table to 0, and this function
    becomes the gate for all premium features without any other code changes."""
    if not user: return False
    try:
        row=get_db().execute("SELECT is_premium FROM users WHERE id=?",(user["id"],)).fetchone()
        return bool(row and row["is_premium"])
    except: return False

def sanitize(value,max_len=500):
    text=str(value).strip()[:max_len]
    while "\n\n\n" in text: text=text.replace("\n\n\n","\n\n")
    return re.sub(r'<[^>]*>','',text)

def valid_date(s):
    """Validates YYYY-MM-DD format and that it's a real calendar date. Returns '' if invalid."""
    if not s or not isinstance(s,str): return ""
    s=s.strip()[:10]
    if not re.match(r'^\d{4}-\d{2}-\d{2}$',s): return ""
    try:
        import datetime
        datetime.date.fromisoformat(s)
        return s
    except ValueError:
        return ""

def is_safe(s):
    bad=["ignore previous","ignore all","disregard","forget your instructions","new instructions","system prompt","you are now","act as","pretend you","jailbreak","<script","javascript:"]
    return not any(b in s.lower() for b in bad)

def verify_admin(code):
    if not ADMIN_CODE or not code: return False
    return hmac.compare_digest(hashlib.sha256(code.encode()).digest(),hashlib.sha256(ADMIN_CODE.encode()).digest())

def get_ip_plan_count(ip):
    try:
        row=get_db().execute("SELECT count FROM ip_plan_usage WHERE ip=?",(ip,)).fetchone()
        return row["count"] if row else 0
    except: return 0

def increment_ip_plan_count(ip):
    try:
        db=get_db()
        db.execute("INSERT INTO ip_plan_usage(ip,count,updated) VALUES(?,1,strftime('%s','now')) ON CONFLICT(ip) DO UPDATE SET count=count+1,updated=strftime('%s','now')",(ip,))
        db.commit()
    except: pass

def call_claude(system_prompt,user_msg,max_tokens=1500,model="claude-sonnet-4-20250514",cache_system=False):
    system_content=[{"type":"text","text":system_prompt,"cache_control":{"type":"ephemeral"}}] if cache_system else system_prompt
    headers={"x-api-key":ANTHROPIC_KEY,"anthropic-version":"2023-06-01","content-type":"application/json"}
    if cache_system: headers["anthropic-beta"]="prompt-caching-2024-07-31"
    response=requests.post("https://api.anthropic.com/v1/messages",headers=headers,
        json={"model":model,"max_tokens":max_tokens,"system":system_content,"messages":[{"role":"user","content":user_msg}]},timeout=35)
    result=response.json()
    if "error" in result: raise Exception(result["error"].get("message","API error"))
    return "".join(b.get("text","") for b in result.get("content",[]))

PLAN_SYSTEM = """You are an expert strength and conditioning coach. Fill in the training plan template exactly. Be specific — use exact weights, sets, reps, and percentages of their 1RM. Use markdown: ## for section headers, - for bullets. No preamble. No closing remarks.

IMPORTANT: Under "## Where You're At" write ONLY 2-3 plain sentences of flowing prose. No sub-headers, no bullets, no dashes — just sentences.

TITLE RULE: The very first line of your response must be a TITLE line in this exact format:
TITLE: [short punchy 3-7 word plan name that captures the goal and style, e.g. "Raw Strength: 4-Day Upper/Lower" or "5-Day PPL Mass Builder"]
Then a blank line, then the rest of the plan.

STRUCTURED_PLAN RULE: After the full markdown plan, on a new line, write "STRUCTURED_PLAN:" followed by a valid JSON object describing Week 1 of the plan in this exact schema:
{"days":[{"day":1,"name":"Upper","exercises":[{"name":"Bench Press","sets":4,"reps":5,"weight":185,"unit":"lbs"},{"name":"Barbell Row","sets":4,"reps":8,"weight":135,"unit":"lbs"}]},{"day":2,"name":"Lower","exercises":[...]}]}
Rules for the JSON:
- Use the exact unit the user specified (lbs or kg).
- For bodyweight exercises, use weight: 0.
- For rep ranges like "8-12", pick the midpoint (10).
- Only include Week 1. Do NOT include every week.
- The JSON must be valid and parseable. No comments, no trailing commas.
- Exercise names must match the names used in the markdown plan exactly."""

def build_plan_prompt(profile,experience,days,split,goal,unit,lifts_text,injuries="",preferences="",log_context=""):
    extras = []
    if injuries: extras.append(f"Injuries/limitations: {injuries}")
    if preferences: extras.append(f"Equipment/preferences: {preferences}")
    extra_block = ("\n" + "\n".join(extras)) if extras else ""
    log_block = f"\nRecent training history (use for progression context):\n{log_context}" if log_context else ""
    return f"""ATHLETE:
Profile: {profile}
Experience: {experience}
Schedule: {days} days/week, {split}
Goal: {goal}
Unit: {unit}{extra_block}
Lifts:
{lifts_text}{log_block}

TEMPLATE TO FILL:

TITLE: [3-7 word punchy plan name]

## Where You're At
[Write 2-3 plain prose sentences about their current level vs their goal. PLAIN TEXT ONLY — no dashes, no bullets, no sub-headers.]

## Weekly Program ({days}-Day {split})
[Each training day labeled Day N - name. List exercises: Name - sets x reps @ weight. Include rest periods.]

## Week-by-Week Progression
[Show exactly how to progress the main lifts over 4 weeks. E.g. "Week 1: Bench 225x5x4, Week 2: 230x5x4, Week 3: 235x4x4, Week 4: 240x5x4". Cover the 2-3 most important lifts.]

## 4-Week Milestone
[Specific numbers to hit]

## 8-Week Milestone
[Specific numbers to hit]

## 12-Week Milestone
[Specific numbers to hit]

## Key Tips
[2-3 tips tailored to their specific situation and any injuries or preferences noted]"""

@app.route("/api/config", methods=["GET"])
def config():
    """Returns public config values — safe to expose to frontend."""
    return jsonify({"contact_email": CONTACT_EMAIL}), 200

@app.route("/api/track-visit",methods=["POST"])
def track_visit():
    """Records a unique daily visit. IP is SHA-256 hashed before storage — raw IPs are never saved."""
    ip=get_ip()
    # Use the general rate limiter to prevent abuse/flooding
    if is_rate_limited(ip): return jsonify({"ok":True}),200
    try:
        # Hash the IP so we never store the raw address in the database
        ip_hash=hashlib.sha256(ip.encode()).hexdigest()[:32]
        today=time.strftime("%Y-%m-%d")
        db=get_db()
        # INSERT OR IGNORE → unique constraint on (date, ip_hash) means one row per visitor per day
        db.execute("INSERT OR IGNORE INTO page_visits(date,ip_hash) VALUES(?,?)",(today,ip_hash))
        db.commit()
    except Exception as e:
        print(f"Track visit error: {e}")
    return jsonify({"ok":True}),200

@app.route("/")
def index(): return send_from_directory("public","index.html")

@app.route("/api/auth/register",methods=["POST"])
def register():
    ip=get_ip()
    if is_auth_rate_limited(ip): return jsonify({"error":"Too many attempts. Wait a few minutes."}),429
    data=request.get_json(silent=True) or {}
    email=sanitize(data.get("email",""),200).lower(); pw=str(data.get("password",""))
    if not email or "@" not in email or "." not in email: return jsonify({"error":"Please enter a valid email address."}),400
    if len(pw)<6: return jsonify({"error":"Password must be at least 6 characters."}),400
    db=get_db()
    try:
        db.execute("INSERT INTO users(email,password) VALUES(?,?)",(email,hash_password(pw))); db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"An account with that email already exists."}),409
    user_id=db.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()["id"]
    token=make_token(); db.execute("INSERT INTO sessions(token,user_id) VALUES(?,?)",(token,user_id)); db.commit()
    return jsonify({"ok":True,"token":token,"email":email}),201

@app.route("/api/auth/login",methods=["POST"])
def login():
    ip=get_ip()
    if is_auth_rate_limited(ip): return jsonify({"error":"Too many attempts. Wait a few minutes."}),429
    data=request.get_json(silent=True) or {}
    email=sanitize(data.get("email",""),200).lower(); pw=str(data.get("password",""))
    db=get_db(); row=db.execute("SELECT id,password FROM users WHERE email=?",(email,)).fetchone()
    if not row or not check_password(pw,row["password"]): return jsonify({"error":"Incorrect email or password."}),401
    token=make_token(); db.execute("INSERT INTO sessions(token,user_id) VALUES(?,?)",(token,row["id"]))
    # Clean up sessions older than 30 days to prevent table bloat
    db.execute("DELETE FROM sessions WHERE user_id=? AND created<=strftime('%s','now')-2592000",(row["id"],))
    db.commit()
    return jsonify({"ok":True,"token":token,"email":email}),200

@app.route("/api/auth/logout",methods=["POST"])
def logout():
    token=request.headers.get("X-Auth-Token","")
    if token: db=get_db(); db.execute("DELETE FROM sessions WHERE token=?",(token,)); db.commit()
    return jsonify({"ok":True}),200

@app.route("/api/auth/me",methods=["GET"])
def me():
    user=get_auth_user()
    if user:
        user=dict(user)
        user["is_premium"]=is_premium_user(user)
    return jsonify({"user":user}),200

@app.route("/api/auth/export",methods=["GET"])
def export_user_data():
    """GDPR Art. 20 / CCPA — right to data portability. Returns everything we store about the user
    in a machine-readable JSON format. Triggered from the user's profile; no admin approval needed."""
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db()
    uid=user["id"]
    u_row=db.execute("SELECT id,email,datetime(created,'unixepoch') as created_at,is_premium FROM users WHERE id=?",(uid,)).fetchone()
    logs=db.execute("SELECT exercise,weight,reps,estimated1rm,unit,note,date,datetime(created,'unixepoch') as created_at FROM workout_log WHERE user_id=? ORDER BY created",(uid,)).fetchall()
    plans=db.execute("SELECT id,title,plan_text,lifts_json,structured_plan,days_per_week,unit,is_active,datetime(created,'unixepoch') as created_at FROM saved_plans WHERE user_id=? ORDER BY created",(uid,)).fetchall()
    sessions=db.execute("SELECT plan_id,week,day,exercise,set_number,prescribed_weight,prescribed_reps,actual_weight,actual_reps,rpe,unit,completed,datetime(completed_at,'unixepoch') as completed_at FROM plan_sessions WHERE user_id=? ORDER BY plan_id,week,day,set_number",(uid,)).fetchall()
    data={
        "export_version":"1.0",
        "exported_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        "account":dict(u_row) if u_row else {},
        "workout_log":[dict(r) for r in logs],
        "saved_plans":[dict(r) for r in plans],
        "plan_sessions":[dict(r) for r in sessions],
        "notes":"This export contains all personal data PlateStack stores about your account. Page visit tracking is anonymized (SHA-256 hashed IP, not tied to your identity) and therefore not included."
    }
    # Force the browser to download it as a .json file
    from flask import Response
    import json as _json
    filename=f"platestack-data-{time.strftime('%Y-%m-%d')}.json"
    return Response(
        _json.dumps(data,indent=2),
        mimetype="application/json",
        headers={"Content-Disposition":f'attachment; filename="{filename}"'}
    )

@app.route("/api/auth/delete-account",methods=["POST"])
def delete_account():
    """GDPR Art. 17 / CCPA — right to erasure. Permanently deletes the user and all their data.
    Requires password confirmation in the request body to prevent accidental/CSRF deletion."""
    ip=get_ip()
    if is_auth_rate_limited(ip): return jsonify({"error":"Too many attempts. Wait a few minutes."}),429
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    data=request.get_json(silent=True) or {}
    confirm_pw=str(data.get("password",""))
    if not confirm_pw: return jsonify({"error":"Password required to confirm deletion."}),400
    db=get_db()
    row=db.execute("SELECT password FROM users WHERE id=?",(user["id"],)).fetchone()
    if not row or not check_password(confirm_pw,row["password"]):
        return jsonify({"error":"Incorrect password."}),401
    uid=user["id"]
    # Delete in dependency order — children first
    db.execute("DELETE FROM plan_sessions WHERE user_id=?",(uid,))
    db.execute("DELETE FROM saved_plans WHERE user_id=?",(uid,))
    db.execute("DELETE FROM workout_log WHERE user_id=?",(uid,))
    db.execute("DELETE FROM sessions WHERE user_id=?",(uid,))
    # Note: ip_plan_usage uses "user:{id}" key — nuke that too
    db.execute("DELETE FROM ip_plan_usage WHERE ip=?",(f"user:{uid}",))
    db.execute("DELETE FROM users WHERE id=?",(uid,))
    db.commit()
    return jsonify({"ok":True}),200

@app.route("/api/plan-usage",methods=["GET"])
def plan_usage():
    user=get_auth_user(); ip=get_ip()
    if user:
        # Account users: track per user_id in ip_plan_usage using "user:{id}" as key
        key=f"user:{user['id']}"
        count=get_ip_plan_count(key)
        return jsonify({"count":count,"limit":USER_PLAN_LIMIT,"unlimited":False,"has_account":True}),200
    count=get_ip_plan_count(ip)
    return jsonify({"count":count,"limit":ANON_PLAN_LIMIT,"unlimited":False,"has_account":False}),200

@app.route("/api/log",methods=["GET"])
def get_log():
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    rows=get_db().execute("SELECT id,exercise,weight,reps,estimated1rm,unit,note,date FROM workout_log WHERE user_id=? ORDER BY date DESC,created DESC LIMIT 500",(user["id"],)).fetchall()
    return jsonify({"log":[dict(r) for r in rows]}),200

@app.route("/api/log",methods=["POST"])
def add_log():
    ip=get_ip()
    if is_rate_limited(ip): return jsonify({"error":"Too many requests."}),429
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    data=request.get_json(silent=True) or {}
    exercise=sanitize(data.get("exercise",""),100); weight=float(data.get("weight",0)); reps=int(data.get("reps",0))
    e1rm=int(data.get("estimated1rm",0)); unit_val=data.get("unit","lbs")
    note=sanitize(data.get("note",""),500); date_val=valid_date(data.get("date",""))
    if not exercise or weight<=0 or reps<=0: return jsonify({"error":"Invalid entry."}),400
    if not date_val: return jsonify({"error":"Invalid date. Use YYYY-MM-DD format."}),400
    if unit_val not in ("lbs","kg"): unit_val="lbs"
    db=get_db()
    db.execute("INSERT INTO workout_log(user_id,exercise,weight,reps,estimated1rm,unit,note,date) VALUES(?,?,?,?,?,?,?,?)",(user["id"],exercise,weight,reps,e1rm,unit_val,note,date_val))
    db.commit(); new_id=db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    return jsonify({"ok":True,"id":new_id}),201

@app.route("/api/log/<int:entry_id>",methods=["DELETE"])
def delete_log(entry_id):
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db(); db.execute("DELETE FROM workout_log WHERE id=? AND user_id=?",(entry_id,user["id"])); db.commit()
    return jsonify({"ok":True}),200

@app.route("/api/log/<int:entry_id>",methods=["PATCH"])
def update_log(entry_id):
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    data=request.get_json(silent=True) or {}
    db=get_db(); fields=[]; values=[]
    if "weight" in data:
        w=float(data["weight"])
        if w>0: fields.append("weight=?"); values.append(w)
    if "reps" in data:
        r=int(data["reps"])
        if r>0:
            fields.append("reps=?"); values.append(r)
            row=db.execute("SELECT weight FROM workout_log WHERE id=?",(entry_id,)).fetchone()
            if row:
                w2=float(data.get("weight",row["weight"]))
                e1rm=int(w2*(1+r/30)) if r>1 else int(w2)
                fields.append("estimated1rm=?"); values.append(e1rm)
    if "note" in data: fields.append("note=?"); values.append(sanitize(str(data["note"]),500))
    if "date" in data:
        d=valid_date(str(data["date"]))
        if d: fields.append("date=?"); values.append(d)
    if fields:
        values.extend([entry_id,user["id"]])
        # Safe: `fields` contains only hardcoded column=? strings, never user input.
        # All actual values are passed as ? parameters.
        db.execute(f"UPDATE workout_log SET {','.join(fields)} WHERE id=? AND user_id=?",values)
        db.commit()
    return jsonify({"ok":True}),200

@app.route("/api/plans",methods=["GET"])
def get_saved_plans():
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    rows=get_db().execute("SELECT id,title,plan_text,lifts_json,is_active,(structured_plan IS NOT NULL) as trackable,datetime(created,'unixepoch') as created_at FROM saved_plans WHERE user_id=? ORDER BY created DESC LIMIT 20",(user["id"],)).fetchall()
    return jsonify({"plans":[dict(r) for r in rows]}),200

@app.route("/api/plans",methods=["POST"])
def save_plan():
    """Saves a plan. If structured data is present and `activate` is true, also makes it the active plan and seeds Week 1 sessions."""
    user=get_auth_user()
    if not user: return jsonify({"ok":False,"error":"Sign in to save plans."}),401
    data=request.get_json(silent=True) or {}
    title=sanitize(data.get("title","Untitled Plan"),200); plan_text=sanitize(data.get("plan_text",""),10000)
    lifts_json=str(data.get("lifts_json",""))[:2000]
    structured=data.get("structured")  # dict or None
    activate=bool(data.get("activate",False))
    days_per_week=0
    unit_val=data.get("unit","lbs")
    if unit_val not in ("lbs","kg"): unit_val="lbs"
    if not plan_text: return jsonify({"ok":False,"error":"Missing plan text."}),400
    # Validate + serialize structured plan safely
    import json as _json
    structured_str=None
    if isinstance(structured,dict) and isinstance(structured.get("days"),list):
        try:
            days_per_week=len(structured["days"])
            structured_str=_json.dumps(structured)[:20000]
        except Exception:
            structured_str=None
            days_per_week=0
    db=get_db()
    if activate and structured_str:
        # Deactivate any previously active plans for this user
        db.execute("UPDATE saved_plans SET is_active=0 WHERE user_id=? AND is_active=1",(user["id"],))
    db.execute("INSERT INTO saved_plans(user_id,title,plan_text,lifts_json,structured_plan,days_per_week,unit,is_active) VALUES(?,?,?,?,?,?,?,?)",
        (user["id"],title,plan_text,lifts_json,structured_str,days_per_week,unit_val,1 if (activate and structured_str) else 0))
    db.commit()
    new_id=db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    # Seed plan_sessions for Week 1 if activating
    if activate and structured_str:
        try:
            plan_obj=_json.loads(structured_str)
            for day_obj in plan_obj.get("days",[]):
                day_num=int(day_obj.get("day",0))
                if day_num<=0: continue
                for ex_idx,ex in enumerate(day_obj.get("exercises",[])):
                    ex_name=sanitize(str(ex.get("name",""))[:100],100)
                    sets=int(ex.get("sets",0) or 0)
                    reps=int(ex.get("reps",0) or 0)
                    weight=float(ex.get("weight",0) or 0)
                    ex_unit=ex.get("unit",unit_val)
                    if ex_unit not in ("lbs","kg"): ex_unit=unit_val
                    if not ex_name or sets<=0 or sets>20: continue
                    for set_num in range(1,sets+1):
                        db.execute("INSERT INTO plan_sessions(plan_id,user_id,week,day,exercise,exercise_order,set_number,prescribed_weight,prescribed_reps,unit) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (new_id,user["id"],1,day_num,ex_name,ex_idx,set_num,weight,reps,ex_unit))
            db.commit()
        except Exception as e:
            print(f"Seed plan sessions failed: {e}")
    return jsonify({"ok":True,"id":new_id,"activated":bool(activate and structured_str)}),201

@app.route("/api/plans/<int:plan_id>",methods=["DELETE"])
def delete_plan(plan_id):
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db()
    # SQLite doesn't have cascades enabled by default — delete children first
    db.execute("DELETE FROM plan_sessions WHERE plan_id=? AND user_id=?",(plan_id,user["id"]))
    db.execute("DELETE FROM saved_plans WHERE id=? AND user_id=?",(plan_id,user["id"]))
    db.commit()
    return jsonify({"ok":True}),200

# ── TRACKER / ACTIVE PLAN ENDPOINTS ─────────────────────────────────────────────
# Adaptation tuning — "standard" linear progression with RPE autoregulation
ADAPT_UPPER_BUMP_LBS = 2.5   # upper-body push/pull progression increment
ADAPT_LOWER_BUMP_LBS = 5.0   # lower-body (squat/DL/press legs) increment
ADAPT_UPPER_BUMP_KG  = 1.25
ADAPT_LOWER_BUMP_KG  = 2.5
DELOAD_PCT           = 0.90  # 10% deload if user is grinding badly

def is_lower_body(exercise_name):
    """Rough heuristic — lower-body moves get bigger weight jumps."""
    n=exercise_name.lower()
    return any(k in n for k in ["squat","deadlift","leg press","hip thrust","lunge","step up","rdl","good morning","calf"])

def bump_amount(exercise_name,unit):
    lower=is_lower_body(exercise_name)
    if unit=="kg":
        return ADAPT_LOWER_BUMP_KG if lower else ADAPT_UPPER_BUMP_KG
    return ADAPT_LOWER_BUMP_LBS if lower else ADAPT_UPPER_BUMP_LBS

def adapt_session_weight(prescribed_weight,prescribed_reps,actual_reps,rpe,exercise_name,unit):
    """Per-session micro-adjustment for the SAME exercise's *next unlogged set* later in the workout.
    Kept conservative — big changes happen at week boundaries.
    Returns (new_weight, reason) or (None, None) if no change."""
    if prescribed_weight<=0 or prescribed_reps<=0 or actual_reps is None or rpe is None:
        return None,None
    bump=bump_amount(exercise_name,unit)
    # Hit or exceeded target reps at low effort → tiny bump on remaining sets
    if actual_reps>=prescribed_reps and rpe<=6:
        return prescribed_weight+bump, f"Easy set (RPE {rpe}) — nudging up {bump}{unit}"
    # Missed target significantly → back off remaining sets
    if actual_reps<=prescribed_reps-2 and rpe>=9:
        new_w=round(prescribed_weight*0.95,1)
        return new_w, f"Struggling (RPE {rpe}) — backing off to {new_w}{unit}"
    return None,None

def adapt_week(db,user_id,plan_id,from_week):
    """Weekly reassessment — looks at ALL logged sets from `from_week` for each exercise,
    decides next-week adjustment, and seeds plan_sessions rows for `from_week + 1`.
    Returns number of exercises seeded."""
    rows=db.execute("""SELECT exercise,exercise_order,set_number,day,prescribed_weight,prescribed_reps,actual_weight,actual_reps,rpe,unit,completed
        FROM plan_sessions WHERE user_id=? AND plan_id=? AND week=? ORDER BY day,exercise_order,set_number""",
        (user_id,plan_id,from_week)).fetchall()
    if not rows: return 0
    # Group by (day, exercise) to decide per-exercise adaptation
    by_ex={}
    for r in rows:
        key=(r["day"],r["exercise"],r["exercise_order"])
        by_ex.setdefault(key,[]).append(dict(r))
    next_week=from_week+1
    seeded=0
    for (day,ex_name,ex_order),sets in by_ex.items():
        unit=sets[0]["unit"]
        prescribed_w=sets[0]["prescribed_weight"] or 0
        prescribed_r=sets[0]["prescribed_reps"] or 0
        completed=[s for s in sets if s["completed"]]
        bump=bump_amount(ex_name,unit)
        new_weight=prescribed_w
        if completed:
            avg_rpe=sum((s["rpe"] or 0) for s in completed)/max(1,len(completed))
            hit_all=all((s["actual_reps"] or 0)>=prescribed_r for s in completed)
            missed_badly=sum(1 for s in completed if (s["actual_reps"] or 0)<=prescribed_r-2)
            if hit_all and avg_rpe<=7:
                new_weight=prescribed_w+bump  # crushing it
            elif hit_all and avg_rpe<=9:
                new_weight=prescribed_w+(bump/2)  # small bump
            elif hit_all and avg_rpe>=10:
                new_weight=prescribed_w  # hold
            elif missed_badly>=len(completed)//2:
                new_weight=round(prescribed_w*DELOAD_PCT,1)  # deload
            else:
                new_weight=prescribed_w  # hold
        # Seed next week's sets with the adapted weight
        for s in sets:
            db.execute("""INSERT INTO plan_sessions(plan_id,user_id,week,day,exercise,exercise_order,set_number,prescribed_weight,prescribed_reps,unit)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (plan_id,user_id,next_week,day,ex_name,ex_order,s["set_number"],new_weight,prescribed_r,unit))
            seeded+=1
    db.commit()
    return seeded

@app.route("/api/active-plan",methods=["GET"])
def get_active_plan():
    """Returns the user's currently active plan + all session rows for progress display."""
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db()
    plan=db.execute("SELECT id,title,plan_text,structured_plan,days_per_week,unit,datetime(created,'unixepoch') as created_at FROM saved_plans WHERE user_id=? AND is_active=1 LIMIT 1",(user["id"],)).fetchone()
    if not plan: return jsonify({"active_plan":None}),200
    sessions=db.execute("SELECT id,week,day,exercise,exercise_order,set_number,prescribed_weight,prescribed_reps,actual_weight,actual_reps,rpe,unit,completed,completed_at FROM plan_sessions WHERE user_id=? AND plan_id=? ORDER BY week,day,exercise_order,set_number",(user["id"],plan["id"])).fetchall()
    return jsonify({"active_plan":dict(plan),"sessions":[dict(s) for s in sessions]}),200

@app.route("/api/plans/<int:plan_id>/deactivate",methods=["POST"])
def deactivate_plan(plan_id):
    """Stops tracking this plan but preserves all logged data."""
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db()
    db.execute("UPDATE saved_plans SET is_active=0 WHERE id=? AND user_id=?",(plan_id,user["id"]))
    db.commit()
    return jsonify({"ok":True}),200

@app.route("/api/plans/<int:plan_id>/activate",methods=["POST"])
def activate_plan(plan_id):
    """Makes an existing saved plan the active one. Seeds Week 1 sessions if missing."""
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    if not is_premium_user(user): return jsonify({"error":"Plan tracking is a premium feature.","premium_required":True}),402
    db=get_db()
    plan=db.execute("SELECT id,structured_plan,unit FROM saved_plans WHERE id=? AND user_id=?",(plan_id,user["id"])).fetchone()
    if not plan: return jsonify({"error":"Plan not found."}),404
    if not plan["structured_plan"]: return jsonify({"error":"This plan is too old to track — regenerate a new plan to use the tracker."}),400
    db.execute("UPDATE saved_plans SET is_active=0 WHERE user_id=? AND is_active=1",(user["id"],))
    db.execute("UPDATE saved_plans SET is_active=1 WHERE id=? AND user_id=?",(plan_id,user["id"]))
    # Seed Week 1 if no sessions exist yet
    existing=db.execute("SELECT COUNT(*) as c FROM plan_sessions WHERE plan_id=? AND user_id=?",(plan_id,user["id"])).fetchone()["c"]
    if existing==0:
        try:
            import json as _json
            plan_obj=_json.loads(plan["structured_plan"])
            unit_val=plan["unit"] or "lbs"
            for day_obj in plan_obj.get("days",[]):
                day_num=int(day_obj.get("day",0))
                if day_num<=0: continue
                for ex_idx,ex in enumerate(day_obj.get("exercises",[])):
                    ex_name=sanitize(str(ex.get("name",""))[:100],100)
                    sets=int(ex.get("sets",0) or 0)
                    reps=int(ex.get("reps",0) or 0)
                    weight=float(ex.get("weight",0) or 0)
                    ex_unit=ex.get("unit",unit_val)
                    if ex_unit not in ("lbs","kg"): ex_unit=unit_val
                    if not ex_name or sets<=0 or sets>20: continue
                    for set_num in range(1,sets+1):
                        db.execute("INSERT INTO plan_sessions(plan_id,user_id,week,day,exercise,exercise_order,set_number,prescribed_weight,prescribed_reps,unit) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (plan_id,user["id"],1,day_num,ex_name,ex_idx,set_num,weight,reps,ex_unit))
        except Exception as e:
            print(f"Activate seed failed: {e}")
    db.commit()
    return jsonify({"ok":True}),200

@app.route("/api/plan-sessions/<int:session_id>/log",methods=["POST"])
def log_session_set(session_id):
    """Log actual performance for one prescribed set. Also returns a per-session micro-adjustment suggestion if warranted."""
    ip=get_ip()
    if is_rate_limited(ip): return jsonify({"error":"Too many requests."}),429
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    if not is_premium_user(user): return jsonify({"error":"Plan tracking is a premium feature.","premium_required":True}),402
    data=request.get_json(silent=True) or {}
    row=get_db().execute("SELECT id,plan_id,week,day,exercise,exercise_order,set_number,prescribed_weight,prescribed_reps,unit FROM plan_sessions WHERE id=? AND user_id=?",(session_id,user["id"])).fetchone()
    if not row: return jsonify({"error":"Session not found."}),404
    try:
        actual_weight=float(data.get("actual_weight",0))
        actual_reps=int(data.get("actual_reps",0))
        rpe=int(data.get("rpe",0))
    except (ValueError,TypeError):
        return jsonify({"error":"Invalid values."}),400
    if actual_weight<0 or actual_weight>5000: return jsonify({"error":"Invalid weight."}),400
    if actual_reps<0 or actual_reps>100: return jsonify({"error":"Invalid reps."}),400
    if rpe<1 or rpe>10: return jsonify({"error":"RPE must be 1-10."}),400
    db=get_db()
    db.execute("UPDATE plan_sessions SET actual_weight=?,actual_reps=?,rpe=?,completed=1,completed_at=strftime('%s','now') WHERE id=? AND user_id=?",
        (actual_weight,actual_reps,rpe,session_id,user["id"]))
    # Also mirror to workout_log so existing charts/history work
    try:
        today=time.strftime("%Y-%m-%d")
        e1rm=int(actual_weight*(1+actual_reps/30)) if actual_reps>1 else int(actual_weight)
        db.execute("INSERT INTO workout_log(user_id,exercise,weight,reps,estimated1rm,unit,note,date) VALUES(?,?,?,?,?,?,?,?)",
            (user["id"],row["exercise"],actual_weight,actual_reps,e1rm,row["unit"] or "lbs",f"Plan: W{row['week']}D{row['day']}",today))
    except Exception as e:
        print(f"Mirror to workout_log failed: {e}")
    db.commit()
    # Per-session micro-adaptation: adjust prescribed_weight on REMAINING unlogged sets of same exercise today
    adjustment=None
    new_weight,reason=adapt_session_weight(row["prescribed_weight"] or 0,row["prescribed_reps"] or 0,actual_reps,rpe,row["exercise"],row["unit"] or "lbs")
    if new_weight is not None and abs(new_weight-(row["prescribed_weight"] or 0))>0.01:
        db.execute("""UPDATE plan_sessions SET prescribed_weight=? WHERE user_id=? AND plan_id=? AND week=? AND day=? AND exercise=? AND set_number>? AND completed=0""",
            (new_weight,user["id"],row["plan_id"],row["week"],row["day"],row["exercise"],row["set_number"]))
        db.commit()
        adjustment={"new_weight":new_weight,"reason":reason}
    return jsonify({"ok":True,"adjustment":adjustment}),200

@app.route("/api/plans/<int:plan_id>/progress",methods=["GET"])
def plan_progress(plan_id):
    """Week-over-week per-exercise progress for charting. Returns average top-set weight per week."""
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db()
    # Verify the user owns this plan
    plan=db.execute("SELECT id,title,unit FROM saved_plans WHERE id=? AND user_id=?",(plan_id,user["id"])).fetchone()
    if not plan: return jsonify({"error":"Plan not found."}),404
    # Aggregate per (exercise, week): best actual_weight across logged sets that week
    rows=db.execute("""SELECT exercise,week,MAX(actual_weight) as top_weight,AVG(actual_weight) as avg_weight,AVG(rpe) as avg_rpe,COUNT(*) as sets_logged
        FROM plan_sessions WHERE user_id=? AND plan_id=? AND completed=1
        GROUP BY exercise,week ORDER BY exercise,week""",(user["id"],plan_id)).fetchall()
    by_ex={}
    for r in rows:
        ex=r["exercise"]
        if ex not in by_ex: by_ex[ex]=[]
        by_ex[ex].append({
            "week":r["week"],
            "top_weight":round(r["top_weight"] or 0,1),
            "avg_weight":round(r["avg_weight"] or 0,1),
            "avg_rpe":round(r["avg_rpe"] or 0,1),
            "sets_logged":r["sets_logged"]
        })
    return jsonify({"plan":dict(plan),"progress":by_ex}),200

@app.route("/api/plans/<int:plan_id>/advance-week",methods=["POST"])
def advance_week(plan_id):
    """End-of-week reassessment. Seeds next week with adapted weights based on this week's performance."""
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    if not is_premium_user(user): return jsonify({"error":"Plan tracking is a premium feature.","premium_required":True}),402
    data=request.get_json(silent=True) or {}
    try: from_week=int(data.get("from_week",1))
    except: from_week=1
    if from_week<1 or from_week>52: return jsonify({"error":"Invalid week."}),400
    db=get_db()
    plan=db.execute("SELECT id FROM saved_plans WHERE id=? AND user_id=? AND is_active=1",(plan_id,user["id"])).fetchone()
    if not plan: return jsonify({"error":"Plan not active."}),404
    # Don't re-seed if already seeded
    existing=db.execute("SELECT COUNT(*) as c FROM plan_sessions WHERE user_id=? AND plan_id=? AND week=?",(user["id"],plan_id,from_week+1)).fetchone()["c"]
    if existing>0: return jsonify({"ok":True,"already_seeded":True,"seeded":0}),200
    seeded=adapt_week(db,user["id"],plan_id,from_week)
    return jsonify({"ok":True,"seeded":seeded,"next_week":from_week+1}),200

@app.route("/api/plan",methods=["POST"])
def plan():
    ip=get_ip()
    if is_rate_limited(ip): return jsonify({"error":"Too many requests. Please wait an hour."}),429
    data=request.get_json(silent=True)
    if not data or not isinstance(data,dict): return jsonify({"error":"Invalid request."}),400
    admin=verify_admin(str(data.get("adminCode",""))); user=get_auth_user()
    # Determine usage key and limit
    if admin:
        pass  # unlimited
    elif user:
        usage_key=f"user:{user['id']}"
        count=get_ip_plan_count(usage_key)
        if count>=USER_PLAN_LIMIT:
            return jsonify({"error":f"You've used all {USER_PLAN_LIMIT} plans on your free account. We'll add more plan options soon!","limit_hit":True}),403
    else:
        count=get_ip_plan_count(ip)
        if count>=ANON_PLAN_LIMIT:
            return jsonify({"error":f"You've used your {ANON_PLAN_LIMIT} free plans. Create a free account to get {USER_PLAN_LIMIT} plans.","limit_hit":True}),403
    lifts=data.get("lifts",[]); unit=data.get("unit","lbs")
    goal=sanitize(data.get("goal",""),400); exp=sanitize(data.get("experience","beginner"),50)
    days=sanitize(str(data.get("days","3")),5); split=sanitize(data.get("split","Full body"),100)
    age=sanitize(str(data.get("age","")),3) if data.get("age") else None
    bw=sanitize(str(data.get("bodyweight","")),20) if data.get("bodyweight") else None
    sex=sanitize(str(data.get("sex","")),10) if data.get("sex") else None
    height=sanitize(str(data.get("height","")),20) if data.get("height") else None
    injuries=sanitize(data.get("injuries",""),300) if data.get("injuries") else ""
    preferences=sanitize(data.get("preferences",""),300) if data.get("preferences") else ""
    if unit not in ("lbs","kg"): unit="lbs"
    if exp not in ("beginner","intermediate","advanced"): exp="beginner"
    for field in [goal,split,injuries,preferences]:
        if not is_safe(field): return jsonify({"error":"Invalid input detected."}),400
    if not isinstance(lifts,list) or not lifts: return jsonify({"error":"No lifts provided."}),400
    if len(lifts)>20: return jsonify({"error":"Maximum 20 lifts allowed."}),400
    clean_lifts=[]
    for l in lifts:
        try:
            name=str(l.get("name",""))[:50].strip(); weight=float(l.get("weight",0))
            reps=int(l.get("reps",0)); max_v=int(l.get("max",0))
            if name and 0<weight<5000 and 0<reps<=50 and is_safe(name):
                clean_lifts.append({"name":name,"weight":weight,"reps":reps,"max":max_v})
        except: continue
    if not clean_lifts: return jsonify({"error":"No valid lifts provided."}),400
    parts=[]
    if age: parts.append(f"Age {age}")
    if bw: parts.append(f"BW {bw}")
    if height: parts.append(f"Height {height}")
    if sex: parts.append(sex.capitalize())
    profile=", ".join(parts) if parts else "Not specified"
    lifts_text="\n".join([f"- {l['name']}: {l['weight']}{unit} x {l['reps']} reps → 1RM ~{l['max']}{unit}" for l in clean_lifts])
    # Build log context from user's recent history if logged in
    log_context=""
    if user:
        try:
            db=get_db()
            recent=db.execute(
                "SELECT exercise,weight,reps,estimated1rm,unit,date FROM workout_log WHERE user_id=? ORDER BY date DESC,created DESC LIMIT 60",
                (user["id"],)
            ).fetchall()
            if recent:
                # Find best estimated1rm per exercise from recent logs
                best={}
                for row in recent:
                    ex=row["exercise"]
                    if ex not in best or row["estimated1rm"]>best[ex]["estimated1rm"]:
                        best[ex]=dict(row)
                lines=[]
                for ex,r in list(best.items())[:10]:
                    lines.append(f"- {ex}: best recent set {r['weight']}{r['unit']} x {r['reps']} reps (est. 1RM {r['estimated1rm']}{r['unit']}) on {r['date']}")
                log_context="\n".join(lines)
        except: pass
    try:
        raw=call_claude(PLAN_SYSTEM,build_plan_prompt(profile,exp,days,split,goal,unit,lifts_text,injuries,preferences,log_context),max_tokens=2500,cache_system=True)
        # Parse AI-generated title out of the response
        plan_title=None
        plan_text=raw
        structured=None
        # First, strip out STRUCTURED_PLAN JSON block if present (so users never see it)
        sp_marker="STRUCTURED_PLAN:"
        if sp_marker in plan_text:
            idx=plan_text.rfind(sp_marker)
            json_part=plan_text[idx+len(sp_marker):].strip()
            plan_text=plan_text[:idx].rstrip()
            # The AI might wrap it in ```json fences — strip those
            json_part=re.sub(r'^```(?:json)?\s*','',json_part)
            json_part=re.sub(r'\s*```\s*$','',json_part).strip()
            try:
                import json as _json
                structured=_json.loads(json_part)
            except Exception as e:
                print(f"Structured plan parse failed: {e}")
                structured=None
        # Parse TITLE: line
        lines=plan_text.split("\n")
        for i,line in enumerate(lines):
            stripped=line.strip()
            if stripped.startswith("TITLE:"):
                plan_title=stripped[6:].strip()
                # Remove the title line (and blank line after) from the plan body
                rest=lines[i+1:]
                while rest and not rest[0].strip():
                    rest=rest[1:]
                plan_text="\n".join(rest)
                break
        if not admin and not user: increment_ip_plan_count(ip)
        elif not admin and user:
            usage_key=f"user:{user['id']}"
            increment_ip_plan_count(usage_key)
        # Return updated count and limit
        if admin:
            new_count,new_limit=0,999
        elif user:
            usage_key=f"user:{user['id']}"
            new_count,new_limit=get_ip_plan_count(usage_key),USER_PLAN_LIMIT
        else:
            new_count,new_limit=get_ip_plan_count(ip),ANON_PLAN_LIMIT
        return jsonify({"plan":plan_text,"plan_title":plan_title,"structured":structured,"admin":admin,"plan_count":new_count,"plan_limit":new_limit,"has_account":bool(user)})
    except requests.exceptions.Timeout: return jsonify({"error":"Request timed out. Try again."}),504
    except Exception as e:
        # Log internally but don't expose stack traces or internal details to the client
        print(f"Plan generation error: {e}")
        return jsonify({"error":"Something went wrong generating your plan. Please try again."}),500

@app.route("/api/question",methods=["POST"])
def question():
    ip=get_ip()
    if is_rate_limited(ip): return jsonify({"error":"Too many requests."}),429
    data=request.get_json(silent=True)
    if not data: return jsonify({"error":"Invalid request."}),400
    plan_text=sanitize(data.get("plan",""),3000); q=sanitize(data.get("question",""),300)
    if not plan_text or not q: return jsonify({"error":"Missing plan or question."}),400
    if not is_safe(q): return jsonify({"error":"Invalid input detected."}),400
    try:
        answer=call_claude("You are an expert strength coach answering a follow-up question about a training plan. Be concise — 2-4 sentences or a short bullet list. Never restate the full plan.",f"Training plan:\n{plan_text}\n\nQuestion: {q}",max_tokens=350,model="claude-haiku-4-5-20251001",cache_system=True)
        return jsonify({"answer":answer})
    except requests.exceptions.Timeout: return jsonify({"error":"Request timed out."}),504
    except Exception as e:
        print(f"Question error: {e}")
        return jsonify({"error":"Something went wrong. Please try again."}),500

@app.route("/api/waitlist",methods=["POST"])
def waitlist():
    data=request.get_json(silent=True) or {}
    email=sanitize(str(data.get("email","")),200).lower()
    if not email or "@" not in email or "." not in email: return jsonify({"ok":False}),400
    try: get_db().execute("INSERT INTO waitlist(email) VALUES(?)",(email,)); get_db().commit()
    except sqlite3.IntegrityError: pass
    try:
        with open(WAITLIST_FILE,"a") as f: f.write(f"{email}\n")
    except: pass
    return jsonify({"ok":True}),200

@app.route("/api/verify-admin",methods=["POST"])
def verify_admin_route():
    ip=get_ip()
    if is_auth_rate_limited(ip): return jsonify({"error":"Too many requests."}),429
    data=request.get_json(silent=True) or {}
    return jsonify({"valid":verify_admin(sanitize(str(data.get("code","")),100))}),200

@app.route("/api/emails",methods=["GET"])
def view_emails():
    code=request.args.get("code","")
    if not verify_admin(code): return "Unauthorized",403
    db=get_db()
    wl=db.execute("SELECT email,datetime(created,'unixepoch') as ts FROM waitlist ORDER BY created DESC").fetchall()
    ur=db.execute("SELECT email,datetime(created,'unixepoch') as ts FROM users ORDER BY created DESC").fetchall()
    # Visit analytics
    total_visits=db.execute("SELECT COUNT(*) as c FROM page_visits").fetchone()["c"]
    today=time.strftime("%Y-%m-%d")
    visits_today=db.execute("SELECT COUNT(*) as c FROM page_visits WHERE date=?",(today,)).fetchone()["c"]
    visits_7d=db.execute("SELECT COUNT(*) as c FROM page_visits WHERE date>=date('now','-7 days')").fetchone()["c"]
    visits_30d=db.execute("SELECT COUNT(*) as c FROM page_visits WHERE date>=date('now','-30 days')").fetchone()["c"]
    # Daily breakdown for last 14 days
    daily=db.execute("SELECT date,COUNT(*) as visits FROM page_visits WHERE date>=date('now','-14 days') GROUP BY date ORDER BY date DESC").fetchall()
    # Plan generation totals
    plans_made=db.execute("SELECT COALESCE(SUM(count),0) as total FROM ip_plan_usage").fetchone()["total"]
    plans_saved=db.execute("SELECT COUNT(*) as c FROM saved_plans").fetchone()["c"]
    workouts_logged=db.execute("SELECT COUNT(*) as c FROM workout_log").fetchone()["c"]
    fmt=request.args.get("format","html")
    if fmt=="json":
        return jsonify({
            "waitlist":[dict(r) for r in wl],
            "accounts":[dict(r) for r in ur],
            "stats":{
                "total_unique_visits":total_visits,
                "visits_today":visits_today,
                "visits_7d":visits_7d,
                "visits_30d":visits_30d,
                "daily_last_14":[dict(r) for r in daily],
                "plans_generated":plans_made,
                "plans_saved":plans_saved,
                "workouts_logged":workouts_logged,
            }
        })
    def tbl(rows,title):
        if not rows: return f"<h2>{title}</h2><p style='color:#999'>None yet.</p>"
        trs="".join(f"<tr><td>{i+1}</td><td>{r['email']}</td><td style='color:#999'>{r['ts']}</td></tr>" for i,r in enumerate(rows))
        return f"<h2>{title} ({len(rows)})</h2><table><thead><tr><th>#</th><th>Email</th><th>Date</th></tr></thead><tbody>{trs}</tbody></table>"
    # Stat cards
    stat_cards=f"""<div class="stats-grid">
        <div class="stat-card"><div class="stat-value">{visits_today}</div><div class="stat-label">Visits today</div></div>
        <div class="stat-card"><div class="stat-value">{visits_7d}</div><div class="stat-label">Last 7 days</div></div>
        <div class="stat-card"><div class="stat-value">{visits_30d}</div><div class="stat-label">Last 30 days</div></div>
        <div class="stat-card"><div class="stat-value">{total_visits}</div><div class="stat-label">All time</div></div>
    </div>
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-value">{len(ur)}</div><div class="stat-label">Accounts</div></div>
        <div class="stat-card"><div class="stat-value">{plans_made}</div><div class="stat-label">Plans generated</div></div>
        <div class="stat-card"><div class="stat-value">{plans_saved}</div><div class="stat-label">Plans saved</div></div>
        <div class="stat-card"><div class="stat-value">{workouts_logged}</div><div class="stat-label">Workouts logged</div></div>
    </div>"""
    # Daily visits table
    if daily:
        daily_rows="".join(f"<tr><td>{r['date']}</td><td>{r['visits']}</td></tr>" for r in daily)
        daily_tbl=f'<h2>Daily visits (last 14 days)</h2><table><thead><tr><th>Date</th><th>Unique visitors</th></tr></thead><tbody>{daily_rows}</tbody></table>'
    else:
        daily_tbl='<h2>Daily visits</h2><p style="color:#999">No visits tracked yet.</p>'
    return f"""<!DOCTYPE html><html><head><title>PlateStack Admin</title><style>body{{font-family:system-ui;padding:2rem;max-width:800px;margin:0 auto;background:#f9f9f9}}h1{{font-size:22px}}h2{{font-size:16px;margin:2rem 0 0.5rem}}table{{width:100%;border-collapse:collapse;font-size:14px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}th{{text-align:left;padding:10px 14px;background:#f0f0f0;border-bottom:2px solid #ddd}}td{{padding:9px 14px;border-bottom:1px solid #eee}}a{{font-size:13px;color:#888;margin-top:1.5rem;display:inline-block}}.stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:1rem 0}}.stat-card{{background:#fff;padding:1rem;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);text-align:center}}.stat-value{{font-size:28px;font-weight:700;color:#f97316;line-height:1}}.stat-label{{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.05em;margin-top:6px}}@media(max-width:600px){{.stats-grid{{grid-template-columns:repeat(2,1fr)}}}}</style></head><body><h1>🏋️ PlateStack Admin</h1>{stat_cards}{daily_tbl}{tbl(ur,"Accounts")}{tbl(wl,"Waitlist")}<a href="?code={code}&format=json">JSON</a></body></html>"""

if __name__=="__main__":
    app.run(debug=False)
