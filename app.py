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
            CREATE TABLE IF NOT EXISTS ip_plan_usage(ip TEXT PRIMARY KEY,count INTEGER NOT NULL DEFAULT 0,updated INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE TABLE IF NOT EXISTS waitlist(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE TABLE IF NOT EXISTS page_visits(id INTEGER PRIMARY KEY AUTOINCREMENT,date TEXT NOT NULL,ip_hash TEXT NOT NULL,created INTEGER NOT NULL DEFAULT(strftime('%s','now')));
            CREATE INDEX IF NOT EXISTS idx_visits_date ON page_visits(date);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_visits_unique ON page_visits(date,ip_hash);
        """)
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
Then a blank line, then the rest of the plan."""

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
    return jsonify({"user":user}),200

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
    rows=get_db().execute("SELECT id,title,plan_text,lifts_json,datetime(created,'unixepoch') as created_at FROM saved_plans WHERE user_id=? ORDER BY created DESC LIMIT 20",(user["id"],)).fetchall()
    return jsonify({"plans":[dict(r) for r in rows]}),200

@app.route("/api/plans",methods=["POST"])
def save_plan():
    user=get_auth_user()
    if not user: return jsonify({"ok":False}),200
    data=request.get_json(silent=True) or {}
    title=sanitize(data.get("title","Untitled Plan"),200); plan_text=sanitize(data.get("plan_text",""),10000)
    lifts_json=str(data.get("lifts_json",""))[:2000]
    if not plan_text: return jsonify({"ok":False}),400
    db=get_db()
    db.execute("INSERT INTO saved_plans(user_id,title,plan_text,lifts_json) VALUES(?,?,?,?)",(user["id"],title,plan_text,lifts_json))
    db.commit(); new_id=db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    return jsonify({"ok":True,"id":new_id}),201

@app.route("/api/plans/<int:plan_id>",methods=["DELETE"])
def delete_plan(plan_id):
    user=get_auth_user()
    if not user: return jsonify({"error":"Not logged in."}),401
    db=get_db(); db.execute("DELETE FROM saved_plans WHERE id=? AND user_id=?",(plan_id,user["id"])); db.commit()
    return jsonify({"ok":True}),200

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
        raw=call_claude(PLAN_SYSTEM,build_plan_prompt(profile,exp,days,split,goal,unit,lifts_text,injuries,preferences,log_context),max_tokens=2000,cache_system=True)
        # Parse AI-generated title out of the response
        plan_title=None
        plan_text=raw
        lines=raw.split("\n")
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
        return jsonify({"plan":plan_text,"plan_title":plan_title,"admin":admin,"plan_count":new_count,"plan_limit":new_limit,"has_account":bool(user)})
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
