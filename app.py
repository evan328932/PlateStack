import os, re, time, hmac, hashlib, secrets, sqlite3
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory, g

app = Flask(__name__, static_folder="public")

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ADMIN_CODE    = os.environ.get("ADMIN_CODE", "")
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "")  # set in Railway env vars
DB_PATH       = os.environ.get("DB_PATH", "liftlab.db")
WAITLIST_FILE = "waitlist.txt"
ANON_PLAN_LIMIT = 2    # no account
USER_PLAN_LIMIT = 4    # free account
FREE_PLAN_LIMIT = 2    # alias used in older code paths

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
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

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

PROGRESSION: For the weekly program, include a simple weekly progression scheme for each main lift (e.g. "+5 lbs/week on squat", "add a rep each week", "deload every 4th week"). Make it concrete and specific to their numbers."""

def build_plan_prompt(profile,experience,days,split,goal,unit,lifts_text,injuries=None,style_prefs=None,log_context=None):
    injuries_line = f"\nInjuries/Limitations: {injuries}" if injuries else ""
    style_line = f"\nTraining Style Preferences: {style_prefs}" if style_prefs else ""
    log_line = f"\nRecent Progress (from their workout log):\n{log_context}" if log_context else ""
    return f"""ATHLETE:
Profile: {profile}
Experience: {experience}
Schedule: {days} days/week, {split}
Goal: {goal}
Unit: {unit}{injuries_line}{style_line}
Lifts:
{lifts_text}{log_line}

TEMPLATE TO FILL:

## TITLE: [Write a short punchy plan title, 4-8 words, e.g. "4-Day Strength Block for Intermediate Lifter" — NO markdown, just plain text after the colon]

## Where You're At
[Write 2-3 plain prose sentences about their current level vs their goal. PLAIN TEXT ONLY — no dashes, no bullets, no sub-headers.]

## Weekly Program ({days}-Day {split})
[Each training day with exercises: name — sets x reps @ % of 1RM (actual {unit})]
[After each main lift, add a progression note: e.g. "+5 {unit}/week" or "add 1 rep/week until 12, then reset"]

## Progression Scheme
[2-3 bullet points: exactly how to add weight/reps week over week for the main lifts. Include a deload recommendation.]

## 4-Week Milestone
[Specific numbers to hit]

## 8-Week Milestone
[Specific numbers to hit]

## 12-Week Milestone
[Specific numbers to hit]

## Key Tips
[2-3 tips tailored to their specific numbers and any injuries/preferences mentioned]"""

@app.route("/api/config", methods=["GET"])
def config():
    """Returns public config values — safe to expose to frontend."""
    return jsonify({"contact_email": CONTACT_EMAIL}), 200

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
    token=make_token(); db.execute("INSERT INTO sessions(token,user_id) VALUES(?,?)",(token,row["id"])); db.commit()
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
    note=sanitize(data.get("note",""),500); date_val=sanitize(data.get("date",""),20)
    if not exercise or weight<=0 or reps<=0: return jsonify({"error":"Invalid entry."}),400
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
    if "date" in data: fields.append("date=?"); values.append(sanitize(str(data["date"]),20))
    if fields:
        values.extend([entry_id,user["id"]])
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
    if unit not in ("lbs","kg"): unit="lbs"
    if exp not in ("beginner","intermediate","advanced"): exp="beginner"
    for field in [goal,split]:
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
    injuries=sanitize(data.get("injuries",""),300) if data.get("injuries") else None
    style_prefs=sanitize(data.get("stylePrefs",""),300) if data.get("stylePrefs") else None
    # Build log context from recent workout history if provided
    log_context=None
    log_entries=data.get("logContext",[])
    if isinstance(log_entries,list) and log_entries:
        lines=[]
        for entry in log_entries[:15]:
            try:
                lines.append(f"- {entry['exercise']}: {entry['weight']}{unit} x {entry['reps']} reps (est. 1RM {entry['estimated1rm']}{unit}) on {entry['date']}")
            except: continue
        if lines: log_context="\n".join(lines)
    lifts_text="\n".join([f"- {l['name']}: {l['weight']}{unit} x {l['reps']} reps → 1RM ~{l['max']}{unit}" for l in clean_lifts])
    try:
        plan_text=call_claude(PLAN_SYSTEM,build_plan_prompt(profile,exp,days,split,goal,unit,lifts_text,injuries,style_prefs,log_context),max_tokens=2500,cache_system=True)
        # Extract AI-generated title from the plan text
        plan_title="Training Plan"
        import re as _re
        title_match=_re.search(r'^##\s+TITLE:\s*(.+)$',plan_text,_re.MULTILINE)
        if title_match:
            plan_title=title_match.group(1).strip()
            # Remove the TITLE line from the plan text shown to users
            plan_text=_re.sub(r'^##\s+TITLE:.*\n?','',plan_text,flags=_re.MULTILINE).lstrip()
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
    except Exception as e: return jsonify({"error":str(e)}),500

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
    except Exception as e: return jsonify({"error":str(e)}),500

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
    fmt=request.args.get("format","html")
    if fmt=="json": return jsonify({"waitlist":[dict(r) for r in wl],"accounts":[dict(r) for r in ur]})
    def tbl(rows,title):
        if not rows: return f"<h2>{title}</h2><p style='color:#999'>None yet.</p>"
        trs="".join(f"<tr><td>{i+1}</td><td>{r['email']}</td><td style='color:#999'>{r['ts']}</td></tr>" for i,r in enumerate(rows))
        return f"<h2>{title} ({len(rows)})</h2><table><thead><tr><th>#</th><th>Email</th><th>Date</th></tr></thead><tbody>{trs}</tbody></table>"
    return f"""<!DOCTYPE html><html><head><title>LiftLab Admin</title><style>body{{font-family:system-ui;padding:2rem;max-width:700px;margin:0 auto;background:#f9f9f9}}h1{{font-size:22px}}h2{{font-size:16px;margin:2rem 0 0.5rem}}table{{width:100%;border-collapse:collapse;font-size:14px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}th{{text-align:left;padding:10px 14px;background:#f0f0f0;border-bottom:2px solid #ddd}}td{{padding:9px 14px;border-bottom:1px solid #eee}}a{{font-size:13px;color:#888;margin-top:1.5rem;display:inline-block}}</style></head><body><h1>🏋️ LiftLab Admin</h1>{tbl(ur,"Accounts")}{tbl(wl,"Waitlist")}<a href="?code={code}&format=json">JSON</a></body></html>"""

if __name__=="__main__":
    app.run(debug=False)
