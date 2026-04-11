import os
import re
import time
import hmac
import hashlib
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder="public")

# ── Config ─────────────────────────────────────────────────────────────────────
# Set these in Railway environment variables:
# ANTHROPIC_API_KEY  — your Anthropic key
# ADMIN_CODE         — your secret unlimited-use code (e.g. "mygymcode2026")
ANTHROPIC_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
ADMIN_CODE     = os.environ.get("ADMIN_CODE", "")

# ── Rate limiting ──────────────────────────────────────────────────────────────
RATE_LIMIT  = 20   # requests per IP per hour (covers plans + questions)
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

# ── Input sanitization ─────────────────────────────────────────────────────────
def sanitize(value, max_len: int = 500) -> str:
    text = str(value).strip()[:max_len]
    # Collapse excessive newlines
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    # Strip any HTML/script tags
    text = re.sub(r'<[^>]*>', '', text)
    return text

def is_safe_string(s: str) -> bool:
    """Reject strings that look like prompt injection attempts."""
    dangerous = [
        "ignore previous", "ignore all", "disregard", "forget your instructions",
        "new instructions", "system prompt", "you are now", "act as",
        "pretend you", "jailbreak", "<script", "javascript:"
    ]
    low = s.lower()
    return not any(d in low for d in dangerous)

# ── Admin code verification ────────────────────────────────────────────────────
def verify_admin(code: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if not ADMIN_CODE or not code:
        return False
    return hmac.compare_digest(
        hashlib.sha256(code.encode()).digest(),
        hashlib.sha256(ADMIN_CODE.encode()).digest()
    )

# ── Anthropic API call ─────────────────────────────────────────────────────────
def call_claude(system_prompt: str, user_msg: str, max_tokens: int = 1400,
                model: str = "claude-sonnet-4-20250514", cache_system: bool = False):
    """
    Calls the Anthropic API. If cache_system=True, marks the system prompt
    for prompt caching (saves ~10-15% on repeated system prompt tokens).
    """
    if cache_system:
        system_content = [
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"}
            }
        ]
    else:
        system_content = system_prompt

    headers = {
        "x-api-key": ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    if cache_system:
        headers["anthropic-beta"] = "prompt-caching-2024-07-31"

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json={
            "model": model,
            "max_tokens": max_tokens,
            "system": system_content,
            "messages": [{"role": "user", "content": user_msg}],
        },
        timeout=35,
    )
    result = response.json()
    if "error" in result:
        raise Exception(result["error"].get("message", "API error"))
    return "".join(block.get("text", "") for block in result.get("content", []))

# ── Structured plan template ───────────────────────────────────────────────────
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

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("public", "index.html")


@app.route("/api/plan", methods=["POST"])
def plan():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests. Please wait an hour and try again."}), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    # Admin bypass check
    admin = verify_admin(str(data.get("adminCode", "")))

    # Validate and sanitize inputs
    lifts   = data.get("lifts", [])
    unit    = data.get("unit", "lbs")
    goal    = sanitize(data.get("goal", ""), 400)
    exp     = sanitize(data.get("experience", "beginner"), 50)
    days    = sanitize(str(data.get("days", "3")), 5)
    split   = sanitize(data.get("split", "Full body"), 100)
    age     = sanitize(str(data.get("age", "")), 3) if data.get("age") else None
    bw      = sanitize(str(data.get("bodyweight", "")), 20) if data.get("bodyweight") else None
    sex     = sanitize(str(data.get("sex", "")), 10) if data.get("sex") else None
    height  = sanitize(str(data.get("height", "")), 20) if data.get("height") else None

    if unit not in ("lbs", "kg"):
        unit = "lbs"
    if exp not in ("beginner", "intermediate", "advanced"):
        exp = "beginner"

    # Prompt injection guard
    for field in [goal, split]:
        if not is_safe_string(field):
            return jsonify({"error": "Invalid input detected."}), 400

    if not isinstance(lifts, list) or not lifts:
        return jsonify({"error": "No lifts provided."}), 400
    if len(lifts) > 20:
        return jsonify({"error": "Maximum 20 lifts allowed."}), 400

    clean_lifts = []
    for l in lifts:
        try:
            name = str(l.get("name", ""))[:50].strip()
            weight = float(l.get("weight", 0))
            reps   = int(l.get("reps", 0))
            max_v  = int(l.get("max", 0))
            if name and 0 < weight < 5000 and 0 < reps <= 50 and is_safe_string(name):
                clean_lifts.append({"name": name, "weight": weight, "reps": reps, "max": max_v})
        except Exception:
            continue

    if not clean_lifts:
        return jsonify({"error": "No valid lifts provided."}), 400

    # Build profile and lifts text
    parts = []
    if age: parts.append(f"Age {age}")
    if bw:  parts.append(f"BW {bw}")
    if height: parts.append(f"Height {height}")
    if sex: parts.append(sex.capitalize())
    profile = ", ".join(parts) if parts else "Not specified"

    lifts_text = "\n".join([
        f"- {l['name']}: {l['weight']}{unit} x {l['reps']} reps → 1RM ~{l['max']}{unit}"
        for l in clean_lifts
    ])

    user_msg = build_plan_prompt(profile, exp, days, split, goal, unit, lifts_text)

    try:
        plan_text = call_claude(
            PLAN_SYSTEM, user_msg,
            max_tokens=1400,
            model="claude-sonnet-4-20250514",
            cache_system=True   # prompt caching on system prompt
        )
        return jsonify({"plan": plan_text, "admin": admin})
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/question", methods=["POST"])
def question():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests. Please wait an hour and try again."}), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    plan_text = sanitize(data.get("plan", ""), 3000)
    q         = sanitize(data.get("question", ""), 300)

    if not plan_text or not q:
        return jsonify({"error": "Missing plan or question."}), 400

    # Prompt injection guard on the question
    if not is_safe_string(q):
        return jsonify({"error": "Invalid input detected."}), 400

    qa_system = "You are an expert strength coach answering a follow-up question about a training plan. Be concise and specific — 2-4 sentences or a short bullet list. Never restate the full plan. Answer only what was asked."
    user_msg  = f"Training plan:\n{plan_text}\n\nQuestion: {q}"

    try:
        # Use Haiku for Q&A — much cheaper, fast, perfectly capable for short answers
        answer = call_claude(
            qa_system, user_msg,
            max_tokens=350,
            model="claude-haiku-4-5-20251001",
            cache_system=True
        )
        return jsonify({"answer": answer})
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/verify-admin", methods=["POST"])
def verify_admin_route():
    """Lets the frontend verify an admin code without exposing the code itself."""
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"valid": False}), 200

    code = sanitize(str(data.get("code", "")), 100)
    return jsonify({"valid": verify_admin(code)}), 200


if __name__ == "__main__":
    app.run(debug=False)
