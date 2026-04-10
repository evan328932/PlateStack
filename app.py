import os
import time
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder="public")

# ── Rate limiting ──────────────────────────────────────────────────────────────
RATE_LIMIT = 15
RATE_WINDOW = 3600
request_log = defaultdict(list)

def is_rate_limited(ip):
    now = time.time()
    window_start = now - RATE_WINDOW
    request_log[ip] = [t for t in request_log[ip] if t > window_start]
    if len(request_log[ip]) >= RATE_LIMIT:
        return True
    request_log[ip].append(now)
    return False

def get_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr

def sanitize(text):
    text = str(text).strip()
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text

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
    if not data:
        return jsonify({"error": "Invalid request."}), 400

    lifts = data.get("lifts", [])
    unit = data.get("unit", "lbs")
    goal = sanitize(data.get("goal", ""))
    experience = sanitize(data.get("experience", "beginner"))

    if not lifts or not isinstance(lifts, list):
        return jsonify({"error": "No lifts provided."}), 400
    if len(lifts) > 20:
        return jsonify({"error": "Maximum 20 lifts allowed."}), 400
    if unit not in ("lbs", "kg"):
        unit = "lbs"
    if experience not in ("beginner", "intermediate", "advanced"):
        experience = "beginner"
    if len(goal) > 500:
        goal = goal[:500]

    # Validate lift data
    clean_lifts = []
    for l in lifts:
        try:
            name = str(l.get("name", ""))[:50].strip()
            weight = float(l.get("weight", 0))
            reps = int(l.get("reps", 0))
            max_val = int(l.get("max", 0))
            if name and 0 < weight < 5000 and 0 < reps <= 50:
                clean_lifts.append({"name": name, "weight": weight, "reps": reps, "max": max_val})
        except Exception:
            continue

    if not clean_lifts:
        return jsonify({"error": "No valid lifts provided."}), 400

    lifts_text = "\n".join([
        f"- {l['name']}: {l['weight']}{unit} × {l['reps']} reps (estimated 1RM: {l['max']}{unit})"
        for l in clean_lifts
    ])

    system_prompt = (
        "You are an expert strength and conditioning coach with deep knowledge of powerlifting, "
        "bodybuilding, and general fitness. You give specific, practical, evidence-based advice. "
        "You write in a direct, motivating tone — like a knowledgeable coach talking to an athlete. "
        "Never give vague generic advice. Always be specific with numbers, sets, reps, and percentages. "
        "Do not add any preamble or closing remarks — just the training plan content."
    )

    user_msg = (
        f"Here are my current lifts:\n{lifts_text}\n\n"
        f"Experience level: {experience}\n"
        f"Goal: {goal}\n"
        f"Units: {unit}\n\n"
        "Based on my lifts and goal, give me:\n"
        "1. A brief analysis of where I'm at relative to my goal\n"
        "2. A specific weekly training program — include exact sets, reps, and percentages of my 1RM for each exercise\n"
        "3. What I should work up to over the next 8-12 weeks with specific milestone targets\n"
        "4. 2-3 key tips specific to my situation\n\n"
        "Be specific with the numbers. Use my actual lift numbers throughout."
    )

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": os.environ.get("ANTHROPIC_API_KEY"),
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1500,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_msg}],
            },
            timeout=30,
        )
        result = response.json()
        if "error" in result:
            return jsonify({"error": result["error"]["message"]}), 500
        plan_text = "".join(block.get("text", "") for block in result.get("content", []))
        return jsonify({"plan": plan_text})

    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False)
