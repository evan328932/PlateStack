import os
import time
import requests
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder="public")

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

def sanitize(text, max_len=500):
    text = str(text).strip()[:max_len]
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text


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
    experience = sanitize(data.get("experience", "beginner"), 50)
    days = sanitize(str(data.get("days", "3")), 10)
    split = sanitize(data.get("split", "Full body"), 100)
    age = data.get("age")
    bodyweight = data.get("bodyweight")
    sex = data.get("sex")
    height = data.get("height")

    if not isinstance(lifts, list) or not lifts:
        return jsonify({"error": "No lifts provided."}), 400
    if len(lifts) > 20:
        return jsonify({"error": "Maximum 20 lifts allowed."}), 400
    if unit not in ("lbs", "kg"):
        unit = "lbs"

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

    # Build athlete profile string
    profile_parts = []
    if age: profile_parts.append(f"Age: {str(age)[:3]}")
    if bodyweight: profile_parts.append(f"Bodyweight: {sanitize(str(bodyweight), 20)}")
    if height: profile_parts.append(f"Height: {sanitize(str(height), 20)}")
    if sex: profile_parts.append(f"Sex: {sanitize(str(sex), 10)}")
    profile = ", ".join(profile_parts) if profile_parts else "Not provided"

    lifts_text = "\n".join([
        f"- {l['name']}: {l['weight']}{unit} x {l['reps']} reps (estimated 1RM: {l['max']}{unit})"
        for l in clean_lifts
    ])

    system_prompt = (
        "You are an expert strength and conditioning coach. "
        "Give specific, practical, evidence-based advice with exact numbers. "
        "Write in a direct, motivating tone like a knowledgeable coach. "
        "Format your response using markdown: use ## for section headers and bullet points for lists. "
        "Never use ** for bolding mid-sentence — only use it for labels like 'Day 1:' or 'Week 1:'. "
        "Do not add preamble or closing remarks — start directly with the plan content."
    )

    user_msg = (
        f"Athlete profile: {profile}\n"
        f"Experience level: {experience}\n"
        f"Training schedule: {days} days per week, {split}\n"
        f"Goal: {goal}\n"
        f"Units: {unit}\n\n"
        f"Current lifts:\n{lifts_text}\n\n"
        "Based on all of this, provide:\n"
        "## Where You're At\n"
        "Brief analysis of current strength levels relative to the goal.\n\n"
        "## Weekly Training Program\n"
        f"A complete {days}-day program matching the {split} split. "
        "Include exact sets, reps, and percentages of 1RM for each exercise. "
        "Lay out each training day clearly.\n\n"
        "## 8-12 Week Progression\n"
        "Specific milestone targets with numbers — what they should hit at 4 weeks, 8 weeks, and 12 weeks.\n\n"
        "## Key Tips\n"
        "2-3 specific tips based on their actual numbers and situation."
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
                "max_tokens": 1800,
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


@app.route("/api/question", methods=["POST"])
def question():
    ip = get_ip()
    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests. Please wait an hour and try again."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request."}), 400

    plan = sanitize(data.get("plan", ""), 4000)
    q = sanitize(data.get("question", ""), 300)

    if not plan or not q:
        return jsonify({"error": "Missing plan or question."}), 400

    system_prompt = (
        "You are an expert strength coach. The user has been given a training plan and has a follow-up question. "
        "Answer specifically and practically based on the plan provided. Be concise — 2-4 sentences or a short list. "
        "Do not restate the entire plan. Just answer the question directly."
    )
    user_msg = f"Here is the training plan:\n\n{plan}\n\nQuestion: {q}"

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
                "max_tokens": 400,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_msg}],
            },
            timeout=20,
        )
        result = response.json()
        if "error" in result:
            return jsonify({"error": result["error"]["message"]}), 500
        answer = "".join(block.get("text", "") for block in result.get("content", []))
        return jsonify({"answer": answer})
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out. Try again."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False)
