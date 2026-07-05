"""
app.py — VisaNet ISO 8583 Decoder, web edition (Flask)

Lets people use the parser via a shared link instead of the desktop GUI.
All actual ISO 8583 decoding is delegated to visa_iso8583_parser_v1.py
(unmodified) through visa_adapter.py (also unmodified from the desktop
app's shared logic) — this file only adds: routing, the free-tries
counter, and license-key unlocking.

FREE TIER / LICENSING MODEL
----------------------------
- Each visitor gets FREE_PARSE_LIMIT (default 10) parses, tracked via a
  signed browser session cookie (no login required).
- To go over the limit, the visitor enters a license key you've sold
  them. Valid, unused keys are stored in keys.json (see generate_keys.py
  to create new ones). Once redeemed, a key is marked "used" and tied to
  that browser session going forward (unlimited parses in that session).

CAVEATS (read before relying on this for revenue)
---------------------------------------------------
1. Session-cookie tracking is easy to bypass (clearing cookies / using a
   private window resets the free-parse counter). This is fine for a
   soft paywall / honest-use MVP, not for hard enforcement.
2. keys.json is a plain file on local disk. On most free hosting tiers
   (including Render's free plan) the filesystem is EPHEMERAL — it can
   reset on redeploy or when the free instance spins down. For anything
   beyond a quick MVP, move key storage to a real database (Render's free
   Postgres tier, or SQLite on a persistent disk add-on).
3. Don't log or persist the raw pasted hex beyond the request lifecycle
   if people might paste real production card traffic — see the notice
   in the page footer.
"""

import os
import re
import json
import secrets
from datetime import datetime, timezone

from flask import Flask, request, jsonify, session, render_template

import visa_iso8583_parser_v1 as visa_parser
from visa_adapter import decode_visa_message, _extract_rrn, _extract_mti

app = Flask(__name__)

# Set a real secret in production via the SECRET_KEY environment variable
# (Render: Dashboard -> your service -> Environment -> add SECRET_KEY).
# Falling back to a random one here just means sessions reset on every
# server restart if you don't set it — fine for local testing only.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

FREE_PARSE_LIMIT = int(os.environ.get("FREE_PARSE_LIMIT", "10"))
KEYS_FILE = os.path.join(os.path.dirname(__file__), "keys.json")


# ── license key storage ──────────────────────────────────────────────────────
def _load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_keys(keys):
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)


def _redeem_key(key: str):
    """Returns (ok: bool, message: str)."""
    key = key.strip()
    keys = _load_keys()
    entry = keys.get(key)
    if entry is None:
        return False, "That key was not found."
    if entry.get("used"):
        return False, "That key has already been used."
    entry["used"] = True
    entry["used_at"] = datetime.now(timezone.utc).isoformat()
    _save_keys(keys)
    return True, "Key accepted — unlimited parsing unlocked for this session."


# ── routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    session.setdefault("parses_used", 0)
    session.setdefault("unlocked", False)
    remaining = None if session["unlocked"] else max(0, FREE_PARSE_LIMIT - session["parses_used"])
    return render_template(
        "index.html",
        remaining=remaining,
        unlocked=session["unlocked"],
        free_limit=FREE_PARSE_LIMIT,
    )


@app.route("/redeem", methods=["POST"])
def redeem():
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"ok": False, "message": "Enter a key first."}), 400
    ok, message = _redeem_key(key)
    if ok:
        session["unlocked"] = True
    return jsonify({"ok": ok, "message": message})


@app.route("/parse", methods=["POST"])
def parse_message():
    session.setdefault("parses_used", 0)
    session.setdefault("unlocked", False)

    if not session["unlocked"] and session["parses_used"] >= FREE_PARSE_LIMIT:
        return jsonify({
            "error": (
                f"You've used all {FREE_PARSE_LIMIT} free parses. "
                "Enter a license key above to keep going."
            ),
            "limit_reached": True,
        }), 402  # Payment Required

    data = request.get_json(silent=True) or {}
    raw = data.get("raw", "")
    if not raw.strip():
        return jsonify({"error": "Paste a hex message first."}), 400

    result, warnings, compact = decode_visa_message(raw)

    if not session["unlocked"]:
        session["parses_used"] += 1

    remaining = None if session["unlocked"] else max(0, FREE_PARSE_LIMIT - session["parses_used"])

    if "error" in result:
        return jsonify({"error": result["error"], "remaining": remaining}), 400

    return jsonify({
        "result": result,
        "warnings": warnings,
        "compact": compact,
        "remaining": remaining,
    })


@app.route("/healthz")
def healthz():
    # simple endpoint so uptime pingers / Render health checks have something to hit
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Local dev only. In production, Render runs this via gunicorn (see Procfile).
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
