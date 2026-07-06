"""
app.py — VisaNet ISO 8583 Decoder, web edition (Flask)

Lets people use the parser via a shared link instead of the desktop GUI.
All actual ISO 8583 decoding is delegated to visa_iso8583_parser_v1.py
(unmodified) through visa_adapter.py (also unmodified from the desktop
app's shared logic) — this file only adds: routing, the free-tries
counter, license-key unlocking, and file export (TXT / Excel download,
mirroring the desktop GUI's "Save TXT Report" / "Save Excel Workbook" /
"Save Both" buttons).

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
4. Exported TXT/XLSX reports are generated in-memory per request and
   streamed straight to the browser as a download — nothing is written
   to permanent disk storage on the server.
"""

import os
import io
import re
import json
import secrets
import tempfile
from datetime import datetime, timezone

from flask import Flask, request, jsonify, session, render_template, send_file

import visa_iso8583_parser_v2 as visa_parser
from visa_adapter import (
    decode_visa_message,
    _prepare_hex_input,
    _extract_rrn,
    _extract_mti,
    HAS_OPENPYXL,
    HAS_FIELD_DETAILS,
)

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


def _within_quota():
    """True if the current session is allowed to parse/export right now."""
    session.setdefault("parses_used", 0)
    session.setdefault("unlocked", False)
    return session["unlocked"] or session["parses_used"] < FREE_PARSE_LIMIT


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
        has_openpyxl=HAS_OPENPYXL,
        has_field_details=HAS_FIELD_DETAILS,
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


@app.route("/export/<fmt>", methods=["POST"])
def export_report(fmt):
    """
    Re-parses the same raw hex the browser already decoded and streams a
    TXT, XLSX, or field-Details report back as a file download — same
    report formats as the desktop GUI's "Save TXT Report" / "Save Excel
    Workbook" / "Save Field Details" buttons (visa_parser.write_txt_report
    / write_xlsx_report / write_detail_report, unmodified).

    Nothing is written to persistent disk: the report is built in a
    short-lived temp file, read back into memory, deleted immediately,
    then sent to the browser.
    """
    if fmt not in ("txt", "xlsx", "details"):
        return jsonify({"error": "Unsupported export format."}), 400

    if fmt == "xlsx" and not HAS_OPENPYXL:
        return jsonify({"error": "Excel export isn't available on this server (openpyxl not installed)."}), 400

    if fmt == "details" and not HAS_FIELD_DETAILS:
        return jsonify({"error": "Field details export isn't available on this server (visa_field_details.py not found)."}), 400

    if not _within_quota():
        return jsonify({
            "error": f"You've used all {FREE_PARSE_LIMIT} free parses. Enter a license key above to keep going.",
            "limit_reached": True,
        }), 402

    data = request.get_json(silent=True) or {}
    raw = data.get("raw", "")
    if not raw.strip():
        return jsonify({"error": "Nothing to export — paste and parse a message first."}), 400

    hex_str = _prepare_hex_input(raw)
    if not hex_str.strip():
        return jsonify({"error": "No hex characters found in input."}), 400

    try:
        compact, rows = visa_parser.parse_message_full(hex_str)
    except Exception as e:
        return jsonify({"error": f"Parser error: {e}"}), 400

    mti = compact.split(":", 1)[0].strip()
    name = visa_parser.get_report_name(rows, mti)
    raw_hex_for_report = raw.strip()

    tmp_path = None
    try:
        suffix = ".xlsx" if fmt == "xlsx" else ".txt"
        fd, tmp_path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)

        if fmt == "txt":
            visa_parser.write_txt_report(tmp_path, raw_hex_for_report, compact, rows)
            mimetype = "text/plain; charset=utf-8"
            download_name = f"{name}.txt"
        elif fmt == "xlsx":
            visa_parser.write_xlsx_report(tmp_path, raw_hex_for_report, compact, rows)
            mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            download_name = f"{name}.xlsx"
        else:  # details
            visa_parser.write_detail_report(tmp_path, rows)
            mimetype = "text/plain; charset=utf-8"
            download_name = f"{name}_details.txt"

        with open(tmp_path, "rb") as f:
            file_bytes = f.read()
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)

    return send_file(
        io.BytesIO(file_bytes),
        as_attachment=True,
        download_name=download_name,
        mimetype=mimetype,
    )


@app.route("/healthz")
def healthz():
    # simple endpoint so uptime pingers / Render health checks have something to hit
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    # Local dev only. In production, Render runs this via gunicorn (see Procfile).
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
