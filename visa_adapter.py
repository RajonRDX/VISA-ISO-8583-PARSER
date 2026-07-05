"""
visa_adapter.py
================
Shared adapter layer between the raw visa_iso8583_parser_v1.py engine and
any front end (Tkinter desktop GUI, Flask web app, CLI, etc).

This module contains ONLY presentation-adjacent glue code. It does not
reimplement any ISO 8583 / VisaNet parsing logic — every actual decode
step is delegated to visa_iso8583_parser_v1.py, unmodified:
    - clean_hex()
    - parse_header()
    - parse_all_bitmaps()
    - parse_message_full()
    - get_report_name()
    - write_txt_report()
    - write_xlsx_report()

Kept dependency-free of any UI toolkit (no tkinter import here) so it can
be safely imported from a headless server process as well as a desktop
GUI.
"""

import re

# -- the untouched parser engine ---------------------------------------------
import visa_iso8583_parser_v1 as visa_parser

try:
    import openpyxl  # noqa: F401  (used internally by visa_parser.write_xlsx_report)
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


# ═══════════════════════════════════════════════════════════════════════════════
# ── DISPLAY-ONLY LOOKUPS (no effect on parsing — purely cosmetic labels) ───────
# ═══════════════════════════════════════════════════════════════════════════════
# Generic ISO 8583 MTI class/function reference. This is a standard MTI digit
# reference, not Visa-specific confirmed data, and is only used to add a
# friendly description next to the raw MTI the parser already decoded.
VISA_MTI_NAMES = {
    "0100": "Authorization Request",
    "0110": "Authorization Response",
    "0120": "Authorization Advice",
    "0130": "Authorization Advice Response",
    "0200": "Financial Request",
    "0210": "Financial Response",
    "0220": "Financial Advice",
    "0230": "Financial Advice Response",
    "0400": "Reversal Request",
    "0410": "Reversal Response",
    "0420": "Reversal Advice",
    "0430": "Reversal Advice Response",
    "0800": "Network Management Request",
    "0810": "Network Management Response",
}

FIELD_KEY_RE = re.compile(r"^F(\d+)\s")


# ═══════════════════════════════════════════════════════════════════════════════
# ── ADAPTER LAYER: turn visa_parser's (compact, rows) into the dict shape ──────
# ── this GUI renders, and clean up noisy pasted/log input before handing ──────
# ── it to the parser.                                                     ─────
# ═══════════════════════════════════════════════════════════════════════════════

def _prepare_hex_input(raw: str) -> str:
    """
    Strip common log-fragment noise (timestamps, 'inp>>'/'out<<' style
    direction markers, comment lines) so users can paste a raw hex string
    OR a log excerpt, same as the WAY4 GUI's input box supports. The
    result is still handed to visa_parser.clean_hex() (unchanged) for the
    actual hex validation/decoding — this function only removes obviously
    non-hex noise beforehand.
    """
    cleaned_lines = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r"\d{2}[./]\d{2}[./]\d{4}", line):
            continue
        if line.lower().startswith(("inp>>", "out<<", "tx:", "rx:", "in:", "out:")):
            continue
        if line.startswith("#"):
            continue
        cleaned_lines.append(line)
    joined = " ".join(cleaned_lines) if cleaned_lines else raw
    hex_only = re.sub(r"[^0-9a-fA-F]", "", joined)
    return hex_only


def _group_field_rows(rows):
    """
    Group the parser's flat (label, description, raw_hex, value) rows by
    top-level field number. Composite fields (34/44/55/62/63/104/111/
    123/126/127) already come back from the parser as multiple rows
    sharing the same field number but distinct labels (e.g. 'F62.1',
    'F62.2', ...) — those are grouped together here for display.
    """
    header_rows = []
    mti_row = None
    fields = {}  # fnum -> {"desc": str, "items": [(label, value), ...]}
    for label, desc, raw_hex, value in rows:
        if label.startswith("H"):
            header_rows.append((label, desc, raw_hex, value))
        elif label == "MTI":
            mti_row = (label, desc, raw_hex, value)
        else:
            m = re.match(r"^F(\d+)", label)
            if not m:
                continue
            fnum = int(m.group(1))
            entry = fields.setdefault(fnum, {"desc": None, "items": []})
            entry["desc"] = desc.split(" - ", 1)[0]
            entry["items"].append((label, value))
    return header_rows, mti_row, fields


def _bitmap_summary(data: bytes, pos: int):
    """
    Read the primary/secondary bitmap bytes for display purposes, and
    reuse visa_parser.parse_all_bitmaps() (unchanged) to get the actual
    list of present field numbers — no bitmap-walking logic is
    reimplemented here.
    """
    primary_bytes = data[pos:pos + 8]
    has_secondary = bool(primary_bytes and (primary_bytes[0] & 0x80))
    secondary_bytes = data[pos + 8:pos + 16] if has_secondary else b""
    present, _end_pos = visa_parser.parse_all_bitmaps(data, pos)
    return (
        primary_bytes.hex().upper(),
        secondary_bytes.hex().upper() if secondary_bytes else "",
        sorted(present.keys()),
    )


def decode_visa_message(raw_msg: str):
    """
    Adapter around visa_parser.parse_message_full(). Returns
    (result_dict, warnings_list, compact_string) — the same three-value
    shape the GUI's render/save code expects.
    On any failure, returns ({"error": "..."}, [], "").
    """
    hex_str = _prepare_hex_input(raw_msg)
    if not hex_str.strip():
        return {"error": "No hex characters found in input."}, [], ""

    try:
        data = visa_parser.clean_hex(hex_str)
    except Exception as e:
        return {"error": str(e)}, [], ""

    if len(data) < 4:
        return {"error": "Message too short (< 4 bytes) to contain a header + MTI"}, [], ""

    try:
        compact, rows = visa_parser.parse_message_full(hex_str)
    except Exception as e:
        return {"error": f"Parser error: {e}"}, [], ""

    header_rows, mti_row, fields = _group_field_rows(rows)
    result = {}
    warnings = []

    if header_rows:
        header_dict = {}
        for label, desc, raw_hex, value in header_rows:
            header_dict[f"{label} — {desc}"] = value
        result["MSG_HEADER"] = header_dict
        if any(label == "H13" for label, _d, _r, _v in header_rows):
            warnings.append(
                "ℹ Reject message header (H13/H14) detected — this path is "
                "implemented per spec text only and not yet validated "
                "against live reject traffic (see parser module notes)."
            )

    if mti_row:
        _label, _desc, _raw, mti_val = mti_row
        mti_full = mti_val if len(mti_val) == 4 else mti_val.rjust(4, "0")
        result["MTI"] = {
            "Code": mti_val,
            "Description": VISA_MTI_NAMES.get(mti_full, "VisaNet Message"),
        }

    try:
        header, hpos = visa_parser.parse_header(data)
        mti_pos = hpos + 2
        primary_hex, secondary_hex, fields_present = _bitmap_summary(data, mti_pos)
        result["BITMAP"] = {
            "Primary (hex)": primary_hex,
            "Secondary (hex)": secondary_hex if secondary_hex else "— not present",
            "Fields present": fields_present,
        }
    except Exception as e:
        warnings.append(f"⚠ Could not summarize bitmap for display: {e}")

    fields_out = {}
    parse_errors = {}
    for fnum in sorted(fields):
        entry = fields[fnum]
        key = f"F{fnum}  {entry['desc']}"
        items = entry["items"]
        if len(items) == 1 and items[0][0] == f"F{fnum}":
            val = items[0][1]
            fields_out[key] = {"Value": val}
        else:
            fields_out[key] = {label: val for label, val in items}
        for label, val in items:
            if isinstance(val, str) and val.startswith("<parse-error:"):
                parse_errors[label] = val
    result["FIELDS"] = fields_out

    if parse_errors:
        result["PARSE_ERRORS"] = parse_errors
        for k, v in parse_errors.items():
            warnings.append(f"🔴 {k}: {v}")

    return result, warnings, compact


def _first_val(v):
    if isinstance(v, dict):
        for val in v.values():
            if val:
                return str(val)
        return ""
    return str(v) if v else ""


def _fields_by_num(fields):
    out = {}
    for k, v in fields.items():
        m = FIELD_KEY_RE.match(k)
        if m:
            out[int(m.group(1))] = v
    return out


def _extract_rrn(result):
    fields = result.get("FIELDS", {})
    by_num = _fields_by_num(fields)
    val = _first_val(by_num.get(37)) if 37 in by_num else ""
    if val.strip():
        return val.strip()
    val = _first_val(by_num.get(11)) if 11 in by_num else ""
    return val.strip() or "UNKNOWN"


def _extract_mti(result):
    m = result.get("MTI", {})
    if isinstance(m, dict):
        return m.get("Code", "UNK")
    return str(m)[:4]
