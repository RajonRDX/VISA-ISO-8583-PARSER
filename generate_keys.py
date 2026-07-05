"""
generate_keys.py — run this yourself to mint new license keys to sell.

Usage:
    python generate_keys.py 5        # generate 5 new unused keys
    python generate_keys.py          # defaults to 1

Keys are appended to keys.json (created if missing). Each key starts
"used": false; the web app flips it to true the first time someone
redeems it successfully.

IMPORTANT: keys.json lives on local disk next to app.py. If you deploy to
a host with an ephemeral filesystem (e.g. Render's free tier), this file
can be wiped on redeploy/restart. For anything beyond a quick MVP, swap
this out for a real database table. See the note in app.py.
"""

import sys
import json
import secrets
import os

KEYS_FILE = os.path.join(os.path.dirname(__file__), "keys.json")


def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_keys(keys):
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)


def make_key():
    # Format: VISA-XXXX-XXXX-XXXX (easy to read out loud / paste)
    parts = [secrets.token_hex(2).upper() for _ in range(3)]
    return "VISA-" + "-".join(parts)


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    keys = load_keys()
    new_keys = []
    for _ in range(count):
        k = make_key()
        while k in keys:  # extremely unlikely, but just in case
            k = make_key()
        keys[k] = {"used": False}
        new_keys.append(k)
    save_keys(keys)
    print(f"Generated {count} new key(s):\n")
    for k in new_keys:
        print(" ", k)
    print(f"\nSaved to {KEYS_FILE}")


if __name__ == "__main__":
    main()
