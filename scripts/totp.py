#!/usr/bin/env python3
"""Current TOTP code for a DEMO account (reads secrets/demo-totp.txt, written by scripts/seed.sh).

    scripts/totp.py nadia.berrada@uni.example            print the current 6-digit code
    scripts/totp.py nadia.berrada@uni.example --fresh    print a code that has not been used yet

The application accepts each 30-second step once (replay protection), so two automated sign-ins by the same user
inside one step need different codes: --fresh waits for the next step when the current one was already handed out.
Lab tool for fictional accounts. A real user reads the code from their own authenticator app.
"""
import base64, hashlib, hmac, struct, sys, time
from pathlib import Path

root = Path(__file__).resolve().parent.parent


def secret_for(email):
    for line in (root / "secrets/demo-totp.txt").read_text().splitlines():
        parts = line.split("\t")
        if parts[0] == email:
            return parts[1]
    raise SystemExit(f"no TOTP secret for {email} in secrets/demo-totp.txt (run scripts/seed.sh)")


def code(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[19] & 0x0F
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 10**6:06d}"


if __name__ == "__main__":
    email = sys.argv[1]
    secret = secret_for(email)
    state = Path(f"/tmp/grants-totp-last-{email}")
    step = int(time.time()) // 30
    if "--fresh" in sys.argv:
        last = int(state.read_text()) if state.exists() else 0
        while step <= last:                       # that step was already used: wait for the next one
            time.sleep(1)
            step = int(time.time()) // 30
        state.write_text(str(step))
    print(code(secret, step))
