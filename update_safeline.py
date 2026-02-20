#!/usr/bin/env python3
import os
import sys
import json
import requests

BASE_URL = os.getenv("SAFELINE_BASE_URL", "").strip()
API_TOKEN = os.getenv("SAFELINE_API_TOKEN", "").strip()
CERT_ID = os.getenv("SAFELINE_CERT_ID", "").strip()

VERIFY_TLS = False
TIMEOUT = 20


def update_cert(fullchain_path: str, privkey_path: str):
    if not BASE_URL:
        raise RuntimeError("Missing SAFELINE_BASE_URL")
    if not API_TOKEN:
        raise RuntimeError("Missing SAFELINE_API_TOKEN")
    if not CERT_ID:
        raise RuntimeError("Missing SAFELINE_CERT_ID")

    with open(fullchain_path, "r", encoding="utf-8") as f:
        crt = f.read()
    with open(privkey_path, "r", encoding="utf-8") as f:
        key = f.read()

    url = f"{BASE_URL}/api/open/cert"

    headers = {
        "X-SLCE-API-TOKEN": API_TOKEN,
        "Content-Type": "application/json",
    }

    payload = {
        "manual": {"crt": crt, "key": key},
        "type": 2,
        "id": int(CERT_ID),
    }

    r = requests.post(
        url,
        headers=headers,
        data=json.dumps(payload),
        verify=VERIFY_TLS,
        timeout=TIMEOUT,
    )

    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text}")

    return r.json()


def main():
    if len(sys.argv) != 3:
        print("Usage: update_safeline.py <fullchain.pem> <privkey.pem>", file=sys.stderr)
        sys.exit(2)

    resp = update_cert(sys.argv[1], sys.argv[2])
    print("OK:", resp)


if __name__ == "__main__":
    main()