#!/usr/bin/env python3
"""
Offline Ed25519 License Key Generator (Windows Admin Application)
Product: macOS / iOS Game Mod (.dylib)
Author: Antigravity Licensing System
"""

import sys
import os
import json
import base64
import time
import uuid
from datetime import datetime, timezone, timedelta

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: The 'cryptography' library is required.")
    print("Install it via: pip install cryptography")
    sys.exit(1)

PRIVATE_KEY_FILE = "ed25519_private.pem"
PUBLIC_KEY_FILE = "ed25519_public.pem"
PUBLIC_KEY_HEADER = "public_key.h"
DEFAULT_PRODUCT_ID = "ROSHack-macOS-v1"

DURATION_OPTIONS = {
    "1": ("1-day", timedelta(days=1)),
    "2": ("7-day", timedelta(days=7)),
    "3": ("30-day", timedelta(days=30)),
    "4": ("90-day", timedelta(days=90)),
    "5": ("365-day", timedelta(days=365)),
    "6": ("lifetime", None)
}

def ensure_keypair():
    """Load or generate Ed25519 keypair."""
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        print(f"[*] Loaded existing private key: {PRIVATE_KEY_FILE}")
        return private_key, public_key

    print("[*] Generating new Ed25519 master keypair...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Save private key securely
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(pem_priv)

    # Save public key
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pem_pub)

    # Export raw 32-byte public key as C header for the .dylib
    raw_pub = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    hex_bytes = ", ".join([f"0x{b:02X}" for b in raw_pub])
    with open(PUBLIC_KEY_HEADER, "w") as f:
        f.write("/* Auto-generated Ed25519 public key - Embed in .dylib only */\n")
        f.write("#ifndef ED25519_PUBLIC_KEY_H\n#define ED25519_PUBLIC_KEY_H\n\n")
        f.write(f"static const unsigned char EMBEDDED_PUBLIC_KEY[32] = {{\n    {hex_bytes}\n}};\n\n")
        f.write(f"#define EMBEDDED_PRODUCT_ID \"{DEFAULT_PRODUCT_ID}\"\n\n")
        f.write("#endif\n")

    print(f"[*] Saved private key: {PRIVATE_KEY_FILE} (DO NOT DISTRIBUTE!)")
    print(f"[*] Saved public key:  {PUBLIC_KEY_FILE}")
    print(f"[*] Exported C header: {PUBLIC_KEY_HEADER} (Include in your .dylib)")
    return private_key, public_key

def generate_license(private_key, duration_type, duration_delta, product_id=DEFAULT_PRODUCT_ID, permissions=None):
    """Create, canonicalize, sign, and encode a license key."""
    now_utc = datetime.now(timezone.utc)
    issued_at = int(now_utc.timestamp())

    if duration_delta is not None:
        expires_at = int((now_utc + duration_delta).timestamp())
    else:
        expires_at = 0  # 0 indicates lifetime

    if permissions is None:
        permissions = ["all", "premium", "aimbot", "esp", "norecoil"]

    license_id = str(uuid.uuid4()).upper()

    # Canonical payload dictionary (deterministic key order)
    payload_dict = {
        "license_id": license_id,
        "product_id": product_id,
        "type": duration_type,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "permissions": permissions
    }

    # Strict JSON serialization without extra whitespace, sorted keys
    canonical_json = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")

    # Ed25519 signature
    signature = private_key.sign(canonical_json)

    # Pack into single transportable key string:
    # Format: KHEANG-<TAG>-<B64_PAYLOAD>.<B64_SIGNATURE>
    tag_map = {
        "1-day": "1D",
        "7-day": "7D",
        "30-day": "30D",
        "90-day": "90D",
        "365-day": "365D",
        "lifetime": "LIFE"
    }
    tag = tag_map.get(duration_type, "7D")
    b64_payload = base64.urlsafe_b64encode(canonical_json).decode("ascii").rstrip("=")
    b64_sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    license_key = f"KHEANG-{tag}-{b64_payload}.{b64_sig}"

    return payload_dict, license_key

def main():
    print("=" * 65)
    print("      OFFLINE ED25519 LICENSE GENERATOR (ADMIN APPLICATION)     ")
    print("=" * 65)

    private_key, public_key = ensure_keypair()

    # CLI direct argument support (e.g., python license_gen.py 7D)
    if len(sys.argv) > 1:
        arg = sys.argv[1].upper().replace("-", "")
        arg_map = {
            "1D": ("1-day", timedelta(days=1)),
            "1": ("1-day", timedelta(days=1)),
            "7D": ("7-day", timedelta(days=7)),
            "2": ("7-day", timedelta(days=7)),
            "30D": ("30-day", timedelta(days=30)),
            "3": ("30-day", timedelta(days=30)),
            "90D": ("90-day", timedelta(days=90)),
            "4": ("90-day", timedelta(days=90)),
            "365D": ("365-day", timedelta(days=365)),
            "5": ("365-day", timedelta(days=365)),
            "LIFE": ("lifetime", None),
            "LIFETIME": ("lifetime", None),
            "6": ("lifetime", None),
        }
        if arg in arg_map:
            duration_type, delta = arg_map[arg]
            prod_id = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PRODUCT_ID
            payload, key = generate_license(private_key, duration_type, delta, prod_id)
            print(f"\nGenerated {duration_type} License Key:")
            print(key)
            return

    while True:
        print("\nSelect license duration to generate:")
        print("  [1] 1-Day License   (KHEANG-1D-...)")
        print("  [2] 7-Day License   (KHEANG-7D-...)")
        print("  [3] 30-Day License  (KHEANG-30D-...)")
        print("  [4] 90-Day License  (KHEANG-90D-...)")
        print("  [5] 365-Day License (KHEANG-365D-...)")
        print("  [6] Lifetime        (KHEANG-LIFE-...)")
        print("  [Q] Quit")

        try:
            choice = input("\nEnter choice [1-6, Q]: ").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if choice == "Q":
            print("Exiting.")
            break

        if choice not in DURATION_OPTIONS:
            print("Invalid choice, please select 1-6.")
            continue

        duration_type, delta = DURATION_OPTIONS[choice]
        try:
            prod_id = input(f"Enter Product ID [{DEFAULT_PRODUCT_ID}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            prod_id = DEFAULT_PRODUCT_ID
        if not prod_id:
            prod_id = DEFAULT_PRODUCT_ID

        payload, key = generate_license(private_key, duration_type, delta, prod_id)

        issued_dt = datetime.fromtimestamp(payload["issued_at"], timezone.utc).astimezone()
        if payload["expires_at"] > 0:
            expires_dt = datetime.fromtimestamp(payload["expires_at"], timezone.utc).astimezone()
            exp_str = expires_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            exp_str = "Lifetime — No Scheduled Expiration"

        print("\n" + "-" * 65)
        print("             GENERATED LICENSE DETAILS (CONFIDENTIAL)           ")
        print("-" * 65)
        print(f" License ID:   {payload['license_id']}")
        print(f" Product ID:   {payload['product_id']}")
        print(f" License Type: {payload['type']}")
        print(f" Issued At:    {issued_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f" Expires At:   {exp_str}")
        print(f" Permissions:  {', '.join(payload['permissions'])}")
        print("-" * 65)
        print("CUSTOMER LICENSE KEY (Copy and send to user):")
        print("-" * 65)
        print(key)
        print("-" * 65)

if __name__ == "__main__":
    main()
