#!/usr/bin/env python3
"""
Comprehensive Test Suite for Offline Ed25519 License System
Tests:
  1. Valid 7-day license (within UTC window)
  2. Valid lifetime license (expires_at = 0)
  3. Expired license (expires_at < current_time)
  4. Forged/tampered payload with original signature
  5. Forged/corrupted signature
  6. Wrong product ID license
  7. Exact 7-day timestamp math (7 * 24 * 3600 seconds)
"""

import sys
import os
import json
import base64
import uuid
from datetime import datetime, timezone, timedelta

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: pip install cryptography is required.")
    sys.exit(1)

# Import generator
from license_gen import ensure_keypair, generate_license, DEFAULT_PRODUCT_ID

def b64url_decode(s):
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)

def verify_token_python(token, public_key, expected_product_id=DEFAULT_PRODUCT_ID, simulated_now=None):
    """Mirror of the C/Objective-C verification logic."""
    if simulated_now is None:
        simulated_now = int(datetime.now(timezone.utc).timestamp())

    trimmed = token.strip()
    tag = None
    if trimmed.startswith("KHEANG-") or trimmed.startswith("ROSVIP-"):
        dot_idx = trimmed.rfind(".")
        if dot_idx == -1:
            return False, "MALFORMED_FORMAT"
        sig_str = trimmed[dot_idx + 1:]
        prefix_and_payload = trimmed[:dot_idx]
        parts = prefix_and_payload.split("-", 2)
        if len(parts) < 3:
            return False, "MALFORMED_FORMAT"
        tag = parts[1]
        payload_str = parts[2]
    elif trimmed.startswith("LIC-1."):
        parts = trimmed.split(".")
        if len(parts) != 3:
            return False, "MALFORMED_FORMAT"
        payload_str = parts[1]
        sig_str = parts[2]
    else:
        return False, "MALFORMED_FORMAT"

    try:
        payload_bytes = b64url_decode(payload_str)
        sig_bytes = b64url_decode(sig_str)
    except Exception:
        return False, "BASE64_DECODE_ERROR"

    if len(sig_bytes) != 64:
        return False, "INVALID_SIG_LENGTH"

    # 1. Cryptographic Signature Verification
    try:
        public_key.verify(sig_bytes, payload_bytes)
    except Exception:
        return False, "INVALID_SIGNATURE"

    # 2. JSON Deserialization
    try:
        data = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, "INVALID_JSON"

    # Tag validation if ROSVIP- format
    if tag:
        tag_map = {"1D": "1-day", "7D": "7-day", "30D": "30-day", "90D": "90-day", "365D": "365-day", "LIFE": "lifetime"}
        if tag_map.get(tag) != data.get("type"):
            return False, "TAG_TYPE_MISMATCH"

    # 3. Product ID Check
    if data.get("product_id") != expected_product_id:
        return False, "PRODUCT_MISMATCH"

    issued_at = data.get("issued_at", 0)
    expires_at = data.get("expires_at", 0)

    # 4. Anti-tamper / Future issued_at check
    if issued_at > (simulated_now + 300):
        return False, "FUTURE_ISSUED_AT"

    # 5. Expiration Check
    if expires_at != 0 and simulated_now > expires_at:
        return False, "LICENSE_EXPIRED"

    return True, "VALID"

def run_test_suite():
    print("=" * 70)
    print("      ROSVIP OFFLINE LICENSE VALIDATION TEST SUITE (Ed25519)      ")
    print("=" * 70)

    private_key, public_key = ensure_keypair()
    all_passed = True
    tests_run = 0

    def assert_test(name, condition, details=""):
        nonlocal all_passed, tests_run
        tests_run += 1
        status = "[PASS]" if condition else "[FAIL]"
        if not condition:
            all_passed = False
        print(f" {status} Test {tests_run}: {name}")
        if details:
            print(f"        Detail: {details}")

    # --- Test 1: Valid 7-day license ---
    payload, key7 = generate_license(private_key, "7-day", timedelta(days=7))
    valid, reason = verify_token_python(key7, public_key)
    assert_test("Valid 7-Day License Activation", valid and reason == "VALID",
                f"License ID: {payload['license_id']}")

    # --- Test 2: Exact 7-day Expiration calculation ---
    expected_delta = 7 * 24 * 3600
    actual_delta = payload["expires_at"] - payload["issued_at"]
    assert_test("Exact 7 x 24h Expiration Timestamp", actual_delta == expected_delta,
                f"Expected {expected_delta}s, got {actual_delta}s")

    # --- Test 3: Valid Lifetime License ---
    payload_life, key_life = generate_license(private_key, "lifetime", None)
    valid_life, reason_life = verify_token_python(key_life, public_key)
    assert_test("Lifetime License (expires_at=0)", valid_life and payload_life["expires_at"] == 0,
                f"Type: {payload_life['type']}, Expires: {payload_life['expires_at']}")

    # --- Test 4: Expired License ---
    # Simulate time past expiration
    simulated_future = payload["expires_at"] + 100
    valid_exp, reason_exp = verify_token_python(key7, public_key, simulated_now=simulated_future)
    assert_test("Reject Expired 7-Day License", not valid_exp and reason_exp == "LICENSE_EXPIRED",
                f"Simulated time {simulated_future} > {payload['expires_at']}")

    # --- Test 5: Forged Signature ---
    dot_idx = key7.rfind(".")
    sig_part = key7[dot_idx + 1:]
    prefix_and_payload = key7[:dot_idx]
    prefix_parts = prefix_and_payload.split("-", 2)
    tag = prefix_parts[1]
    b64_payload = prefix_parts[2]

    tampered_sig = base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip("=")
    forged_key = f"{prefix_and_payload}.{tampered_sig}"
    valid_forged, reason_forged = verify_token_python(forged_key, public_key)
    assert_test("Reject Forged/Corrupted Signature", not valid_forged and reason_forged == "INVALID_SIGNATURE",
                f"Result: {reason_forged}")

    # --- Test 6: Tampered Payload with Original Signature ---
    raw_payload = b64url_decode(b64_payload)
    payload_obj = json.loads(raw_payload.decode("utf-8"))
    payload_obj["expires_at"] = 0  # Hacker tries to turn 7-day into lifetime
    tampered_json = json.dumps(payload_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    tampered_b64 = base64.urlsafe_b64encode(tampered_json).decode("ascii").rstrip("=")
    tampered_payload_key = f"{prefix_parts[0]}-{tag}-{tampered_b64}.{sig_part}"
    valid_tamper, reason_tamper = verify_token_python(tampered_payload_key, public_key)
    assert_test("Reject Tampered Payload (7-day -> Lifetime)", not valid_tamper and reason_tamper == "INVALID_SIGNATURE",
                f"Result: {reason_tamper}")

    # --- Test 7: Duration Tag Tampering ---
    tag_tampered_key = f"{prefix_parts[0]}-LIFE-{b64_payload}.{sig_part}"
    valid_tag_tamper, reason_tag_tamper = verify_token_python(tag_tampered_key, public_key)
    assert_test(f"Reject Tag Tampering ({prefix_parts[0]}-7D -> {prefix_parts[0]}-LIFE)", not valid_tag_tamper and reason_tag_tamper == "TAG_TYPE_MISMATCH",
                f"Result: {reason_tag_tamper}")

    # --- Test 8: Wrong Product ID ---
    _, key_wrong_prod = generate_license(private_key, "7-day", timedelta(days=7), product_id="AnotherGame-v2")
    valid_prod, reason_prod = verify_token_python(key_wrong_prod, public_key, expected_product_id="ROSVIP-iOS-v1")
    assert_test("Reject Wrong Product ID", not valid_prod and reason_prod == "PRODUCT_MISMATCH",
                f"Result: {reason_prod}")

    # --- Test 9: Malformed Token String ---
    valid_mal, reason_mal = verify_token_python("INVALID-TOKEN-STRING", public_key)
    assert_test("Reject Malformed Token", not valid_mal and reason_mal == "MALFORMED_FORMAT",
                f"Result: {reason_mal}")

    print("-" * 70)
    if all_passed:
        print(f"[*] ALL {tests_run} TESTS PASSED SUCCESSFULLY! ROSVIP offline Ed25519 verified.")
    else:
        print(f"[!] SOME TESTS FAILED.")
    print("=" * 70)
    return all_passed

if __name__ == "__main__":
    run_test_suite()
