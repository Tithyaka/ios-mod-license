# Offline Ed25519 License System for macOS / iOS Game Mod (.dylib)

This document provides complete implementation details, architectural rationale, source code breakdown, and testing procedures for the **Offline License-Key System** integrated into your game mod.

---

## 1. System Architecture & Cryptographic Design

```
+------------------------------------+
|  Windows Administrator Machine     |
|  (license_gen.py)                  |
|  - Holds Ed25519 Private Key       |
|  - Signs License Payloads          |
+------------------------------------+
                  |
                  | Customer License Key: LIC-1.<B64_PAYLOAD>.<B64_SIGNATURE>
                  v
+------------------------------------+
|  Target Client (macOS / iOS)       |
|  (LOLiOS-FREE.dylib / Game Mod)    |
|  - Contains 32-byte Public Key     |
|  - Verifies Ed25519 Signature      |
|  - Checks Product ID & Expiration  |
|  - Prevents Clock Rollbacks        |
|  - Stores Key in macOS Keychain    |
+------------------------------------+
```

### Why Ed25519?
- **Asymmetric Security**: The game mod only contains the 32-byte public key (`EMBEDDED_PUBLIC_KEY`). The private signing key never leaves the administrator's computer. Even with full binary decompilation, a malicious user cannot forge valid signatures.
- **Compactness**: Ed25519 signatures are exactly 64 bytes, and public keys are 32 bytes, producing compact license tokens (`LIC-1.xxxx.yyyy`) that fit easily into text input dialogs.
- **High Performance**: Pure C99 verification takes less than 1 millisecond on ARM64 and x86_64 CPUs, ensuring game startup and UI responsiveness are completely unaffected.

---

## 2. Windows Python License Generator (`license_gen.py`)

### Prerequisites
Install the official cryptographic primitives library:
```bash
pip install cryptography
```

### Running the Generator
```bash
python license_gen.py
```

### Generated License Structure
The generator creates a canonical JSON payload:
```json
{
  "expires_at": 1792882800,
  "issued_at": 1792278000,
  "license_id": "4B1E9F10-6C78-4A15-B9F2-C5E0D71B20A1",
  "permissions": ["all", "premium", "aimbot", "esp", "norecoil"],
  "product_id": "ROSHack-macOS-v1",
  "type": "7-day"
}
```
The payload is deterministically serialized (sorted keys, no spaces), signed with the Ed25519 private key, and encoded as URL-safe Base64:
```
LIC-1.<Base64_Payload>.<Base64_64Byte_Signature>
```

### Supported License Durations
1. **1-Day**: Exact 24 hours ($86,400\text{ seconds}$)
2. **7-Day**: Exact 7 × 24 hours ($604,800\text{ seconds}$)
3. **30-Day**: 30 × 24 hours ($2,592,000\text{ seconds}$)
4. **90-Day**: 90 × 24 hours ($7,776,000\text{ seconds}$)
5. **365-Day**: 365 × 24 hours ($31,536,000\text{ seconds}$)
6. **Lifetime**: `expires_at = 0` (No scheduled expiration)

---

## 3. macOS `.dylib` Native Source Components

The implementation is split into modular, production-ready source files located in `license_system/`:

| File | Purpose |
| :--- | :--- |
| `ed25519_verify.h` / `.c` | Self-contained, standard C99 Ed25519 verification (zero external libraries required). |
| `LicenseStorage.h` / `.m` | Secure local persistence using macOS Keychain (`Security.framework`) with application support cache fallback. |
| `LicenseVerifier.h` / `.m` | Validates license tokens, parses canonical JSON payloads, checks product IDs, verifies UTC expiration, and detects system clock tampering. |
| `LicenseUI.h` / `.m` | Native in-game activation modal (`UIAlertController` for iOS/Catalyst or `NSAlert` for AppKit macOS) with key input, expiration breakdown, and feature locking. |

### Integration Hook Example
In your mod's entry point (`doExpand` or constructor), wrap the menu opening with the license check:

```objc
#import "LicenseUI.h"

// In your menu trigger or console button handler:
- (void)doExpand {
    [LicenseUI checkOrPromptActivationWithCompletion:^(BOOL success, LicenseInfo * _Nullable info) {
        if (success) {
            // License is valid -> display cheat menu
            [NSObject caidan];
        } else {
            // License is missing or expired -> features remain locked
            NSLog(@"[Mod] Access denied: %@", [info statusMessage]);
        }
    }];
}
```

---

## 4. Anti-Tamper & Clock Rollback Protections

### 1. Clock Rollback Detection
Offline expiration relies on the local system clock. A common bypass attempt is winding the system clock back to a date prior to expiration.
- **Protection**: Every time the mod runs, it records the latest observed UTC timestamp into Keychain/storage.
- If the current system time is found to be before the last observed timestamp (minus a 5-minute grace period for NTP network sync adjustments), the system fails closed with:
  ```
  LicenseStatusClockTampered ("Clock Rollback Detected — License Locked")
  ```
- Any license with an `issued_at` date in the future is similarly rejected.

### 2. Digital Signature Coverage
- The expiration timestamp, license ID, product ID, and license type are all **inside the payload covered by the digital signature**.
- Modifying a single bit of the expiration date invalidates the 64-byte Ed25519 signature and causes immediate rejection.

### 3. Realistic Threat Model Disclaimer
> [!WARNING]
> While public-key cryptography guarantees that unauthorized license keys cannot be forged or altered, offline DRM on a client machine cannot be mathematically 100% immune to an attacker with full kernel/root control, hardware debuggers, or memory hooking tools (e.g., patching the return value of `isLicenseActive`).
> This design stops:
> - Key sharing / key generators by unauthorized users
> - Text/payload editing (changing 7-day to lifetime)
> - Re-entering expired keys
> - Simple system clock rollback tricks

---

## 5. Test Suite & Acceptance Testing

Run the test suite to verify all cryptographic and expiration constraints:
```bash
python test_licenses.py
```

### Acceptance Test Matrix
| Test Case | Scenario | Expected Result |
| :--- | :--- | :--- |
| **Valid 7-Day** | Freshly generated 7-day key within issuance window | **VALID** (Unlocks features) |
| **Exact 7-Day Math** | Difference between `expires_at` and `issued_at` | **604,800 seconds** exactly |
| **Lifetime Key** | `expires_at = 0` | **VALID** ("Lifetime — No Scheduled Expiration") |
| **Expired License** | Simulated time $> expires\_at$ | **REJECTED** ("License Expired — Please Contact the Administrator") |
| **Forged Signature** | Modified signature bytes | **REJECTED** ("Invalid Digital Signature") |
| **Payload Tampering** | Changing `expires_at` from 7-day to 0 | **REJECTED** ("Invalid Digital Signature") |
| **Wrong Product ID** | Key issued for `AnotherGame-v2` | **REJECTED** ("Wrong Product License") |
| **Malformed Key** | Corrupted base64 or garbage string | **REJECTED** ("Malformed License Format") |
