#!/bin/bash
set -e

echo "=================================================================="
echo "   Building LicenseGuard.dylib with Apple Clang Toolchain        "
echo "=================================================================="

# 1. Verify all required source files exist
REQUIRED_FILES=(
    "ROSVIP_entry.m"
    "LicenseUI.m"
    "LicenseVerifier.m"
    "LicenseStorage.m"
    "ed25519_verify.c"
    "ed25519_verify.h"
    "public_key.h"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "[-] ERROR: Missing required file: $file"
        exit 1
    fi
    echo "[+] Found source: $file"
done

# 2. Check Apple developer toolchain
XCODE_DIR=$(xcode-select -p)
echo "[*] Active Xcode Developer directory: $XCODE_DIR"

IOS_SDK=$(xcrun --sdk iphoneos --show-sdk-path 2>/dev/null || echo "")
MAC_SDK=$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || echo "")

echo "[*] iOS SDK Path:   $IOS_SDK"
echo "[*] macOS SDK Path: $MAC_SDK"

COMMON_SRCS=(
    "ed25519_verify.c"
    "LicenseStorage.m"
    "LicenseVerifier.m"
    "LicenseUI.m"
    "ROSVIP_entry.m"
)

# -------------------------------------------------------------
# Target 1: iOS ARM64 (Primary target for your game mod)
# -------------------------------------------------------------
if [ -n "$IOS_SDK" ]; then
    echo ""
    echo "[*] Compiling Target 1: iOS ARM64 (arm64-apple-ios12.0)..."
    clang -dynamiclib \
        -target arm64-apple-ios12.0 \
        -isysroot "$IOS_SDK" \
        -fobjc-arc \
        -O3 \
        -Wall -Wextra -Wno-unused-parameter \
        -framework Foundation \
        -framework UIKit \
        -framework Security \
        -install_name @rpath/LicenseGuard.dylib \
        "${COMMON_SRCS[@]}" \
        -o LicenseGuard.dylib

    # Also save an explicit copy named LicenseGuard-iOS-arm64.dylib
    cp LicenseGuard.dylib LicenseGuard-iOS-arm64.dylib

    # Ad-hoc code sign for local injection compatibility
    codesign -s - -f LicenseGuard.dylib
    codesign -s - -f LicenseGuard-iOS-arm64.dylib

    echo "[+] Successfully built: LicenseGuard.dylib (iOS ARM64)"
else
    echo "[-] Warning: iphoneos SDK not available on this runner."
fi

# -------------------------------------------------------------
# Target 2: macOS Universal (arm64 + x86_64 for macOS game mod)
# -------------------------------------------------------------
if [ -n "$MAC_SDK" ]; then
    echo ""
    echo "[*] Compiling Target 2: macOS Universal (arm64 + x86_64)..."
    clang -dynamiclib \
        -target arm64-apple-macos10.15 \
        -isysroot "$MAC_SDK" \
        -fobjc-arc \
        -O3 \
        -framework Foundation \
        -framework AppKit \
        -framework Security \
        -install_name @rpath/LicenseGuard.dylib \
        "${COMMON_SRCS[@]}" \
        -o LicenseGuard-macOS-arm64.dylib

    clang -dynamiclib \
        -target x86_64-apple-macos10.15 \
        -isysroot "$MAC_SDK" \
        -fobjc-arc \
        -O3 \
        -framework Foundation \
        -framework AppKit \
        -framework Security \
        -install_name @rpath/LicenseGuard.dylib \
        "${COMMON_SRCS[@]}" \
        -o LicenseGuard-macOS-x86_64.dylib

    lipo -create LicenseGuard-macOS-arm64.dylib LicenseGuard-macOS-x86_64.dylib -output LicenseGuard-macOS-universal.dylib
    rm -f LicenseGuard-macOS-arm64.dylib LicenseGuard-macOS-x86_64.dylib
    codesign -s - -f LicenseGuard-macOS-universal.dylib
    echo "[+] Successfully built: LicenseGuard-macOS-universal.dylib (Universal Binary)"

    # If iOS SDK was not available, use macOS as main output
    if [ ! -f "LicenseGuard.dylib" ]; then
        cp LicenseGuard-macOS-universal.dylib LicenseGuard.dylib
    fi
fi

# -------------------------------------------------------------
# 3. Verify Built Binaries
# -------------------------------------------------------------
echo ""
echo "=================================================================="
echo "                 Apple Binary Verification                       "
echo "=================================================================="
echo "--- File Details ---"
file LicenseGuard.dylib
file LicenseGuard-*-arm64.dylib 2>/dev/null || true
file LicenseGuard-macOS-universal.dylib 2>/dev/null || true

echo ""
echo "--- Architecture & Load Commands (otool -vh) ---"
otool -vh LicenseGuard.dylib

echo ""
echo "--- Linked Frameworks (otool -L) ---"
otool -L LicenseGuard.dylib

echo ""
echo "[*] Build completed successfully with ZERO errors!"
