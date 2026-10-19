/**
 * ROSVIP_entry.m
 *
 * Constructor entry point for ROSVIP.dylib.
 * Hooks into LicenseGuard's offline HWID-locked license system.
 *
 * No Cloudflare worker or online validation required.
 * All verification is performed 100% offline using Ed25519 signatures
 * and device-bound 1-key-per-device HWID locking.
 *
 * Injection chain:
 *   ROSVIP.dylib  (game mod features)
 *     └─ LicenseGuard.dylib  (offline HWID license verification)
 *
 * The license gate fires 2 seconds after process load so UIWindow is ready.
 * If the user has no valid key → activation prompt shown.
 * If the user has a valid HWID-locked key → "RoS VIP Active" info dialog.
 * Cancelling or failing activation calls exit(0) immediately.
 */

#import <Foundation/Foundation.h>
#import "LicenseUI.h"
#import "LicenseVerifier.h"

__attribute__((constructor))
static void ROSVIPLicenseInit(void) {
    // Wait 2 seconds after dylib load so UIWindow / RootViewController is available
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
        dispatch_get_main_queue(),
        ^{
            [LicenseUI checkOrPromptActivationWithCompletion:^(BOOL success, LicenseInfo * _Nullable info) {
                if (success) {
                    // License verified — KheangZzIOS features unlocked
                    NSLog(@"[KheangZzIOS] ✅ License verified. Type: %@ | Remaining: %@",
                          info.type ?: @"unknown",
                          [info formattedRemainingTime]);
                } else {
                    // License missing, expired, or HWID mismatch — features locked
                    NSLog(@"[KheangZzIOS] ❌ License check failed: %@", [info statusMessage]);
                }
            }];
        }
    );
}
