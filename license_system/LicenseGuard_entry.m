#import <Foundation/Foundation.h>
#import "LicenseUI.h"
#import "LicenseVerifier.h"

__attribute__((constructor))
static void LicenseGuardInit(void) {
    // Wait 2 seconds after game process loads so the main UIWindow is available
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [LicenseUI checkOrPromptActivationWithCompletion:^(BOOL success, LicenseInfo * _Nullable info) {
            if (success) {
                NSLog(@"[LicenseGuard] License verified successfully. Time remaining: %@", [info formattedRemainingTime]);
            } else {
                NSLog(@"[LicenseGuard] License check failed or expired: %@", [info statusMessage]);
            }
        }];
    });
}
