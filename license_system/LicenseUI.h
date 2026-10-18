#import <Foundation/Foundation.h>
#import "LicenseVerifier.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^LicenseActivationCallback)(BOOL success, LicenseInfo *info);

@interface LicenseUI : NSObject

/**
 * Checks license status on startup. If invalid/expired/missing, displays activation UI.
 * If valid, invokes completion immediately with success.
 */
+ (void)checkOrPromptActivationWithCompletion:(nullable LicenseActivationCallback)completion;

/**
 * Explicitly displays the License Status & Activation dialog.
 */
+ (void)showActivationDialogWithInitialMessage:(nullable NSString *)message
                                   completion:(nullable LicenseActivationCallback)completion;

/**
 * Helper to check whether features are unlocked.
 */
+ (BOOL)isLicenseActive;

@end

NS_ASSUME_NONNULL_END
