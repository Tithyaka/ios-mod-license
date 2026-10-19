/**
 * LicenseUI.m — RoS VIP Offline License Activation UI
 *
 * Shows:
 *   • Active License: key type, exact expire date+time, days/hours remaining
 *   • Activation: HWID display + Copy, key input, Activate / Exit buttons
 *   • Failure:    clear error reason + Try Again / Exit
 *
 * No network calls — 100% offline Ed25519 + HWID device lock.
 */

#import "LicenseUI.h"
#import "LicenseVerifier.h"
#import "LicenseStorage.h"

#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
#import <AppKit/AppKit.h>
#else
#import <UIKit/UIKit.h>
#endif

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

static NSString *ROSVIPFormatFullExpireDateTime(LicenseInfo *info) {
    if (info.isLifetime) {
        return @"♾  Lifetime Access — Never Expires";
    }
    if (info.expiresAt <= 0) {
        return @"No expiration data";
    }
    NSDate *expDate = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)info.expiresAt];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale      = [NSLocale currentLocale];
    df.timeZone    = [NSTimeZone localTimeZone];
    df.dateFormat  = @"EEEE, MMM d yyyy  •  HH:mm:ss (zzz)";
    return [df stringFromDate:expDate];
}

static NSString *ROSVIPFormatIssuedDateTime(LicenseInfo *info) {
    if (info.issuedAt <= 0) return @"—";
    NSDate *d = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)info.issuedAt];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale     = [NSLocale currentLocale];
    df.timeZone   = [NSTimeZone localTimeZone];
    df.dateFormat = @"MMM d yyyy, HH:mm (zzz)";
    return [df stringFromDate:d];
}

static NSString *ROSVIPKeyTypeLabel(LicenseInfo *info) {
    if (!info.type || info.type.length == 0) return @"—";
    NSString *t = info.type;
    if ([t isEqualToString:@"lifetime"])  return @"♾  Lifetime";
    if ([t isEqualToString:@"1-day"])     return @"⚡ 1-Day Pass";
    if ([t isEqualToString:@"7-day"])     return @"📅 7-Day Pass";
    if ([t isEqualToString:@"30-day"])    return @"📅 30-Day Pass";
    if ([t isEqualToString:@"90-day"])    return @"📅 90-Day Pass";
    if ([t isEqualToString:@"365-day"])   return @"📅 365-Day Pass";
    return t;
}

static NSString *ROSVIPBuildActiveMessage(LicenseInfo *info) {
    NSString *keyDisplay = info.rawKey ?: info.licenseId ?: @"ROSVIP-ACTIVE";

    // Trim very long signed keys for display
    if (keyDisplay.length > 48) {
        keyDisplay = [[keyDisplay substringToIndex:45] stringByAppendingString:@"…"];
    }

    NSString *typeLabel   = ROSVIPKeyTypeLabel(info);
    NSString *issuedLabel = ROSVIPFormatIssuedDateTime(info);
    NSString *expLabel    = ROSVIPFormatFullExpireDateTime(info);
    NSString *remLabel    = info.isLifetime ? @"♾  Unlimited" : [info formattedRemainingTime];

    return [NSString stringWithFormat:
        @"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        @"  KEY TYPE:   %@\n"
        @"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        @"  Activated:  %@\n"
        @"  Expires:    %@\n"
        @"  Remaining:  %@\n"
        @"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        @"  Key: %@",
        typeLabel, issuedLabel, expLabel, remLabel, keyDisplay
    ];
}

// ─────────────────────────────────────────────────────────────
// LicenseUI Implementation
// ─────────────────────────────────────────────────────────────

@implementation LicenseUI

static BOOL s_isLicenseActive = NO;
static LicenseInfo *s_currentInfo = nil;

+ (BOOL)isLicenseActive {
    return s_isLicenseActive;
}

#if !TARGET_OS_OSX || TARGET_OS_MACCATALYST
+ (nullable UIViewController *)getTopViewController {
    UIWindow *window = nil;
    // iOS 13+ scene-based
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) { window = w; break; }
                }
                if (!window) window = scene.windows.firstObject;
                break;
            }
        }
    }
    if (!window) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        window = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
    }
    if (!window && [UIApplication sharedApplication].windows.count > 0) {
        window = [UIApplication sharedApplication].windows.firstObject;
    }
    UIViewController *rootVC = window.rootViewController;
    while (rootVC.presentedViewController) {
        rootVC = rootVC.presentedViewController;
    }
    return rootVC;
}
#endif

// ─────────────────────────────────────────────────────────────
// Entry point called by ROSVIP_entry.m constructor
// ─────────────────────────────────────────────────────────────

+ (void)checkOrPromptActivationWithCompletion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        LicenseInfo *info = [LicenseVerifier validateInstalledLicense];
        s_currentInfo = info;

        if (info.isUsable) {
            s_isLicenseActive = YES;
            NSLog(@"[ROSVIP] ✅ License active — %@ | Expires: %@",
                  ROSVIPKeyTypeLabel(info),
                  ROSVIPFormatFullExpireDateTime(info));
            [self showActiveLicenseInfoDialog:info completion:completion];
        } else {
            s_isLicenseActive = NO;
            NSLog(@"[ROSVIP] ⛔ License required: %@", [info statusMessage]);
            [self showActivationDialogWithInitialMessage:[info statusMessage] completion:completion];
        }
    });
}

// ─────────────────────────────────────────────────────────────
// Active License Dialog — shows full expire date + time
// ─────────────────────────────────────────────────────────────

+ (void)showActiveLicenseInfoDialog:(LicenseInfo *)info completion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *message = ROSVIPBuildActiveMessage(info);

#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText    = @"🔓 KheangZzIOS VIP — License Active";
        alert.informativeText = message;
        [alert addButtonWithTitle:@"▶  Continue to Game"];
        [alert runModal];
        if (completion) completion(YES, info);

#else
        UIViewController *rootVC = [self getTopViewController];
        if (!rootVC) {
            if (completion) completion(YES, info);
            return;
        }

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"🔓 KheangZzIOS VIP — Active"
                             message:message
                      preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"▶  Continue to Game"
                                                 style:UIAlertActionStyleDefault
                                               handler:^(UIAlertAction * _Nonnull action) {
            if (completion) completion(YES, info);
        }]];

        [rootVC presentViewController:alert animated:YES completion:nil];
#endif
    });
}

// ─────────────────────────────────────────────────────────────
// Activation Dialog — HWID display + key input
// ─────────────────────────────────────────────────────────────

+ (void)showActivationDialogWithInitialMessage:(nullable NSString *)message
                                    completion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *hwid = [LicenseStorage getDeviceHWID];

#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"🔐 RoS VIP Activation";

        NSString *body = message
            ? [NSString stringWithFormat:@"%@\n\n📱 Your Device ID:\n%@\n\nSend this ID to the admin on Telegram to receive your key.", message, hwid]
            : [NSString stringWithFormat:@"📱 Your Device ID:\n%@\n\nSend this ID to the admin on Telegram, then paste your key below:", hwid];

        alert.informativeText = body;
        [alert addButtonWithTitle:@"✅ Activate"];
        [alert addButtonWithTitle:@"❌ Exit Game"];

        NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 360, 24)];
        input.placeholderString = @"e.g. KHEANG-1D-JUIFDR or KHEANG-7D-A8B2-C4F1-1FC3";
        alert.accessoryView = input;

        NSInteger response = [alert runModal];
        if (response == NSAlertFirstButtonReturn) {
            NSString *key = [[input stringValue] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            NSError *err = nil;
            LicenseInfo *result = [LicenseVerifier activateKey:key error:&err];
            s_currentInfo = result;

            if (result.isUsable) {
                s_isLicenseActive = YES;
                [self showActiveLicenseInfoDialog:result completion:completion];
            } else {
                s_isLicenseActive = NO;
                [self showActivationDialogWithInitialMessage:[result statusMessage] completion:completion];
            }
        } else {
            exit(0);
        }

#else
        UIViewController *rootVC = [self getTopViewController];
        if (!rootVC) return;

        NSString *title = @"🔐 KheangZzIOS VIP Activation";
        NSString *body = message
            ? [NSString stringWithFormat:@"⚠️  %@\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━\n📱 Your Device ID (HWID):\n%@\n━━━━━━━━━━━━━━━━━━━━━━━━━━\nSend this ID to the admin on Telegram to get your key.", message, hwid]
            : [NSString stringWithFormat:@"━━━━━━━━━━━━━━━━━━━━━━━━━━\n📱 Your Device ID (HWID):\n%@\n━━━━━━━━━━━━━━━━━━━━━━━━━━\nSend this to the admin on Telegram, then enter your key below:", hwid];

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:body
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull tf) {
            tf.placeholder       = @"e.g. KHEANG-1D-JUIFDR or KHEANG-7D-A8B2-C4F1-1FC3";
            tf.clearButtonMode   = UITextFieldViewModeWhileEditing;
            tf.autocorrectionType      = UITextAutocorrectionTypeNo;
            tf.autocapitalizationType  = UITextAutocapitalizationTypeAllCharacters;
            tf.spellCheckingType       = UITextSpellCheckingTypeNo;
        }];

        // ── Activate ──────────────────────────────────────────
        UIAlertAction *activateAction = [UIAlertAction
            actionWithTitle:@"✅  Activate"
                      style:UIAlertActionStyleDefault
                    handler:^(UIAlertAction * _Nonnull action) {
            UITextField *tf = alert.textFields.firstObject;
            NSString *key   = [tf.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            NSError *err    = nil;
            LicenseInfo *result = [LicenseVerifier activateKey:key error:&err];
            s_currentInfo   = result;

            if (result.isUsable) {
                s_isLicenseActive = YES;

                // Success dialog — show full expire date/time
                NSString *successMsg = ROSVIPBuildActiveMessage(result);
                UIAlertController *ok = [UIAlertController
                    alertControllerWithTitle:@"✅ KheangZzIOS VIP Activated!"
                                     message:successMsg
                              preferredStyle:UIAlertControllerStyleAlert];
                [ok addAction:[UIAlertAction actionWithTitle:@"▶  Play Game"
                                                       style:UIAlertActionStyleDefault
                                                     handler:^(UIAlertAction * _Nonnull act) {
                    if (completion) completion(YES, result);
                }]];
                [rootVC presentViewController:ok animated:YES completion:nil];

            } else {
                s_isLicenseActive = NO;
                UIAlertController *errAlert = [UIAlertController
                    alertControllerWithTitle:@"❌ Activation Failed"
                                     message:[result statusMessage]
                              preferredStyle:UIAlertControllerStyleAlert];
                [errAlert addAction:[UIAlertAction actionWithTitle:@"🔄  Try Again"
                                                             style:UIAlertActionStyleDefault
                                                           handler:^(UIAlertAction * _Nonnull act) {
                    [self showActivationDialogWithInitialMessage:[result statusMessage] completion:completion];
                }]];
                [errAlert addAction:[UIAlertAction actionWithTitle:@"❌  Exit Game"
                                                             style:UIAlertActionStyleDestructive
                                                           handler:^(UIAlertAction * _Nonnull act) {
                    exit(0);
                }]];
                [rootVC presentViewController:errAlert animated:YES completion:nil];
            }
        }];

        // ── Copy Device ID ────────────────────────────────────
        NSString *copyTitle = [NSString stringWithFormat:@"📋  Copy Device ID  (%@)", hwid];
        UIAlertAction *copyHwidAction = [UIAlertAction
            actionWithTitle:copyTitle
                      style:UIAlertActionStyleDefault
                    handler:^(UIAlertAction * _Nonnull action) {
            [UIPasteboard generalPasteboard].string = hwid;
            [self showActivationDialogWithInitialMessage:
                @"✅ Device ID copied! Send it to the RoS VIP admin on Telegram."
             completion:completion];
        }];

        // ── Exit / Cancel ─────────────────────────────────────
        UIAlertAction *cancelAction = [UIAlertAction
            actionWithTitle:@"✕  Cancel (Exit Game)"
                      style:UIAlertActionStyleDestructive
                    handler:^(UIAlertAction * _Nonnull action) {
            exit(0);
        }];

        [alert addAction:activateAction];
        [alert addAction:copyHwidAction];
        [alert addAction:cancelAction];

        [rootVC presentViewController:alert animated:YES completion:nil];
#endif
    });
}

@end
