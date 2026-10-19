#import "LicenseUI.h"
#import "LicenseVerifier.h"
#import "LicenseStorage.h"

#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
#import <AppKit/AppKit.h>
#else
#import <UIKit/UIKit.h>
#endif

@implementation LicenseUI

static BOOL s_isLicenseActive = NO;
static LicenseInfo *s_currentInfo = nil;

+ (BOOL)isLicenseActive {
    return s_isLicenseActive;
}

#if !TARGET_OS_OSX || TARGET_OS_MACCATALYST
+ (nullable UIViewController *)getTopViewController {
    UIWindow *window = [UIApplication sharedApplication].keyWindow;
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

+ (void)checkOrPromptActivationWithCompletion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        LicenseInfo *info = [LicenseVerifier validateInstalledLicense];
        s_currentInfo = info;

        if (info.isUsable) {
            s_isLicenseActive = YES;
            // On subsequent game launches with active license:
            // Display alert showing active key and exact expiration date
            [self showActiveLicenseInfoDialog:info completion:completion];
        } else {
            s_isLicenseActive = NO;
            NSString *msg = [info statusMessage];
            [self showActivationDialogWithInitialMessage:msg completion:completion];
        }
    });
}

+ (void)showActiveLicenseInfoDialog:(LicenseInfo *)info completion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"KheangZzIOS VIP Active";
        alert.informativeText = [NSString stringWithFormat:@"Key: %@\nExpires: %@\nRemaining: %@",
                                 info.rawKey ?: info.licenseId ?: @"KHEANG-7D-ACTIVE",
                                 [info formattedExpirationDate],
                                 [info formattedRemainingTime]];
        [alert addButtonWithTitle:@"Continue to Game"];
        [alert runModal];
        if (completion) completion(YES, info);
#else
        UIViewController *rootVC = [self getTopViewController];
        if (!rootVC) {
            if (completion) completion(YES, info);
            return;
        }

        NSString *title = @"KheangZzIOS VIP Active";
        NSString *keyText = info.rawKey ?: info.licenseId ?: @"KHEANG-7D-ACTIVE";
        NSString *expText = [info formattedExpirationDate];
        NSString *remText = [info formattedRemainingTime];

        NSString *message = [NSString stringWithFormat:@"Key: %@\n\nExpiration: %@\nTime Left: %@",
                             keyText, expText, remText];

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"Continue to Game"
                                                 style:UIAlertActionStyleDefault
                                               handler:^(UIAlertAction * _Nonnull action) {
            if (completion) completion(YES, info);
        }]];

        [rootVC presentViewController:alert animated:YES completion:nil];
#endif
    });
}

+ (void)showActivationDialogWithInitialMessage:(nullable NSString *)message
                                   completion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Mod License Activation";
        alert.informativeText = message ?: @"Please enter your offline license key below:";
        [alert addButtonWithTitle:@"Activate"];
        [alert addButtonWithTitle:@"Exit Game"];

        NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 320, 24)];
        input.placeholderString = @"e.g. KHEANG-7D-HUIES";
        alert.accessoryView = input;

        NSInteger response = [alert runModal];
        if (response == NSAlertFirstButtonReturn) {
            NSString *key = [input stringValue];
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
            // User clicked exit/cancel -> terminate immediately
            exit(0);
        }
#else
        UIViewController *rootVC = [self getTopViewController];
        if (!rootVC) return;

        NSString *title = @"License Activation";
        NSString *body = message ?: @"Enter your offline license key to activate mod features:";

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:body
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
            textField.placeholder = @"e.g. KHEANG-7D-HUIES";
            textField.clearButtonMode = UITextFieldViewModeWhileEditing;
        }];

        UIAlertAction *activateAction = [UIAlertAction actionWithTitle:@"Activate"
                                                                 style:UIAlertActionStyleDefault
                                                               handler:^(UIAlertAction * _Nonnull action) {
            UITextField *tf = alert.textFields.firstObject;
            NSString *key = tf.text;
            NSError *err = nil;
            LicenseInfo *result = [LicenseVerifier activateKey:key error:&err];
            s_currentInfo = result;

            if (result.isUsable) {
                s_isLicenseActive = YES;
                UIAlertController *successAlert = [UIAlertController
                    alertControllerWithTitle:@"License Activated"
                                     message:[NSString stringWithFormat:@"Key: %@\nExpires: %@\nRemaining: %@",
                                              result.rawKey ?: key, [result formattedExpirationDate], [result formattedRemainingTime]]
                              preferredStyle:UIAlertControllerStyleAlert];
                [successAlert addAction:[UIAlertAction actionWithTitle:@"Play Game"
                                                                 style:UIAlertActionStyleDefault
                                                               handler:^(UIAlertAction * _Nonnull act) {
                    if (completion) completion(YES, result);
                }]];
                [rootVC presentViewController:successAlert animated:YES completion:nil];
            } else {
                s_isLicenseActive = NO;
                UIAlertController *errAlert = [UIAlertController
                    alertControllerWithTitle:@"Activation Failed"
                                     message:[result statusMessage]
                              preferredStyle:UIAlertControllerStyleAlert];
                [errAlert addAction:[UIAlertAction actionWithTitle:@"Try Again"
                                                             style:UIAlertActionStyleDefault
                                                           handler:^(UIAlertAction * _Nonnull act) {
                    [self showActivationDialogWithInitialMessage:[result statusMessage] completion:completion];
                }]];
                [errAlert addAction:[UIAlertAction actionWithTitle:@"Exit Game"
                                                             style:UIAlertActionStyleDestructive
                                                           handler:^(UIAlertAction * _Nonnull act) {
                    // Immediate crash / exit on cancel/refusal
                    exit(0);
                }]];
                [rootVC presentViewController:errAlert animated:YES completion:nil];
            }
        }];

        // When user clicks cancel -> CRASH & CLOSE GAME IMMEDIATELY
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel (Exit Game)"
                                                               style:UIAlertActionStyleDestructive
                                                             handler:^(UIAlertAction * _Nonnull action) {
            exit(0);
        }];

        [alert addAction:activateAction];
        [alert addAction:cancelAction];

        [rootVC presentViewController:alert animated:YES completion:nil];
#endif
    });
}

@end
