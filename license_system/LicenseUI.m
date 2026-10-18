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

+ (void)checkOrPromptActivationWithCompletion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        LicenseInfo *info = [LicenseVerifier validateInstalledLicense];
        s_currentInfo = info;

        if (info.isUsable) {
            s_isLicenseActive = YES;
            if (completion) completion(YES, info);
        } else {
            s_isLicenseActive = NO;
            NSString *msg = [info statusMessage];
            [self showActivationDialogWithInitialMessage:msg completion:completion];
        }
    });
}

+ (void)showActivationDialogWithInitialMessage:(nullable NSString *)message
                                   completion:(nullable LicenseActivationCallback)completion {
    dispatch_async(dispatch_get_main_queue(), ^{
#if TARGET_OS_OSX && !TARGET_OS_MACCATALYST
        // --- macOS Native AppKit NSAlert ---
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Mod License Activation";
        alert.informativeText = message ?: @"Please enter your offline license key below:";
        [alert addButtonWithTitle:@"Activate"];
        [alert addButtonWithTitle:@"Exit / Cancel"];

        NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 320, 24)];
        input.placeholderString = @"Paste LIC-1.xxx.yyy key here";
        alert.accessoryView = input;

        NSInteger response = [alert runModal];
        if (response == NSAlertFirstButtonReturn) {
            NSString *key = [input stringValue];
            NSError *err = nil;
            LicenseInfo *result = [LicenseVerifier activateKey:key error:&err];
            s_currentInfo = result;

            if (result.isUsable) {
                s_isLicenseActive = YES;
                NSAlert *okAlert = [[NSAlert alloc] init];
                okAlert.messageText = @"License Activated Successfully";
                okAlert.informativeText = [NSString stringWithFormat:@"Type: %@\nExpires: %@\nRemaining: %@",
                                           result.type, [result formattedExpirationDate], [result formattedRemainingTime]];
                [okAlert runModal];
                if (completion) completion(YES, result);
            } else {
                s_isLicenseActive = NO;
                [self showActivationDialogWithInitialMessage:[result statusMessage] completion:completion];
            }
        } else {
            if (completion) completion(NO, s_currentInfo);
        }
#else
        // --- iOS / Mac Catalyst UIAlertController (Matches existing mod style) ---
        UIViewController *rootVC = nil;
        UIWindow *window = [UIApplication sharedApplication].keyWindow;
        if (!window && [UIApplication sharedApplication].windows.count > 0) {
            window = [UIApplication sharedApplication].windows.firstObject;
        }
        rootVC = window.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }

        if (!rootVC) return;

        NSString *title = @"License Activation";
        NSString *body = message ?: @"Enter your offline license key to activate mod features:";

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                       message:body
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
            textField.placeholder = @"Paste LIC-1.xxx.yyy key here";
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
                                     message:[NSString stringWithFormat:@"Type: %@\nExpires: %@\nRemaining: %@",
                                              result.type, [result formattedExpirationDate], [result formattedRemainingTime]]
                              preferredStyle:UIAlertControllerStyleAlert];
                [successAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [rootVC presentViewController:successAlert animated:YES completion:nil];
                if (completion) completion(YES, result);
            } else {
                s_isLicenseActive = NO;
                [self showActivationDialogWithInitialMessage:[result statusMessage] completion:completion];
            }
        }];

        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"Cancel"
                                                               style:UIAlertActionStyleCancel
                                                             handler:^(UIAlertAction * _Nonnull action) {
            if (completion) completion(NO, s_currentInfo);
        }];

        [alert addAction:activateAction];
        [alert addAction:cancelAction];

        [rootVC presentViewController:alert animated:YES completion:nil];
#endif
    });
}

@end
