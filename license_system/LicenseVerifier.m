#import "LicenseVerifier.h"
#import "LicenseStorage.h"
#import "ed25519_verify.h"
#import <CommonCrypto/CommonDigest.h>

#define HWID_SALT "KHEANG_VIP_SALT_2026_OFFLINE"

static BOOL VerifyHWIDChecksum(NSString *tag, NSString *cleanHWID, NSString *checksum) {
    const char *salts[] = {
        "KHEANG_VIP_SALT_2026_OFFLINE",
        "ROSVIP_HWID_SALT_2026_OFFLINE"
    };
    for (int i = 0; i < 2; i++) {
        NSString *input = [NSString stringWithFormat:@"%s:%@:%@", salts[i], [tag uppercaseString], [cleanHWID uppercaseString]];
        const char *cStr = [input UTF8String];
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(cStr, (CC_LONG)strlen(cStr), digest);
        NSString *exp = [NSString stringWithFormat:@"%02X%02X", digest[0], digest[1]];
        if ([[checksum uppercaseString] isEqualToString:exp]) {
            return YES;
        }
    }
    return NO;
}

// If public_key.h is generated, include it; otherwise use embedded default
#if __has_include("public_key.h")
#include "public_key.h"
#else
// Default placeholder - will be updated when python keygen runs
static const unsigned char EMBEDDED_PUBLIC_KEY[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define EMBEDDED_PRODUCT_ID "ROSVIP-iOS-v1"
#endif

@implementation LicenseInfo

- (BOOL)isUsable {
    return self.status == LicenseStatusValid;
}

- (int64_t)remainingSeconds {
    if (self.isLifetime) return INT64_MAX;
    int64_t now = (int64_t)[[NSDate date] timeIntervalSince1970];
    int64_t rem = self.expiresAt - now;
    return (rem > 0) ? rem : 0;
}

- (NSString *)formattedExpirationDate {
    if (self.isLifetime) {
        return @"Lifetime — No Scheduled Expiration";
    }
    NSDate *expDate = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)self.expiresAt];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateStyle = NSDateFormatterMediumStyle;
    df.timeStyle = NSDateFormatterShortStyle;
    df.timeZone = [NSTimeZone localTimeZone];
    return [df stringFromDate:expDate];
}

- (NSString *)formattedRemainingTime {
    if (self.isLifetime) {
        return @"Lifetime Access";
    }
    int64_t secs = [self remainingSeconds];
    if (secs <= 0) {
        return @"0m (Expired)";
    }
    int64_t days = secs / 86400;
    int64_t hours = (secs % 86400) / 3600;
    int64_t minutes = (secs % 3600) / 60;

    if (days > 0) {
        return [NSString stringWithFormat:@"%lld days, %lld hours, %lld minutes", days, hours, minutes];
    } else if (hours > 0) {
        return [NSString stringWithFormat:@"%lld hours, %lld minutes", hours, minutes];
    } else {
        return [NSString stringWithFormat:@"%lld minutes", minutes];
    }
}

- (NSString *)statusMessage {
    switch (self.status) {
        case LicenseStatusValid:
            return self.isLifetime ? @"Active (Lifetime)" : [NSString stringWithFormat:@"Active (%@ remaining)", [self formattedRemainingTime]];
        case LicenseStatusNotActivated:
            return @"No License Installed — Please Activate";
        case LicenseStatusExpired:
            return @"License Expired — This key has expired and cannot be used anymore. Please enter a new key.";
        case LicenseStatusClockTampered:
            return @"Clock Rollback Detected — License Locked";
        case LicenseStatusInvalidSignature:
            return @"Invalid Digital Signature — License Rejected";
        case LicenseStatusProductMismatch:
            return @"Wrong Product License — Incompatible Key";
        case LicenseStatusMalformedKey:
            return @"Malformed License Format — Invalid Key";
        case LicenseStatusHWIDMismatch:
            return @"Hardware ID Mismatch — This key is locked to a different device! 1 Key = 1 Device.";
    }
}

@end

@implementation LicenseVerifier

+ (NSData *)base64UrlDecode:(NSString *)base64Url {
    NSString *base64 = [base64Url stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    while (base64.length % 4 != 0) {
        base64 = [base64 stringByAppendingString:@"="];
    }
    return [[NSData alloc] initWithBase64EncodedString:base64 options:0];
}

+ (LicenseInfo *)verifyKey:(NSString *)licenseKey {
    LicenseInfo *info = [[LicenseInfo alloc] init];
    info.status = LicenseStatusMalformedKey;

    if (!licenseKey || licenseKey.length == 0) {
        info.status = LicenseStatusNotActivated;
        return info;
    }

    NSString *trimmed = [licenseKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    int64_t now = (int64_t)[[NSDate date] timeIntervalSince1970];

    // 1. Check if token was retrieved from storage in format: "KEY|EXPIRES|ISSUED"
    if ([trimmed containsString:@"|"]) {
        NSArray *parts = [trimmed componentsSeparatedByString:@"|"];
        if (parts.count >= 3) {
            info.rawKey = parts[0];
            info.expiresAt = [parts[1] longLongValue];
            info.issuedAt = [parts[2] longLongValue];
            info.isLifetime = (info.expiresAt == 0);
            info.productId = @(EMBEDDED_PRODUCT_ID);
            info.licenseId = info.rawKey;

            NSArray *tagParts = [info.rawKey componentsSeparatedByString:@"-"];
            if (tagParts.count >= 2) {
                NSString *tag = [tagParts[1] uppercaseString];
                if ([tag isEqualToString:@"1D"]) info.type = @"1-day";
                else if ([tag isEqualToString:@"7D"]) info.type = @"7-day";
                else if ([tag isEqualToString:@"30D"]) info.type = @"30-day";
                else if ([tag isEqualToString:@"90D"]) info.type = @"90-day";
                else if ([tag isEqualToString:@"365D"]) info.type = @"365-day";
                else if ([tag isEqualToString:@"LIFE"]) info.type = @"lifetime";
                else info.type = @"custom";
            }

            // Record in ledger
            [LicenseStorage saveActivatedKeyRecord:info.rawKey issuedAt:info.issuedAt expiresAt:info.expiresAt];

            if (!info.isLifetime && now > info.expiresAt) {
                info.status = LicenseStatusExpired;
                return info;
            }

            int64_t lastObserved = [LicenseStorage loadLastObservedTime];
            if (lastObserved > 0 && now < (lastObserved - 300)) {
                info.status = LicenseStatusClockTampered;
                return info;
            }
            if (now > lastObserved) {
                [LicenseStorage saveLastObservedTime:now];
            }

            info.status = LicenseStatusValid;
            return info;
        }
    }

    // 2. Check if user entered short key (e.g. "KHEANG-1D-XXXXXX" or "KHEANG-7D-A8B2-C4F1-1FC3")
    if (([trimmed hasPrefix:@"KHEANG-"] || [trimmed hasPrefix:@"ROSVIP-"]) && ![trimmed containsString:@"."]) {
        NSArray *parts = [trimmed componentsSeparatedByString:@"-"];
        if (parts.count >= 3) {
            NSString *tag = [parts[1] uppercaseString];
            NSString *keyHwid = nil;
            NSString *checksum = nil;

            if (parts.count == 5) {
                // Format: ROSVIP-7D-A8B2-C4F1-1FC3
                keyHwid = [NSString stringWithFormat:@"%@-%@", parts[2], parts[3]];
                checksum = parts[4];
            } else if (parts.count == 4) {
                // Format: ROSVIP-7D-A8B2C4F1-1FC3
                keyHwid = parts[2];
                checksum = parts[3];
            }

            // If HWID is present, verify checksum and device HWID
            if (keyHwid && checksum) {
                NSString *cleanKeyHwid = [[keyHwid stringByReplacingOccurrencesOfString:@"-" withString:@""] uppercaseString];
                if (!VerifyHWIDChecksum(tag, cleanKeyHwid, checksum)) {
                    info.status = LicenseStatusMalformedKey;
                    return info;
                }

                NSString *curHwid = [[[LicenseStorage getDeviceHWID] stringByReplacingOccurrencesOfString:@"-" withString:@""] uppercaseString];
                if (![cleanKeyHwid isEqualToString:curHwid]) {
                    info.status = LicenseStatusHWIDMismatch;
                    return info;
                }
            }

            int64_t durationSeconds = 0;
            NSString *durType = @"custom";

            if ([tag isEqualToString:@"1D"]) { durationSeconds = 86400LL; durType = @"1-day"; }
            else if ([tag isEqualToString:@"7D"]) { durationSeconds = 7LL * 86400LL; durType = @"7-day"; }
            else if ([tag isEqualToString:@"30D"]) { durationSeconds = 30LL * 86400LL; durType = @"30-day"; }
            else if ([tag isEqualToString:@"90D"]) { durationSeconds = 90LL * 86400LL; durType = @"90-day"; }
            else if ([tag isEqualToString:@"365D"]) { durationSeconds = 365LL * 86400LL; durType = @"365-day"; }
            else if ([tag isEqualToString:@"LIFE"]) { durationSeconds = 0LL; durType = @"lifetime"; }
            else {
                info.status = LicenseStatusMalformedKey;
                return info;
            }

            info.rawKey = trimmed;
            info.licenseId = trimmed;
            info.productId = @(EMBEDDED_PRODUCT_ID);
            info.type = durType;
            info.permissions = @[@"all", @"premium", @"aimbot", @"esp", @"norecoil"];

            // Check if key was previously activated in device ledger
            NSDictionary *record = [LicenseStorage recordForActivatedKey:trimmed];
            if (record) {
                int64_t recExpires = [record[@"expiresAt"] longLongValue];
                int64_t recIssued = [record[@"issuedAt"] longLongValue];
                info.issuedAt = recIssued;
                info.expiresAt = recExpires;
                info.isLifetime = (recExpires == 0);

                if (!info.isLifetime && now > recExpires) {
                    info.status = LicenseStatusExpired;
                    return info;
                }

                int64_t lastObserved = [LicenseStorage loadLastObservedTime];
                if (lastObserved > 0 && now < (lastObserved - 300)) {
                    info.status = LicenseStatusClockTampered;
                    return info;
                }
                if (now > lastObserved) {
                    [LicenseStorage saveLastObservedTime:now];
                }

                info.status = LicenseStatusValid;
                return info;
            }

            info.issuedAt = now;
            info.isLifetime = (durationSeconds == 0);
            info.expiresAt = info.isLifetime ? 0 : (now + durationSeconds);

            [LicenseStorage saveLastObservedTime:now];

            info.status = LicenseStatusValid;
            return info;
        }
    }

    NSString *payloadStr = nil;
    NSString *sigStr = nil;
    NSString *tag = nil;

    if ([trimmed hasPrefix:@"KHEANG-"] || [trimmed hasPrefix:@"ROSVIP-"]) {
        NSRange lastDot = [trimmed rangeOfString:@"." options:NSBackwardsSearch];
        if (lastDot.location == NSNotFound) {
            info.status = LicenseStatusMalformedKey;
            return info;
        }
        sigStr = [trimmed substringFromIndex:lastDot.location + 1];
        NSString *prefixAndPayload = [trimmed substringToIndex:lastDot.location];

        NSRange firstHyphen = [prefixAndPayload rangeOfString:@"-"];
        if (firstHyphen.location == NSNotFound) {
            info.status = LicenseStatusMalformedKey;
            return info;
        }
        NSString *afterFirst = [prefixAndPayload substringFromIndex:firstHyphen.location + 1];
        NSRange secondHyphen = [afterFirst rangeOfString:@"-"];
        if (secondHyphen.location == NSNotFound) {
            info.status = LicenseStatusMalformedKey;
            return info;
        }
        tag = [afterFirst substringToIndex:secondHyphen.location];
        payloadStr = [afterFirst substringFromIndex:secondHyphen.location + 1];
    } else if ([trimmed hasPrefix:@"LIC-1."]) {
        NSArray *parts = [trimmed componentsSeparatedByString:@"."];
        if (parts.count == 3) {
            payloadStr = parts[1];
            sigStr = parts[2];
        }
    }

    if (!payloadStr || !sigStr) {
        info.status = LicenseStatusMalformedKey;
        return info;
    }

    NSData *payloadData = [self base64UrlDecode:payloadStr];
    NSData *signatureData = [self base64UrlDecode:sigStr];

    if (!payloadData || !signatureData || signatureData.length != 64) {
        info.status = LicenseStatusMalformedKey;
        return info;
    }

    // 1. Verify Ed25519 cryptographic signature over canonical payload
    int verifyResult = ed25519_verify_signature(
        (const unsigned char *)signatureData.bytes,
        (const unsigned char *)payloadData.bytes,
        payloadData.length,
        EMBEDDED_PUBLIC_KEY
    );

    if (verifyResult != 0) {
        info.status = LicenseStatusInvalidSignature;
        return info;
    }

    // 2. Parse Canonical JSON payload
    NSError *jsonError = nil;
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:payloadData options:0 error:&jsonError];
    if (jsonError || ![dict isKindOfClass:[NSDictionary class]]) {
        info.status = LicenseStatusMalformedKey;
        return info;
    }

    info.licenseId = dict[@"license_id"];
    info.productId = dict[@"product_id"];
    info.type = dict[@"type"];
    info.issuedAt = [dict[@"issued_at"] longLongValue];
    info.expiresAt = [dict[@"expires_at"] longLongValue];
    info.isLifetime = (info.expiresAt == 0);
    info.permissions = dict[@"permissions"] ?: @[];

    // Verify duration tag matches signed type if ROSVIP- format is used
    if (tag) {
        BOOL tagMatches = NO;
        if ([tag isEqualToString:@"1D"] && [info.type isEqualToString:@"1-day"]) tagMatches = YES;
        else if ([tag isEqualToString:@"7D"] && [info.type isEqualToString:@"7-day"]) tagMatches = YES;
        else if ([tag isEqualToString:@"30D"] && [info.type isEqualToString:@"30-day"]) tagMatches = YES;
        else if ([tag isEqualToString:@"90D"] && [info.type isEqualToString:@"90-day"]) tagMatches = YES;
        else if ([tag isEqualToString:@"365D"] && [info.type isEqualToString:@"365-day"]) tagMatches = YES;
        else if ([tag isEqualToString:@"LIFE"] && [info.type isEqualToString:@"lifetime"]) tagMatches = YES;
        if (!tagMatches) {
            info.status = LicenseStatusInvalidSignature;
            return info;
        }
    }

    // 3. Verify Product ID (compatible across ROSVIP, ROSHack, and LOLiOS)
    if (![info.productId isEqualToString:@(EMBEDDED_PRODUCT_ID)] &&
        ![info.productId isEqualToString:@"ROSHack-macOS-v1"] &&
        ![info.productId isEqualToString:@"ROSVIP-iOS-v1"] &&
        ![info.productId isEqualToString:@"LOLiOS-FREE"] &&
        ![info.productId isEqualToString:@"LOLiOS-v1"]) {
        info.status = LicenseStatusProductMismatch;
        return info;
    }

    // 3.5 Verify HWID if bound in payload
    if (dict[@"hwid"]) {
        NSString *reqHwid = [[dict[@"hwid"] stringByReplacingOccurrencesOfString:@"-" withString:@""] uppercaseString];
        NSString *deviceHwid = [[[LicenseStorage getDeviceHWID] stringByReplacingOccurrencesOfString:@"-" withString:@""] uppercaseString];
        if (![reqHwid isEqualToString:deviceHwid]) {
            info.status = LicenseStatusHWIDMismatch;
            return info;
        }
    }

    // 4. Verify Clock & Expiration against UTC current time
    now = (int64_t)[[NSDate date] timeIntervalSince1970];

    // Anti-Rollback Check
    int64_t lastObserved = [LicenseStorage loadLastObservedTime];
    // Tolerance: Allow up to 300 seconds (5 minutes) backwards drift for NTP sync
    if (lastObserved > 0 && now < (lastObserved - 300)) {
        info.status = LicenseStatusClockTampered;
        return info;
    }

    // Reject future issued_at timestamps (tolerance 300s)
    if (info.issuedAt > (now + 300)) {
        info.status = LicenseStatusClockTampered;
        return info;
    }

    // Expiration enforcement
    if (!info.isLifetime && now > info.expiresAt) {
        info.status = LicenseStatusExpired;
        return info;
    }

    // Update last observed valid time
    if (now > lastObserved) {
        [LicenseStorage saveLastObservedTime:now];
    }

    info.rawKey = trimmed;
    info.status = LicenseStatusValid;
    return info;
}

+ (LicenseInfo *)validateInstalledLicense {
    NSString *token = [LicenseStorage loadLicenseToken];
    if (!token) {
        LicenseInfo *info = [[LicenseInfo alloc] init];
        info.status = LicenseStatusNotActivated;
        return info;
    }
    return [self verifyKey:token];
}

+ (LicenseInfo *)activateKey:(NSString *)licenseKey error:(NSError **)error {
    LicenseInfo *info = [self verifyKey:licenseKey];
    if (info.status == LicenseStatusValid) {
        NSString *tokenToSave = licenseKey;
        if (![licenseKey containsString:@"."] && info.rawKey) {
            tokenToSave = [NSString stringWithFormat:@"%@|%lld|%lld", info.rawKey, info.expiresAt, info.issuedAt];
        }
        [LicenseStorage saveActivatedKeyRecord:info.rawKey ?: licenseKey issuedAt:info.issuedAt expiresAt:info.expiresAt];
        [LicenseStorage saveLicenseToken:tokenToSave error:error];
    }
    return info;
}

@end
