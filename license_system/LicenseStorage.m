#import "LicenseStorage.h"
#import <Security/Security.h>

static NSString * const kKeychainService = @"com.gamemod.license";
static NSString * const kKeychainAccountLicense = @"active_license_key";
static NSString * const kKeychainAccountTime = @"last_seen_timestamp";

@implementation LicenseStorage

+ (NSString *)fallbackDirectory {
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
    NSString *base = [paths firstObject] ?: NSTemporaryDirectory();
    NSString *dir = [base stringByAppendingPathComponent:@".license_cache"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

+ (BOOL)saveLicenseToken:(NSString *)token error:(NSError **)error {
    if (!token || token.length == 0) return NO;

    NSData *data = [token dataUsingEncoding:NSUTF8StringEncoding];

    // 1. Try macOS Keychain
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: kKeychainAccountLicense
    };

    NSDictionary *attributes = @{
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock
    };

    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *newQuery = [query mutableCopy];
        [newQuery addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)newQuery, NULL);
    }

    if (status == errSecSuccess) {
        return YES;
    }

    // 2. Fallback to application support file if Keychain unavailable in sandbox
    NSString *filePath = [[self fallbackDirectory] stringByAppendingPathComponent:@"license.dat"];
    return [data writeToFile:filePath atomically:YES];
}

+ (nullable NSString *)loadLicenseToken {
    // 1. Try Keychain
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: kKeychainAccountLicense,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        NSData *data = (__bridge_transfer NSData *)result;
        return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    }

    // 2. Try Fallback file
    NSString *filePath = [[self fallbackDirectory] stringByAppendingPathComponent:@"license.dat"];
    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    if (fileData) {
        return [[NSString alloc] initWithData:fileData encoding:NSUTF8StringEncoding];
    }

    return nil;
}

+ (void)deleteLicenseToken {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: kKeychainAccountLicense
    };
    SecItemDelete((__bridge CFDictionaryRef)query);

    NSString *filePath = [[self fallbackDirectory] stringByAppendingPathComponent:@"license.dat"];
    [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
}

+ (BOOL)saveLastObservedTime:(int64_t)epochSeconds {
    NSString *timeStr = [NSString stringWithFormat:@"%lld", epochSeconds];
    NSData *data = [timeStr dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: kKeychainAccountTime
    };

    NSDictionary *attributes = @{
        (__bridge id)kSecValueData: data,
        (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAfterFirstUnlock
    };

    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *newQuery = [query mutableCopy];
        [newQuery addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)newQuery, NULL);
    }

    NSString *filePath = [[self fallbackDirectory] stringByAppendingPathComponent:@".ts"];
    [data writeToFile:filePath atomically:YES];

    return (status == errSecSuccess);
}

+ (int64_t)loadLastObservedTime {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: kKeychainAccountTime,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result != NULL) {
        NSData *data = (__bridge_transfer NSData *)result;
        NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        return [str longLongValue];
    }

    NSString *filePath = [[self fallbackDirectory] stringByAppendingPathComponent:@".ts"];
    NSData *fileData = [NSData dataWithContentsOfFile:filePath];
    if (fileData) {
        NSString *str = [[NSString alloc] initWithData:fileData encoding:NSUTF8StringEncoding];
        return [str longLongValue];
    }

    return 0;
}

@end
