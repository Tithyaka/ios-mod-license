#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LicenseStorage : NSObject

/**
 * Saves the raw signed license token to macOS Keychain with fallback.
 */
+ (BOOL)saveLicenseToken:(NSString *)token error:(NSError **)error;

/**
 * Loads the stored signed license token. Returns nil if none exists.
 */
+ (nullable NSString *)loadLicenseToken;

/**
 * Deletes stored license token (e.g., when resetting or deactivated).
 */
+ (void)deleteLicenseToken;

/**
 * Saves the latest observed timestamp (UTC epoch seconds) for clock-tamper protection.
 */
+ (BOOL)saveLastObservedTime:(int64_t)epochSeconds;

/**
 * Loads the latest observed timestamp. Returns 0 if none stored.
 */
+ (int64_t)loadLastObservedTime;

/**
 * Loads activation record for a key to prevent key reuse after expiration.
 */
+ (nullable NSDictionary *)recordForActivatedKey:(NSString *)key;

/**
 * Permanently logs key activation and its expiration timestamp.
 */
+ (void)saveActivatedKeyRecord:(NSString *)key issuedAt:(int64_t)issuedAt expiresAt:(int64_t)expiresAt;

@end

NS_ASSUME_NONNULL_END
