#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LicenseStatus) {
    LicenseStatusValid = 0,
    LicenseStatusNotActivated,
    LicenseStatusExpired,
    LicenseStatusClockTampered,
    LicenseStatusInvalidSignature,
    LicenseStatusProductMismatch,
    LicenseStatusMalformedKey
};

@interface LicenseInfo : NSObject

@property (nonatomic, assign) LicenseStatus status;
@property (nonatomic, copy) NSString *licenseId;
@property (nonatomic, copy) NSString *productId;
@property (nonatomic, copy) NSString *type;
@property (nonatomic, assign) int64_t issuedAt;
@property (nonatomic, assign) int64_t expiresAt;
@property (nonatomic, assign) BOOL isLifetime;
@property (nonatomic, copy) NSArray<NSString *> *permissions;

- (int64_t)remainingSeconds;
- (NSString *)formattedExpirationDate;
- (NSString *)formattedRemainingTime;
- (NSString *)statusMessage;
- (BOOL)isUsable;

@end

@interface LicenseVerifier : NSObject

/**
 * Validates a raw license key string offline.
 */
+ (LicenseInfo *)verifyKey:(NSString *)licenseKey;

/**
 * Validates currently installed/saved license from Keychain.
 */
+ (LicenseInfo *)validateInstalledLicense;

/**
 * Activates a new license key, verifies it, and stores it if valid.
 */
+ (LicenseInfo *)activateKey:(NSString *)licenseKey error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
