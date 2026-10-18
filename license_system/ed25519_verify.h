#ifndef ED25519_VERIFY_H
#define ED25519_VERIFY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verifies an Ed25519 digital signature.
 *
 * @param signature Pointer to 64-byte signature.
 * @param message Pointer to message data buffer.
 * @param message_len Length of message buffer in bytes.
 * @param public_key Pointer to 32-byte Ed25519 raw public key.
 * @return 0 if valid, non-zero if invalid / signature check failed.
 */
int ed25519_verify_signature(
    const unsigned char *signature,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *public_key
);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_VERIFY_H */
