/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Functions for the core crypto.
 */
#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The number of bytes in a Tox public key.
 */
#define CRYPTO_PUBLIC_KEY_SIZE         32

uint32_t crypto_public_key_size(void);

/**
 * The number of bytes in a Tox secret key.
 */
#define CRYPTO_SECRET_KEY_SIZE         32

uint32_t crypto_secret_key_size(void);

/**
 * The number of bytes in a shared key computed from public and secret keys.
 */
#define CRYPTO_SHARED_KEY_SIZE         32

uint32_t crypto_shared_key_size(void);

/**
 * The number of bytes in a symmetric key.
 */
#define CRYPTO_SYMMETRIC_KEY_SIZE      CRYPTO_SHARED_KEY_SIZE

uint32_t crypto_symmetric_key_size(void);

/**
 * The number of bytes needed for the MAC (message authentication code) in an
 * encrypted message.
 */
#define CRYPTO_MAC_SIZE                16

uint32_t crypto_mac_size(void);

/**
 * The number of bytes in a nonce used for encryption/decryption.
 */
#define CRYPTO_NONCE_SIZE              24

uint32_t crypto_nonce_size(void);

/**
 * The number of bytes in a SHA256 hash.
 */
#define CRYPTO_SHA256_SIZE             32

uint32_t crypto_sha256_size(void);

/**
 * The number of bytes in a SHA512 hash.
 */
#define CRYPTO_SHA512_SIZE             64

uint32_t crypto_sha512_size(void);

/**
 * A `memcmp`-like function whose running time does not depend on the input
 * bytes, only on the input length. Useful to compare sensitive data where
 * timing attacks could reveal that data.
 *
 * This means for instance that comparing "aaaa" and "aaaa" takes 4 time, and
 * "aaaa" and "baaa" also takes 4 time. With a regular `memcmp`, the latter may
 * take 1 time, because it immediately knows that the two strings are not equal.
 */
int32_t crypto_memcmp(const uint8_t *p1, const uint8_t *p2, size_t length);

/**
 * A `bzero`-like function which won't be optimised away by the compiler. Some
 * compilers will inline `bzero` or `memset` if they can prove that there will
 * be no reads to the written data. Use this function if you want to be sure the
 * memory is indeed zeroed.
 */
void crypto_memzero(void *data, size_t length);

/**
 * Compute a SHA256 hash (32 bytes).
 */
void crypto_sha256(uint8_t *hash, const uint8_t *data, size_t length);

/**
 * Compute a SHA512 hash (64 bytes).
 */
void crypto_sha512(uint8_t *hash, const uint8_t *data, size_t length);

/**
 * Compare 2 public keys of length CRYPTO_PUBLIC_KEY_SIZE, not vulnerable to
 * timing attacks.
 *
 * @return 0 if both mem locations of length are equal, -1 if they are not.
 */
int32_t public_key_cmp(const uint8_t *pk1, const uint8_t *pk2);

/**
 * Return a random 8 bit integer.
 */
uint8_t random_u08(void);

/**
 * Return a random 16 bit integer.
 */
uint16_t random_u16(void);

/**
 * Return a random 32 bit integer.
 */
uint32_t random_u32(void);

/**
 * Return a random 64 bit integer.
 */
uint64_t random_u64(void);

/**
 * Fill the given nonce with random bytes.
 */
void random_nonce(uint8_t *nonce);

/**
 * Fill an array of bytes with random values.
 */
void random_bytes(uint8_t *bytes, size_t length);

/**
 * Check if a Tox public key CRYPTO_PUBLIC_KEY_SIZE is valid or not. This
 * should only be used for input validation.
 *
 * @return false if it isn't, true if it is.
 */
bool public_key_valid(const uint8_t *public_key);

/**
 * Generate a new random keypair. Every call to this function is likely to
 * generate a different keypair.
 */
int32_t crypto_new_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * Derive the public key from a given secret key.
 */
void crypto_derive_public_key(uint8_t *public_key, const uint8_t *secret_key);

/**
 * Encrypt plain text of the given length to encrypted of length +
 * CRYPTO_MAC_SIZE using the public key (CRYPTO_PUBLIC_KEY_SIZE bytes) of the
 * receiver and the secret key of the sender and a CRYPTO_NONCE_SIZE byte
 * nonce.
 *
 * @return -1 if there was a problem, length of encrypted data if everything
 * was fine.
 */
int32_t encrypt_data(const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *nonce, const uint8_t *plain,
                     size_t length, uint8_t *encrypted);

/**
 * Decrypt encrypted text of the given length to plain text of the given length
 * - CRYPTO_MAC_SIZE using the public key (CRYPTO_PUBLIC_KEY_SIZE bytes) of
 * the sender, the secret key of the receiver and a CRYPTO_NONCE_SIZE byte
 * nonce.
 *
 * @return -1 if there was a problem (decryption failed), length of plain text
 * data if everything was fine.
 */
int32_t decrypt_data(const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *nonce,
                     const uint8_t *encrypted, size_t length, uint8_t *plain);

/**
 * Fast encrypt/decrypt operations. Use if this is not a one-time communication.
 * encrypt_precompute does the shared-key generation once so it does not have
 * to be performed on every encrypt/decrypt.
 */
int32_t encrypt_precompute(const uint8_t *public_key, const uint8_t *secret_key, uint8_t *shared_key);

/**
 * Encrypts plain of length length to encrypted of length + CRYPTO_MAC_SIZE
 * using a shared key CRYPTO_SYMMETRIC_KEY_SIZE big and a CRYPTO_NONCE_SIZE
 * byte nonce.
 *
 * @return -1 if there was a problem, length of encrypted data if everything
 * was fine.
 */
int32_t encrypt_data_symmetric(const uint8_t *shared_key, const uint8_t *nonce, const uint8_t *plain, size_t length,
                               uint8_t *encrypted);

/**
 * Decrypts encrypted of length length to plain of length length -
 * CRYPTO_MAC_SIZE using a shared key CRYPTO_SHARED_KEY_SIZE big and a
 * CRYPTO_NONCE_SIZE byte nonce.
 *
 * @return -1 if there was a problem (decryption failed), length of plain data
 * if everything was fine.
 */
int32_t decrypt_data_symmetric(const uint8_t *shared_key, const uint8_t *nonce, const uint8_t *encrypted, size_t length,
                               uint8_t *plain);

/**
 * Increment the given nonce by 1 in big endian (rightmost byte incremented
 * first).
 */
void increment_nonce(uint8_t *nonce);

/**
 * Increment the given nonce by a given number. The number should be in host
 * byte order.
 */
void increment_nonce_number(uint8_t *nonce, uint32_t host_order_num);

/**
 * Fill a key CRYPTO_SYMMETRIC_KEY_SIZE big with random bytes.
 */
void new_symmetric_key(uint8_t *key);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_CRYPTO_CORE_H
