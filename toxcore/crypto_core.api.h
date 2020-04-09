%{
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
%}

/**
 * The number of bytes in a Tox public key.
 */
const CRYPTO_PUBLIC_KEY_SIZE = 32;

/**
 * The number of bytes in a Tox secret key.
 */
const CRYPTO_SECRET_KEY_SIZE = 32;

/**
 * The number of bytes in a shared key computed from public and secret keys.
 */
const CRYPTO_SHARED_KEY_SIZE = 32;

/**
 * The number of bytes in a symmetric key.
 */
const CRYPTO_SYMMETRIC_KEY_SIZE = CRYPTO_SHARED_KEY_SIZE;

/**
 * The number of bytes needed for the MAC (message authentication code) in an
 * encrypted message.
 */
const CRYPTO_MAC_SIZE = 16;

/**
 * The number of bytes in a nonce used for encryption/decryption.
 */
const CRYPTO_NONCE_SIZE = 24;

/**
 * The number of bytes in a SHA256 hash.
 */
const CRYPTO_SHA256_SIZE = 32;

/**
 * The number of bytes in a SHA512 hash.
 */
const CRYPTO_SHA512_SIZE = 64;

/**
 * A `memcmp`-like function whose running time does not depend on the input
 * bytes, only on the input length. Useful to compare sensitive data where
 * timing attacks could reveal that data.
 *
 * This means for instance that comparing "aaaa" and "aaaa" takes 4 time, and
 * "aaaa" and "baaa" also takes 4 time. With a regular `memcmp`, the latter may
 * take 1 time, because it immediately knows that the two strings are not equal.
 */
static int32_t crypto_memcmp(const uint8_t *p1, const uint8_t *p2, size_t length);

/**
 * A `bzero`-like function which won't be optimised away by the compiler. Some
 * compilers will inline `bzero` or `memset` if they can prove that there will
 * be no reads to the written data. Use this function if you want to be sure the
 * memory is indeed zeroed.
 */
static void crypto_memzero(void *data, size_t length);

/**
 * Compute a SHA256 hash (32 bytes).
 */
static void crypto_sha256(uint8_t[CRYPTO_SHA256_SIZE] hash, const uint8_t[length] data);

/**
 * Compute a SHA512 hash (64 bytes).
 */
static void crypto_sha512(uint8_t[CRYPTO_SHA512_SIZE] hash, const uint8_t[length] data);

/**
 * Compare 2 public keys of length CRYPTO_PUBLIC_KEY_SIZE, not vulnerable to
 * timing attacks.
 *
 * @return 0 if both mem locations of length are equal, -1 if they are not.
 */
static int32_t public_key_cmp(
    const uint8_t[CRYPTO_PUBLIC_KEY_SIZE] pk1,
    const uint8_t[CRYPTO_PUBLIC_KEY_SIZE] pk2);

namespace random {

/**
 * Return a random 8 bit integer.
 */
static uint8_t u08();

/**
 * Return a random 16 bit integer.
 */
static uint16_t u16();

/**
 * Return a random 32 bit integer.
 */
static uint32_t u32();

/**
 * Return a random 64 bit integer.
 */
static uint64_t u64();

/**
 * Fill the given nonce with random bytes.
 */
static void nonce(uint8_t[CRYPTO_NONCE_SIZE] nonce);

/**
 * Fill an array of bytes with random values.
 */
static void bytes(uint8_t[length] bytes);

}

/**
 * Check if a Tox public key CRYPTO_PUBLIC_KEY_SIZE is valid or not. This
 * should only be used for input validation.
 *
 * @return false if it isn't, true if it is.
 */
static bool public_key_valid(const uint8_t[CRYPTO_PUBLIC_KEY_SIZE] public_key);

/**
 * Generate a new random keypair. Every call to this function is likely to
 * generate a different keypair.
 */
static int32_t crypto_new_keypair(
    uint8_t[CRYPTO_PUBLIC_KEY_SIZE] public_key,
    uint8_t[CRYPTO_SECRET_KEY_SIZE] secret_key);

/**
 * Derive the public key from a given secret key.
 */
static void crypto_derive_public_key(
    uint8_t[CRYPTO_PUBLIC_KEY_SIZE] public_key,
    const uint8_t[CRYPTO_SECRET_KEY_SIZE] secret_key);

/**
 * Encrypt plain text of the given length to encrypted of length +
 * $CRYPTO_MAC_SIZE using the public key ($CRYPTO_PUBLIC_KEY_SIZE bytes) of the
 * receiver and the secret key of the sender and a $CRYPTO_NONCE_SIZE byte
 * nonce.
 *
 * @return -1 if there was a problem, length of encrypted data if everything
 * was fine.
 */
static int32_t encrypt_data(
    const uint8_t[CRYPTO_PUBLIC_KEY_SIZE] public_key,
    const uint8_t[CRYPTO_SECRET_KEY_SIZE] secret_key,
    const uint8_t[CRYPTO_NONCE_SIZE] nonce,
    const uint8_t[length] plain,
    uint8_t *encrypted);


/**
 * Decrypt encrypted text of the given length to plain text of the given length
 * - $CRYPTO_MAC_SIZE using the public key ($CRYPTO_PUBLIC_KEY_SIZE bytes) of
 * the sender, the secret key of the receiver and a $CRYPTO_NONCE_SIZE byte
 * nonce.
 *
 * @return -1 if there was a problem (decryption failed), length of plain text
 * data if everything was fine.
 */
static int32_t decrypt_data(
    const uint8_t[CRYPTO_PUBLIC_KEY_SIZE] public_key,
    const uint8_t[CRYPTO_SECRET_KEY_SIZE] secret_key,
    const uint8_t[CRYPTO_NONCE_SIZE] nonce,
    const uint8_t[length] encrypted,
    uint8_t *plain);

/**
 * Fast encrypt/decrypt operations. Use if this is not a one-time communication.
 * $encrypt_precompute does the shared-key generation once so it does not have
 * to be performed on every encrypt/decrypt.
 */
static int32_t encrypt_precompute(
    const uint8_t[CRYPTO_PUBLIC_KEY_SIZE] public_key,
    const uint8_t[CRYPTO_SECRET_KEY_SIZE] secret_key,
    uint8_t[CRYPTO_SHARED_KEY_SIZE] shared_key);

/**
 * Encrypts plain of length length to encrypted of length + $CRYPTO_MAC_SIZE
 * using a shared key $CRYPTO_SYMMETRIC_KEY_SIZE big and a $CRYPTO_NONCE_SIZE
 * byte nonce.
 *
 * @return -1 if there was a problem, length of encrypted data if everything
 * was fine.
 */
static int32_t encrypt_data_symmetric(
    const uint8_t[CRYPTO_SHARED_KEY_SIZE] shared_key,
    const uint8_t[CRYPTO_NONCE_SIZE] nonce,
    const uint8_t[length] plain,
    uint8_t *encrypted);

/**
 * Decrypts encrypted of length length to plain of length length -
 * $CRYPTO_MAC_SIZE using a shared key CRYPTO_SHARED_KEY_SIZE big and a
 * $CRYPTO_NONCE_SIZE byte nonce.
 *
 * @return -1 if there was a problem (decryption failed), length of plain data
 * if everything was fine.
 */
static int32_t decrypt_data_symmetric(
    const uint8_t[CRYPTO_SHARED_KEY_SIZE] shared_key,
    const uint8_t[CRYPTO_NONCE_SIZE] nonce,
    const uint8_t[length] encrypted,
    uint8_t *plain);

/**
 * Increment the given nonce by 1 in big endian (rightmost byte incremented
 * first).
 */
static void increment_nonce(uint8_t[CRYPTO_NONCE_SIZE] nonce);

/**
 * Increment the given nonce by a given number. The number should be in host
 * byte order.
 */
static void increment_nonce_number(uint8_t[CRYPTO_NONCE_SIZE] nonce, uint32_t host_order_num);

/**
 * Fill a key CRYPTO_SYMMETRIC_KEY_SIZE big with random bytes.
 */
static void new_symmetric_key(uint8_t[CRYPTO_SYMMETRIC_KEY_SIZE] key);

%{
#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_CRYPTO_CORE_H
%}
