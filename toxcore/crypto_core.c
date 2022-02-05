/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Functions for the core crypto.
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
 */
#include "crypto_core.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"

#ifndef VANILLA_NACL
// We use libsodium by default.
#include <sodium.h>
#else
#include <crypto_box.h>
#include <crypto_hash_sha256.h>
#include <crypto_hash_sha512.h>
#include <crypto_scalarmult_curve25519.h>
#include <crypto_verify_16.h>
#include <crypto_verify_32.h>
#include <randombytes.h>
#endif

#ifndef crypto_box_MACBYTES
#define crypto_box_MACBYTES (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#endif

//!TOKSTYLE-
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include "../testing/fuzzing/fuzz_adapter.h"
#endif
//!TOKSTYLE+

static_assert(CRYPTO_PUBLIC_KEY_SIZE == crypto_box_PUBLICKEYBYTES,
              "CRYPTO_PUBLIC_KEY_SIZE should be equal to crypto_box_PUBLICKEYBYTES");
static_assert(CRYPTO_SECRET_KEY_SIZE == crypto_box_SECRETKEYBYTES,
              "CRYPTO_SECRET_KEY_SIZE should be equal to crypto_box_SECRETKEYBYTES");
static_assert(CRYPTO_SHARED_KEY_SIZE == crypto_box_BEFORENMBYTES,
              "CRYPTO_SHARED_KEY_SIZE should be equal to crypto_box_BEFORENMBYTES");
static_assert(CRYPTO_SYMMETRIC_KEY_SIZE == crypto_box_BEFORENMBYTES,
              "CRYPTO_SYMMETRIC_KEY_SIZE should be equal to crypto_box_BEFORENMBYTES");
static_assert(CRYPTO_MAC_SIZE == crypto_box_MACBYTES,
              "CRYPTO_MAC_SIZE should be equal to crypto_box_MACBYTES");
static_assert(CRYPTO_NONCE_SIZE == crypto_box_NONCEBYTES,
              "CRYPTO_NONCE_SIZE should be equal to crypto_box_NONCEBYTES");
static_assert(CRYPTO_SHA256_SIZE == crypto_hash_sha256_BYTES,
              "CRYPTO_SHA256_SIZE should be equal to crypto_hash_sha256_BYTES");
static_assert(CRYPTO_SHA512_SIZE == crypto_hash_sha512_BYTES,
              "CRYPTO_SHA512_SIZE should be equal to crypto_hash_sha512_BYTES");
static_assert(CRYPTO_PUBLIC_KEY_SIZE == 32,
              "CRYPTO_PUBLIC_KEY_SIZE is required to be 32 bytes for public_key_cmp to work");

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static uint8_t *crypto_malloc(size_t bytes)
{
    uint8_t *ptr = (uint8_t *)malloc(bytes);

    if (ptr != nullptr) {
        crypto_memlock(ptr, bytes);
    }

    return ptr;
}

static void crypto_free(uint8_t *ptr, size_t bytes)
{
    if (ptr != nullptr) {
        crypto_memzero(ptr, bytes);
        crypto_memunlock(ptr, bytes);
    }

    free(ptr);
}
#endif  // !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)

void crypto_memzero(void *data, size_t length)
{
#ifndef VANILLA_NACL
    sodium_memzero(data, length);
#else
    memset(data, 0, length);
#endif
}

bool crypto_memlock(void *data, size_t length)
{
#ifndef VANILLA_NACL

    if (sodium_mlock(data, length) != 0) {
        return false;
    }

    return true;
#else
    return false;
#endif
}

bool crypto_memunlock(void *data, size_t length)
{
#ifndef VANILLA_NACL

    if (sodium_munlock(data, length) != 0) {
        return false;
    }

    return true;
#else
    return false;
#endif
}

int32_t public_key_cmp(const uint8_t *pk1, const uint8_t *pk2)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Hope that this is better for the fuzzer
    return memcmp(pk1, pk2, CRYPTO_PUBLIC_KEY_SIZE) == 0 ? 0 : -1;
#else
    return crypto_verify_32(pk1, pk2);
#endif
}

int32_t crypto_sha512_cmp(const uint8_t *cksum1, const uint8_t *cksum2)
{
#ifndef VANILLA_NACL
    return crypto_verify_64(cksum1, cksum2);
#else
    return crypto_verify_32(cksum1, cksum2) && crypto_verify_32(cksum1 + 8, cksum2 + 8);
#endif
}

uint8_t random_u08(void)
{
    uint8_t randnum;
    random_bytes(&randnum, 1);
    return randnum;
}

uint16_t random_u16(void)
{
    uint16_t randnum;
    random_bytes((uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint32_t random_u32(void)
{
    uint32_t randnum;
    random_bytes((uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint64_t random_u64(void)
{
    uint64_t randnum;
    random_bytes((uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint32_t random_range_u32(uint32_t upper_bound)
{
#ifdef VANILLA_NACL
    return random_u32() % upper_bound;
#else
    return randombytes_uniform(upper_bound);
#endif  // VANILLA_NACL
}

bool public_key_valid(const uint8_t *public_key)
{
    if (public_key[31] >= 128) { /* Last bit of key is always zero. */
        return 0;
    }

    return 1;
}

int32_t encrypt_precompute(const uint8_t *public_key, const uint8_t *secret_key,
                           uint8_t *shared_key)
{
    return crypto_box_beforenm(shared_key, public_key, secret_key);
}

int32_t encrypt_data_symmetric(const uint8_t *secret_key, const uint8_t *nonce,
                               const uint8_t *plain, size_t length, uint8_t *encrypted)
{
    if (length == 0 || !secret_key || !nonce || !plain || !encrypted) {
        return -1;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Don't encrypt anything.
    memcpy(encrypted, plain, length);
    // Zero MAC to avoid uninitialized memory reads.
    memset(encrypted + length, 0, crypto_box_MACBYTES);
#else

    const size_t size_temp_plain = length + crypto_box_ZEROBYTES;
    const size_t size_temp_encrypted = length + crypto_box_MACBYTES + crypto_box_BOXZEROBYTES;

    uint8_t *temp_plain = crypto_malloc(size_temp_plain);
    uint8_t *temp_encrypted = crypto_malloc(size_temp_encrypted);

    if (temp_plain == nullptr || temp_encrypted == nullptr) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // crypto_box_afternm requires the entire range of the output array be
    // initialised with something. It doesn't matter what it's initialised with,
    // so we'll pick 0x00.
    memset(temp_encrypted, 0, size_temp_encrypted);

    memset(temp_plain, 0, crypto_box_ZEROBYTES);
    // Pad the message with 32 0 bytes.
    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

    if (crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce,
                           secret_key) != 0) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // Unpad the encrypted message.
    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);

    crypto_free(temp_plain, size_temp_plain);
    crypto_free(temp_encrypted, size_temp_encrypted);
#endif
    return length + crypto_box_MACBYTES;
}

int32_t decrypt_data_symmetric(const uint8_t *secret_key, const uint8_t *nonce,
                               const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (length <= crypto_box_BOXZEROBYTES || !secret_key || !nonce || !encrypted || !plain) {
        return -1;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    assert(length >= crypto_box_MACBYTES);
    memcpy(plain, encrypted, length - crypto_box_MACBYTES);  // Don't encrypt anything
#else

    const size_t size_temp_plain = length + crypto_box_ZEROBYTES;
    const size_t size_temp_encrypted = length + crypto_box_BOXZEROBYTES;

    uint8_t *temp_plain = crypto_malloc(size_temp_plain);
    uint8_t *temp_encrypted = crypto_malloc(size_temp_encrypted);

    if (temp_plain == nullptr || temp_encrypted == nullptr) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // crypto_box_open_afternm requires the entire range of the output array be
    // initialised with something. It doesn't matter what it's initialised with,
    // so we'll pick 0x00.
    memset(temp_plain, 0, size_temp_plain);

    memset(temp_encrypted, 0, crypto_box_BOXZEROBYTES);
    // Pad the message with 16 0 bytes.
    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);

    if (crypto_box_open_afternm(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES, nonce,
                                secret_key) != 0) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_MACBYTES);

    crypto_free(temp_plain, size_temp_plain);
    crypto_free(temp_encrypted, size_temp_encrypted);
#endif
    return length - crypto_box_MACBYTES;
}

int32_t encrypt_data(const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *nonce,
                     const uint8_t *plain, size_t length, uint8_t *encrypted)
{
    if (!public_key || !secret_key) {
        return -1;
    }

    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    int ret = encrypt_data_symmetric(k, nonce, plain, length, encrypted);
    crypto_memzero(k, sizeof(k));
    return ret;
}

int32_t decrypt_data(const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *nonce,
                     const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (!public_key || !secret_key) {
        return -1;
    }

    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    int ret = decrypt_data_symmetric(k, nonce, encrypted, length, plain);
    crypto_memzero(k, sizeof(k));
    return ret;
}

void increment_nonce(uint8_t *nonce)
{
    /* TODO(irungentoo): use `increment_nonce_number(nonce, 1)` or
     * sodium_increment (change to little endian).
     *
     * NOTE don't use breaks inside this loop.
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    uint_fast16_t carry = 1U;

    for (uint32_t i = crypto_box_NONCEBYTES; i != 0; --i) {
        carry += (uint_fast16_t)nonce[i - 1];
        nonce[i - 1] = (uint8_t)carry;
        carry >>= 8;
    }
}

void increment_nonce_number(uint8_t *nonce, uint32_t increment)
{
    /* NOTE don't use breaks inside this loop
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    uint8_t num_as_nonce[crypto_box_NONCEBYTES] = {0};
    num_as_nonce[crypto_box_NONCEBYTES - 4] = increment >> 24;
    num_as_nonce[crypto_box_NONCEBYTES - 3] = increment >> 16;
    num_as_nonce[crypto_box_NONCEBYTES - 2] = increment >> 8;
    num_as_nonce[crypto_box_NONCEBYTES - 1] = increment;

    uint_fast16_t carry = 0U;

    for (uint32_t i = crypto_box_NONCEBYTES; i != 0; --i) {
        carry += (uint_fast16_t)nonce[i - 1] + (uint_fast16_t)num_as_nonce[i - 1];
        nonce[i - 1] = (uint8_t)carry;
        carry >>= 8;
    }
}

void random_nonce(uint8_t *nonce)
{
    random_bytes(nonce, crypto_box_NONCEBYTES);
}

void new_symmetric_key(uint8_t *key)
{
    random_bytes(key, CRYPTO_SYMMETRIC_KEY_SIZE);
}

int32_t crypto_new_keypair(uint8_t *public_key, uint8_t *secret_key)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    random_bytes(secret_key, CRYPTO_SECRET_KEY_SIZE);
    memset(public_key, 0, CRYPTO_PUBLIC_KEY_SIZE);  // Make MSAN happy
    crypto_scalarmult_curve25519_base(public_key, secret_key);
    return 0;
#else
    return crypto_box_keypair(public_key, secret_key);
#endif
}

void crypto_derive_public_key(uint8_t *public_key, const uint8_t *secret_key)
{
    crypto_scalarmult_curve25519_base(public_key, secret_key);
}

void crypto_sha256(uint8_t *hash, const uint8_t *data, size_t length)
{
    crypto_hash_sha256(hash, data, length);
}

void crypto_sha512(uint8_t *hash, const uint8_t *data, size_t length)
{
    crypto_hash_sha512(hash, data, length);
}

void random_bytes(uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    fuzz_random_bytes(data, length);
#else
    randombytes(data, length);
#endif
}
