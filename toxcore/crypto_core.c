/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Functions for the core crypto.
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "crypto_core.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"

#ifndef VANILLA_NACL
/* We use libsodium by default. */
#include <sodium.h>
#else
#include <crypto_box.h>
#include <crypto_hash_sha256.h>
#include <crypto_hash_sha512.h>
#include <crypto_scalarmult_curve25519.h>
#include <crypto_verify_16.h>
#include <crypto_verify_32.h>
#include <randombytes.h>
#define crypto_box_MACBYTES (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#endif

#if CRYPTO_PUBLIC_KEY_SIZE != crypto_box_PUBLICKEYBYTES
#error "CRYPTO_PUBLIC_KEY_SIZE should be equal to crypto_box_PUBLICKEYBYTES"
#endif

#if CRYPTO_SECRET_KEY_SIZE != crypto_box_SECRETKEYBYTES
#error "CRYPTO_SECRET_KEY_SIZE should be equal to crypto_box_SECRETKEYBYTES"
#endif

#if CRYPTO_SHARED_KEY_SIZE != crypto_box_BEFORENMBYTES
#error "CRYPTO_SHARED_KEY_SIZE should be equal to crypto_box_BEFORENMBYTES"
#endif

#if CRYPTO_SYMMETRIC_KEY_SIZE != crypto_box_BEFORENMBYTES
#error "CRYPTO_SYMMETRIC_KEY_SIZE should be equal to crypto_box_BEFORENMBYTES"
#endif

#if CRYPTO_MAC_SIZE != crypto_box_MACBYTES
#error "CRYPTO_MAC_SIZE should be equal to crypto_box_MACBYTES"
#endif

#if CRYPTO_NONCE_SIZE != crypto_box_NONCEBYTES
#error "CRYPTO_NONCE_SIZE should be equal to crypto_box_NONCEBYTES"
#endif

#if CRYPTO_SHA256_SIZE != crypto_hash_sha256_BYTES
#error "CRYPTO_SHA256_SIZE should be equal to crypto_hash_sha256_BYTES"
#endif

#if CRYPTO_SHA512_SIZE != crypto_hash_sha512_BYTES
#error "CRYPTO_SHA512_SIZE should be equal to crypto_hash_sha512_BYTES"
#endif

#if CRYPTO_PUBLIC_KEY_SIZE != 32
#error "CRYPTO_PUBLIC_KEY_SIZE is required to be 32 bytes for public_key_cmp to work,"
#endif

static uint8_t *crypto_malloc(size_t bytes)
{
    return (uint8_t *)malloc(bytes);
}

static void crypto_free(uint8_t *ptr, size_t bytes)
{
    if (ptr != nullptr) {
        crypto_memzero(ptr, bytes);
    }

    free(ptr);
}

int32_t public_key_cmp(const uint8_t *pk1, const uint8_t *pk2)
{
    return crypto_verify_32(pk1, pk2);
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

bool public_key_valid(const uint8_t *public_key)
{
    if (public_key[31] >= 128) { /* Last bit of key is always zero. */
        return 0;
    }

    return 1;
}

/* Precomputes the shared key from their public_key and our secret_key.
 * This way we can avoid an expensive elliptic curve scalar multiply for each
 * encrypt/decrypt operation.
 * shared_key has to be crypto_box_BEFORENMBYTES bytes long.
 */
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

    const size_t size_temp_plain = length + crypto_box_ZEROBYTES;
    const size_t size_temp_encrypted = length + crypto_box_MACBYTES + crypto_box_BOXZEROBYTES;

    uint8_t *temp_plain = crypto_malloc(size_temp_plain);
    uint8_t *temp_encrypted = crypto_malloc(size_temp_encrypted);

    if (temp_plain == nullptr || temp_encrypted == nullptr) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

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

    return length + crypto_box_MACBYTES;
}

int32_t decrypt_data_symmetric(const uint8_t *secret_key, const uint8_t *nonce,
                               const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (length <= crypto_box_BOXZEROBYTES || !secret_key || !nonce || !encrypted || !plain) {
        return -1;
    }

    const size_t size_temp_plain = length + crypto_box_ZEROBYTES;
    const size_t size_temp_encrypted = length + crypto_box_BOXZEROBYTES;

    uint8_t *temp_plain = crypto_malloc(size_temp_plain);
    uint8_t *temp_encrypted = crypto_malloc(size_temp_encrypted);

    if (temp_plain == nullptr || temp_encrypted == nullptr) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

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

/* Increment the given nonce by 1. */
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
    uint32_t i = crypto_box_NONCEBYTES;
    uint_fast16_t carry = 1U;

    for (; i != 0; --i) {
        carry += (uint_fast16_t)nonce[i - 1];
        nonce[i - 1] = (uint8_t)carry;
        carry >>= 8;
    }
}

static uint32_t host_to_network(uint32_t x)
{
#if !defined(BYTE_ORDER) || BYTE_ORDER == LITTLE_ENDIAN
    return ((x >> 24) & 0x000000FF) |  // move byte 3 to byte 0
           ((x >> 8) & 0x0000FF00) |   // move byte 2 to byte 1
           ((x << 8) & 0x00FF0000) |   // move byte 1 to byte 2
           ((x << 24) & 0xFF000000);   // move byte 0 to byte 3
#else
    return x;
#endif
}

/* increment the given nonce by num */
void increment_nonce_number(uint8_t *nonce, uint32_t host_order_num)
{
    /* NOTE don't use breaks inside this loop
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    const uint32_t big_endian_num = host_to_network(host_order_num);
    const uint8_t *const num_vec = (const uint8_t *)&big_endian_num;
    uint8_t num_as_nonce[crypto_box_NONCEBYTES] = {0};
    num_as_nonce[crypto_box_NONCEBYTES - 4] = num_vec[0];
    num_as_nonce[crypto_box_NONCEBYTES - 3] = num_vec[1];
    num_as_nonce[crypto_box_NONCEBYTES - 2] = num_vec[2];
    num_as_nonce[crypto_box_NONCEBYTES - 1] = num_vec[3];

    uint32_t i = crypto_box_NONCEBYTES;
    uint_fast16_t carry = 0U;

    for (; i != 0; --i) {
        carry += (uint_fast16_t)nonce[i - 1] + (uint_fast16_t)num_as_nonce[i - 1];
        nonce[i - 1] = (uint8_t)carry;
        carry >>= 8;
    }
}

/* Fill the given nonce with random bytes. */
void random_nonce(uint8_t *nonce)
{
    random_bytes(nonce, crypto_box_NONCEBYTES);
}

/* Fill a key CRYPTO_SYMMETRIC_KEY_SIZE big with random bytes */
void new_symmetric_key(uint8_t *key)
{
    random_bytes(key, CRYPTO_SYMMETRIC_KEY_SIZE);
}

int32_t crypto_new_keypair(uint8_t *public_key, uint8_t *secret_key)
{
    return crypto_box_keypair(public_key, secret_key);
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
    randombytes(data, length);
}
