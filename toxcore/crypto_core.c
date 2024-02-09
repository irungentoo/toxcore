/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "crypto_core.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "attributes.h"
#include "ccompat.h"
#include "util.h"

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
static_assert(CRYPTO_HMAC_SIZE == crypto_auth_BYTES,
              "CRYPTO_HMAC_SIZE should be equal to crypto_auth_BYTES");
static_assert(CRYPTO_HMAC_KEY_SIZE == crypto_auth_KEYBYTES,
              "CRYPTO_HMAC_KEY_SIZE should be equal to crypto_auth_KEYBYTES");
static_assert(CRYPTO_SHA256_SIZE == crypto_hash_sha256_BYTES,
              "CRYPTO_SHA256_SIZE should be equal to crypto_hash_sha256_BYTES");
static_assert(CRYPTO_SHA512_SIZE == crypto_hash_sha512_BYTES,
              "CRYPTO_SHA512_SIZE should be equal to crypto_hash_sha512_BYTES");
static_assert(CRYPTO_PUBLIC_KEY_SIZE == 32,
              "CRYPTO_PUBLIC_KEY_SIZE is required to be 32 bytes for pk_equal to work");

static_assert(CRYPTO_SIGNATURE_SIZE == crypto_sign_BYTES,
              "CRYPTO_SIGNATURE_SIZE should be equal to crypto_sign_BYTES");
static_assert(CRYPTO_SIGN_PUBLIC_KEY_SIZE == crypto_sign_PUBLICKEYBYTES,
              "CRYPTO_SIGN_PUBLIC_KEY_SIZE should be equal to crypto_sign_PUBLICKEYBYTES");
static_assert(CRYPTO_SIGN_SECRET_KEY_SIZE == crypto_sign_SECRETKEYBYTES,
              "CRYPTO_SIGN_SECRET_KEY_SIZE should be equal to crypto_sign_SECRETKEYBYTES");

bool create_extended_keypair(Extended_Public_Key *pk, Extended_Secret_Key *sk, const Random *rng)
{
    /* create signature key pair */
    uint8_t seed[crypto_sign_SEEDBYTES];
    random_bytes(rng, seed, crypto_sign_SEEDBYTES);
    crypto_sign_seed_keypair(pk->sig, sk->sig, seed);
    crypto_memzero(seed, crypto_sign_SEEDBYTES);

    /* convert public signature key to public encryption key */
    const int res1 = crypto_sign_ed25519_pk_to_curve25519(pk->enc, pk->sig);

    /* convert secret signature key to secret encryption key */
    const int res2 = crypto_sign_ed25519_sk_to_curve25519(sk->enc, sk->sig);

    return res1 == 0 && res2 == 0;
}

const uint8_t *get_enc_key(const Extended_Public_Key *key)
{
    return key->enc;
}

const uint8_t *get_sig_pk(const Extended_Public_Key *key)
{
    return key->sig;
}

void set_sig_pk(Extended_Public_Key *key, const uint8_t *sig_pk)
{
    memcpy(key->sig, sig_pk, SIG_PUBLIC_KEY_SIZE);
}

const uint8_t *get_sig_sk(const Extended_Secret_Key *key)
{
    return key->sig;
}

const uint8_t *get_chat_id(const Extended_Public_Key *key)
{
    return key->sig;
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
static uint8_t *crypto_malloc(size_t bytes)
{
    uint8_t *ptr = (uint8_t *)malloc(bytes);

    if (ptr != nullptr) {
        crypto_memlock(ptr, bytes);
    }

    return ptr;
}

nullable(1)
static void crypto_free(uint8_t *ptr, size_t bytes)
{
    if (ptr != nullptr) {
        crypto_memzero(ptr, bytes);
        crypto_memunlock(ptr, bytes);
    }

    free(ptr);
}
#endif /* !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) */

void crypto_memzero(void *data, size_t length)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    memzero((uint8_t *)data, length);
#else
    sodium_memzero(data, length);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_memlock(void *data, size_t length)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return false;
#else

    return sodium_mlock(data, length) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_memunlock(void *data, size_t length)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return false;
#else

    return sodium_munlock(data, length) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool pk_equal(const uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE])
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Hope that this is better for the fuzzer
    return memcmp(pk1, pk2, CRYPTO_PUBLIC_KEY_SIZE) == 0;
#else
    return crypto_verify_32(pk1, pk2) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

void pk_copy(uint8_t dest[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t src[CRYPTO_PUBLIC_KEY_SIZE])
{
    memcpy(dest, src, CRYPTO_PUBLIC_KEY_SIZE);
}

bool crypto_sha512_eq(const uint8_t cksum1[CRYPTO_SHA512_SIZE], const uint8_t cksum2[CRYPTO_SHA512_SIZE])
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Hope that this is better for the fuzzer
    return memcmp(cksum1, cksum2, CRYPTO_SHA512_SIZE) == 0;
#else
    return crypto_verify_64(cksum1, cksum2) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_sha256_eq(const uint8_t cksum1[CRYPTO_SHA256_SIZE], const uint8_t cksum2[CRYPTO_SHA256_SIZE])
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Hope that this is better for the fuzzer
    return memcmp(cksum1, cksum2, CRYPTO_SHA256_SIZE) == 0;
#else
    return crypto_verify_32(cksum1, cksum2) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

uint8_t random_u08(const Random *rng)
{
    uint8_t randnum;
    random_bytes(rng, &randnum, 1);
    return randnum;
}

uint16_t random_u16(const Random *rng)
{
    uint16_t randnum;
    random_bytes(rng, (uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint32_t random_u32(const Random *rng)
{
    uint32_t randnum;
    random_bytes(rng, (uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint64_t random_u64(const Random *rng)
{
    uint64_t randnum;
    random_bytes(rng, (uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint32_t random_range_u32(const Random *rng, uint32_t upper_bound)
{
    return rng->funcs->random_uniform(rng->obj, upper_bound);
}

bool crypto_signature_create(uint8_t signature[CRYPTO_SIGNATURE_SIZE],
                             const uint8_t *message, uint64_t message_length,
                             const uint8_t secret_key[SIG_SECRET_KEY_SIZE])
{
    return crypto_sign_detached(signature, nullptr, message, message_length, secret_key) == 0;
}

bool crypto_signature_verify(const uint8_t signature[CRYPTO_SIGNATURE_SIZE],
                             const uint8_t *message, uint64_t message_length,
                             const uint8_t public_key[SIG_PUBLIC_KEY_SIZE])
{
    return crypto_sign_verify_detached(signature, message, message_length, public_key) == 0;
}

bool public_key_valid(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    /* Last bit of key is always zero. */
    return public_key[31] < 128;
}

int32_t encrypt_precompute(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                           const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                           uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE])
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memcpy(shared_key, public_key, CRYPTO_SHARED_KEY_SIZE);
    return 0;
#else
    return crypto_box_beforenm(shared_key, public_key, secret_key);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

int32_t encrypt_data_symmetric(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                               const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               const uint8_t *plain, size_t length, uint8_t *encrypted)
{
    if (length == 0 || shared_key == nullptr || nonce == nullptr || plain == nullptr || encrypted == nullptr) {
        return -1;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Don't encrypt anything.
    memcpy(encrypted, plain, length);
    // Zero MAC to avoid uninitialized memory reads.
    memzero(encrypted + length, crypto_box_MACBYTES);
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
    memzero(temp_encrypted, size_temp_encrypted);

    memzero(temp_plain, crypto_box_ZEROBYTES);
    // Pad the message with 32 0 bytes.
    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

    if (crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce,
                           shared_key) != 0) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // Unpad the encrypted message.
    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);

    crypto_free(temp_plain, size_temp_plain);
    crypto_free(temp_encrypted, size_temp_encrypted);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    assert(length < INT32_MAX - crypto_box_MACBYTES);
    return (int32_t)(length + crypto_box_MACBYTES);
}

int32_t decrypt_data_symmetric(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                               const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (length <= crypto_box_BOXZEROBYTES || shared_key == nullptr || nonce == nullptr || encrypted == nullptr
            || plain == nullptr) {
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
    memzero(temp_plain, size_temp_plain);

    memzero(temp_encrypted, crypto_box_BOXZEROBYTES);
    // Pad the message with 16 0 bytes.
    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);

    if (crypto_box_open_afternm(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES, nonce,
                                shared_key) != 0) {
        crypto_free(temp_plain, size_temp_plain);
        crypto_free(temp_encrypted, size_temp_encrypted);
        return -1;
    }

    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_MACBYTES);

    crypto_free(temp_plain, size_temp_plain);
    crypto_free(temp_encrypted, size_temp_encrypted);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    assert(length > crypto_box_MACBYTES);
    assert(length < INT32_MAX);
    return (int32_t)(length - crypto_box_MACBYTES);
}

int32_t encrypt_data(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                     const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     const uint8_t *plain, size_t length, uint8_t *encrypted)
{
    if (public_key == nullptr || secret_key == nullptr) {
        return -1;
    }

    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    const int ret = encrypt_data_symmetric(k, nonce, plain, length, encrypted);
    crypto_memzero(k, sizeof(k));
    return ret;
}

int32_t decrypt_data(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                     const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (public_key == nullptr || secret_key == nullptr) {
        return -1;
    }

    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    const int ret = decrypt_data_symmetric(k, nonce, encrypted, length, plain);
    crypto_memzero(k, sizeof(k));
    return ret;
}

void increment_nonce(uint8_t nonce[CRYPTO_NONCE_SIZE])
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

void increment_nonce_number(uint8_t nonce[CRYPTO_NONCE_SIZE], uint32_t increment)
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

void random_nonce(const Random *rng, uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    random_bytes(rng, nonce, crypto_box_NONCEBYTES);
}

void new_symmetric_key(const Random *rng, uint8_t key[CRYPTO_SYMMETRIC_KEY_SIZE])
{
    random_bytes(rng, key, CRYPTO_SYMMETRIC_KEY_SIZE);
}

int32_t crypto_new_keypair(const Random *rng,
                           uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                           uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE])
{
    random_bytes(rng, secret_key, CRYPTO_SECRET_KEY_SIZE);
    memzero(public_key, CRYPTO_PUBLIC_KEY_SIZE);  // Make MSAN happy
    crypto_derive_public_key(public_key, secret_key);
    return 0;
}

void crypto_derive_public_key(uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                              const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE])
{
    crypto_scalarmult_curve25519_base(public_key, secret_key);
}

void new_hmac_key(const Random *rng, uint8_t key[CRYPTO_HMAC_KEY_SIZE])
{
    random_bytes(rng, key, CRYPTO_HMAC_KEY_SIZE);
}

void crypto_hmac(uint8_t auth[CRYPTO_HMAC_SIZE], const uint8_t key[CRYPTO_HMAC_KEY_SIZE],
                 const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memcpy(auth, key, 16);
    memcpy(auth + 16, data, length < 16 ? length : 16);
#else
    crypto_auth(auth, data, length, key);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_hmac_verify(const uint8_t auth[CRYPTO_HMAC_SIZE], const uint8_t key[CRYPTO_HMAC_KEY_SIZE],
                        const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return memcmp(auth, key, 16) == 0 && memcmp(auth + 16, data, length < 16 ? length : 16) == 0;
#else
    return crypto_auth_verify(auth, data, length, key) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

void crypto_sha256(uint8_t hash[CRYPTO_SHA256_SIZE], const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memzero(hash, CRYPTO_SHA256_SIZE);
    memcpy(hash, data, length < CRYPTO_SHA256_SIZE ? length : CRYPTO_SHA256_SIZE);
#else
    crypto_hash_sha256(hash, data, length);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

void crypto_sha512(uint8_t hash[CRYPTO_SHA512_SIZE], const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memzero(hash, CRYPTO_SHA512_SIZE);
    memcpy(hash, data, length < CRYPTO_SHA512_SIZE ? length : CRYPTO_SHA512_SIZE);
#else
    crypto_hash_sha512(hash, data, length);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

non_null()
static void sys_random_bytes(void *obj, uint8_t *bytes, size_t length)
{
    randombytes(bytes, length);
}

non_null()
static uint32_t sys_random_uniform(void *obj, uint32_t upper_bound)
{
    return randombytes_uniform(upper_bound);
}

static const Random_Funcs os_random_funcs = {
    sys_random_bytes,
    sys_random_uniform,
};

static const Random os_random_obj = {&os_random_funcs};

const Random *os_random(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    // It is safe to call this function more than once and from different
    // threads -- subsequent calls won't have any effects.
    if (sodium_init() == -1) {
        return nullptr;
    }
    return &os_random_obj;
}

void random_bytes(const Random *rng, uint8_t *bytes, size_t length)
{
    rng->funcs->random_bytes(rng->obj, bytes, length);
}
