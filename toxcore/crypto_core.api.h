%{
/* crypto_core.h
 *
 * Functions for the core crypto.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef CORE_CRYPTO_H
#define CORE_CRYPTO_H

#include "network.h"
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
 * The number of bytes in a shared key computed from public and secret key.
 */
const CRYPTO_SHARED_KEY_SIZE = 32;

/**
 * The number of bytes in a random symmetric key.
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

static int32_t crypto_memcmp(const void *p1, const void *p2, size_t length);
static void crypto_memzero(void *data, size_t length);

static void crypto_sha256(uint8_t *hash, const uint8_t[length] data);
static void crypto_sha512(uint8_t *hash, const uint8_t[length] data);

static void crypto_derive_public_key(uint8_t *public_key, uint8_t *secret_key);

/**
 * compare 2 public keys of length CRYPTO_PUBLIC_KEY_SIZE, not vulnerable to timing attacks.
 * returns 0 if both mem locations of length are equal,
 * return -1 if they are not.
 */
static int32_t public_key_cmp(const uint8_t *pk1, const uint8_t *pk2);

/**
 * Return a random 32 bit integer.
 */
static uint32_t random_int();

/**
 * Return a random 64 bit integer.
 */
static uint64_t random_64b();

/**
 * Check if a Tox public key CRYPTO_PUBLIC_KEY_SIZE is valid or not.
 * This should only be used for input validation.
 *
 * return 0 if it isn't.
 * return 1 if it is.
 */
static int32_t public_key_valid(const uint8_t *public_key);

static int32_t crypto_new_keypair(uint8_t *public_key, uint8_t *secret_key);

/**
 * Encrypts plain of length length to encrypted of length + 16 using the
 * public key(32 bytes) of the receiver and the secret key of the sender and a 24 byte nonce.
 *
 *  return -1 if there was a problem.
 *  return length of encrypted data if everything was fine.
 */
static int32_t encrypt_data(
    const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *nonce,
    const uint8_t *plain, uint32_t length, uint8_t *encrypted);


/**
 * Decrypts encrypted of length length to plain of length length - 16 using the
 * public key(32 bytes) of the sender, the secret key of the receiver and a 24 byte nonce.
 *
 *  return -1 if there was a problem (decryption failed).
 *  return length of plain data if everything was fine.
 */
static int32_t decrypt_data(
    const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *nonce,
    const uint8_t *encrypted, uint32_t length, uint8_t *plain);

/**
 * Fast encrypt/decrypt operations. Use if this is not a one-time communication.
 * encrypt_precompute does the shared-key generation once so it does not have
 * to be preformed on every encrypt/decrypt.
 */
static int32_t encrypt_precompute(
    const uint8_t *public_key, const uint8_t *secret_key, uint8_t *enc_key);

/**
 * Encrypts plain of length length to encrypted of length + 16 using a
 * secret key CRYPTO_SYMMETRIC_KEY_SIZE big and a 24 byte nonce.
 *
 *  return -1 if there was a problem.
 *  return length of encrypted data if everything was fine.
 */
static int32_t encrypt_data_symmetric(
    const uint8_t *secret_key, const uint8_t *nonce, const uint8_t *plain,
    uint32_t length, uint8_t *encrypted);

/**
 * Decrypts encrypted of length length to plain of length length - 16 using a
 * secret key CRYPTO_SYMMETRIC_KEY_SIZE big and a 24 byte nonce.
 *
 *  return -1 if there was a problem (decryption failed).
 *  return length of plain data if everything was fine.
 */
static int32_t decrypt_data_symmetric(
    const uint8_t *secret_key, const uint8_t *nonce, const uint8_t *encrypted,
    uint32_t length, uint8_t *plain);

/**
 * Increment the given nonce by 1.
 */
static void increment_nonce(uint8_t *nonce);

/**
 * Increment the given nonce by num.
 */
static void increment_nonce_number(uint8_t *nonce, uint32_t host_order_num);

/**
 * Fill the given nonce with random bytes.
 */
static void random_nonce(uint8_t *nonce);

/**
 * Fill a key CRYPTO_SYMMETRIC_KEY_SIZE big with random bytes.
 */
static void new_symmetric_key(uint8_t *key);

/**
 * Fill an array of bytes with random values.
 */
static void random_bytes(uint8_t[length] bytes);

%{
#endif
%}
