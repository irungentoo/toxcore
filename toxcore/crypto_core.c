/* net_crypto.c
 *
 * Functions for the core crypto.
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "crypto_core.h"

/* Use this instead of memcmp; not vulnerable to timing attacks. */
uint8_t crypto_iszero(uint8_t *mem, uint32_t length)
{
    uint8_t check = 0;
    uint32_t i;

    for (i = 0; i < length; ++i) {
        check |= mem[i];
    }

    return check; // We return zero if mem is made out of zeroes.
}

/* Precomputes the shared key from their public_key and our secret_key.
 * This way we can avoid an expensive elliptic curve scalar multiply for each
 * encrypt/decrypt operation.
 * enc_key has to be crypto_box_BEFORENMBYTES bytes long.
 */
void encrypt_precompute(uint8_t *public_key, uint8_t *secret_key, uint8_t *enc_key)
{
    crypto_box_beforenm(enc_key, public_key, secret_key);
}

int encrypt_data_symmetric(uint8_t *secret_key, uint8_t *nonce, uint8_t *plain, uint32_t length, uint8_t *encrypted)
{
    if (length == 0)
        return -1;

    uint8_t temp_plain[length + crypto_box_ZEROBYTES];
    uint8_t temp_encrypted[length + crypto_box_MACBYTES + crypto_box_BOXZEROBYTES];

    memset(temp_plain, 0, crypto_box_ZEROBYTES);
    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length); // Pad the message with 32 0 bytes.

    if (crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce, secret_key) != 0)
        return -1;

    /* Unpad the encrypted message. */
    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);
    return length + crypto_box_MACBYTES;
}

int decrypt_data_symmetric(uint8_t *secret_key, uint8_t *nonce, uint8_t *encrypted, uint32_t length, uint8_t *plain)
{
    if (length <= crypto_box_BOXZEROBYTES)
        return -1;

    uint8_t temp_plain[length + crypto_box_ZEROBYTES];
    uint8_t temp_encrypted[length + crypto_box_BOXZEROBYTES];

    memset(temp_plain, 0, crypto_box_BOXZEROBYTES);
    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length); // Pad the message with 16 0 bytes.

    if (crypto_box_open_afternm(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES, nonce, secret_key) != 0)
        return -1;

    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_MACBYTES);
    return length - crypto_box_MACBYTES;
}

int encrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce,
                 uint8_t *plain, uint32_t length, uint8_t *encrypted)
{
    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    return encrypt_data_symmetric(k, nonce, plain, length, encrypted);
}

int decrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce,
                 uint8_t *encrypted, uint32_t length, uint8_t *plain)
{
    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    return decrypt_data_symmetric(k, nonce, encrypted, length, plain);
}


/* Increment the given nonce by 1. */
void increment_nonce(uint8_t *nonce)
{
    uint32_t i;

    for (i = crypto_box_NONCEBYTES; i != 0; --i) {
        ++nonce[i - 1];

        if (nonce[i - 1] != 0)
            break;
    }
}
/* increment the given nonce by num */
void increment_nonce_number(uint8_t *nonce, uint32_t num)
{
    uint32_t num1, num2;
    memcpy(&num1, nonce + (crypto_box_NONCEBYTES - sizeof(num1)), sizeof(num1));
    num1 = ntohl(num1);
    num2 = num + num1;

    if (num2 < num1) {
        uint32_t i;

        for (i = crypto_box_NONCEBYTES - sizeof(num1); i != 0; --i) {
            ++nonce[i - 1];

            if (nonce[i - 1] != 0)
                break;
        }
    }

    num2 = htonl(num2);
    memcpy(nonce + (crypto_box_NONCEBYTES - sizeof(num2)), &num2, sizeof(num2));
}

/* Fill the given nonce with random bytes. */
void random_nonce(uint8_t *nonce)
{
    randombytes(nonce, crypto_box_NONCEBYTES);
}

/* Fill a key crypto_box_KEYBYTES big with random bytes */
void new_symmetric_key(uint8_t *key)
{
    randombytes(key, crypto_box_KEYBYTES);
}

static uint8_t base_nonce[crypto_box_NONCEBYTES];
static uint8_t nonce_set = 0;

/* Gives a nonce guaranteed to be different from previous ones.*/
void new_nonce(uint8_t *nonce)
{
    if (nonce_set == 0) {
        random_nonce(base_nonce);
        nonce_set = 1;
    }

    increment_nonce(base_nonce);
    memcpy(nonce, base_nonce, crypto_box_NONCEBYTES);
}