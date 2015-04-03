/* toxencryptsave.c
 *
 * The Tox encrypted save functions.
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

#include "toxencryptsave.h"
#include "defines.h"
#include "../toxcore/crypto_core.h"
#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#ifdef VANILLA_NACL
#include "crypto_pwhash_scryptsalsa208sha256/crypto_pwhash_scryptsalsa208sha256.h"
#include "crypto_pwhash_scryptsalsa208sha256/utils.h" /* sodium_memzero */
#include <crypto_hash_sha256.h>
#endif

#if TOX_PASS_SALT_LENGTH != crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#error TOX_PASS_SALT_LENGTH is assumed to be equal to crypto_pwhash_scryptsalsa208sha256_SALTBYTES
#endif

#if TOX_PASS_KEY_LENGTH != crypto_box_KEYBYTES
#error TOX_PASS_KEY_LENGTH is assumed to be equal to crypto_box_KEYBYTES
#endif

#if TOX_PASS_ENCRYPTION_EXTRA_LENGTH != (crypto_box_MACBYTES + crypto_box_NONCEBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES + TOX_ENC_SAVE_MAGIC_LENGTH)
#error TOX_PASS_ENCRYPTION_EXTRA_LENGTH is assumed to be equal to (crypto_box_MACBYTES + crypto_box_NONCEBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES + TOX_ENC_SAVE_MAGIC_LENGTH)
#endif

/* Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */

/* This retrieves the salt used to encrypt the given data, which can then be passed to
 * derive_key_with_salt to produce the same key as was previously used. Any encrpyted
 * data with this module can be used as input.
 *
 * returns true if magic number matches
 * success does not say anything about the validity of the data, only that data of
 * the appropriate size was copied
 */
bool tox_get_salt(const uint8_t *data, uint8_t *salt)
{
    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0)
        return 0;

    data += TOX_ENC_SAVE_MAGIC_LENGTH;
    memcpy(salt, data, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    return 1;
}

/* Generates a secret symmetric key from the given passphrase. out_key must be at least
 * TOX_PASS_KEY_LENGTH bytes long.
 * Be sure to not compromise the key! Only keep it in memory, do not write to disk.
 * The password is zeroed after key derivation.
 * The key should only be used with the other functions in this module, as it
 * includes a salt.
 * Note that this function is not deterministic; to derive the same key from a
 * password, you also must know the random salt that was used. See below.
 *
 * returns true on success
 */
bool tox_derive_key_from_pass(uint8_t *passphrase, size_t pplength, TOX_PASS_KEY *out_key,
                              TOX_ERR_KEY_DERIVATION *error)
{
    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    randombytes(salt, sizeof salt);
    return tox_derive_key_with_salt(passphrase, pplength, salt, out_key, error);
}

/* Same as above, except with use the given salt for deterministic key derivation.
 * The salt must be TOX_PASS_SALT_LENGTH bytes in length.
 */
bool tox_derive_key_with_salt(uint8_t *passphrase, size_t pplength, uint8_t *salt, TOX_PASS_KEY *out_key,
                              TOX_ERR_KEY_DERIVATION *error)
{
    if (pplength == 0 || !passphrase || !salt || !out_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return 0;
    }

    uint8_t passkey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(passkey, passphrase, pplength);

    uint8_t key[crypto_box_KEYBYTES];

    /* Derive a key from the password */
    /* http://doc.libsodium.org/key_derivation/README.html */
    /* note that, according to the documentation, a generic pwhash interface will be created
     * once the pwhash competition (https://password-hashing.net/) is over */
    if (crypto_pwhash_scryptsalsa208sha256(
                key, sizeof(key), (char *)passkey, sizeof(passkey), salt,
                crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return 0;
    }

    sodium_memzero(passkey, crypto_hash_sha256_BYTES); /* wipe plaintext pw */
    memcpy(out_key->salt, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    memcpy(out_key->key, key, crypto_box_KEYBYTES);
    SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_OK);
    return 1;
}

/* Encrypt arbitrary with a key produced by tox_derive_key_*. The output
 * array must be at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long.
 * key must be TOX_PASS_KEY_LENGTH bytes.
 * If you already have a symmetric key from somewhere besides this module, simply
 * call encrypt_data_symmetric in toxcore/crypto_core directly.
 *
 * returns true on success
 */
bool tox_pass_key_encrypt(const uint8_t *data, size_t data_len, const TOX_PASS_KEY *key, uint8_t *out,
                          TOX_ERR_ENCRYPTION *error)
{
    if (data_len == 0 || !data || !key || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_NULL);
        return 0;
    }

    /* the output data consists of, in order:
     * salt, nonce, mac, enc_data
     * where the mac is automatically prepended by the encrypt()
     * the salt+nonce is called the prefix
     * I'm not sure what else I'm supposed to do with the salt and nonce, since we
     * need them to decrypt the data
     */

    /* first add the magic number */
    memcpy(out, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH);
    out += TOX_ENC_SAVE_MAGIC_LENGTH;

    /* then add the rest prefix */
    memcpy(out, key->salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    out += crypto_pwhash_scryptsalsa208sha256_SALTBYTES;

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    memcpy(out, nonce, crypto_box_NONCEBYTES);
    out += crypto_box_NONCEBYTES;

    /* now encrypt */
    if (encrypt_data_symmetric(key->key, nonce, data, data_len, out)
            != data_len + crypto_box_MACBYTES) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_FAILED);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_OK);
    return 1;
}

/* Encrypts the given data with the given passphrase. The output array must be
 * at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
 * to tox_derive_key_from_pass and tox_pass_key_encrypt.
 *
 * returns true on success
 */
bool tox_pass_encrypt(const uint8_t *data, size_t data_len, uint8_t *passphrase, size_t pplength, uint8_t *out,
                      TOX_ERR_ENCRYPTION *error)
{
    TOX_PASS_KEY key;
    TOX_ERR_KEY_DERIVATION _error;

    if (!tox_derive_key_from_pass(passphrase, pplength, &key, &_error)) {
        if (_error == TOX_ERR_KEY_DERIVATION_NULL) {
            SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_NULL);
        } else if (_error == TOX_ERR_KEY_DERIVATION_FAILED) {
            SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED);
        }

        return 0;
    }

    return tox_pass_key_encrypt(data, data_len, &key, out, error);
}

/* This is the inverse of tox_pass_key_encrypt, also using only keys produced by
 * tox_derive_key_from_pass.
 *
 * the output data has size data_length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH
 *
 * returns true on success
 */
bool tox_pass_key_decrypt(const uint8_t *data, size_t length, const TOX_PASS_KEY *key, uint8_t *out,
                          TOX_ERR_DECRYPTION *error)
{
    if (length <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return 0;
    }

    if (!data || !key || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return 0;
    }

    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return 0;
    }

    data += TOX_ENC_SAVE_MAGIC_LENGTH;
    data += crypto_pwhash_scryptsalsa208sha256_SALTBYTES; // salt only affects key derivation

    size_t decrypt_length = length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH;

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, data, crypto_box_NONCEBYTES);
    data += crypto_box_NONCEBYTES;

    /* decrypt the data */
    if (decrypt_data_symmetric(key->key, nonce, data, decrypt_length + crypto_box_MACBYTES, out)
            != decrypt_length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_FAILED);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_OK);
    return 1;
}

/* Decrypts the given data with the given passphrase. The output array must be
 * at least data_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
 * to tox_pass_key_decrypt.
 *
 * the output data has size data_length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH
 *
 * returns true on success
 */
bool tox_pass_decrypt(const uint8_t *data, size_t length, uint8_t *passphrase, size_t pplength, uint8_t *out,
                      TOX_ERR_DECRYPTION *error)
{
    if (length <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH || pplength == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return 0;
    }

    if (!data || !passphrase || !out) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return 0;
    }

    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return 0;
    }

    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    memcpy(salt, data + TOX_ENC_SAVE_MAGIC_LENGTH, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

    /* derive the key */
    TOX_PASS_KEY key;

    if (!tox_derive_key_with_salt(passphrase, pplength, salt, &key, NULL)) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED);
        return 0;
    }

    return tox_pass_key_decrypt(data, length, &key, out, error);
}

/* Determines whether or not the given data is encrypted (by checking the magic number)
 */
bool tox_is_data_encrypted(const uint8_t *data)
{
    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0)
        return 1;
    else
        return 0;
}
