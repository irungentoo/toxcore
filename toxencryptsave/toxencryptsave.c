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
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"

#ifdef VANILLA_NACL
#include "crypto_pwhash_scryptsalsa208sha256/crypto_pwhash_scryptsalsa208sha256.h"
#include "crypto_pwhash_scryptsalsa208sha256/utils.h" /* sodium_memzero */
#include <crypto_hash_sha256.h>
#endif

/* This "module" provides functions analogous to tox_load and tox_save in toxcore
 * Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */

/*  return size of the messenger data (for encrypted saving). */
uint32_t tox_encrypted_size(const Tox *tox)
{
    return tox_size(tox) + TOX_PASS_ENCRYPTION_EXTRA_LENGTH + TOX_ENC_SAVE_MAGIC_LENGTH;
}

/* Generates a secret symmetric key from the given passphrase. out_key must be at least
 * TOX_PASS_KEY_LENGTH bytes long.
 * Be sure to not compromise the key! Only keep it in memory, do not write to disk.
 * This function is fairly cheap, but irungentoo insists that you be allowed to
 * cache the result if you want, to minimize computation for repeated encryptions.
 * The password is zeroed after key derivation.
 * The key should only be used with the other functions in this module, as it
 * includes a salt.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_derive_key_from_pass(uint8_t *passphrase, uint32_t pplength, uint8_t *out_key)
{
    if (pplength == 0)
        return -1;

    uint8_t passkey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(passkey, passphrase, pplength);
    /* First derive a key from the password */
    /* http://doc.libsodium.org/key_derivation/README.html */
    /* note that, according to the documentation, a generic pwhash interface will be created
     * once the pwhash competition (https://password-hashing.net/) is over */
    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    uint8_t key[crypto_box_KEYBYTES];
    randombytes(salt, sizeof salt);

    if (crypto_pwhash_scryptsalsa208sha256(
                key, sizeof(key), passkey, sizeof(passkey), salt,
                crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        /* out of memory most likely */
        return -1;
    }

    sodium_memzero(passkey, crypto_hash_sha256_BYTES); /* wipe plaintext pw */
    memcpy(out_key, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    memcpy(out_key + crypto_pwhash_scryptsalsa208sha256_SALTBYTES, key, crypto_box_KEYBYTES);
    return 0;
}

/* Encrypt arbitrary with a key produced by tox_derive_key_from_pass. The output
 * array must be at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long.
 * key must be TOX_PASS_KEY_LENGTH bytes.
 * If you already have a symmetric key from somewhere besides this module, simply
 * call encrypt_data_symmetric in toxcore/crypto_core directly.
 *
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_pass_key_encrypt(uint8_t *data, uint32_t data_len, const uint8_t *key, uint8_t *out)
{
    /* the output data consists of, in order:
     * salt, nonce, mac, enc_data
     * where the mac is automatically prepended by the encrypt()
     * the salt+nonce is called the prefix
     * I'm not sure what else I'm supposed to do with the salt and nonce, since we
     * need them to decrypt the data
     */

    /* first add the prefix */
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    memcpy(out, key, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    key += crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
    out += crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
    memcpy(out, nonce, crypto_box_NONCEBYTES);
    out += crypto_box_NONCEBYTES;

    /* now encrypt */
    if (encrypt_data_symmetric(key, nonce, data, data_len, out)
            != data_len + crypto_box_MACBYTES) {
        return -1;
    }

    return 0;
}

/* Encrypts the given data with the given passphrase. The output array must be
 * at least data_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long. This delegates
 * to tox_derive_key_from_pass and tox_pass_key_encrypt.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_pass_encrypt(uint8_t *data, uint32_t data_len, uint8_t *passphrase, uint32_t pplength, uint8_t *out)
{
    uint8_t key[TOX_PASS_KEY_LENGTH];

    if (tox_derive_key_from_pass(passphrase, pplength, key) == -1)
        return -1;

    return tox_pass_key_encrypt(data, data_len, key, out);
}

/* Save the messenger data encrypted with the given password.
 * data must be at least tox_encrypted_size().
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_save(const Tox *tox, uint8_t *data, uint8_t *passphrase, uint32_t pplength)
{
    /* first get plain save data */
    uint32_t temp_size = tox_size(tox);
    uint8_t temp_data[temp_size];
    tox_save(tox, temp_data);

    /* the output data consists of, in order: magic number, enc_data */
    /* first add the magic number */
    memcpy(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH);
    data += TOX_ENC_SAVE_MAGIC_LENGTH;

    /* now encrypt */
    return tox_pass_encrypt(temp_data, temp_size, passphrase, pplength, data);
}

/* This is the inverse of tox_pass_key_encrypt, also using only keys produced by
 * tox_derive_key_from_pass.
 *
 * returns the length of the output data (== data_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH) on success
 * returns -1 on failure
 */
int tox_pass_key_decrypt(const uint8_t *data, uint32_t length, const uint8_t *key, uint8_t *out)
{
    if (length <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH)
        return -1;

    uint32_t decrypt_length = length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    //uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];

    //memcpy(salt, data, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    key += crypto_pwhash_scryptsalsa208sha256_SALTBYTES; // ignore the salt, which is only needed for kdf
    data += crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
    memcpy(nonce, data, crypto_box_NONCEBYTES);
    data += crypto_box_NONCEBYTES;

    /* decrypt the data */
    if (decrypt_data_symmetric(key, nonce, data, decrypt_length + crypto_box_MACBYTES, out)
            != decrypt_length) {
        return -1;
    }

    return decrypt_length;
}

/* Decrypts the given data with the given passphrase. The output array must be
 * at least data_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes long.
 *
 * returns the length of the output data (== data_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH) on success
 * returns -1 on failure
 */
int tox_pass_decrypt(const uint8_t *data, uint32_t length, uint8_t *passphrase, uint32_t pplength, uint8_t *out)
{

    uint8_t passkey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(passkey, passphrase, pplength);

    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    memcpy(salt, data, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

    /* derive the key */
    uint8_t key[crypto_box_KEYBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES];

    if (crypto_pwhash_scryptsalsa208sha256(
                key + crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
                crypto_box_KEYBYTES, passkey, sizeof(passkey), salt,
                crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        /* out of memory most likely */
        return -1;
    }

    sodium_memzero(passkey, crypto_hash_sha256_BYTES); /* wipe plaintext pw */

    return tox_pass_key_decrypt(data, length, key, out);
}

/* Load the messenger from encrypted data of size length.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_load(Tox *tox, const uint8_t *data, uint32_t length, uint8_t *passphrase, uint32_t pplength)
{
    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0)
        return -1;

    data += TOX_ENC_SAVE_MAGIC_LENGTH;
    length -= TOX_ENC_SAVE_MAGIC_LENGTH;

    uint32_t decrypt_length = length - TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t temp_data[decrypt_length];

    if (tox_pass_decrypt(data, length, passphrase, pplength, temp_data)
            != decrypt_length)
        return -1;

    return tox_load(tox, temp_data, decrypt_length);
}

/* Determines whether or not the given data is encrypted (by checking the magic number)
 *
 * returns 1 if it is encrypted
 * returns 0 otherwise
 */
int tox_is_save_encrypted(const uint8_t *data)
{
    if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0)
        return 1;
    else
        return 0;
}
