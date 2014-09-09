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

#include "toxencryptsave.h"

/* This "module" provides functions analogous to tox_load and tox_save in toxcore
 * Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */

/*  return size of the messenger data (for encrypted saving). */
uint32_t tox_encrypted_size(const Tox *tox)
{
    return tox_size(tox) + crypto_box_MACBYTES + crypto_box_NONCEBYTES
            + crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
}

/* Save the messenger data encrypted with the given password.
 * data must be at least tox_encrypted_size().
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_save(const Tox *tox, uint8_t *data, uint8_t *passphrase, uint32_t pplength)
{
    if (pplength == 0)
         return -1;
    
    /* First derive a key from the password */
    /* http://doc.libsodium.org/key_derivation/README.html */
    /* note that, according to the documentation, a generic pwhash interface will be created
     * once the pwhash competition (https://password-hashing.net/) is over */
    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    uint8_t key[crypto_box_KEYBYTES];
    randombytes_buf(salt, sizeof salt);

    if (crypto_pwhash_scryptsalsa208sha256(
            key, sizeof(key), passphrase, pplength, salt,
            crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
            crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) { 
        /* out of memory most likely */
        return -1;
    }
    sodium_memzero(passphrase, pplength); /* wipe plaintext pw */

    /* next get plain save data */
    uint32_t temp_size = tox_size(tox);
    uint8_t temp_data[temp_size];
    tox_save(tox, temp_data);
    
    /* now encrypt.
     * the output data consists of, in order:
     * salt, nonce, mac, enc_data
     * where the mac is automatically prepended by the encrypt()
     * the salt+nonce is called the prefix
     * I'm not sure what else I'm supposed to do with the salt and nonce, since we
     * need them to decrypt the data
     */
    uint32_t prefix_size = crypto_box_NONCEBYTES+crypto_pwhash_scryptsalsa208sha256_SALTBYTES;

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    if (encrypt_data_symmetric(key, nonce, temp_data, temp_size, data + prefix_size)
           != temp_size + crypto_box_MACBYTES) {
        return -1;
    }
    
    /* add the prefix */
    memcpy(data, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    memcpy(data + crypto_pwhash_scryptsalsa208sha256_SALTBYTES, nonce, crypto_box_NONCEBYTES);

    return 0;
}

/* Load the messenger from encrypted data of size length.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_load(Tox *tox, const uint8_t *data, uint32_t length, uint8_t *passphrase, uint32_t pplength)
{
    if (length <= crypto_box_MACBYTES + crypto_box_NONCEBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES)
        return -1;

    uint32_t decrypt_length = length - crypto_box_MACBYTES - crypto_box_NONCEBYTES
                                    - crypto_pwhash_scryptsalsa208sha256_SALTBYTES;
    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];
    
    memcpy(salt, data, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    memcpy(nonce, data + crypto_pwhash_scryptsalsa208sha256_SALTBYTES, crypto_box_NONCEBYTES);
    
    /* derive the key */
    uint8_t key[crypto_box_KEYBYTES];
    if (crypto_pwhash_scryptsalsa208sha256(
            key, sizeof(key), passphrase, pplength, salt,
            crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
            crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) { 
        /* out of memory most likely */
        return -1;
    }
    sodium_memzero(passphrase, pplength); /* wipe plaintext pw */

    /* decrypt the data */
    uint8_t temp_data[decrypt_length];
    if (decrypt_data_symmetric(key, nonce, data+crypto_pwhash_scryptsalsa208sha256_SALTBYTES+crypto_box_NONCEBYTES,
            decrypt_length + crypto_box_MACBYTES, temp_data)
            != decrypt_length) {
        return -1;
    }

    return tox_load(tox, temp_data, decrypt_length);
}
