/* toxencryptsave.h
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

#ifndef TOXENCRYPTSAVE_H
#define TOXENCRYPTSAVE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#ifndef TOX_DEFINED
#define TOX_DEFINED
typedef struct Tox Tox;
struct Tox_Options;
#endif

// these functions provide access to these defines in toxencryptsave.c, which
// otherwise aren't actually available in clients...
int tox_pass_encryption_extra_length();

int tox_pass_key_length();

int tox_pass_salt_length();

/*  return size of the messenger data (for encrypted Messenger saving). */
uint32_t tox_encrypted_size(const Tox *tox);

/* This "module" provides functions analogous to tox_load and tox_save in toxcore,
 * as well as functions for encryption of arbitrary client data (e.g. chat logs).
 *
 * It is conceptually organized into two parts. The first part are the functions
 * with "key" in the name. To use these functions, first derive an encryption key
 * from a password with tox_derive_key_from_pass, and use the returned key to
 * encrypt the data. The second part takes the password itself instead of the key,
 * and then delegates to the first part to derive the key before de/encryption,
 * which can simplify client code; however, key derivation is very expensive
 * compared to the actual encryption, so clients that do a lot of encryption should
 * favor using the first part intead of the second part.
 *
 * The encrypted data is prepended with a magic number, to aid validity checking
 * (no guarantees are made of course).
 *
 * Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */


/******************************* BEGIN PART 2 *******************************
 * For simplicty, the second part of the module is presented first. The API for
 * the first part is analgous, with some extra functions for key handling. If
 * your code spends too much time using these functions, consider using the part
 * 1 functions instead.
 */

/* Encrypts the given data with the given passphrase. The output array must be
 * at least data_len + tox_pass_encryption_extra_length() bytes long. This delegates
 * to tox_derive_key_from_pass and tox_pass_key_encrypt.
 *
 * tox_encrypted_save() is a good example of how to use this function.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_pass_encrypt(const uint8_t *data, uint32_t data_len, uint8_t *passphrase, uint32_t pplength, uint8_t *out);

/* Save the messenger data encrypted with the given password.
 * data must be at least tox_encrypted_size().
 *
 * NOTE: Unlike tox_save(), this function may fail. Be sure to check its return
 * value.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_save(const Tox *tox, uint8_t *data, uint8_t *passphrase, uint32_t pplength);

/* Decrypts the given data with the given passphrase. The output array must be
 * at least data_len - tox_pass_encryption_extra_length() bytes long. This delegates
 * to tox_pass_key_decrypt.
 *
 * tox_encrypted_load() is a good example of how to use this function.
 *
 * returns the length of the output data (== data_len - tox_pass_encryption_extra_length()) on success
 * returns -1 on failure
 */
int tox_pass_decrypt(const uint8_t *data, uint32_t length, uint8_t *passphrase, uint32_t pplength, uint8_t *out);

typedef enum TOX_ERR_ENCRYPTED_NEW {
    TOX_ERR_ENCRYPTED_NEW_OK,
    TOX_ERR_ENCRYPTED_NEW_NULL,
    /**
     * The function was unable to allocate enough memory to store the internal
     * structures for the Tox object.
     */
    TOX_ERR_ENCRYPTED_NEW_MALLOC,
    /**
     * The function was unable to bind to a port. This may mean that all ports
     * have already been bound, e.g. by other Tox instances, or it may mean
     * a permission error. You may be able to gather more information from errno.
     */
    TOX_ERR_ENCRYPTED_NEW_PORT_ALLOC,
    /**
     * proxy_type was invalid.
     */
    TOX_ERR_ENCRYPTED_NEW_PROXY_BAD_TYPE,
    /**
     * proxy_type was valid but the proxy_host passed had an invalid format
     * or was NULL.
     */
    TOX_ERR_ENCRYPTED_NEW_PROXY_BAD_HOST,
    /**
     * proxy_type was valid, but the proxy_port was invalid.
     */
    TOX_ERR_ENCRYPTED_NEW_PROXY_BAD_PORT,
    /**
     * The proxy host passed could not be resolved.
     */
    TOX_ERR_ENCRYPTED_NEW_PROXY_NOT_FOUND,
    /**
     * The byte array to be loaded contained an encrypted save.
     */
    TOX_ERR_ENCRYPTED_NEW_LOAD_ENCRYPTED,
    /**
     * The data format was invalid. This can happen when loading data that was
     * saved by an older version of Tox, or when the data has been corrupted.
     * When loading from badly formatted data, some data may have been loaded,
     * and the rest is discarded. Passing an invalid length parameter also
     * causes this error.
     */
    TOX_ERR_ENCRYPTED_NEW_LOAD_BAD_FORMAT,
    /**
     * The encrypted byte array could not be decrypted. Either the data was
     * corrupt or the password/key was incorrect.
     *
     * NOTE: This error code is only set by tox_encrypted_new() and
     * tox_encrypted_key_new(), in the toxencryptsave module.
     */
    TOX_ERR_ENCRYPTED_NEW_LOAD_DECRYPTION_FAILED
} TOX_ERR_ENCRYPTED_NEW;

/* Load the new messenger from encrypted data of size length.
 * All other arguments are like toxcore/tox_new().
 *
 * returns NULL on failure; see the documentation in toxcore/tox.h.
 */
Tox *tox_encrypted_new(const struct Tox_Options *options, const uint8_t *data, size_t length, uint8_t *passphrase,
                       size_t pplength, TOX_ERR_ENCRYPTED_NEW *error);


/******************************* BEGIN PART 1 *******************************
 * And now part "1", which does the actual encryption, and is rather less cpu
 * intensive than part one. The first 3 functions are for key handling.
 */

/* Generates a secret symmetric key from the given passphrase. out_key must be at least
 * tox_pass_key_length() bytes long.
 * Be sure to not compromise the key! Only keep it in memory, do not write to disk.
 * The password is zeroed after key derivation.
 * The key should only be used with the other functions in this module, as it
 * includes a salt.
 * Note that this function is not deterministic; to derive the same key from a
 * password, you also must know the random salt that was used. See below.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_derive_key_from_pass(uint8_t *passphrase, uint32_t pplength, uint8_t *out_key);

/* Same as above, except with use the given salt for deterministic key derivation.
 * The salt must be tox_salt_length() bytes in length.
 */
int tox_derive_key_with_salt(uint8_t *passphrase, uint32_t pplength, uint8_t *salt, uint8_t *out_key);

/* This retrieves the salt used to encrypt the given data, which can then be passed to
 * derive_key_with_salt to produce the same key as was previously used. Any encrpyted
 * data with this module can be used as input.
 *
 * returns -1 if the magic number is wrong
 * returns 0 otherwise (no guarantee about validity of data)
 */
int tox_get_salt(uint8_t *data, uint8_t *salt);

/* Now come the functions that are analogous to the part 2 functions. */

/* Encrypt arbitrary with a key produced by tox_derive_key_. The output
 * array must be at least data_len + tox_pass_encryption_extra_length() bytes long.
 * key must be tox_pass_key_length() bytes.
 * If you already have a symmetric key from somewhere besides this module, simply
 * call encrypt_data_symmetric in toxcore/crypto_core directly.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_pass_key_encrypt(const uint8_t *data, uint32_t data_len, const uint8_t *key, uint8_t *out);

/* Save the messenger data encrypted with the given key from tox_derive_key.
 * data must be at least tox_encrypted_size().
 *
 * NOTE: Unlike tox_save(), this function may fail. Be sure to check its return
 * value.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_key_save(const Tox *tox, uint8_t *data, uint8_t *key);

/* This is the inverse of tox_pass_key_encrypt, also using only keys produced by
 * tox_derive_key_from_pass.
 *
 * returns the length of the output data (== data_len - tox_pass_encryption_extra_length()) on success
 * returns -1 on failure
 */
int tox_pass_key_decrypt(const uint8_t *data, uint32_t length, const uint8_t *key, uint8_t *out);

/* Load the messenger from encrypted data of size length, with key from tox_derive_key.
 * All other arguments are like toxcore/tox_new().
 *
 * returns NULL on failure; see the documentation in toxcore/tox.h.
 */
Tox *tox_encrypted_key_new(const struct Tox_Options *options, const uint8_t *data, size_t length, uint8_t *key,
                           TOX_ERR_ENCRYPTED_NEW *error);


/* Determines whether or not the given data is encrypted (by checking the magic number)
 *
 * returns 1 if it is encrypted
 * returns 0 otherwise
 */
int tox_is_data_encrypted(const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif
