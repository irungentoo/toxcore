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

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

// these two functions provide access to these defines in toxencryptsave.c, which
//otherwise aren't actually available in clients...
int tox_pass_encryption_extra_length();

int tox_pass_key_length();

/* This "module" provides functions analogous to tox_load and tox_save in toxcore
 * Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */

/*  return size of the messenger data (for encrypted saving). */
uint32_t tox_encrypted_size(const Tox *tox);

/* Generates a secret symmetric key from the given passphrase. out_key must be at least
 * tox_pass_key_length() bytes long.
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
int tox_derive_key_from_pass(uint8_t *passphrase, uint32_t pplength, uint8_t *out_key);

/* Encrypt arbitrary with a key produced by tox_derive_key_from_pass. The output
 * array must be at least data_len + tox_pass_encryption_extra_length() bytes long.
 * key must be tox_pass_key_length() bytes.
 * If you already have a symmetric key from somewhere besides this module, simply
 * call encrypt_data_symmetric in toxcore/crypto_core directly.
 *
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_pass_key_encrypt(const uint8_t *data, uint32_t data_len, const uint8_t *key, uint8_t *out);

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
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_save(const Tox *tox, uint8_t *data, uint8_t *passphrase, uint32_t pplength);

/* This is the inverse of tox_pass_key_encrypt, also using only keys produced by
 * tox_derive_key_from_pass.
 *
 * returns the length of the output data (== data_len - tox_pass_encryption_extra_length()) on success
 * returns -1 on failure
 */
int tox_pass_key_decrypt(const uint8_t* data, uint32_t length, const uint8_t* key, uint8_t* out);

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

/* Load the messenger from encrypted data of size length.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_encrypted_load(Tox *tox, const uint8_t *data, uint32_t length, uint8_t *passphrase, uint32_t pplength);

/* Determines whether or not the given data is encrypted (by checking the magic number)
 *
 * returns 1 if it is encrypted
 * returns 0 otherwise
 */
int tox_is_save_encrypted(const uint8_t *data);

#ifdef __cplusplus
}
#endif

#endif
