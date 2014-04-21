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

/* return zero if the buffer contains only zeros. */
uint8_t crypto_iszero(uint8_t *buffer, uint32_t blen);

/* Encrypts plain of length length to encrypted of length + 16 using the
 * public key(32 bytes) of the receiver and the secret key of the sender and a 24 byte nonce.
 *
 *  return -1 if there was a problem.
 *  return length of encrypted data if everything was fine.
 */
int encrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce,
                 uint8_t *plain, uint32_t length, uint8_t *encrypted);


/* Decrypts encrypted of length length to plain of length length - 16 using the
 * public key(32 bytes) of the sender, the secret key of the receiver and a 24 byte nonce.
 *
 *  return -1 if there was a problem (decryption failed).
 *  return length of plain data if everything was fine.
 */
int decrypt_data(uint8_t *public_key, uint8_t *secret_key, uint8_t *nonce,
                 uint8_t *encrypted, uint32_t length, uint8_t *plain);

/* Fast encrypt/decrypt operations. Use if this is not a one-time communication.
   encrypt_precompute does the shared-key generation once so it does not have
   to be preformed on every encrypt/decrypt. */
void encrypt_precompute(uint8_t *public_key, uint8_t *secret_key, uint8_t *enc_key);

/* Encrypts plain of length length to encrypted of length + 16 using a
 * secret key crypto_box_KEYBYTES big and a 24 byte nonce.
 *
 *  return -1 if there was a problem.
 *  return length of encrypted data if everything was fine.
 */
int encrypt_data_symmetric(uint8_t *secret_key, uint8_t *nonce, uint8_t *plain, uint32_t length, uint8_t *encrypted);

/* Decrypts encrypted of length length to plain of length length - 16 using a
 * secret key crypto_box_KEYBYTES big and a 24 byte nonce.
 *
 *  return -1 if there was a problem (decryption failed).
 *  return length of plain data if everything was fine.
 */
int decrypt_data_symmetric(uint8_t *secret_key, uint8_t *nonce, uint8_t *encrypted, uint32_t length, uint8_t *plain);

/* Increment the given nonce by 1. */
void increment_nonce(uint8_t *nonce);

/* increment the given nonce by num */
void increment_nonce_number(uint8_t *nonce, uint32_t num);

/* Fill the given nonce with random bytes. */
void random_nonce(uint8_t *nonce);

/* Fill a key crypto_box_KEYBYTES big with random bytes */
void new_symmetric_key(uint8_t *key);

/*Gives a nonce guaranteed to be different from previous ones.*/
void new_nonce(uint8_t *nonce);

#endif
