/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Batch encryption functions.
 */
#include "toxencryptsave.h"

#include <sodium.h>

#include <stdlib.h>
#include <string.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/crypto_core.h"
#include "defines.h"

static_assert(TOX_PASS_SALT_LENGTH == crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
              "TOX_PASS_SALT_LENGTH is assumed to be equal to crypto_pwhash_scryptsalsa208sha256_SALTBYTES");
static_assert(TOX_PASS_KEY_LENGTH == CRYPTO_SHARED_KEY_SIZE,
              "TOX_PASS_KEY_LENGTH is assumed to be equal to CRYPTO_SHARED_KEY_SIZE");
static_assert(TOX_PASS_ENCRYPTION_EXTRA_LENGTH == (crypto_box_MACBYTES + crypto_box_NONCEBYTES +
              crypto_pwhash_scryptsalsa208sha256_SALTBYTES + TOX_ENC_SAVE_MAGIC_LENGTH),
              "TOX_PASS_ENCRYPTION_EXTRA_LENGTH is assumed to be equal to (crypto_box_MACBYTES + crypto_box_NONCEBYTES + crypto_pwhash_scryptsalsa208sha256_SALTBYTES + TOX_ENC_SAVE_MAGIC_LENGTH)");

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)

uint32_t tox_pass_salt_length(void)
{
    return TOX_PASS_SALT_LENGTH;
}
uint32_t tox_pass_key_length(void)
{
    return TOX_PASS_KEY_LENGTH;
}
uint32_t tox_pass_encryption_extra_length(void)
{
    return TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
}

struct Tox_Pass_Key {
    uint8_t salt[TOX_PASS_SALT_LENGTH];
    uint8_t key[TOX_PASS_KEY_LENGTH];
};

void tox_pass_key_free(Tox_Pass_Key *key)
{
    free(key);
}

/* Clients should consider alerting their users that, unlike plain data, if even one bit
 * becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 */

/**
 * Retrieves the salt used to encrypt the given data.
 *
 * The retrieved salt can then be passed to tox_pass_key_derive_with_salt to
 * produce the same key as was previously used. Any data encrypted with this
 * module can be used as input.
 *
 * The cipher text must be at least TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes in length.
 * The salt must be TOX_PASS_SALT_LENGTH bytes in length.
 * If the passed byte arrays are smaller than required, the behaviour is
 * undefined.
 *
 * If the cipher text pointer or the salt is NULL, this function returns false.
 *
 * Success does not say anything about the validity of the data, only that
 * data of the appropriate size was copied.
 *
 * @return true on success.
 */
bool tox_get_salt(const uint8_t *ciphertext, uint8_t *salt, Tox_Err_Get_Salt *error)
{
    if (ciphertext == nullptr || salt == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_SALT_NULL);
        return false;
    }

    if (memcmp(ciphertext, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_SALT_BAD_FORMAT);
        return false;
    }

    ciphertext += TOX_ENC_SAVE_MAGIC_LENGTH;
    memcpy(salt, ciphertext, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    SET_ERROR_PARAMETER(error, TOX_ERR_GET_SALT_OK);
    return true;
}

/**
 * Generates a secret symmetric key from the given passphrase.
 *
 * Be sure to not compromise the key! Only keep it in memory, do not write
 * it to disk.
 *
 * Note that this function is not deterministic; to derive the same key from
 * a password, you also must know the random salt that was used. A
 * deterministic version of this function is `tox_pass_key_derive_with_salt`.
 *
 * @param passphrase The user-provided password. Can be empty.
 * @param passphrase_len The length of the password.
 *
 * @return new symmetric key on success, NULL on failure.
 */
Tox_Pass_Key *tox_pass_key_derive(const uint8_t *passphrase, size_t passphrase_len,
                                  Tox_Err_Key_Derivation *error)
{
    const Random *rng = system_random();

    if (rng == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return nullptr;
    }

    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    random_bytes(rng, salt, sizeof(salt));
    return tox_pass_key_derive_with_salt(passphrase, passphrase_len, salt, error);
}

/**
 * Same as above, except use the given salt for deterministic key derivation.
 *
 * @param passphrase The user-provided password. Can be empty.
 * @param passphrase_len The length of the password.
 * @param salt An array of at least TOX_PASS_SALT_LENGTH bytes.
 *
 * @return new symmetric key on success, NULL on failure.
 */
Tox_Pass_Key *tox_pass_key_derive_with_salt(const uint8_t *passphrase, size_t passphrase_len,
        const uint8_t *salt, Tox_Err_Key_Derivation *error)
{
    if (salt == nullptr || (passphrase == nullptr && passphrase_len != 0)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_NULL);
        return nullptr;
    }

    uint8_t passkey[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(passkey, passphrase, passphrase_len);

    uint8_t key[CRYPTO_SHARED_KEY_SIZE];

    // Derive a key from the password
    // http://doc.libsodium.org/key_derivation/README.html
    // note that, according to the documentation, a generic pwhash interface will be created
    // once the pwhash competition (https://password-hashing.net/) is over */
    if (crypto_pwhash_scryptsalsa208sha256(
                key, sizeof(key), (char *)passkey, sizeof(passkey), salt,
                crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 2, /* slightly stronger */
                crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return nullptr;
    }

    crypto_memzero(passkey, crypto_hash_sha256_BYTES); /* wipe plaintext pw */

    Tox_Pass_Key *out_key = (Tox_Pass_Key *)calloc(1, sizeof(Tox_Pass_Key));

    if (out_key == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_FAILED);
        return nullptr;
    }

    memcpy(out_key->salt, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    memcpy(out_key->key, key, CRYPTO_SHARED_KEY_SIZE);
    SET_ERROR_PARAMETER(error, TOX_ERR_KEY_DERIVATION_OK);
    return out_key;
}

/**
 * Encrypt a plain text with a key produced by tox_pass_key_derive or tox_pass_key_derive_with_salt.
 *
 * The output array must be at least `plaintext_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
 * bytes long.
 *
 * @param plaintext A byte array of length `plaintext_len`.
 * @param plaintext_len The length of the plain text array. Bigger than 0.
 * @param ciphertext The cipher text array to write the encrypted data to.
 *
 * @return true on success.
 */
bool tox_pass_key_encrypt(const Tox_Pass_Key *key, const uint8_t *plaintext, size_t plaintext_len,
                          uint8_t *ciphertext, Tox_Err_Encryption *error)
{
    const Random *rng = system_random();

    if (rng == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_FAILED);
        return false;
    }

    if (plaintext_len == 0 || plaintext == nullptr || key == nullptr || ciphertext == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_NULL);
        return false;
    }

    // the output data consists of, in order:
    // salt, nonce, mac, enc_data
    // where the mac is automatically prepended by the encrypt()
    // the salt+nonce is called the prefix
    // I'm not sure what else I'm supposed to do with the salt and nonce, since we
    // need them to decrypt the data

    /* first add the magic number */
    memcpy(ciphertext, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH);
    ciphertext += TOX_ENC_SAVE_MAGIC_LENGTH;

    /* then add the rest prefix */
    memcpy(ciphertext, key->salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    ciphertext += crypto_pwhash_scryptsalsa208sha256_SALTBYTES;

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(rng, nonce);
    memcpy(ciphertext, nonce, crypto_box_NONCEBYTES);
    ciphertext += crypto_box_NONCEBYTES;

    /* now encrypt */
    if (encrypt_data_symmetric(key->key, nonce, plaintext, plaintext_len, ciphertext)
            != plaintext_len + crypto_box_MACBYTES) {
        SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_FAILED);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_OK);
    return true;
}

/**
 * Encrypts the given data with the given passphrase.
 *
 * The output array must be at least `plaintext_len + TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
 * bytes long. This delegates to tox_pass_key_derive and
 * tox_pass_key_encrypt.
 *
 * @param plaintext A byte array of length `plaintext_len`.
 * @param plaintext_len The length of the plain text array. Bigger than 0.
 * @param passphrase The user-provided password. Can be empty.
 * @param passphrase_len The length of the password.
 * @param ciphertext The cipher text array to write the encrypted data to.
 *
 * @return true on success.
 */
bool tox_pass_encrypt(const uint8_t *plaintext, size_t plaintext_len, const uint8_t *passphrase, size_t passphrase_len,
                      uint8_t *ciphertext, Tox_Err_Encryption *error)
{
    Tox_Err_Key_Derivation err;
    Tox_Pass_Key *key = tox_pass_key_derive(passphrase, passphrase_len, &err);

    if (key == nullptr) {
        if (err == TOX_ERR_KEY_DERIVATION_NULL) {
            SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_NULL);
        } else if (err == TOX_ERR_KEY_DERIVATION_FAILED) {
            SET_ERROR_PARAMETER(error, TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED);
        }

        return false;
    }

    const bool result = tox_pass_key_encrypt(key, plaintext, plaintext_len, ciphertext, error);
    tox_pass_key_free(key);
    return result;
}

/**
 * This is the inverse of tox_pass_key_encrypt, also using only keys produced by
 * tox_pass_key_derive or tox_pass_key_derive_with_salt.
 *
 * @param ciphertext A byte array of length `ciphertext_len`.
 * @param ciphertext_len The length of the cipher text array. At least TOX_PASS_ENCRYPTION_EXTRA_LENGTH.
 * @param plaintext The plain text array to write the decrypted data to.
 *
 * @return true on success.
 */
bool tox_pass_key_decrypt(const Tox_Pass_Key *key, const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t *plaintext, Tox_Err_Decryption *error)
{
    if (ciphertext_len <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return false;
    }

    if (ciphertext == nullptr || key == nullptr || plaintext == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return false;
    }

    if (memcmp(ciphertext, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return false;
    }

    ciphertext += TOX_ENC_SAVE_MAGIC_LENGTH;
    ciphertext += crypto_pwhash_scryptsalsa208sha256_SALTBYTES; // salt only affects key derivation

    const size_t decrypt_length = ciphertext_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH;

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, ciphertext, crypto_box_NONCEBYTES);
    ciphertext += crypto_box_NONCEBYTES;

    /* decrypt the ciphertext */
    if (decrypt_data_symmetric(key->key, nonce, ciphertext, decrypt_length + crypto_box_MACBYTES, plaintext)
            != decrypt_length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_FAILED);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_OK);
    return true;
}

/**
 * Decrypts the given data with the given passphrase.
 *
 * The output array must be at least `ciphertext_len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH`
 * bytes long. This delegates to tox_pass_key_decrypt.
 *
 * @param ciphertext A byte array of length `ciphertext_len`.
 * @param ciphertext_len The length of the cipher text array. At least TOX_PASS_ENCRYPTION_EXTRA_LENGTH.
 * @param passphrase The user-provided password. Can be empty.
 * @param passphrase_len The length of the password.
 * @param plaintext The plain text array to write the decrypted data to.
 *
 * @return true on success.
 */
bool tox_pass_decrypt(const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *passphrase,
                      size_t passphrase_len, uint8_t *plaintext, Tox_Err_Decryption *error)
{
    if (ciphertext_len <= TOX_PASS_ENCRYPTION_EXTRA_LENGTH) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_INVALID_LENGTH);
        return false;
    }

    if (ciphertext == nullptr || passphrase == nullptr || plaintext == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_NULL);
        return false;
    }

    if (memcmp(ciphertext, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_BAD_FORMAT);
        return false;
    }

    uint8_t salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    memcpy(salt, ciphertext + TOX_ENC_SAVE_MAGIC_LENGTH, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

    /* derive the key */
    Tox_Pass_Key *key = tox_pass_key_derive_with_salt(passphrase, passphrase_len, salt, nullptr);

    if (key == nullptr) {
        /* out of memory most likely */
        SET_ERROR_PARAMETER(error, TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED);
        return false;
    }

    const bool result = tox_pass_key_decrypt(key, ciphertext, ciphertext_len, plaintext, error);
    tox_pass_key_free(key);
    return result;
}

/**
 * Determines whether or not the given data is encrypted by this module.
 *
 * It does this check by verifying that the magic number is the one put in
 * place by the encryption functions.
 *
 * The data must be at least TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes in length.
 * If the passed byte array is smaller than required, the behaviour is
 * undefined.
 *
 * If the data pointer is NULL, the behaviour is undefined
 *
 * @return true if the data is encrypted by this module.
 */
bool tox_is_data_encrypted(const uint8_t *data)
{
    return memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0;
}
