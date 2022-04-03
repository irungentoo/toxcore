/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2016 Tox Developers.
 */

/**
 * Batch encryption functions.
 */

#ifndef C_TOXCORE_TOXENCRYPTSAVE_TOXENCRYPTSAVE_H
#define C_TOXCORE_TOXENCRYPTSAVE_TOXENCRYPTSAVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 *
 * This module is organized into two parts.
 *
 * 1. A simple API operating on plain text/cipher text data and a password to
 *    encrypt or decrypt it.
 * 2. A more advanced API that splits key derivation and encryption into two
 *    separate function calls.
 *
 * The first part is implemented in terms of the second part and simply calls
 * the separate functions in sequence. Since key derivation is very expensive
 * compared to the actual encryption, clients that do a lot of crypto should
 * prefer the advanced API and reuse pass-key objects.
 *
 * To use the second part, first derive an encryption key from a password with
 * tox_pass_key_derive, then use the derived key to encrypt the data.
 *
 * The encrypted data is prepended with a magic number, to aid validity
 * checking (no guarantees are made of course). Any data to be decrypted must
 * start with the magic number.
 *
 * Clients should consider alerting their users that, unlike plain data, if
 * even one bit becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 *
 ******************************************************************************/



/**
 * The size of the salt part of a pass-key.
 */
#define TOX_PASS_SALT_LENGTH           32

uint32_t tox_pass_salt_length(void);

/**
 * The size of the key part of a pass-key.
 */
#define TOX_PASS_KEY_LENGTH            32

uint32_t tox_pass_key_length(void);

/**
 * The amount of additional data required to store any encrypted byte array.
 * Encrypting an array of N bytes requires N + TOX_PASS_ENCRYPTION_EXTRA_LENGTH
 * bytes in the encrypted byte array.
 */
#define TOX_PASS_ENCRYPTION_EXTRA_LENGTH 80

uint32_t tox_pass_encryption_extra_length(void);

typedef enum Tox_Err_Key_Derivation {

    /**
     * The function returned successfully.
     */
    TOX_ERR_KEY_DERIVATION_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_KEY_DERIVATION_NULL,

    /**
     * The crypto lib was unable to derive a key from the given passphrase,
     * which is usually a lack of memory issue.
     */
    TOX_ERR_KEY_DERIVATION_FAILED,

} Tox_Err_Key_Derivation;


typedef enum Tox_Err_Encryption {

    /**
     * The function returned successfully.
     */
    TOX_ERR_ENCRYPTION_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_ENCRYPTION_NULL,

    /**
     * The crypto lib was unable to derive a key from the given passphrase,
     * which is usually a lack of memory issue. The functions accepting keys
     * do not produce this error.
     */
    TOX_ERR_ENCRYPTION_KEY_DERIVATION_FAILED,

    /**
     * The encryption itself failed.
     */
    TOX_ERR_ENCRYPTION_FAILED,

} Tox_Err_Encryption;


typedef enum Tox_Err_Decryption {

    /**
     * The function returned successfully.
     */
    TOX_ERR_DECRYPTION_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_DECRYPTION_NULL,

    /**
     * The input data was shorter than TOX_PASS_ENCRYPTION_EXTRA_LENGTH bytes
     */
    TOX_ERR_DECRYPTION_INVALID_LENGTH,

    /**
     * The input data is missing the magic number (i.e. wasn't created by this
     * module, or is corrupted).
     */
    TOX_ERR_DECRYPTION_BAD_FORMAT,

    /**
     * The crypto lib was unable to derive a key from the given passphrase,
     * which is usually a lack of memory issue. The functions accepting keys
     * do not produce this error.
     */
    TOX_ERR_DECRYPTION_KEY_DERIVATION_FAILED,

    /**
     * The encrypted byte array could not be decrypted. Either the data was
     * corrupted or the password/key was incorrect.
     */
    TOX_ERR_DECRYPTION_FAILED,

} Tox_Err_Decryption;



/*******************************************************************************
 *
 *                                BEGIN PART 1
 *
 * The simple API is presented first. If your code spends too much time using
 * these functions, consider using the advanced functions instead and caching
 * the generated pass-key.
 *
 ******************************************************************************/



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
                      uint8_t *ciphertext, Tox_Err_Encryption *error);

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
                      size_t passphrase_len, uint8_t *plaintext, Tox_Err_Decryption *error);


/*******************************************************************************
 *
 *                                BEGIN PART 2
 *
 * And now part 2, which does the actual encryption, and can be used to write
 * less CPU intensive client code than part one.
 *
 ******************************************************************************/



/**
 * This type represents a pass-key.
 *
 * A pass-key and a password are two different concepts: a password is given
 * by the user in plain text. A pass-key is the generated symmetric key used
 * for encryption and decryption. It is derived from a salt and the
 * user-provided password.
 *
 * The Tox_Pass_Key structure is hidden in the implementation. It can be created
 * using tox_pass_key_derive or tox_pass_key_derive_with_salt and must be deallocated using tox_pass_key_free.
 */
#ifndef TOX_PASS_KEY_DEFINED
#define TOX_PASS_KEY_DEFINED
typedef struct Tox_Pass_Key Tox_Pass_Key;
#endif /* TOX_PASS_KEY_DEFINED */

/**
 * Deallocate a Tox_Pass_Key. This function behaves like `free()`, so NULL is an
 * acceptable argument value.
 */
void tox_pass_key_free(Tox_Pass_Key *key);

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
        Tox_Err_Key_Derivation *error);

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
        const uint8_t *salt, Tox_Err_Key_Derivation *error);

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
                          uint8_t *ciphertext, Tox_Err_Encryption *error);

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
                          uint8_t *plaintext, Tox_Err_Decryption *error);

typedef enum Tox_Err_Get_Salt {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GET_SALT_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_GET_SALT_NULL,

    /**
     * The input data is missing the magic number (i.e. wasn't created by this
     * module, or is corrupted).
     */
    TOX_ERR_GET_SALT_BAD_FORMAT,

} Tox_Err_Get_Salt;


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
bool tox_get_salt(const uint8_t *ciphertext, uint8_t *salt, Tox_Err_Get_Salt *error);

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
bool tox_is_data_encrypted(const uint8_t *data);


#ifdef __cplusplus
}
#endif

//!TOKSTYLE-

typedef Tox_Err_Key_Derivation TOX_ERR_KEY_DERIVATION;
typedef Tox_Err_Encryption TOX_ERR_ENCRYPTION;
typedef Tox_Err_Decryption TOX_ERR_DECRYPTION;
typedef Tox_Err_Get_Salt TOX_ERR_GET_SALT;

//!TOKSTYLE+

#endif // C_TOXCORE_TOXENCRYPTSAVE_TOXENCRYPTSAVE_H
