%{
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2016 Tox Developers.
 */

/*
 * Batch encryption functions.
 */
#ifndef C_TOXCORE_TOXENCRYPTSAVE_TOXENCRYPTSAVE_H
#define C_TOXCORE_TOXENCRYPTSAVE_TOXENCRYPTSAVE_H

//!TOKSTYLE-

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
%}

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
 * ${tox.pass_Key.derive}, then use the derived key to encrypt the data.
 *
 * The encrypted data is prepended with a magic number, to aid validity
 * checking (no guarantees are made of course). Any data to be decrypted must
 * start with the magic number.
 *
 * Clients should consider alerting their users that, unlike plain data, if
 * even one bit becomes corrupted, the data will be entirely unrecoverable.
 * Ditto if they forget their password, there is no way to recover the data.
 *
 *******************************************************************************/

class tox {

/**
 * The size of the salt part of a pass-key.
 */
const PASS_SALT_LENGTH                  = 32;
/**
 * The size of the key part of a pass-key.
 */
const PASS_KEY_LENGTH                   = 32;
/**
 * The amount of additional data required to store any encrypted byte array.
 * Encrypting an array of N bytes requires N + $PASS_ENCRYPTION_EXTRA_LENGTH
 * bytes in the encrypted byte array.
 */
const PASS_ENCRYPTION_EXTRA_LENGTH      = 80;

error for key_derivation {
  NULL,
  /**
   * The crypto lib was unable to derive a key from the given passphrase,
   * which is usually a lack of memory issue.
   */
  FAILED,
}

error for encryption {
  NULL,
  /**
   * The crypto lib was unable to derive a key from the given passphrase,
   * which is usually a lack of memory issue. The functions accepting keys
   * do not produce this error.
   */
  KEY_DERIVATION_FAILED,
  /**
   * The encryption itself failed.
   */
  FAILED,
}

error for decryption {
  NULL,
  /**
   * The input data was shorter than $PASS_ENCRYPTION_EXTRA_LENGTH bytes
   */
  INVALID_LENGTH,
  /**
   * The input data is missing the magic number (i.e. wasn't created by this
   * module, or is corrupted).
   */
  BAD_FORMAT,
  /**
   * The crypto lib was unable to derive a key from the given passphrase,
   * which is usually a lack of memory issue. The functions accepting keys
   * do not produce this error.
   */
  KEY_DERIVATION_FAILED,
  /**
   * The encrypted byte array could not be decrypted. Either the data was
   * corrupted or the password/key was incorrect.
   */
  FAILED,
}


/*******************************************************************************
 *
 *                                BEGIN PART 1
 *
 * The simple API is presented first. If your code spends too much time using
 * these functions, consider using the advanced functions instead and caching
 * the generated pass-key.
 *
 *******************************************************************************/

/**
 * Encrypts the given data with the given passphrase.
 *
 * The output array must be at least `plaintext_len + $PASS_ENCRYPTION_EXTRA_LENGTH`
 * bytes long. This delegates to ${pass_Key.derive} and
 * ${pass_Key.encrypt}.
 *
 * @param plaintext A byte array of length `plaintext_len`.
 * @param plaintext_len The length of the plain text array. Bigger than 0.
 * @param passphrase The user-provided password. Can be empty.
 * @param passphrase_len The length of the password.
 * @param ciphertext The cipher text array to write the encrypted data to.
 *
 * @return true on success.
 */
static bool pass_encrypt(const uint8_t[plaintext_len] plaintext, const uint8_t[passphrase_len] passphrase, uint8_t *ciphertext)
    with error for encryption;


/**
 * Decrypts the given data with the given passphrase.
 *
 * The output array must be at least `ciphertext_len - $PASS_ENCRYPTION_EXTRA_LENGTH`
 * bytes long. This delegates to ${pass_Key.decrypt}.
 *
 * @param ciphertext A byte array of length `ciphertext_len`.
 * @param ciphertext_len The length of the cipher text array. At least $PASS_ENCRYPTION_EXTRA_LENGTH.
 * @param passphrase The user-provided password. Can be empty.
 * @param passphrase_len The length of the password.
 * @param plaintext The plain text array to write the decrypted data to.
 *
 * @return true on success.
 */
static bool pass_decrypt(const uint8_t[ciphertext_len] ciphertext, const uint8_t[passphrase_len] passphrase, uint8_t *plaintext)
    with error for decryption;


/*******************************************************************************
 *
 *                                BEGIN PART 2
 *
 * And now part 2, which does the actual encryption, and can be used to write
 * less CPU intensive client code than part one.
 *
 *******************************************************************************/

class pass_Key {
  /**
   * This type represents a pass-key.
   *
   * A pass-key and a password are two different concepts: a password is given
   * by the user in plain text. A pass-key is the generated symmetric key used
   * for encryption and decryption. It is derived from a salt and the user-
   * provided password.
   *
   * The $this structure is hidden in the implementation. It can be created
   * using $derive or $derive_with_salt and must be deallocated using $free.
   */
  struct this;

  /**
   * Deallocate a $this. This function behaves like free(), so NULL is an
   * acceptable argument value.
   */
  void free();

  /**
   * Generates a secret symmetric key from the given passphrase.
   *
   * Be sure to not compromise the key! Only keep it in memory, do not write
   * it to disk.
   *
   * Note that this function is not deterministic; to derive the same key from
   * a password, you also must know the random salt that was used. A
   * deterministic version of this function is $derive_with_salt.
   *
   * @param passphrase The user-provided password. Can be empty.
   * @param passphrase_len The length of the password.
   *
   * @return true on success.
   */
  static this derive(const uint8_t[passphrase_len] passphrase)
      with error for key_derivation;

  /**
   * Same as above, except use the given salt for deterministic key derivation.
   *
   * @param passphrase The user-provided password. Can be empty.
   * @param passphrase_len The length of the password.
   * @param salt An array of at least $PASS_SALT_LENGTH bytes.
   *
   * @return true on success.
   */
  static this derive_with_salt(const uint8_t[passphrase_len] passphrase, const uint8_t[PASS_SALT_LENGTH] salt)
      with error for key_derivation;

  /**
   * Encrypt a plain text with a key produced by $derive or $derive_with_salt.
   *
   * The output array must be at least `plaintext_len + $PASS_ENCRYPTION_EXTRA_LENGTH`
   * bytes long.
   *
   * @param plaintext A byte array of length `plaintext_len`.
   * @param plaintext_len The length of the plain text array. Bigger than 0.
   * @param ciphertext The cipher text array to write the encrypted data to.
   *
   * @return true on success.
   */
  const bool encrypt(const uint8_t[plaintext_len] plaintext, uint8_t *ciphertext)
      with error for encryption;

  /**
   * This is the inverse of $encrypt, also using only keys produced by
   * $derive or $derive_with_salt.
   *
   * @param ciphertext A byte array of length `ciphertext_len`.
   * @param ciphertext_len The length of the cipher text array. At least $PASS_ENCRYPTION_EXTRA_LENGTH.
   * @param plaintext The plain text array to write the decrypted data to.
   *
   * @return true on success.
   */
  const bool decrypt(const uint8_t[ciphertext_len] ciphertext, uint8_t *plaintext)
      with error for decryption;
}

/**
 * Retrieves the salt used to encrypt the given data.
 *
 * The retrieved salt can then be passed to ${pass_Key.derive_with_salt} to
 * produce the same key as was previously used. Any data encrypted with this
 * module can be used as input.
 *
 * The cipher text must be at least $PASS_ENCRYPTION_EXTRA_LENGTH bytes in length.
 * The salt must be $PASS_SALT_LENGTH bytes in length.
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
static bool get_salt(const uint8_t *ciphertext, uint8_t[PASS_SALT_LENGTH] salt) {
  NULL,
  /**
   * The input data is missing the magic number (i.e. wasn't created by this
   * module, or is corrupted).
   */
  BAD_FORMAT,
}

/**
 * Determines whether or not the given data is encrypted by this module.
 *
 * It does this check by verifying that the magic number is the one put in
 * place by the encryption functions.
 *
 * The data must be at least $PASS_ENCRYPTION_EXTRA_LENGTH bytes in length.
 * If the passed byte array is smaller than required, the behaviour is
 * undefined.
 *
 * If the data pointer is NULL, the behaviour is undefined
 *
 * @return true if the data is encrypted by this module.
 */
static bool is_data_encrypted(const uint8_t *data);

}

%{

#ifdef __cplusplus
}
#endif

typedef TOX_ERR_KEY_DERIVATION Tox_Err_Key_Derivation;
typedef TOX_ERR_ENCRYPTION Tox_Err_Encryption;
typedef TOX_ERR_DECRYPTION Tox_Err_Decryption;
typedef TOX_ERR_GET_SALT Tox_Err_Get_Salt;

//!TOKSTYLE+

#endif // C_TOXCORE_TOXENCRYPTSAVE_TOXENCRYPTSAVE_H
%}
