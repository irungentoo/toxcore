#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sodium.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"
#include "auto_test_support.h"
#include "check_compat.h"

static unsigned char test_salt[TOX_PASS_SALT_LENGTH] = {0xB1, 0xC2, 0x09, 0xEE, 0x50, 0x6C, 0xF0, 0x20, 0xC4, 0xD6, 0xEB, 0xC0, 0x44, 0x51, 0x3B, 0x60, 0x4B, 0x39, 0x4A, 0xCF, 0x09, 0x53, 0x4F, 0xEA, 0x08, 0x41, 0xFA, 0xCA, 0x66, 0xD2, 0x68, 0x7F};
static unsigned char known_key[TOX_PASS_KEY_LENGTH] = {0x29, 0x36, 0x1c, 0x9e, 0x65, 0xbb, 0x46, 0x8b, 0xde, 0xa1, 0xac, 0xf, 0xd5, 0x11, 0x81, 0xc8, 0x29, 0x28, 0x17, 0x23, 0xa6, 0xc3, 0x6b, 0x77, 0x2e, 0xd7, 0xd3, 0x10, 0xeb, 0xd2, 0xf7, 0xc8};
static const char *pw = "hunter2";
static unsigned int pwlen = 7;

static unsigned char known_key2[CRYPTO_SHARED_KEY_SIZE] = {0x7a, 0xfa, 0x95, 0x45, 0x36, 0x8a, 0xa2, 0x5c, 0x40, 0xfd, 0xc0, 0xe2, 0x35, 0x8, 0x7, 0x88, 0xfa, 0xf9, 0x37, 0x86, 0xeb, 0xff, 0x50, 0x4f, 0x3, 0xe2, 0xf6, 0xd9, 0xef, 0x9, 0x17, 0x1};
// same as above, except standard opslimit instead of extra ops limit for test_known_kdf, and hash pw before kdf for compat

/* cause I'm shameless */
static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}

static void test_known_kdf(void)
{
    unsigned char out[CRYPTO_SHARED_KEY_SIZE];
    int16_t res = crypto_pwhash_scryptsalsa208sha256(out,
                  CRYPTO_SHARED_KEY_SIZE,
                  pw,
                  pwlen,
                  test_salt,
                  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 8,
                  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    ck_assert_msg(res != -1, "crypto function failed");
    ck_assert_msg(memcmp(out, known_key, CRYPTO_SHARED_KEY_SIZE) == 0, "derived key is wrong");
}

static void test_save_friend(void)
{
    Tox *tox1 = tox_new_log(nullptr, nullptr, nullptr);
    Tox *tox2 = tox_new_log(nullptr, nullptr, nullptr);
    ck_assert_msg(tox1 || tox2, "Failed to create 2 tox instances");
    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox1, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test != UINT32_MAX, "Failed to add friend");

    size_t size = tox_get_savedata_size(tox1);
    uint8_t *data = (uint8_t *)malloc(size);
    ck_assert(data != nullptr);
    tox_get_savedata(tox1, data);
    size_t size2 = size + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *enc_data = (uint8_t *)malloc(size2);
    ck_assert(enc_data != nullptr);
    Tox_Err_Encryption error1;
    bool ret = tox_pass_encrypt(data, size, (const uint8_t *)"correcthorsebatterystaple", 25, enc_data, &error1);
    ck_assert_msg(ret, "failed to encrypted save: %d", error1);
    ck_assert_msg(tox_is_data_encrypted(enc_data), "magic number missing");

    struct Tox_Options *options = tox_options_new(nullptr);
    ck_assert(options != nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, enc_data, size2);

    Tox_Err_New err2;
    Tox *tox3 = tox_new_log(options, &err2, nullptr);
    ck_assert_msg(err2 == TOX_ERR_NEW_LOAD_ENCRYPTED, "wrong error! %d. should fail with %d", err2,
                  TOX_ERR_NEW_LOAD_ENCRYPTED);
    ck_assert_msg(tox3 == nullptr, "tox_new with error should return NULL");
    uint8_t *dec_data = (uint8_t *)malloc(size);
    ck_assert(dec_data != nullptr);
    Tox_Err_Decryption err3;
    ret = tox_pass_decrypt(enc_data, size2, (const uint8_t *)"correcthorsebatterystaple", 25, dec_data, &err3);
    ck_assert_msg(ret, "failed to decrypt save: %d", err3);
    tox_options_set_savedata_data(options, dec_data, size);
    tox3 = tox_new_log(options, &err2, nullptr);
    ck_assert_msg(err2 == TOX_ERR_NEW_OK, "failed to load from decrypted data: %d", err2);
    uint8_t address2[TOX_PUBLIC_KEY_SIZE];
    ret = tox_friend_get_public_key(tox3, 0, address2, nullptr);
    ck_assert_msg(ret, "no friends!");
    ck_assert_msg(memcmp(address, address2, TOX_PUBLIC_KEY_SIZE) == 0, "addresses don't match!");

    size = tox_get_savedata_size(tox3);
    uint8_t *data2 = (uint8_t *)malloc(size);
    ck_assert(data2 != nullptr);
    tox_get_savedata(tox3, data2);
    Tox_Err_Key_Derivation keyerr;
    Tox_Pass_Key *key = tox_pass_key_derive((const uint8_t *)"123qweasdzxc", 12, &keyerr);
    ck_assert_msg(key != nullptr, "pass key allocation failure");
    memcpy((uint8_t *)key, test_salt, TOX_PASS_SALT_LENGTH);
    memcpy((uint8_t *)key + TOX_PASS_SALT_LENGTH, known_key2, TOX_PASS_KEY_LENGTH);
    size2 = size + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *encdata2 = (uint8_t *)malloc(size2);
    ck_assert(encdata2 != nullptr);
    ret = tox_pass_key_encrypt(key, data2, size, encdata2, &error1);
    ck_assert_msg(ret, "failed to key encrypt %d", error1);
    ck_assert_msg(tox_is_data_encrypted(encdata2), "magic number the second missing");

    uint8_t *out1 = (uint8_t *)malloc(size);
    ck_assert(out1 != nullptr);
    uint8_t *out2 = (uint8_t *)malloc(size);
    ck_assert(out2 != nullptr);
    ret = tox_pass_decrypt(encdata2, size2, (const uint8_t *)pw, pwlen, out1, &err3);
    ck_assert_msg(ret, "failed to pw decrypt %d", err3);
    ret = tox_pass_key_decrypt(key, encdata2, size2, out2, &err3);
    ck_assert_msg(ret, "failed to key decrypt %d", err3);
    ck_assert_msg(memcmp(out1, out2, size) == 0, "differing output data");

    // and now with the code in use (I only bothered with manually to debug this, and it seems a waste
    // to remove the manual check now that it's there)
    tox_options_set_savedata_data(options, out1, size);
    Tox *tox4 = tox_new_log(options, &err2, nullptr);
    ck_assert_msg(err2 == TOX_ERR_NEW_OK, "failed to new the third");
    uint8_t address5[TOX_PUBLIC_KEY_SIZE];
    ret = tox_friend_get_public_key(tox4, 0, address5, nullptr);
    ck_assert_msg(ret, "no friends! the third");
    ck_assert_msg(memcmp(address, address2, TOX_PUBLIC_KEY_SIZE) == 0, "addresses don't match! the third");

    tox_pass_key_free(key);
    tox_options_free(options);

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
    tox_kill(tox4);

    free(out2);
    free(out1);
    free(encdata2);
    free(data2);
    free(dec_data);
    free(enc_data);
    free(data);
}

static void test_keys(void)
{
    Tox_Err_Encryption encerr;
    Tox_Err_Decryption decerr;
    Tox_Err_Key_Derivation keyerr;
    const uint8_t *key_char = (const uint8_t *)"123qweasdzxc";
    Tox_Pass_Key *key = tox_pass_key_derive(key_char, 12, &keyerr);
    ck_assert_msg(key != nullptr, "generic failure 1: %d", keyerr);
    const uint8_t *string = (const uint8_t *)"No Patrick, mayonnaise is not an instrument."; // 44

    uint8_t encrypted[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
    bool ret = tox_pass_key_encrypt(key, string, 44, encrypted, &encerr);
    ck_assert_msg(ret, "generic failure 2: %d", encerr);

    // Testing how tox handles encryption of large messages.
    int size_large = 30 * 1024 * 1024;
    int ciphertext_length2a = size_large + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    int plaintext_length2a = size_large;
    uint8_t *encrypted2a = (uint8_t *)malloc(ciphertext_length2a);
    ck_assert(encrypted2a != nullptr);
    uint8_t *in_plaintext2a = (uint8_t *)malloc(plaintext_length2a);
    ck_assert(in_plaintext2a != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    random_bytes(rng, in_plaintext2a, plaintext_length2a);
    ret = tox_pass_encrypt(in_plaintext2a, plaintext_length2a, key_char, 12, encrypted2a, &encerr);
    ck_assert_msg(ret, "tox_pass_encrypt failure 2a: %d", encerr);

    // Decryption of same message.
    uint8_t *out_plaintext2a = (uint8_t *)malloc(plaintext_length2a);
    ck_assert(out_plaintext2a != nullptr);
    ret = tox_pass_decrypt(encrypted2a, ciphertext_length2a, key_char, 12, out_plaintext2a, &decerr);
    ck_assert_msg(ret, "tox_pass_decrypt failure 2a: %d", decerr);
    ck_assert_msg(memcmp(in_plaintext2a, out_plaintext2a, plaintext_length2a) == 0, "Large message decryption failed");
    free(encrypted2a);
    free(in_plaintext2a);
    free(out_plaintext2a);

    uint8_t encrypted2[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
    ret = tox_pass_encrypt(string, 44, key_char, 12, encrypted2, &encerr);
    ck_assert_msg(ret, "generic failure 3: %d", encerr);

    uint8_t out1[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
    uint8_t out2[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];

    ret = tox_pass_key_decrypt(key, encrypted, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, out1, &decerr);
    ck_assert_msg(ret, "generic failure 4: %d", decerr);
    ck_assert_msg(memcmp(out1, string, 44) == 0, "decryption 1 failed");

    ret = tox_pass_decrypt(encrypted2, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)"123qweasdzxc", 12, out2,
                           &decerr);
    ck_assert_msg(ret, "generic failure 5: %d", decerr);
    ck_assert_msg(memcmp(out2, string, 44) == 0, "decryption 2 failed");

    ret = tox_pass_decrypt(encrypted2, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, nullptr, 0, out2, &decerr);
    ck_assert_msg(!ret, "Decrypt succeeded with wrong pass");
    ck_assert_msg(decerr != TOX_ERR_DECRYPTION_FAILED, "Bad error code %d", decerr);

    // test that pass_decrypt can decrypt things from pass_key_encrypt
    ret = tox_pass_decrypt(encrypted, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)"123qweasdzxc", 12, out1,
                           &decerr);
    ck_assert_msg(ret, "generic failure 6: %d", decerr);
    ck_assert_msg(memcmp(out1, string, 44) == 0, "decryption 3 failed");

    uint8_t salt[TOX_PASS_SALT_LENGTH];
    Tox_Err_Get_Salt salt_err;
    ck_assert_msg(tox_get_salt(encrypted, salt, &salt_err), "couldn't get salt");
    ck_assert_msg(salt_err == TOX_ERR_GET_SALT_OK, "get_salt returned an error");
    Tox_Pass_Key *key2 = tox_pass_key_derive_with_salt((const uint8_t *)"123qweasdzxc", 12, salt, &keyerr);
    ck_assert_msg(key2 != nullptr, "generic failure 7: %d", keyerr);
    ck_assert_msg(0 == memcmp(key, key2, TOX_PASS_KEY_LENGTH + TOX_PASS_SALT_LENGTH), "salt comparison failed");
    tox_pass_key_free(key2);
    tox_pass_key_free(key);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    test_known_kdf();
    test_save_friend();
    test_keys();

    return 0;
}
