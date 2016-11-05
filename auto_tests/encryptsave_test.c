#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "helpers.h"

#include "../toxcore/tox.h"

#include "../toxcore/crypto_core.h"
#include "../toxencryptsave/toxencryptsave.h"
#ifdef VANILLA_NACL
#include "../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/crypto_pwhash_scryptsalsa208sha256.h"
#endif

static unsigned char test_salt[32] = {0xB1, 0xC2, 0x09, 0xEE, 0x50, 0x6C, 0xF0, 0x20, 0xC4, 0xD6, 0xEB, 0xC0, 0x44, 0x51, 0x3B, 0x60, 0x4B, 0x39, 0x4A, 0xCF, 0x09, 0x53, 0x4F, 0xEA, 0x08, 0x41, 0xFA, 0xCA, 0x66, 0xD2, 0x68, 0x7F};
static unsigned char known_key[crypto_box_BEFORENMBYTES] = {0x29, 0x36, 0x1c, 0x9e, 0x65, 0xbb, 0x46, 0x8b, 0xde, 0xa1, 0xac, 0xf, 0xd5, 0x11, 0x81, 0xc8, 0x29, 0x28, 0x17, 0x23, 0xa6, 0xc3, 0x6b, 0x77, 0x2e, 0xd7, 0xd3, 0x10, 0xeb, 0xd2, 0xf7, 0xc8};
static const char *pw = "hunter2";
static unsigned int pwlen = 7;

static unsigned char known_key2[crypto_box_BEFORENMBYTES] = {0x7a, 0xfa, 0x95, 0x45, 0x36, 0x8a, 0xa2, 0x5c, 0x40, 0xfd, 0xc0, 0xe2, 0x35, 0x8, 0x7, 0x88, 0xfa, 0xf9, 0x37, 0x86, 0xeb, 0xff, 0x50, 0x4f, 0x3, 0xe2, 0xf6, 0xd9, 0xef, 0x9, 0x17, 0x1};
// same as above, except standard opslimit instead of extra ops limit for test_known_kdf, and hash pw before kdf for compat

/* cause I'm shameless */
static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, 0);
    }
}

START_TEST(test_known_kdf)
{
    unsigned char out[crypto_box_BEFORENMBYTES];
    int res = crypto_pwhash_scryptsalsa208sha256(out,
              crypto_box_BEFORENMBYTES,
              pw,
              pwlen,
              test_salt,
              crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 8,
              crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    ck_assert_msg(res != -1, "crypto function failed");
    ck_assert_msg(memcmp(out, known_key, crypto_box_BEFORENMBYTES) == 0, "derived key is wrong");
}
END_TEST

START_TEST(test_save_friend)
{
    Tox *tox1 = tox_new_log(0, 0, 0);
    Tox *tox2 = tox_new_log(0, 0, 0);
    ck_assert_msg(tox1 || tox2, "Failed to create 2 tox instances");
    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox1, address, (const uint8_t *)"Gentoo", 7, 0);
    ck_assert_msg(test != UINT32_MAX, "Failed to add friend");

    size_t size = tox_get_savedata_size(tox1);
    uint8_t data[size];
    tox_get_savedata(tox1, data);
    size_t size2 = size + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t enc_data[size2];
    TOX_ERR_ENCRYPTION error1;
    bool ret = tox_pass_encrypt(data, size, (const uint8_t *)"correcthorsebatterystaple", 25, enc_data, &error1);
    ck_assert_msg(ret, "failed to encrypted save: %u", error1);
    ck_assert_msg(tox_is_data_encrypted(enc_data), "magic number missing");

    struct Tox_Options options;
    tox_options_default(&options);
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options.savedata_data = enc_data;
    options.savedata_length = size2;

    TOX_ERR_NEW err2;
    Tox *tox3 = tox_new_log(&options, &err2, 0);
    ck_assert_msg(err2 == TOX_ERR_NEW_LOAD_ENCRYPTED, "wrong error! %u. should fail with %u", err2,
                  TOX_ERR_NEW_LOAD_ENCRYPTED);
    ck_assert_msg(tox3 == NULL, "tox_new with error should return NULL");
    uint8_t dec_data[size];
    TOX_ERR_DECRYPTION err3;
    ret = tox_pass_decrypt(enc_data, size2, (const uint8_t *)"correcthorsebatterystaple", 25, dec_data, &err3);
    ck_assert_msg(ret, "failed to decrypt save: %u", err3);
    options.savedata_data = dec_data;
    options.savedata_length = size;
    tox3 = tox_new_log(&options, &err2, 0);
    ck_assert_msg(err2 == TOX_ERR_NEW_OK, "failed to load from decrypted data: %u", err2);
    uint8_t address2[TOX_PUBLIC_KEY_SIZE];
    ret = tox_friend_get_public_key(tox3, 0, address2, 0);
    ck_assert_msg(ret, "no friends!");
    ck_assert_msg(memcmp(address, address2, TOX_PUBLIC_KEY_SIZE) == 0, "addresses don't match!");

    size = tox_get_savedata_size(tox3);
    uint8_t data2[size];
    tox_get_savedata(tox3, data2);
    TOX_PASS_KEY key;
    memcpy(key.salt, test_salt, 32);
    memcpy(key.key, known_key2, crypto_box_BEFORENMBYTES);
    size2 = size + TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t encdata2[size2];
    ret = tox_pass_key_encrypt(data2, size, &key, encdata2, &error1);
    ck_assert_msg(ret, "failed to key encrypt %u", error1);
    ck_assert_msg(tox_is_data_encrypted(encdata2), "magic number the second missing");

    uint8_t out1[size], out2[size];
    ret = tox_pass_decrypt(encdata2, size2, (const uint8_t *)pw, pwlen, out1, &err3);
    ck_assert_msg(ret, "failed to pw decrypt %u", err3);
    ret = tox_pass_key_decrypt(encdata2, size2, &key, out2, &err3);
    ck_assert_msg(ret, "failed to key decrypt %u", err3);
    ck_assert_msg(memcmp(out1, out2, size) == 0, "differing output data");

    // and now with the code in use (I only bothered with manually to debug this, and it seems a waste
    // to remove the manual check now that it's there)
    options.savedata_data = out1;
    options.savedata_length = size;
    Tox *tox4 = tox_new_log(&options, &err2, 0);
    ck_assert_msg(err2 == TOX_ERR_NEW_OK, "failed to new the third");
    uint8_t address5[TOX_PUBLIC_KEY_SIZE];
    ret = tox_friend_get_public_key(tox4, 0, address5, 0);
    ck_assert_msg(ret, "no friends! the third");
    ck_assert_msg(memcmp(address, address2, TOX_PUBLIC_KEY_SIZE) == 0, "addresses don't match! the third");

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
    tox_kill(tox4);
}
END_TEST

START_TEST(test_keys)
{
    TOX_ERR_ENCRYPTION encerr;
    TOX_ERR_DECRYPTION decerr;
    TOX_ERR_KEY_DERIVATION keyerr;
    TOX_PASS_KEY key;
    bool ret = tox_derive_key_from_pass((const uint8_t *)"123qweasdzxc", 12, &key, &keyerr);
    ck_assert_msg(ret, "generic failure 1: %u", keyerr);
    const uint8_t *string = (const uint8_t *)"No Patrick, mayonnaise is not an instrument."; // 44

    uint8_t encrypted[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
    ret = tox_pass_key_encrypt(string, 44, &key, encrypted, &encerr);
    ck_assert_msg(ret, "generic failure 2: %u", encerr);

    uint8_t encrypted2[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
    ret = tox_pass_encrypt(string, 44, (const uint8_t *)"123qweasdzxc", 12, encrypted2, &encerr);
    ck_assert_msg(ret, "generic failure 3: %u", encerr);

    uint8_t out1[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];
    uint8_t out2[44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH];

    ret = tox_pass_key_decrypt(encrypted, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, &key, out1, &decerr);
    ck_assert_msg(ret, "generic failure 4: %u", decerr);
    ck_assert_msg(memcmp(out1, string, 44) == 0, "decryption 1 failed");

    ret = tox_pass_decrypt(encrypted2, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)"123qweasdzxc", 12, out2,
                           &decerr);
    ck_assert_msg(ret, "generic failure 5: %u", decerr);
    ck_assert_msg(memcmp(out2, string, 44) == 0, "decryption 2 failed");

    ret = tox_pass_decrypt(encrypted2, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, NULL, 0, out2, &decerr);
    ck_assert_msg(!ret, "Decrypt succeeded with wrong pass");
    ck_assert_msg(decerr != TOX_ERR_DECRYPTION_FAILED, "Bad error code %u", decerr);

    // test that pass_decrypt can decrypt things from pass_key_encrypt
    ret = tox_pass_decrypt(encrypted, 44 + TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)"123qweasdzxc", 12, out1,
                           &decerr);
    ck_assert_msg(ret, "generic failure 6: %u", decerr);
    ck_assert_msg(memcmp(out1, string, 44) == 0, "decryption 3 failed");

    uint8_t salt[TOX_PASS_SALT_LENGTH];
    ck_assert_msg(tox_get_salt(encrypted, salt), "couldn't get salt");
    TOX_PASS_KEY key2;
    ret = tox_derive_key_with_salt((const uint8_t *)"123qweasdzxc", 12, salt, &key2, &keyerr);
    ck_assert_msg(ret, "generic failure 7: %u", keyerr);
    ck_assert_msg(0 == memcmp(&key, &key2, sizeof(TOX_PASS_KEY)), "salt comparison failed");
}
END_TEST

static Suite *encryptsave_suite(void)
{
    Suite *s = suite_create("encryptsave");

    DEFTESTCASE_SLOW(known_kdf, 60);
    DEFTESTCASE_SLOW(save_friend, 20);
    DEFTESTCASE_SLOW(keys, 30);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *encryptsave =  encryptsave_suite();
    SRunner *test_runner = srunner_create(encryptsave);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
