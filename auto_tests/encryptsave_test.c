#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "helpers.h"

#include "../toxcore/tox.h"

#include "../toxencryptsave/toxencryptsave.h"
#include "../toxcore/crypto_core.h"
#ifdef VANILLA_NACL
#include "../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/crypto_pwhash_scryptsalsa208sha256.h"
#include "../toxencryptsave/crypto_pwhash_scryptsalsa208sha256/utils.h" /* sodium_memzero */
#endif

unsigned char salt[32] = {0xB1, 0xC2, 0x09, 0xEE, 0x50, 0x6C, 0xF0, 0x20, 0xC4, 0xD6, 0xEB, 0xC0, 0x44, 0x51, 0x3B, 0x60, 0x4B, 0x39, 0x4A, 0xCF, 0x09, 0x53, 0x4F, 0xEA, 0x08, 0x41, 0xFA, 0xCA, 0x66, 0xD2, 0x68, 0x7F};
unsigned char known_key[crypto_box_BEFORENMBYTES] = {0x29, 0x36, 0x1c, 0x9e, 0x65, 0xbb, 0x46, 0x8b, 0xde, 0xa1, 0xac, 0xf, 0xd5, 0x11, 0x81, 0xc8, 0x29, 0x28, 0x17, 0x23, 0xa6, 0xc3, 0x6b, 0x77, 0x2e, 0xd7, 0xd3, 0x10, 0xeb, 0xd2, 0xf7, 0xc8};
char *pw = "hunter2";
unsigned int pwlen = 7;

unsigned char known_key2[crypto_box_BEFORENMBYTES] = {0x7a, 0xfa, 0x95, 0x45, 0x36, 0x8a, 0xa2, 0x5c, 0x40, 0xfd, 0xc0, 0xe2, 0x35, 0x8, 0x7, 0x88, 0xfa, 0xf9, 0x37, 0x86, 0xeb, 0xff, 0x50, 0x4f, 0x3, 0xe2, 0xf6, 0xd9, 0xef, 0x9, 0x17, 0x1};
// same as above, except standard opslimit instead of extra ops limit for test_known_kdf, and hash pw before kdf for compat

/* cause I'm shameless */
void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536)
        return;

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}

START_TEST(test_known_kdf)
{
    unsigned char out[crypto_box_BEFORENMBYTES];
    crypto_pwhash_scryptsalsa208sha256(out,
                                       crypto_box_BEFORENMBYTES,
                                       pw,
                                       pwlen,
                                       salt,
                                       crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE * 8,
                                       crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    ck_assert_msg(memcmp(out, known_key, crypto_box_BEFORENMBYTES) == 0, "derived key is wrong");
}
END_TEST

START_TEST(test_save_friend)
{
    Tox *tox1 = tox_new(0);
    Tox *tox2 = tox_new(0);
    ck_assert_msg(tox1 || tox2, "Failed to create 2 tox instances");
    uint32_t to_compare = 974536;
    tox_callback_friend_request(tox2, accept_friend_request, &to_compare);
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(tox2, address);
    int test = tox_add_friend(tox1, address, (uint8_t *)"Gentoo", 7);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint32_t size = tox_encrypted_size(tox1);
    uint8_t data[size];
    test = tox_encrypted_save(tox1, data, "correcthorsebatterystaple", 25);
    ck_assert_msg(test == 0, "failed to encrypted save");
    ck_assert_msg(tox_is_save_encrypted(data) == 1, "magic number missing");

    Tox *tox3 = tox_new(0);
    test = tox_encrypted_load(tox3, data, size, "correcthorsebatterystaple", 25);
    ck_assert_msg(test == 0, "failed to encrypted load");
    uint8_t address2[TOX_CLIENT_ID_SIZE];
    test = tox_get_client_id(tox3, 0, address2);
    ck_assert_msg(test == 0, "no friends!");
    ck_assert_msg(memcmp(address, address2, TOX_CLIENT_ID_SIZE) == 0, "addresses don't match!");

    size = tox_encrypted_size(tox3);
    uint8_t data2[size];
    uint8_t key[32 + crypto_box_BEFORENMBYTES];
    memcpy(key, salt, 32);
    memcpy(key + 32, known_key2, crypto_box_BEFORENMBYTES);
    test = tox_encrypted_key_save(tox3, data2, key);
    ck_assert_msg(test == 0, "failed to encrypted save the second");
    ck_assert_msg(tox_is_save_encrypted(data2) == 1, "magic number the second missing");

    // first test tox_encrypted_key_load
    Tox *tox4 = tox_new(0);
    test = tox_encrypted_key_load(tox4, data2, size, key);
    ck_assert_msg(test == 0, "failed to encrypted load the second");
    uint8_t address4[TOX_CLIENT_ID_SIZE];
    test = tox_get_client_id(tox4, 0, address4);
    ck_assert_msg(test == 0, "no friends! the second");
    ck_assert_msg(memcmp(address, address2, TOX_CLIENT_ID_SIZE) == 0, "addresses don't match! the second");

    // now test compaitibilty with tox_encrypted_load, first manually...
    uint8_t out1[size], out2[size];
    printf("Trying to decrypt from pw:\n");
    uint32_t sz1 = tox_pass_decrypt(data2, size, pw, pwlen, out1);
    uint32_t sz2 = tox_pass_key_decrypt(data2, size, key, out2);
    ck_assert_msg(sz1 == sz2, "differing output sizes");
    ck_assert_msg(memcmp(out1, out2, sz1) == 0, "differing output data");

    // and now with the code in use (I only bothered with manually to debug this, and it seems a waste
    // to remove the manual check now that it's there)
    Tox *tox5 = tox_new(0);
    test = tox_encrypted_load(tox5, data2, size, pw, pwlen);
    ck_assert_msg(test == 0, "failed to encrypted load the third");
    uint8_t address5[TOX_CLIENT_ID_SIZE];
    test = tox_get_client_id(tox4, 0, address5);
    ck_assert_msg(test == 0, "no friends! the third");
    ck_assert_msg(memcmp(address, address2, TOX_CLIENT_ID_SIZE) == 0, "addresses don't match! the third");
}
END_TEST

START_TEST(test_keys)
{
    uint8_t key[tox_pass_key_length()];
    tox_derive_key_from_pass("123qweasdzxc", 12, key);
    uint8_t *string = "No Patrick, mayonnaise is not an instrument."; // 44

    uint8_t encrypted[44 + tox_pass_encryption_extra_length()];
    int sz = tox_pass_key_encrypt(string, 44, key, encrypted);

    uint8_t encrypted2[44 + tox_pass_encryption_extra_length()];
    int sz2 = tox_pass_encrypt(string, 44, "123qweasdzxc", 12, encrypted2);

    ck_assert_msg(sz == sz2, "an encryption failed");

    uint8_t out1[44 + tox_pass_encryption_extra_length()];
    uint8_t out2[44 + tox_pass_encryption_extra_length()];

    sz = tox_pass_key_decrypt(encrypted, 44 + tox_pass_encryption_extra_length(), key, out1);
    ck_assert_msg(sz == 44, "sz isn't right");
    ck_assert_msg(memcmp(out1, string, 44) == 0, "decryption 1 failed");

    sz2 = tox_pass_decrypt(encrypted2, 44 + tox_pass_encryption_extra_length(), "123qweasdzxc", 12, out2);
    ck_assert_msg(sz2 == 44, "sz2 isn't right");
    ck_assert_msg(memcmp(out2, string, 44) == 0, "decryption 2 failed");

    // test that pass_decrypt can decrypt things from pass_key_encrypt
    sz = tox_pass_decrypt(encrypted, 44 + tox_pass_encryption_extra_length(), "123qweasdzxc", 12, out1);
    ck_assert_msg(sz == 44, "sz isn't right");
    ck_assert_msg(memcmp(out1, string, 44) == 0, "decryption 3 failed");

    uint8_t salt[tox_pass_salt_length()];
    ck_assert_msg(0 == tox_get_salt(encrypted, salt), "couldn't get salt");
    uint8_t key2[tox_pass_key_length()];
    tox_derive_key_with_salt("123qweasdzxc", 12, salt, key2);
    ck_assert_msg(0 == memcmp(key, key2, tox_pass_key_length()), "salt comparison failed");
}
END_TEST

Suite *encryptsave_suite(void)
{
    Suite *s = suite_create("encryptsave");

    DEFTESTCASE_SLOW(known_kdf, 60); /* is 5-10 seconds on my computer, but is directly dependent on CPU */
    DEFTESTCASE(save_friend);
    DEFTESTCASE(keys);

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

