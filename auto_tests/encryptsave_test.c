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

unsigned char salt[32] = {0xB1,0xC2,0x09,0xEE,0x50,0x6C,0xF0,0x20,0xC4,0xD6,0xEB,0xC0,0x44,0x51,0x3B,0x60,0x4B,0x39,0x4A,0xCF,0x09,0x53,0x4F,0xEA,0x08,0x41,0xFA,0xCA,0x66,0xD2,0x68,0x7F};
unsigned char key[crypto_box_BEFORENMBYTES] = {0xd1, 0x7, 0x4e, 0xfc, 0x49, 0x2d, 0x99, 0x16, 0xba, 0x4a, 0x4c, 0xc4, 0x92, 0x9, 0xb0, 0x9a, 0xa1, 0xa2, 0xe8, 0xe3, 0x45, 0xe7, 0xf5, 0x50, 0x54, 0x61, 0xd7, 0x3e, 0x2, 0x38, 0xe6, 0xa4};
char* pw = "hunter2";
unsigned int pwlen = 7;

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
                                       crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
                                       crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
     ck_assert_msg(memcmp(out, key, crypto_box_BEFORENMBYTES) == 0, "derived key is wrong");
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
    ck_assert_msg(tox_is_data_encrypted(data) == 1, "magic number missing");
    Tox *tox3 = tox_new(0);
    test = tox_encrypted_load(tox3, data, size, "correcthorsebatterystaple", 25);
    ck_assert_msg(test == 0, "failed to encrypted load");
    uint8_t address2[TOX_CLIENT_ID_SIZE];
    test = tox_get_client_id(tox3, 0, address2);
    ck_assert_msg(test == 0, "no friends!");
    ck_assert_msg(memcmp(address, address2, TOX_CLIENT_ID_SIZE) == 0, "addresses don't match!");
}
END_TEST

Suite * encryptsave_suite(void)
{
    Suite *s = suite_create("encryptsave");

    DEFTESTCASE_SLOW(known_kdf, 60);
    DEFTESTCASE(save_friend);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite * encryptsave =  encryptsave_suite();
    SRunner *test_runner = srunner_create(encryptsave);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}

