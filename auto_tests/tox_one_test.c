/* Auto Tests: One instance.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

START_TEST(test_one)
{
    {
        TOX_ERR_OPTIONS_NEW o_err;
        struct Tox_Options *o1 = tox_options_new(&o_err);
        struct Tox_Options o2;
        tox_options_default(&o2);
        ck_assert_msg(o_err == TOX_ERR_OPTIONS_NEW_OK, "tox_options_new wrong error");
        ck_assert_msg(memcmp(o1, &o2, sizeof(struct Tox_Options)) == 0, "tox_options_new error");
        tox_options_free(o1);
    }

    uint32_t index[] = { 1, 2 };
    Tox *tox1 = tox_new_log(0, 0, &index[0]);
    Tox *tox2 = tox_new_log(0, 0, &index[1]);

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(tox1, &error) == 33445, "First Tox instance did not bind to udp port 33445.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox1, address);
    TOX_ERR_FRIEND_ADD error;
    uint32_t ret = tox_friend_add(tox1, address, (const uint8_t *)"m", 1, &error);
    ck_assert_msg(ret == UINT32_MAX && error == TOX_ERR_FRIEND_ADD_OWN_KEY, "Adding own address worked.");

    tox_self_get_address(tox2, address);
    uint8_t message[TOX_MAX_FRIEND_REQUEST_LENGTH + 1];
    ret = tox_friend_add(tox1, address, NULL, 0, &error);
    ck_assert_msg(ret == UINT32_MAX && error == TOX_ERR_FRIEND_ADD_NULL, "Sending request with no message worked.");
    ret = tox_friend_add(tox1, address, message, 0, &error);
    ck_assert_msg(ret == UINT32_MAX && error == TOX_ERR_FRIEND_ADD_NO_MESSAGE, "Sending request with no message worked.");
    ret = tox_friend_add(tox1, address, message, sizeof(message), &error);
    ck_assert_msg(ret == UINT32_MAX && error == TOX_ERR_FRIEND_ADD_TOO_LONG,
                  "TOX_MAX_FRIEND_REQUEST_LENGTH is too big.");

    address[0]++;
    ret = tox_friend_add(tox1, address, (const uint8_t *)"m", 1, &error);
    ck_assert_msg(ret == UINT32_MAX && error == TOX_ERR_FRIEND_ADD_BAD_CHECKSUM,
                  "Adding address with bad checksum worked.");

    tox_self_get_address(tox2, address);
    ret = tox_friend_add(tox1, address, message, TOX_MAX_FRIEND_REQUEST_LENGTH, &error);
    ck_assert_msg(ret == 0 && error == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend.");
    ret = tox_friend_add(tox1, address, message, TOX_MAX_FRIEND_REQUEST_LENGTH, &error);
    ck_assert_msg(ret == UINT32_MAX && error == TOX_ERR_FRIEND_ADD_ALREADY_SENT, "Adding friend twice worked.");

    uint8_t name[TOX_MAX_NAME_LENGTH];
    int i;

    for (i = 0; i < TOX_MAX_NAME_LENGTH; ++i) {
        name[i] = rand();
    }

    tox_self_set_name(tox1, name, sizeof(name), 0);
    ck_assert_msg(tox_self_get_name_size(tox1) == sizeof(name), "Can't set name of TOX_MAX_NAME_LENGTH");

    tox_self_get_address(tox1, address);
    size_t save_size = tox_get_savedata_size(tox1);
    uint8_t data[save_size];
    tox_get_savedata(tox1, data);

    tox_kill(tox2);
    TOX_ERR_NEW err_n;

    struct Tox_Options options;
    tox_options_default(&options);
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options.savedata_data = data;
    options.savedata_length = save_size;
    tox2 = tox_new_log(&options, &err_n, &index[1]);
    ck_assert_msg(err_n == TOX_ERR_NEW_OK, "Load failed");

    ck_assert_msg(tox_self_get_name_size(tox2) == sizeof name, "Wrong name size.");

    uint8_t address2[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address2);
    ck_assert_msg(memcmp(address2, address, TOX_ADDRESS_SIZE) == 0, "Wrong address.");
    uint8_t new_name[TOX_MAX_NAME_LENGTH] = { 0 };
    tox_self_get_name(tox2, new_name);
    ck_assert_msg(memcmp(name, new_name, TOX_MAX_NAME_LENGTH) == 0, "Wrong name");

    uint8_t sk[TOX_SECRET_KEY_SIZE];
    tox_self_get_secret_key(tox2, sk);
    tox_kill(tox2);

    tox_options_default(&options);
    options.savedata_type = TOX_SAVEDATA_TYPE_SECRET_KEY;
    options.savedata_data = sk;
    options.savedata_length = sizeof(sk);
    tox2 = tox_new_log(&options, &err_n, &index[1]);
    ck_assert_msg(err_n == TOX_ERR_NEW_OK, "Load failed");
    uint8_t address3[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address3);
    ck_assert_msg(memcmp(address3, address, TOX_PUBLIC_KEY_SIZE) == 0, "Wrong public key.");
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, pk);
    ck_assert_msg(memcmp(pk, address, TOX_PUBLIC_KEY_SIZE) == 0, "Wrong public key.");

    tox_kill(tox1);
    tox_kill(tox2);
}
END_TEST


static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox one");

    DEFTESTCASE(one);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
