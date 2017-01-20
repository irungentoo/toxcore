/* Auto Tests: One instance.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

static void set_random_name_and_status_message(Tox *tox, uint8_t *name, uint8_t *status_message)
{
    int i;

    for (i = 0; i < TOX_MAX_NAME_LENGTH; ++i) {
        name[i] = rand();
    }

    for (i = 0; i < TOX_MAX_STATUS_MESSAGE_LENGTH; ++i) {
        status_message[i] = rand();
    }
}

START_TEST(test_one)
{
    uint8_t name[TOX_MAX_NAME_LENGTH];
    uint8_t status_message[TOX_MAX_STATUS_MESSAGE_LENGTH];

    uint8_t name2[TOX_MAX_NAME_LENGTH];
    uint8_t status_message2[TOX_MAX_STATUS_MESSAGE_LENGTH];

    uint32_t index[] = { 1, 2 };
    Tox *tox1 = tox_new_log(0, 0, &index[0]);
    set_random_name_and_status_message(tox1, name, status_message);
    Tox *tox2 = tox_new_log(0, 0, &index[1]);
    set_random_name_and_status_message(tox2, name2, status_message2);

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

    tox_self_set_name(tox1, name, sizeof(name), 0);
    ck_assert_msg(tox_self_get_name_size(tox1) == sizeof(name), "Can't set name of TOX_MAX_NAME_LENGTH");

    tox_self_set_status_message(tox1, status_message, sizeof(status_message), 0);
    ck_assert_msg(tox_self_get_status_message_size(tox1) == sizeof(status_message),
                  "Can't set status message of TOX_MAX_STATUS_MESSAGE_LENGTH");

    tox_self_get_address(tox1, address);
    size_t save_size = tox_get_savedata_size(tox1);
    VLA(uint8_t, data, save_size);
    tox_get_savedata(tox1, data);

    tox_kill(tox2);
    TOX_ERR_NEW err_n;

    struct Tox_Options *options = tox_options_new(NULL);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, data, save_size);
    tox2 = tox_new_log(options, &err_n, &index[1]);
    ck_assert_msg(err_n == TOX_ERR_NEW_OK, "Load failed");

    ck_assert_msg(tox_self_get_name_size(tox2) == sizeof name, "Wrong name size.");
    ck_assert_msg(tox_self_get_status_message_size(tox2) == sizeof status_message, "Wrong status message size");

    uint8_t name_loaded[TOX_MAX_NAME_LENGTH] = { 0 };
    tox_self_get_name(tox2, name_loaded);
    ck_assert_msg(!memcmp(name, name_loaded, sizeof name), "Wrong name.");

    uint8_t status_message_loaded[TOX_MAX_STATUS_MESSAGE_LENGTH] = { 0 };
    tox_self_get_status_message(tox2, status_message_loaded);
    ck_assert_msg(!memcmp(status_message, status_message_loaded, sizeof status_message_loaded), "Wrong status message.");

    uint8_t address2[TOX_ADDRESS_SIZE] = { 0 };
    tox_self_get_address(tox2, address2);
    ck_assert_msg(memcmp(address2, address, TOX_ADDRESS_SIZE) == 0, "Wrong address.");
    uint8_t new_name[TOX_MAX_NAME_LENGTH] = { 0 };
    tox_self_get_name(tox2, new_name);
    ck_assert_msg(memcmp(name, new_name, TOX_MAX_NAME_LENGTH) == 0, "Wrong name");

    uint8_t sk[TOX_SECRET_KEY_SIZE];
    tox_self_get_secret_key(tox2, sk);
    tox_kill(tox2);

    tox_options_default(options);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_SECRET_KEY);
    tox_options_set_savedata_data(options, sk, sizeof(sk));
    tox2 = tox_new_log(options, &err_n, &index[1]);
    ck_assert_msg(err_n == TOX_ERR_NEW_OK, "Load failed");
    uint8_t address3[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address3);
    ck_assert_msg(memcmp(address3, address, TOX_PUBLIC_KEY_SIZE) == 0, "Wrong public key.");
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, pk);
    ck_assert_msg(memcmp(pk, address, TOX_PUBLIC_KEY_SIZE) == 0, "Wrong public key.");

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(tox1, &error) == 33445, "First Tox instance did not bind to udp port 33445.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    tox_options_free(options);
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
