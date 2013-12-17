#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"

#ifdef __WIN32__
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

void accept_friend_request(uint8_t *public_key, uint8_t *data, uint16_t length, void *userdata)
{
    Tox *t = userdata;

    if (length == 7 && memcmp("Gentoo", data, 7) == 0)
        tox_add_friend_norequest(t, public_key);
}

START_TEST(test_few_clients)
{
    long long unsigned int cur_time = time(NULL);
    Tox *tox1 = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    Tox *tox2 = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    Tox *tox3 = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    ck_assert_msg(tox1 || tox2 || tox3, "Failed to create 3 tox instances");
    tox_callback_friend_request(tox2, accept_friend_request, tox2);
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(tox2, address);
    int test = tox_add_friend(tox3, address, "Gentoo", 7);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    while (1) {
        tox_do(tox1);
        tox_do(tox2);
        tox_do(tox3);

        if (tox_get_friend_connection_status(tox2, 0) == 1 && tox_get_friend_connection_status(tox3, 0) == 1)
            break;

        c_sleep(50);
    }

    printf("test_few_clients succeeded, took %llu seconds\n", time(NULL) - cur_time);
}
END_TEST


#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);
Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox");

    DEFTESTCASE_SLOW(few_clients, 30);

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

