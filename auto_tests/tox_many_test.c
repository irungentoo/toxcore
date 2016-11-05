/* Auto Tests: Many clients.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, 0);
    }
}


#define NUM_TOXES 90
#define NUM_FRIENDS 50

START_TEST(test_many_clients)
{
    long long unsigned int cur_time = time(NULL);
    Tox *toxes[NUM_TOXES];
    uint32_t index[NUM_TOXES];
    uint32_t i, j;
    uint32_t to_comp = 974536;

    for (i = 0; i < NUM_TOXES; ++i) {
        index[i] = i + 1;
        toxes[i] = tox_new_log(0, 0, &index[i]);
        ck_assert_msg(toxes[i] != 0, "Failed to create tox instances %u", i);
        tox_callback_friend_request(toxes[i], accept_friend_request);
    }

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(toxes[0], &error) == 33445, "First Tox instance did not bind to udp port 33445.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    unsigned int num_f = 0;

    for (i = 0; i < NUM_TOXES; ++i) {
        num_f += tox_self_get_friend_list_size(toxes[i]);
    }

    ck_assert_msg(num_f == 0, "bad num friends: %u", num_f);

    for (i = 0; i < NUM_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = rand() % NUM_TOXES;
        pairs[i].tox2 = (pairs[i].tox1 + rand() % (NUM_TOXES - 1) + 1) % NUM_TOXES;

        for (j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox1 && pairs[j].tox1 == pairs[i].tox2) {
                goto loop_top;
            }
        }

        tox_self_get_address(toxes[pairs[i].tox1], address);

        TOX_ERR_FRIEND_ADD test;
        uint32_t num = tox_friend_add(toxes[pairs[i].tox2], address, (const uint8_t *)"Gentoo", 7, &test);

        if (test == TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
            goto loop_top;
        }

        ck_assert_msg(num != UINT32_MAX && test == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend error code: %i", test);
    }

    for (i = 0; i < NUM_TOXES; ++i) {
        num_f += tox_self_get_friend_list_size(toxes[i]);
    }

    ck_assert_msg(num_f == NUM_FRIENDS, "bad num friends: %u", num_f);

    uint16_t last_count = 0;

    while (1) {
        uint16_t counter = 0;

        for (i = 0; i < NUM_TOXES; ++i) {
            for (j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
                if (tox_friend_get_connection_status(toxes[i], j, 0) == TOX_CONNECTION_UDP) {
                    ++counter;
                }
            }
        }

        if (counter != last_count) {
            printf("many_clients got to %u\n", counter);
            last_count = counter;
        }

        if (counter == NUM_FRIENDS * 2) {
            break;
        }

        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        c_sleep(50);
    }

    for (i = 0; i < NUM_TOXES; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients succeeded, took %llu seconds\n", time(NULL) - cur_time);
}
END_TEST

#ifdef TRAVIS_ENV
static const uint8_t timeout_mux = 20;
#else
static const uint8_t timeout_mux = 10;
#endif

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox");

    DEFTESTCASE_SLOW(many_clients, 8 * timeout_mux);

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
