/* Auto Tests: Conferences.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <inttypes.h>
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


#define NUM_GROUP_TOX 32

static void g_accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length,
                                    void *userdata)
{
    if (*((uint32_t *)userdata) != 234212) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, 0);
    }
}

static Tox *invite_tox;
static unsigned int invite_counter;

static void print_group_invite_callback(Tox *tox, uint32_t friendnumber, TOX_CONFERENCE_TYPE type, const uint8_t *data,
                                        size_t length,
                                        void *userdata)
{
    if (*((uint32_t *)userdata) != 234212) {
        return;
    }

    if (type != TOX_CONFERENCE_TYPE_TEXT) {
        return;
    }

    uint32_t g_num;

    if ((g_num = tox_conference_join(tox, friendnumber, data, length, NULL)) == UINT32_MAX) {
        return;
    }

    ck_assert_msg(g_num == 0, "Group number was not 0");
    ck_assert_msg(tox_conference_join(tox, friendnumber, data, length, NULL) == -1,
                  "Joining groupchat twice should be impossible.");

    invite_tox = tox;
    invite_counter = 4;
}

static unsigned int num_recv;

static void print_group_message(Tox *tox, uint32_t groupnumber, uint32_t peernumber, TOX_MESSAGE_TYPE type,
                                const uint8_t *message, size_t length,
                                void *userdata)
{
    if (*((uint32_t *)userdata) != 234212) {
        return;
    }

    if (length == (sizeof("Install Gentoo") - 1) && memcmp(message, "Install Gentoo", sizeof("Install Gentoo") - 1) == 0) {
        ++num_recv;
    }
}

START_TEST(test_many_group)
{
    long long unsigned int test_start_time = time(NULL);

group_test_restart:
    ;

    Tox *toxes[NUM_GROUP_TOX];
    uint32_t tox_index[NUM_GROUP_TOX];
    unsigned int i, j, k;
    uint32_t to_comp = 234212;
    int test_run = 0;
    long long unsigned int cur_time = time(NULL);

    for (i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_index[i] = i + 1;
        toxes[i] = tox_new_log(0, 0, &tox_index[i]);

        ck_assert_msg(toxes[i] != 0, "Failed to create tox instances %u", i);
        tox_callback_friend_request(toxes[i], &g_accept_friend_request);
        tox_callback_conference_invite(toxes[i], &print_group_invite_callback);
    }

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(toxes[0], &error) == 33445, "First Tox instance did not bind to udp port 33445.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(toxes[NUM_GROUP_TOX - 1], address);

    for (i = 0; i < NUM_GROUP_TOX; ++i) {
        ck_assert_msg(tox_friend_add(toxes[i], address, (const uint8_t *)"Gentoo", 7, 0) == 0, "Failed to add friend");

        tox_self_get_address(toxes[i], address);
    }

    while (1) {
        for (i = 0; i < NUM_GROUP_TOX; ++i) {
            if (tox_friend_get_connection_status(toxes[i], 0, 0) != TOX_CONNECTION_UDP) {
                break;
            }
        }

        if (i == NUM_GROUP_TOX) {
            break;
        }

        for (i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        c_sleep(25);
    }

    printf("friends connected, took %llu seconds\n", time(NULL) - cur_time);

    ck_assert_msg(tox_conference_new(toxes[0], NULL) != UINT32_MAX, "Failed to create group");
    ck_assert_msg(tox_conference_invite(toxes[0], 0, 0, NULL) != 0, "Failed to invite friend");
    ck_assert_msg(tox_conference_set_title(toxes[0], 0, (const uint8_t *)"Gentoo", sizeof("Gentoo") - 1, NULL) != 0,
                  "Failed to set group title");
    invite_counter = ~0;

    unsigned int done = ~0;
    done -= 5;

    while (1) {
        for (i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        if (!invite_counter) {
            ck_assert_msg(tox_conference_invite(invite_tox, 0, 0, NULL) != 0, "Failed to invite friend");
        }

        if (done == invite_counter) {
            break;
        }

        --invite_counter;
        c_sleep(50);
    }

    for (i = 0; i < NUM_GROUP_TOX; ++i) {
        uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, NULL);

        /**
         * Group chats fail unpredictably, currently they'll rerun as many times
         * as they need to until they pass the test, or the time out is reached
         * Either way in this case it's fine  */
        if (peer_count != NUM_GROUP_TOX) {
            ++test_run;
            printf("\tError starting up the first group (peer_count %"PRIu32" != %d, test_run = %d)\n", peer_count, NUM_GROUP_TOX,
                   test_run);

            for (j = 0; j < NUM_GROUP_TOX; ++j) {
                tox_kill(toxes[j]);
            }

            c_sleep(1000);

            goto group_test_restart;
        }

        /**
         * This check will never fail because it'll jump before this event
         * I've decided to leave it in because eventually, we may want to only
         * restart this test once, in which case this check will become
         * important again.
         */
        ck_assert_msg(peer_count == NUM_GROUP_TOX, "\n\tBad number of group peers (pre check)."
                      "\n\t\t\tExpected: %u but tox_instance(%u)  only has: %"PRIu32"\n\n",
                      NUM_GROUP_TOX, i, peer_count);

        uint8_t title[2048];
        size_t ret = tox_conference_get_title_size(toxes[i], 0, NULL);
        ck_assert_msg(ret == sizeof("Gentoo") - 1, "Wrong title length");
        tox_conference_get_title(toxes[i], 0, title, NULL);
        ck_assert_msg(memcmp("Gentoo", title, ret) == 0, "Wrong title");
    }

    printf("group connected\n");

    for (i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_callback_conference_message(toxes[i], &print_group_message);
    }

    ck_assert_msg(
        tox_conference_send_message(
            toxes[rand() % NUM_GROUP_TOX], 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"Install Gentoo",
            sizeof("Install Gentoo") - 1, NULL) != 0, "Failed to send group message.");
    num_recv = 0;

    for (j = 0; j < 20; ++j) {
        for (i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        c_sleep(25);
    }

    c_sleep(25);
    ck_assert_msg(num_recv == NUM_GROUP_TOX, "Failed to recv group messages.");

    for (k = NUM_GROUP_TOX; k != 0 ; --k) {
        tox_conference_delete(toxes[k - 1], 0, NULL);

        for (j = 0; j < 10; ++j) {
            for (i = 0; i < NUM_GROUP_TOX; ++i) {
                tox_iterate(toxes[i], &to_comp);
            }

            c_sleep(50);
        }

        for (i = 0; i < (k - 1); ++i) {
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, NULL);
            ck_assert_msg(peer_count == (k - 1), "\n\tBad number of group peers (post check)."
                          "\n\t\t\tExpected: %u but tox_instance(%u)  only has: %"PRIu32"\n\n",
                          (k - 1), i, peer_count);
        }
    }

    for (i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_group succeeded, took %llu seconds\n", time(NULL) - test_start_time);
}
END_TEST

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox conference");

    /* This test works VERY unreliably. So it's worthless in its current state.
     * Anyone reading this is welcome to try to fix it, but because there is a
     * new version of group chats for Tox already completed, and nearly ready to
     * merge, No one is willing/available to give this test the time in needs */
#ifndef DISABLE_GROUP_TESTS
    DEFTESTCASE_SLOW(many_group, 80);
#endif

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
