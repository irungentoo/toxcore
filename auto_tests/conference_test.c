/* Auto Tests: Conferences.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "check_compat.h"

#include <inttypes.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

#define NUM_GROUP_TOX 8

static void handle_self_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    int id = *(int *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%d: is now connected\n", id);
    } else {
        printf("tox #%d: is now disconnected\n", id);
    }
}

static void handle_friend_connection_status(Tox *tox, uint32_t friendnumber, TOX_CONNECTION connection_status,
        void *user_data)
{
    int id = *(int *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%d: is now connected to friend %d\n", id, friendnumber);
    } else {
        printf("tox #%d: is now disconnected from friend %d\n", id, friendnumber);
    }
}

static void handle_conference_invite(Tox *tox, uint32_t friendnumber, TOX_CONFERENCE_TYPE type, const uint8_t *data,
                                     size_t length, void *user_data)
{
    int id = *(int *)user_data;
    ck_assert_msg(type == TOX_CONFERENCE_TYPE_TEXT, "tox #%d: wrong conference type: %d", id, type);

    TOX_ERR_CONFERENCE_JOIN err;
    uint32_t g_num = tox_conference_join(tox, friendnumber, data, length, &err);

    ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK, "tox #%d: error joining group: %d", id, err);
    ck_assert_msg(g_num == 0, "tox #%d: group number was not 0", id);

    // Try joining again. We should only be allowed to join once.
    tox_conference_join(tox, friendnumber, data, length, &err);
    ck_assert_msg(err != TOX_ERR_CONFERENCE_JOIN_OK,
                  "tox #%d: joining groupchat twice should be impossible.", id);

    if (tox_self_get_friend_list_size(tox) > 1) {
        printf("tox #%d: inviting next friend\n", id);
        ck_assert_msg(tox_conference_invite(tox, 1, g_num, nullptr) != 0, "Failed to invite friend");
    } else {
        printf("tox #%d was the last tox, no further invites happening\n", id);
    }
}

static unsigned int num_recv;

static void handle_conference_message(Tox *tox, uint32_t groupnumber, uint32_t peernumber, TOX_MESSAGE_TYPE type,
                                      const uint8_t *message, size_t length, void *user_data)
{
    if (length == (sizeof("Install Gentoo") - 1) && memcmp(message, "Install Gentoo", sizeof("Install Gentoo") - 1) == 0) {
        ++num_recv;
    }
}

START_TEST(test_many_group)
{
    const time_t test_start_time = time(nullptr);

    Tox *toxes[NUM_GROUP_TOX];
    uint32_t tox_index[NUM_GROUP_TOX];
    time_t cur_time = time(nullptr);
    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_start_port(opts, 33445);
    tox_options_set_end_port(opts, 34445);

    printf("creating %d toxes\n", NUM_GROUP_TOX);

    for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
        TOX_ERR_NEW err;
        tox_index[i] = i + 1;
        toxes[i] = tox_new_log(opts, &err, &tox_index[i]);

        ck_assert_msg(toxes[i] != nullptr, "Failed to create tox instance %u: error %d", i, err);
        tox_callback_self_connection_status(toxes[i], &handle_self_connection_status);
        tox_callback_friend_connection_status(toxes[i], &handle_friend_connection_status);
        tox_callback_conference_invite(toxes[i], &handle_conference_invite);
    }

    tox_options_free(opts);

    {
        TOX_ERR_GET_PORT error;
        const uint16_t port = tox_self_get_udp_port(toxes[0], &error);
        ck_assert_msg(33445 <= port && port <= 33545,
                      "First Tox instance did not bind to udp port inside [33445, 33545].\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    printf("creating a chain of friends\n");

    for (unsigned i = 1; i < NUM_GROUP_TOX; ++i) {
        TOX_ERR_FRIEND_ADD err;
        uint8_t key[TOX_PUBLIC_KEY_SIZE];

        tox_self_get_public_key(toxes[i - 1], key);
        tox_friend_add_norequest(toxes[i], key, &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend: error %d", err);

        tox_self_get_public_key(toxes[i], key);
        tox_friend_add_norequest(toxes[i - 1], key, &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend: error %d", err);
    }

    printf("waiting for everyone to come online\n");
    unsigned online_count = 0;

    while (online_count != NUM_GROUP_TOX) {
        online_count = 0;

        for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &tox_index[i]);
            online_count += tox_friend_get_connection_status(toxes[i], 0, nullptr) != TOX_CONNECTION_NONE;
        }

        printf("currently %d toxes are online\n", online_count);
        fflush(stdout);

        c_sleep(1000);
    }

    printf("friends connected, took %d seconds\n", (int)(time(nullptr) - cur_time));

    ck_assert_msg(tox_conference_new(toxes[0], nullptr) != UINT32_MAX, "Failed to create group");
    printf("tox #%d: inviting its first friend\n", tox_index[0]);
    ck_assert_msg(tox_conference_invite(toxes[0], 0, 0, nullptr) != 0, "Failed to invite friend");
    ck_assert_msg(tox_conference_set_title(toxes[0], 0, (const uint8_t *)"Gentoo", sizeof("Gentoo") - 1, nullptr) != 0,
                  "Failed to set group title");

    // One iteration for all the invitations to happen.
    for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_iterate(toxes[i], &tox_index[i]);
    }

    cur_time = time(nullptr);
    printf("waiting for all toxes to be in the group\n");
    unsigned invited_count = 0;

    while (invited_count != NUM_GROUP_TOX) {
        invited_count = 0;
        printf("current peer counts: [");

        for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &tox_index[i]);
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, nullptr);
            invited_count += peer_count == NUM_GROUP_TOX;

            if (i != 0) {
                printf(", ");
            }

            printf("%d", peer_count);
        }

        printf("]\n");
        fflush(stdout);

        c_sleep(1000);
    }

    for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
        uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, nullptr);

        ck_assert_msg(peer_count == NUM_GROUP_TOX, "\n\tBad number of group peers (pre check)."
                      "\n\t\t\tExpected: %u but tox_instance(%u)  only has: %" PRIu32 "\n\n",
                      NUM_GROUP_TOX, i, peer_count);

        uint8_t title[2048];
        size_t ret = tox_conference_get_title_size(toxes[i], 0, nullptr);
        ck_assert_msg(ret == sizeof("Gentoo") - 1, "Wrong title length");
        tox_conference_get_title(toxes[i], 0, title, nullptr);
        ck_assert_msg(memcmp("Gentoo", title, ret) == 0, "Wrong title");
    }

    printf("group connected, took %d seconds\n", (int)(time(nullptr) - cur_time));

    for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_callback_conference_message(toxes[i], &handle_conference_message);
    }

    TOX_ERR_CONFERENCE_SEND_MESSAGE err;
    ck_assert_msg(
        tox_conference_send_message(
            toxes[rand() % NUM_GROUP_TOX], 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"Install Gentoo",
            sizeof("Install Gentoo") - 1, &err) != 0, "Failed to send group message.");
    ck_assert_msg(
        err == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK, "Failed to send group message.");
    num_recv = 0;

    for (unsigned j = 0; j < 20; ++j) {
        for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &tox_index[i]);
        }

        c_sleep(25);
    }

    c_sleep(25);
    ck_assert_msg(num_recv == NUM_GROUP_TOX, "Failed to recv group messages.");

    for (unsigned k = NUM_GROUP_TOX; k != 0 ; --k) {
        tox_conference_delete(toxes[k - 1], 0, nullptr);

        for (unsigned j = 0; j < 10; ++j) {
            for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
                tox_iterate(toxes[i], &tox_index[i]);
            }

            c_sleep(50);
        }

        for (unsigned i = 0; i < (k - 1); ++i) {
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, nullptr);
            ck_assert_msg(peer_count == (k - 1), "\n\tBad number of group peers (post check)."
                          "\n\t\t\tExpected: %u but tox_instance(%u)  only has: %" PRIu32 "\n\n",
                          (k - 1), i, peer_count);
        }
    }

    for (unsigned i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_group succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}
END_TEST

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox conference");

    DEFTESTCASE_SLOW(many_group, 80);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(nullptr));

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
