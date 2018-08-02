/* Auto Tests: Conferences.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

#define NUM_GROUP_TOX 16
#define GROUP_MESSAGE "Install Gentoo"

#define NAME_FORMAT_STR "Tox #%4u"
#define NAMELEN 9
#define NAME_FORMAT "%9s"

typedef struct State {
    uint32_t id;
    bool invited_next;
} State;

static void handle_self_connection_status(
    Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", state->id);
    } else {
        printf("tox #%u: is now disconnected\n", state->id);
    }
}

static void handle_friend_connection_status(
    Tox *tox, uint32_t friendnumber, TOX_CONNECTION connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", state->id, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", state->id, friendnumber);
    }
}

static void handle_conference_invite(
    Tox *tox, uint32_t friendnumber, TOX_CONFERENCE_TYPE type,
    const uint8_t *data, size_t length, void *user_data)
{
    const State *state = (State *)user_data;
    ck_assert_msg(type == TOX_CONFERENCE_TYPE_TEXT, "tox #%u: wrong conference type: %d", state->id, type);

    TOX_ERR_CONFERENCE_JOIN err;
    uint32_t g_num = tox_conference_join(tox, friendnumber, data, length, &err);

    ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK, "tox #%u: error joining group: %d", state->id, err);
    ck_assert_msg(g_num == 0, "tox #%u: group number was not 0", state->id);

    // Try joining again. We should only be allowed to join once.
    tox_conference_join(tox, friendnumber, data, length, &err);
    ck_assert_msg(err != TOX_ERR_CONFERENCE_JOIN_OK,
                  "tox #%u: joining groupchat twice should be impossible.", state->id);
}

static void handle_conference_connected(
    Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    if (state->invited_next || tox_self_get_friend_list_size(tox) <= 1) {
        return;
    }

    TOX_ERR_CONFERENCE_INVITE err;
    tox_conference_invite(tox, 1, 0, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox #%u failed to invite next friend: err = %d", state->id, err);
    printf("tox #%u: invited next friend\n", state->id);
    state->invited_next = true;
}

static uint16_t num_recv;

static void handle_conference_message(
    Tox *tox, uint32_t groupnumber, uint32_t peernumber, TOX_MESSAGE_TYPE type,
    const uint8_t *message, size_t length, void *user_data)
{
    if (length == (sizeof(GROUP_MESSAGE) - 1) && memcmp(message, GROUP_MESSAGE, sizeof(GROUP_MESSAGE) - 1) == 0) {
        ++num_recv;
    }
}

static void run_conference_tests(Tox **toxes, State *state)
{
    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_callback_conference_message(toxes[i], &handle_conference_message);
    }

    TOX_ERR_CONFERENCE_SEND_MESSAGE err;
    ck_assert_msg(
        tox_conference_send_message(
            toxes[random_u32() % NUM_GROUP_TOX], 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)GROUP_MESSAGE,
            sizeof(GROUP_MESSAGE) - 1, &err) != 0, "failed to send group message");
    ck_assert_msg(
        err == TOX_ERR_CONFERENCE_SEND_MESSAGE_OK, "failed to send group message");
    num_recv = 0;

    for (uint8_t j = 0; j < 20; ++j) {
        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &state[i]);
        }

        c_sleep(25);
    }

    c_sleep(25);
    ck_assert_msg(num_recv == NUM_GROUP_TOX, "failed to recv group messages");

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        for (uint16_t j = 0; j < NUM_GROUP_TOX; ++j) {
            const size_t len = tox_conference_peer_get_name_size(toxes[i], 0, j, nullptr);
            ck_assert_msg(len == NAMELEN, "name of #%u according to #%u has incorrect length %u", state[j].id, state[i].id,
                          (unsigned int)len);
            uint8_t name[NAMELEN];
            tox_conference_peer_get_name(toxes[i], 0, j, name, nullptr);
            char expected_name[NAMELEN + 1];
            snprintf(expected_name, NAMELEN + 1, NAME_FORMAT_STR, state[j].id);
            ck_assert_msg(memcmp(name, expected_name, NAMELEN) == 0,
                          "name of #%u according to #%u is \"" NAME_FORMAT "\"; expected \"%s\"",
                          state[j].id, state[i].id, name, expected_name);
        }
    }

    for (uint16_t k = NUM_GROUP_TOX; k != 0 ; --k) {
        tox_conference_delete(toxes[k - 1], 0, nullptr);

        for (uint8_t j = 0; j < 10; ++j) {
            for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
                tox_iterate(toxes[i], &state[i]);
            }

            c_sleep(50);
        }

        for (uint16_t i = 0; i < k - 1; ++i) {
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, nullptr);
            ck_assert_msg(peer_count == (k - 1), "\n\tBad number of group peers (post check)."
                          "\n\t\t\tExpected: %u but tox_instance(%u) only has: %u\n\n",
                          k - 1, i, (unsigned)peer_count);
        }
    }
}

static void test_many_group(void)
{
    const time_t test_start_time = time(nullptr);

    Tox *toxes[NUM_GROUP_TOX];
    State state[NUM_GROUP_TOX];
    memset(state, 0, NUM_GROUP_TOX * sizeof(State));
    time_t cur_time = time(nullptr);
    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_start_port(opts, 33445);
    tox_options_set_end_port(opts, 34445);

    printf("creating %d toxes\n", NUM_GROUP_TOX);

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        TOX_ERR_NEW err;
        state[i].id = i + 1;
        toxes[i] = tox_new_log(opts, &err, &state[i]);

        ck_assert_msg(toxes[i] != nullptr, "failed to create tox instance %u: error %d", i, err);
        tox_callback_self_connection_status(toxes[i], &handle_self_connection_status);
        tox_callback_friend_connection_status(toxes[i], &handle_friend_connection_status);
        tox_callback_conference_invite(toxes[i], &handle_conference_invite);
        tox_callback_conference_connected(toxes[i], &handle_conference_connected);

        char name[NAMELEN + 1];
        snprintf(name, NAMELEN + 1, NAME_FORMAT_STR, state[i].id);
        tox_self_set_name(toxes[i], (const uint8_t *)name, NAMELEN, nullptr);

        if (i != 0) {
            uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
            tox_self_get_dht_id(toxes[0], dht_key);
            const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);

            tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, nullptr);
        }
    }

    tox_options_free(opts);

    printf("creating a chain of friends\n");

    for (unsigned i = 1; i < NUM_GROUP_TOX; ++i) {
        TOX_ERR_FRIEND_ADD err;
        uint8_t key[TOX_PUBLIC_KEY_SIZE];

        tox_self_get_public_key(toxes[i - 1], key);
        tox_friend_add_norequest(toxes[i], key, &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "failed to add friend: error %d", err);

        tox_self_get_public_key(toxes[i], key);
        tox_friend_add_norequest(toxes[i - 1], key, &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "failed to add friend: error %d", err);
    }

    printf("waiting for everyone to come online\n");
    unsigned online_count = 0;

    while (online_count != NUM_GROUP_TOX) {
        online_count = 0;

        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &state[i]);
            online_count += tox_friend_get_connection_status(toxes[i], 0, nullptr) != TOX_CONNECTION_NONE;
        }

        printf("currently %u toxes are online\n", online_count);
        fflush(stdout);

        c_sleep(1000);
    }

    printf("friends connected, took %d seconds\n", (int)(time(nullptr) - cur_time));

    ck_assert_msg(tox_conference_new(toxes[0], nullptr) != UINT32_MAX, "failed to create group");
    printf("tox #%u: inviting its first friend\n", state[0].id);
    ck_assert_msg(tox_conference_invite(toxes[0], 0, 0, nullptr) != 0, "failed to invite friend");
    state[0].invited_next = true;
    ck_assert_msg(tox_conference_set_title(toxes[0], 0, (const uint8_t *)"Gentoo", sizeof("Gentoo") - 1, nullptr) != 0,
                  "failed to set group title");


    printf("waiting for invitations to be made\n");
    uint16_t invited_count = 0;

    while (invited_count != NUM_GROUP_TOX - 1) {
        invited_count = 0;

        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &state[i]);
            invited_count += state[i].invited_next;
        }

        c_sleep(50);
    }

    cur_time = time(nullptr);
    printf("waiting for all toxes to be in the group\n");
    uint16_t fully_connected_count = 0;

    while (fully_connected_count != NUM_GROUP_TOX) {
        fully_connected_count = 0;
        printf("current peer counts: [");

        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            tox_iterate(toxes[i], &state[i]);
            TOX_ERR_CONFERENCE_PEER_QUERY err;
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, &err);

            if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
                peer_count = 0;
            }

            fully_connected_count += peer_count == NUM_GROUP_TOX;

            if (i != 0) {
                printf(", ");
            }

            printf("%u", peer_count);
        }

        printf("]\n");
        fflush(stdout);

        c_sleep(200);
    }

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, nullptr);

        ck_assert_msg(peer_count == NUM_GROUP_TOX, "\n\tBad number of group peers (pre check)."
                      "\n\t\t\tExpected: %d but tox_instance(%u)  only has: %u\n\n",
                      NUM_GROUP_TOX, i, (unsigned)peer_count);

        uint8_t title[2048];
        size_t ret = tox_conference_get_title_size(toxes[i], 0, nullptr);
        ck_assert_msg(ret == sizeof("Gentoo") - 1, "Wrong title length");
        tox_conference_get_title(toxes[i], 0, title, nullptr);
        ck_assert_msg(memcmp("Gentoo", title, ret) == 0, "Wrong title");
    }

    printf("group connected, took %d seconds\n", (int)(time(nullptr) - cur_time));

    run_conference_tests(toxes, state);

    printf("tearing down toxes\n");

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_group succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_many_group();
    return 0;
}
