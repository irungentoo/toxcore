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
#define NUM_DISCONNECT 8
#define GROUP_MESSAGE "Install Gentoo"

#define NAMELEN 9
#define NAME_FORMAT_STR "Tox #%4u"
#define NEW_NAME_FORMAT_STR "New #%4u"

typedef struct State {
    uint32_t index;
    uint64_t clock;

    bool invited_next;
} State;

#include "run_auto_test.h"

static void handle_self_connection_status(
    Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", state->index);
    } else {
        printf("tox #%u: is now disconnected\n", state->index);
    }
}

static void handle_friend_connection_status(
    Tox *tox, uint32_t friendnumber, TOX_CONNECTION connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", state->index, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", state->index, friendnumber);
    }
}

static void handle_conference_invite(
    Tox *tox, uint32_t friendnumber, TOX_CONFERENCE_TYPE type,
    const uint8_t *data, size_t length, void *user_data)
{
    const State *state = (State *)user_data;
    ck_assert_msg(type == TOX_CONFERENCE_TYPE_TEXT, "tox #%u: wrong conference type: %d", state->index, type);

    TOX_ERR_CONFERENCE_JOIN err;
    uint32_t g_num = tox_conference_join(tox, friendnumber, data, length, &err);

    ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK, "tox #%u: error joining group: %d", state->index, err);
    ck_assert_msg(g_num == 0, "tox #%u: group number was not 0", state->index);

    // Try joining again. We should only be allowed to join once.
    tox_conference_join(tox, friendnumber, data, length, &err);
    ck_assert_msg(err != TOX_ERR_CONFERENCE_JOIN_OK,
                  "tox #%u: joining groupchat twice should be impossible.", state->index);
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
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox #%u failed to invite next friend: err = %d", state->index, err);
    printf("tox #%u: invited next friend\n", state->index);
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

static bool toxes_are_disconnected_from_group(uint32_t tox_count, Tox **toxes, int disconnected_count,
        bool *disconnected)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (disconnected[i]) {
            continue;
        }

        if (tox_conference_peer_count(toxes[i], 0, nullptr) > tox_count - NUM_DISCONNECT) {
            return false;
        }
    }

    return true;
}

static bool all_connected_to_group(uint32_t tox_count, Tox **toxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (tox_conference_peer_count(toxes[i], 0, nullptr) < tox_count) {
            return false;
        }
    }

    return true;
}

/* returns a random index at which a list of booleans is false
 * (some such index is required to exist)
 * */
static uint32_t random_false_index(bool *list, const uint32_t length)
{
    uint32_t index;

    do {
        index = random_u32() % length;
    } while (list[index]);

    return index;
}

static void run_conference_tests(Tox **toxes, State *state)
{
    /* disabling name propagation check for now, as it occasionally fails due
     * to disconnections too short to trigger freezing */
    const bool check_name_propagation = false;

    printf("letting random toxes timeout\n");
    bool disconnected[NUM_GROUP_TOX] = {0};

    ck_assert(NUM_DISCONNECT < NUM_GROUP_TOX);

    for (uint16_t i = 0; i < NUM_DISCONNECT; ++i) {
        uint32_t disconnect = random_false_index(disconnected, NUM_GROUP_TOX);
        disconnected[disconnect] = true;
        printf("Disconnecting #%u\n", state[disconnect].index);
    }

    do {
        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            if (!disconnected[i]) {
                tox_iterate(toxes[i], &state[i]);
                state[i].clock += 1000;
            }
        }

        c_sleep(20);
    } while (!toxes_are_disconnected_from_group(NUM_GROUP_TOX, toxes, NUM_DISCONNECT, disconnected));

    if (check_name_propagation) {
        printf("changing names\n");

        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            char name[NAMELEN + 1];
            snprintf(name, NAMELEN + 1, NEW_NAME_FORMAT_STR, state[i].index);
            tox_self_set_name(toxes[i], (const uint8_t *)name, NAMELEN, nullptr);
        }
    }

    printf("reconnecting toxes\n");

    do {
        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    } while (!all_connected_to_group(NUM_GROUP_TOX, toxes));

    printf("running conference tests\n");

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

    for (uint8_t j = 0; j < NUM_GROUP_TOX * 2; ++j) {
        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    }

    ck_assert_msg(num_recv == NUM_GROUP_TOX, "failed to recv group messages");

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        for (uint16_t j = 0; j < NUM_GROUP_TOX; ++j) {
            const size_t len = tox_conference_peer_get_name_size(toxes[i], 0, j, nullptr);
            ck_assert_msg(len == NAMELEN, "name of #%u according to #%u has incorrect length %u", state[j].index, state[i].index,
                          (unsigned int)len);

            if (check_name_propagation) {
                uint8_t name[NAMELEN];
                tox_conference_peer_get_name(toxes[i], 0, j, name, nullptr);
                /* Note the toxes will have been reordered */
                ck_assert_msg(memcmp(name, "New", 3) == 0,
                              "name of #%u according to #%u not updated", state[j].index, state[i].index);
            }
        }
    }

    for (uint16_t k = NUM_GROUP_TOX; k != 0 ; --k) {
        tox_conference_delete(toxes[k - 1], 0, nullptr);

        for (uint8_t j = 0; j < 10 || j < NUM_GROUP_TOX; ++j) {
            iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
        }

        for (uint16_t i = 0; i < k - 1; ++i) {
            uint32_t peer_count = tox_conference_peer_count(toxes[i], 0, nullptr);
            ck_assert_msg(peer_count == (k - 1), "\n\tBad number of group peers (post check)."
                          "\n\t\t\tExpected: %u but tox_instance(%u) only has: %u\n\n",
                          k - 1, i, (unsigned)peer_count);
        }
    }
}

static void test_many_group(Tox **toxes, State *state)
{
    const time_t test_start_time = time(nullptr);

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_callback_self_connection_status(toxes[i], &handle_self_connection_status);
        tox_callback_friend_connection_status(toxes[i], &handle_friend_connection_status);
        tox_callback_conference_invite(toxes[i], &handle_conference_invite);
        tox_callback_conference_connected(toxes[i], &handle_conference_connected);

        char name[NAMELEN + 1];
        snprintf(name, NAMELEN + 1, NAME_FORMAT_STR, state[i].index);
        tox_self_set_name(toxes[i], (const uint8_t *)name, NAMELEN, nullptr);
    }

    ck_assert_msg(tox_conference_new(toxes[0], nullptr) != UINT32_MAX, "failed to create group");
    printf("tox #%u: inviting its first friend\n", state[0].index);
    ck_assert_msg(tox_conference_invite(toxes[0], 0, 0, nullptr) != 0, "failed to invite friend");
    state[0].invited_next = true;
    ck_assert_msg(tox_conference_set_title(toxes[0], 0, (const uint8_t *)"Gentoo", sizeof("Gentoo") - 1, nullptr) != 0,
                  "failed to set group title");


    printf("waiting for invitations to be made\n");
    uint16_t invited_count = 0;

    do {
        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        invited_count = 0;

        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
            invited_count += state[i].invited_next;
        }
    } while (invited_count != NUM_GROUP_TOX - 1);

    uint64_t pregroup_clock = state[0].clock;
    printf("waiting for all toxes to be in the group\n");
    uint16_t fully_connected_count = 0;

    do {
        fully_connected_count = 0;
        printf("current peer counts: [");

        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
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
    } while (fully_connected_count != NUM_GROUP_TOX);

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

    printf("group connected, took %d seconds\n", (int)((state[0].clock - pregroup_clock) / 1000));

    run_conference_tests(toxes, state);

    printf("test_many_group succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_GROUP_TOX, test_many_group, true);
    return 0;
}
