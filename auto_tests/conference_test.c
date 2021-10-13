/* Auto Tests: Conferences.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

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
    Tox *tox, Tox_Connection connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected\n", state->index);
    } else {
        printf("tox #%u: is now disconnected\n", state->index);
    }
}

static void handle_friend_connection_status(
    Tox *tox, uint32_t friendnumber, Tox_Connection connection_status, void *user_data)
{
    const State *state = (State *)user_data;

    if (connection_status != TOX_CONNECTION_NONE) {
        printf("tox #%u: is now connected to friend %u\n", state->index, friendnumber);
    } else {
        printf("tox #%u: is now disconnected from friend %u\n", state->index, friendnumber);
    }
}

static void handle_conference_invite(
    Tox *tox, uint32_t friendnumber, Tox_Conference_Type type,
    const uint8_t *data, size_t length, void *user_data)
{
    const State *state = (State *)user_data;
    ck_assert_msg(type == TOX_CONFERENCE_TYPE_TEXT, "tox #%u: wrong conference type: %d", state->index, type);

    Tox_Err_Conference_Join err;
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

    Tox_Err_Conference_Invite err;
    tox_conference_invite(tox, 1, 0, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox #%u failed to invite next friend: err = %d", state->index, err);
    printf("tox #%u: invited next friend\n", state->index);
    state->invited_next = true;
}

static uint32_t num_recv;

static void handle_conference_message(
    Tox *tox, uint32_t groupnumber, uint32_t peernumber, Tox_Message_Type type,
    const uint8_t *message, size_t length, void *user_data)
{
    if (length == (sizeof(GROUP_MESSAGE) - 1) && memcmp(message, GROUP_MESSAGE, sizeof(GROUP_MESSAGE) - 1) == 0) {
        ++num_recv;
    }
}

static bool toxes_are_disconnected_from_group(uint32_t tox_count, Tox **toxes,
        bool *disconnected)
{
    uint32_t num_disconnected = 0;

    for (uint32_t i = 0; i < tox_count; ++i) {
        num_disconnected += disconnected[i];
    }

    for (uint32_t i = 0; i < tox_count; i++) {
        if (disconnected[i]) {
            continue;
        }

        if (tox_conference_peer_count(toxes[i], 0, nullptr) > tox_count - num_disconnected) {
            return false;
        }
    }

    return true;
}

static void disconnect_toxes(uint32_t tox_count, Tox **toxes, State *state,
                             const bool *disconnect, const bool *exclude)
{
    /* Fake a network outage for a set of peers D by iterating only the other
     * peers D' until the connections time out according to D', then iterating
     * only D until the connections time out according to D. */

    VLA(bool, disconnect_now, tox_count);
    bool invert = false;

    do {
        for (uint32_t i = 0; i < tox_count; ++i) {
            disconnect_now[i] = exclude[i] || (invert ^ disconnect[i]);
        }

        do {
            for (uint32_t i = 0; i < tox_count; ++i) {
                if (!disconnect_now[i]) {
                    tox_iterate(toxes[i], &state[i]);
                    state[i].clock += 1000;
                }
            }

            c_sleep(20);
        } while (!toxes_are_disconnected_from_group(tox_count, toxes, disconnect_now));

        invert = !invert;
    } while (invert);
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

static bool names_propagated(uint32_t tox_count, Tox **toxes, State *state)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        for (uint32_t j = 0; j < tox_count; ++j) {
            const size_t len = tox_conference_peer_get_name_size(toxes[i], 0, j, nullptr);

            if (len != NAMELEN) {
                return false;
            }
        }
    }

    return true;
}


/**
 * returns a random index at which a list of booleans is false
 * (some such index is required to exist)
 */
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
    /* disabling name change propagation check for now, as it occasionally
     * fails due to disconnections too short to trigger freezing */
    const bool check_name_change_propagation = false;

    /* each peer should freeze at least its two friends, but freezing more
     * should not be necessary */
    const uint32_t max_frozen = max_u32(2, NUM_DISCONNECT / 2);
    printf("restricting number of frozen peers to %u\n", max_frozen);

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        Tox_Err_Conference_Set_Max_Offline err;
        tox_conference_set_max_offline(toxes[i], 0, max_frozen, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK,
                      "tox #%u failed to set max offline: err = %d", state[i].index, err);
    }

    printf("letting random toxes timeout\n");
    bool disconnected[NUM_GROUP_TOX] = {0};
    bool restarting[NUM_GROUP_TOX] = {0};

    ck_assert(NUM_DISCONNECT < NUM_GROUP_TOX);

    for (uint32_t i = 0; i < NUM_DISCONNECT; ++i) {
        uint32_t disconnect = random_false_index(disconnected, NUM_GROUP_TOX);
        disconnected[disconnect] = true;

        if (i < NUM_DISCONNECT / 2) {
            restarting[disconnect] = true;
            printf("Restarting #%u\n", state[disconnect].index);
        } else {
            printf("Disconnecting #%u\n", state[disconnect].index);
        }
    }

    uint8_t *save[NUM_GROUP_TOX];
    size_t save_size[NUM_GROUP_TOX];

    for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
        if (restarting[i]) {
            save_size[i] = tox_get_savedata_size(toxes[i]);
            ck_assert_msg(save_size[i] != 0, "save is invalid size %u", (unsigned)save_size[i]);
            save[i] = (uint8_t *)malloc(save_size[i]);
            ck_assert_msg(save[i] != nullptr, "malloc failed");
            tox_get_savedata(toxes[i], save[i]);
            tox_kill(toxes[i]);
        }
    }

    disconnect_toxes(NUM_GROUP_TOX, toxes, state, disconnected, restarting);

    for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
        if (restarting[i]) {
            struct Tox_Options *const options = tox_options_new(nullptr);
            ck_assert(options != nullptr);
            tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
            tox_options_set_savedata_data(options, save[i], save_size[i]);
            toxes[i] = tox_new_log(options, nullptr, &state[i].index);
            ck_assert(toxes[i] != nullptr);
            tox_options_free(options);
            free(save[i]);

            set_mono_time_callback(toxes[i], &state[i]);
            tox_conference_set_max_offline(toxes[i], 0, max_frozen, nullptr);
        }
    }

    if (check_name_change_propagation) {
        printf("changing names\n");

        for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
            char name[NAMELEN + 1];
            snprintf(name, NAMELEN + 1, NEW_NAME_FORMAT_STR, state[i].index);
            tox_self_set_name(toxes[i], (const uint8_t *)name, NAMELEN, nullptr);
        }
    }

    for (uint16_t i = 0; i < NUM_GROUP_TOX; ++i) {
        const uint32_t num_frozen = tox_conference_offline_peer_count(toxes[i], 0, nullptr);
        ck_assert_msg(num_frozen <= max_frozen,
                      "tox #%u has too many offline peers: %u\n",
                      state[i].index, num_frozen);
    }

    printf("reconnecting toxes\n");

    do {
        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    } while (!all_connected_to_group(NUM_GROUP_TOX, toxes));

    printf("running conference tests\n");

    for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
        tox_callback_conference_message(toxes[i], &handle_conference_message);

        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    }

    Tox_Err_Conference_Send_Message err;
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

    if (check_name_change_propagation) {
        for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
            for (uint32_t j = 0; j < NUM_GROUP_TOX; ++j) {
                uint8_t name[NAMELEN];
                tox_conference_peer_get_name(toxes[i], 0, j, name, nullptr);
                /* Note the toxes will have been reordered */
                ck_assert_msg(memcmp(name, "New", 3) == 0,
                              "name of #%u according to #%u not updated", state[j].index, state[i].index);
            }
        }
    }

    for (uint32_t k = NUM_GROUP_TOX; k != 0 ; --k) {
        tox_conference_delete(toxes[k - 1], 0, nullptr);

        for (uint8_t j = 0; j < 10 || j < NUM_GROUP_TOX; ++j) {
            iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
        }

        for (uint32_t i = 0; i < k - 1; ++i) {
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

    for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
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
    uint32_t invited_count = 0;

    do {
        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        invited_count = 0;

        for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
            invited_count += state[i].invited_next;
        }
    } while (invited_count != NUM_GROUP_TOX - 1);

    uint64_t pregroup_clock = state[0].clock;
    printf("waiting for all toxes to be in the group\n");
    uint32_t fully_connected_count = 0;

    do {
        fully_connected_count = 0;
        printf("current peer counts: [");

        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);

        for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
            Tox_Err_Conference_Peer_Query err;
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

    for (uint32_t i = 0; i < NUM_GROUP_TOX; ++i) {
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

    printf("waiting for names to propagate\n");

    do {
        iterate_all_wait(NUM_GROUP_TOX, toxes, state, ITERATION_INTERVAL);
    } while (!names_propagated(NUM_GROUP_TOX, toxes, state));

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
