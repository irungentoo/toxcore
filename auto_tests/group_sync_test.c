/*
 * Tests syncing capabilities of groups: we attempt to have multiple peers change the
 * group state in a number of ways and make sure that all peers end up with the same
 * resulting state after a short period.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "auto_test_support.h"

#include "../toxcore/tox.h"
#include "../toxcore/util.h"

// these should be kept relatively low so integration tests don't always flake out
// but they can be increased for local stress testing
#define NUM_GROUP_TOXES 5
#define ROLE_SPAM_ITERATIONS 1
#define TOPIC_SPAM_ITERATIONS 1

typedef struct Peers {
    uint32_t  num_peers;
    int64_t   *peer_ids;
} Peers;

typedef struct State {
    uint8_t   callback_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t    topic_length;
    Peers     *peers;
} State;

static int add_peer(Peers *peers, uint32_t peer_id)
{
    const uint32_t new_idx = peers->num_peers;

    int64_t *tmp_list = (int64_t *)realloc(peers->peer_ids, sizeof(int64_t) * (peers->num_peers + 1));

    if (tmp_list == nullptr) {
        return -1;
    }

    ++peers->num_peers;

    tmp_list[new_idx] = (int64_t)peer_id;

    peers->peer_ids = tmp_list;

    return 0;
}

static int del_peer(Peers *peers, uint32_t peer_id)
{
    bool found_peer = false;
    int64_t i;

    for (i = 0; i < peers->num_peers; ++i) {
        if (peers->peer_ids[i] == peer_id) {
            found_peer = true;
            break;
        }
    }

    if (!found_peer) {
        return -1;
    }

    --peers->num_peers;

    if (peers->num_peers == 0) {
        free(peers->peer_ids);
        peers->peer_ids = nullptr;
        return 0;
    }

    if (peers->num_peers != i) {
        peers->peer_ids[i] = peers->peer_ids[peers->num_peers];
    }

    peers->peer_ids[peers->num_peers] = -1;

    int64_t *tmp_list = (int64_t *)realloc(peers->peer_ids, sizeof(int64_t) * (peers->num_peers));

    if (tmp_list == nullptr) {
        return -1;
    }

    peers->peer_ids = tmp_list;

    return 0;
}

static void peers_cleanup(Peers *peers)
{
    free(peers->peer_ids);
    free(peers);
}

static void group_peer_join_handler(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);

    ck_assert(add_peer(state->peers, peer_id) == 0);

}

static void group_peer_exit_handler(const Tox_Event_Group_Peer_Exit *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint32_t peer_id = tox_event_group_peer_exit_get_peer_id(event);

    ck_assert(del_peer(state->peers, peer_id) == 0);

}

static void group_topic_handler(const Tox_Event_Group_Topic *event, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    const uint8_t *topic = tox_event_group_topic_get_topic(event);
    const size_t length = tox_event_group_topic_get_topic_length(event);

    ck_assert(length <= TOX_GROUP_MAX_TOPIC_LENGTH);

    memcpy(state->callback_topic, (const char *)topic, length);
    state->topic_length = length;
}

static bool all_peers_connected(const AutoTox *autotoxes, uint32_t groupnumber)
{
    for (uint32_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        // make sure we got an invite response
        if (tox_group_get_name_size(autotoxes[i].tox, groupnumber, nullptr) != 4) {
            return false;
        }

        // make sure we're actually connected
        if (!tox_group_is_connected(autotoxes[i].tox, groupnumber, nullptr)) {
            return false;
        }

        const State *state = (const State *)autotoxes[i].state;

        // make sure all peers are connected to one another
        if (state->peers->num_peers == NUM_GROUP_TOXES - 1) {
            return false;
        }
    }

    return true;
}

static unsigned int get_peer_roles_checksum(const Tox *tox, const State *state, uint32_t groupnumber)
{
    Tox_Group_Role role = tox_group_self_get_role(tox, groupnumber, nullptr);
    unsigned int checksum = (unsigned int)role;

    for (size_t i = 0; i < state->peers->num_peers; ++i) {
        role = tox_group_peer_get_role(tox, groupnumber, (uint32_t)state->peers->peer_ids[i], nullptr);
        checksum += (unsigned int)role;
    }

    return checksum;
}

static bool all_peers_see_same_roles(const AutoTox *autotoxes, uint32_t num_peers, uint32_t groupnumber)
{
    const State *state0 = (const State *)autotoxes[0].state;
    unsigned int expected_checksum = get_peer_roles_checksum(autotoxes[0].tox, state0, groupnumber);

    for (size_t i = 0; i < num_peers; ++i) {
        const State *state = (const State *)autotoxes[i].state;
        unsigned int checksum = get_peer_roles_checksum(autotoxes[i].tox, state, groupnumber);

        if (checksum != expected_checksum) {
            return false;
        }
    }

    return true;
}

static void role_spam(const Random *rng, AutoTox *autotoxes, uint32_t num_peers, uint32_t num_demoted,
                      uint32_t groupnumber)
{
    const State *state0 = (const State *)autotoxes[0].state;
    Tox *tox0 = autotoxes[0].tox;

    for (size_t iters = 0; iters < ROLE_SPAM_ITERATIONS; ++iters) {
        // founder randomly promotes or demotes one of the non-mods
        uint32_t idx = min_u32(random_u32(rng) % num_demoted, state0->peers->num_peers);
        Tox_Group_Role f_role = random_u32(rng) % 2 == 0 ? TOX_GROUP_ROLE_MODERATOR : TOX_GROUP_ROLE_USER;
        int64_t peer_id = state0->peers->peer_ids[idx];

        if (peer_id >= 0) {
            tox_group_set_role(tox0, groupnumber, (uint32_t)peer_id, f_role, nullptr);
        }

        // mods randomly promote or demote one of the non-mods
        for (uint32_t i = 1; i < num_peers; ++i) {
            const State *state_i = (const State *)autotoxes[i].state;

            for (uint32_t j = num_demoted; j < num_peers; ++j) {
                if (i >= state_i->peers->num_peers) {
                    continue;
                }

                const State *state_j = (const State *)autotoxes[j].state;
                Tox_Group_Role role = random_u32(rng) % 2 == 0 ? TOX_GROUP_ROLE_USER : TOX_GROUP_ROLE_OBSERVER;
                peer_id = state_j->peers->peer_ids[i];

                if (peer_id >= 0) {
                    tox_group_set_role(autotoxes[j].tox, groupnumber, (uint32_t)peer_id, role, nullptr);
                }
            }
        }

        iterate_all_wait(autotoxes, num_peers, ITERATION_INTERVAL);
    }

    do {
        iterate_all_wait(autotoxes, num_peers, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(autotoxes, num_peers, groupnumber));
}

/* All peers attempt to set a unique topic.
 *
 * Return true if all peers successfully changed the topic.
 */
static bool set_topic_all_peers(const Random *rng, AutoTox *autotoxes, size_t num_peers, uint32_t groupnumber)
{
    for (size_t i = 0; i < num_peers; ++i) {
        char new_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        snprintf(new_topic, sizeof(new_topic), "peer %zu's topic %u", i, random_u32(rng));
        const size_t length = strlen(new_topic);

        Tox_Err_Group_Topic_Set err;
        tox_group_set_topic(autotoxes[i].tox, groupnumber, (const uint8_t *)new_topic, length, &err);

        if (err != TOX_ERR_GROUP_TOPIC_SET_OK) {
            return false;
        }
    }

    return true;
}

/* Returns true if all peers have the same topic, and the topic from the get_topic API function
 * matches the last topic they received in the topic callback.
 */
static bool all_peers_have_same_topic(const AutoTox *autotoxes, uint32_t num_peers, uint32_t groupnumber)
{
    uint8_t expected_topic[TOX_GROUP_MAX_TOPIC_LENGTH];

    Tox_Err_Group_State_Query query_err;
    size_t expected_topic_length = tox_group_get_topic_size(autotoxes[0].tox, groupnumber, &query_err);

    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);

    tox_group_get_topic(autotoxes[0].tox, groupnumber, expected_topic, &query_err);

    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);

    const State *state0 = (const State *)autotoxes[0].state;

    if (expected_topic_length != state0->topic_length) {
        return false;
    }

    if (memcmp(state0->callback_topic, expected_topic, expected_topic_length) != 0) {
        return false;
    }

    for (size_t i = 1; i < num_peers; ++i) {
        size_t topic_length = tox_group_get_topic_size(autotoxes[i].tox, groupnumber, &query_err);

        ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);

        if (topic_length != expected_topic_length) {
            return false;
        }

        uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        tox_group_get_topic(autotoxes[i].tox, groupnumber, topic, &query_err);

        ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);

        if (memcmp(expected_topic, (const char *)topic, topic_length) != 0) {
            return false;
        }

        const State *state = (const State *)autotoxes[i].state;

        if (topic_length != state->topic_length) {
            return false;
        }

        if (memcmp(state->callback_topic, (const char *)topic, topic_length) != 0) {
            return false;
        }
    }

    return true;
}

static void topic_spam(const Random *rng, AutoTox *autotoxes, uint32_t num_peers, uint32_t groupnumber)
{
    for (size_t i = 0; i < TOPIC_SPAM_ITERATIONS; ++i) {
        do {
            iterate_all_wait(autotoxes, num_peers, ITERATION_INTERVAL);
        } while (!set_topic_all_peers(rng, autotoxes, num_peers, groupnumber));
    }

    fprintf(stderr, "all peers set the topic at the same time\n");

    do {
        iterate_all_wait(autotoxes, num_peers, ITERATION_INTERVAL);
    } while (!all_peers_have_same_topic(autotoxes, num_peers, groupnumber));

    fprintf(stderr, "all peers see the same topic\n");
}

static void group_sync_test(AutoTox *autotoxes)
{
    ck_assert(NUM_GROUP_TOXES >= 5);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_events_callback_group_peer_join(autotoxes[i].dispatch, group_peer_join_handler);
        tox_events_callback_group_topic(autotoxes[i].dispatch, group_topic_handler);
        tox_events_callback_group_peer_exit(autotoxes[i].dispatch, group_peer_exit_handler);

        State *state = (State *)autotoxes[i].state;
        state->peers = (Peers *)calloc(1, sizeof(Peers));

        ck_assert(state->peers != nullptr);
    }

    Tox *tox0 = autotoxes[0].tox;
    State *state0 = (State *)autotoxes[0].state;

    Tox_Err_Group_New err_new;
    uint32_t groupnumber = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *) "test", 4,
                                         (const uint8_t *)"test", 4,  &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    fprintf(stderr, "tox0 creats new group and invites all his friends");

    Tox_Err_Group_State_Query id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(tox0, groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERY_OK, "%d", id_err);

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        Tox_Err_Group_Join join_err;
        tox_group_join(autotoxes[i].tox, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    do {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    } while (!all_peers_connected(autotoxes, groupnumber));

    fprintf(stderr, "%d peers joined the group\n", NUM_GROUP_TOXES);

    Tox_Err_Group_Set_Topic_Lock lock_set_err;
    tox_group_set_topic_lock(tox0, groupnumber, TOX_GROUP_TOPIC_LOCK_DISABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_SET_TOPIC_LOCK_OK, "failed to disable topic lock: %d",
                  lock_set_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    fprintf(stderr, "founder disabled topic lock; all peers try to set the topic\n");

    topic_spam(rng, autotoxes, NUM_GROUP_TOXES, groupnumber);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    tox_group_set_topic_lock(tox0, groupnumber, TOX_GROUP_TOPIC_LOCK_ENABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_SET_TOPIC_LOCK_OK, "failed to enable topic lock: %d",
                  lock_set_err);

    do {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    } while (!all_peers_have_same_topic(autotoxes, NUM_GROUP_TOXES, groupnumber)
             && !all_peers_see_same_roles(autotoxes, NUM_GROUP_TOXES, groupnumber)
             && state0->peers->num_peers != NUM_GROUP_TOXES - 1);

    Tox_Err_Group_Set_Role role_err;

    for (size_t i = 0; i < state0->peers->num_peers; ++i) {
        tox_group_set_role(tox0, groupnumber, (uint32_t)state0->peers->peer_ids[i], TOX_GROUP_ROLE_MODERATOR,
                           &role_err);
        ck_assert_msg(role_err == TOX_ERR_GROUP_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);
    }

    fprintf(stderr, "founder enabled topic lock and set all peers to moderator role\n");

    do {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(autotoxes, NUM_GROUP_TOXES, groupnumber));

    topic_spam(rng, autotoxes, NUM_GROUP_TOXES, groupnumber);

    const unsigned int num_demoted = state0->peers->num_peers / 2;

    fprintf(stderr, "founder demoting %u moderators to user\n", num_demoted);

    for (size_t i = 0; i < num_demoted; ++i) {
        tox_group_set_role(tox0, groupnumber, (uint32_t)state0->peers->peer_ids[i], TOX_GROUP_ROLE_USER,
                           &role_err);
        ck_assert_msg(role_err == TOX_ERR_GROUP_SET_ROLE_OK, "Failed to set user. error: %d", role_err);
    }

    do {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(autotoxes, NUM_GROUP_TOXES, groupnumber));

    fprintf(stderr, "Remaining moderators spam change non-moderator roles\n");

    role_spam(rng, autotoxes, NUM_GROUP_TOXES, num_demoted, groupnumber);

    fprintf(stderr, "All peers see the same roles\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        tox_group_leave(autotoxes[i].tox, groupnumber, nullptr, 0, nullptr);

        State *state = (State *)autotoxes[i].state;
        peers_cleanup(state->peers);
    }

    fprintf(stderr, "All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_sync_test, sizeof(State), &autotest_opts);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef ROLE_SPAM_ITERATIONS
#undef TOPIC_SPAM_ITERATIONS
