/*
 * Tests that we can successfully change the group topic, that all peers receive topic changes
 * and that the topic lock works as intended.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "auto_test_support.h"
#include "check_compat.h"

#include "../toxcore/tox.h"
#include "../toxcore/group_chats.h"

#define NUM_GROUP_TOXES 3

#define TOPIC "They're waiting for you Gordon...in the test chamber"
#define TOPIC_LEN (sizeof(TOPIC) - 1)

#define TOPIC2 "They're waiting for you Gordon...in the test chamber 2.0"
#define TOPIC_LEN2 (sizeof(TOPIC2) - 1)

#define GROUP_NAME "The Test Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

#define PEER0_NICK "Koresh"
#define PEER0_NICK_LEN  (sizeof(PEER0_NICK) - 1)

typedef struct State {
    uint32_t peer_id;  // the id of the peer we set to observer
} State;

static bool all_group_peers_connected(const AutoTox *autotoxes, uint32_t tox_count, uint32_t groupnumber,
                                      size_t name_length, uint32_t peer_limit)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        // make sure we got an invite
        if (tox_group_get_name_size(autotoxes[i].tox, groupnumber, nullptr) != name_length) {
            return false;
        }

        // make sure we got a sync response
        if (peer_limit != 0 && tox_group_get_peer_limit(autotoxes[i].tox, groupnumber, nullptr) != peer_limit) {
            return false;
        }

        // make sure we're actually connected
        if (!tox_group_is_connected(autotoxes[i].tox, groupnumber, nullptr)) {
            return false;
        }
    }

    return true;
}

static void group_peer_join_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    state->peer_id = peer_id;
}

static void group_topic_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *topic,
                                size_t length, void *user_data)
{
    ck_assert(length <= TOX_GROUP_MAX_TOPIC_LENGTH);

    Tox_Err_Group_State_Queries query_err;
    uint8_t topic2[TOX_GROUP_MAX_TOPIC_LENGTH];
    tox_group_get_topic(tox, groupnumber, topic2, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    size_t topic_length = tox_group_get_topic_size(tox, groupnumber, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(topic_length == length && memcmp(topic, topic2, length) == 0,
                  "topic differs in callback: %s, %s", topic, topic2);
}

static void group_topic_lock_handler(Tox *tox, uint32_t groupnumber, Tox_Group_Topic_Lock topic_lock, void *user_data)
{
    Tox_Err_Group_State_Queries err;
    Tox_Group_Topic_Lock current_lock = tox_group_get_topic_lock(tox, groupnumber, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(topic_lock == current_lock, "topic locks differ in callback");
}

/* Sets group topic.
 *
 * Return true on success.
 */
static bool set_topic(Tox *tox, uint32_t groupnumber, const char *topic, size_t length)
{
    Tox_Err_Group_Topic_Set err;
    tox_group_set_topic(tox, groupnumber, (const uint8_t *)topic, length, &err);

    return err == TOX_ERR_GROUP_TOPIC_SET_OK;
}

/* Returns 0 if group topic matches expected topic.
 * Returns a value < 0 on failure.
 */
static int check_topic(const Tox *tox, uint32_t groupnumber, const char *expected_topic, size_t expected_length)
{
    Tox_Err_Group_State_Queries query_err;
    size_t topic_length = tox_group_get_topic_size(tox, groupnumber, &query_err);

    if (query_err != TOX_ERR_GROUP_STATE_QUERIES_OK) {
        return -1;
    }

    if (expected_length != topic_length) {
        return -2;
    }

    uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    tox_group_get_topic(tox, groupnumber, topic, &query_err);

    if (query_err != TOX_ERR_GROUP_STATE_QUERIES_OK) {
        return -3;
    }

    if (memcmp(expected_topic, (const char *)topic, topic_length) != 0) {
        return -4;
    }

    return 0;
}

static void wait_topic_lock(AutoTox *autotoxes, uint32_t groupnumber, Tox_Group_Topic_Lock expected_lock)
{
    while (1) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            Tox_Err_Group_State_Queries err;
            Tox_Group_Topic_Lock topic_lock = tox_group_get_topic_lock(autotoxes[i].tox, groupnumber, &err);
            ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);

            if (topic_lock == expected_lock) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            break;
        }
    }
}

/* Waits for all peers in group to see the same topic */
static void wait_state_topic(AutoTox *autotoxes, uint32_t groupnumber, const char *topic, size_t length)
{
    while (1) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            const int c_ret = check_topic(autotoxes[i].tox, groupnumber, topic, length);

            if (c_ret == 0) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            break;
        }
    }
}

/* All peers attempt to set the topic.
 *
 * Returns the number of peers who succeeeded.
 */
static uint32_t set_topic_all_peers(const Random *rng, AutoTox *autotoxes, size_t num_peers, uint32_t groupnumber)
{
    uint32_t change_count = 0;

    for (size_t i = 0; i < num_peers; ++i) {
        char new_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        snprintf(new_topic, sizeof(new_topic), "peer %zu changes topic %u", i, random_u32(rng));
        size_t length = strlen(new_topic);

        if (set_topic(autotoxes[i].tox, groupnumber, new_topic, length)) {
            wait_state_topic(autotoxes, groupnumber, new_topic, length);
            ++change_count;
        } else {
            fprintf(stderr, "Peer %zu couldn't set the topic\n", i);
        }
    }

    return change_count;
}

static void group_topic_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES >= 3, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    const Random *rng = system_random();
    ck_assert(rng != nullptr);

    Tox *tox0 = autotoxes[0].tox;
    const State *state0 = (const State *)autotoxes[0].state;

    tox_callback_group_peer_join(tox0, group_peer_join_handler);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_topic(autotoxes[i].tox, group_topic_handler);
        tox_callback_group_topic_lock(autotoxes[i].tox, group_topic_lock_handler);
    }

    /* Tox1 creates a group and is the founder of a newly created group */
    Tox_Err_Group_New new_err;
    const uint32_t groupnumber = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME,
                                 GROUP_NAME_LEN,
                                 (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, &new_err);

    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    /* Founder sets group topic before anyone else joins */
    const bool s_ret = set_topic(tox0, groupnumber, TOPIC, TOPIC_LEN);
    ck_assert_msg(s_ret, "Founder failed to set topic");

    /* Founder gets the Chat ID and implicitly shares it publicly */
    Tox_Err_Group_State_Queries id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox0, groupnumber, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        Tox_Err_Group_Join join_err;
        tox_group_join(autotoxes[i].tox, chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);

        c_sleep(100);
    }

    fprintf(stderr, "Peers attempting to join group\n");

    all_group_peers_connected(autotoxes, NUM_GROUP_TOXES, groupnumber, GROUP_NAME_LEN, MAX_GC_PEERS_DEFAULT);

    wait_state_topic(autotoxes, groupnumber, TOPIC, TOPIC_LEN);

    /* Founder disables topic lock */
    Tox_Err_Group_Founder_Set_Topic_Lock lock_set_err;
    tox_group_founder_set_topic_lock(tox0, groupnumber, TOX_GROUP_TOPIC_LOCK_DISABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to disable topic lock: %d",
                  lock_set_err);

    fprintf(stderr, "Topic lock disabled\n");

    /* make sure every peer sees the topic lock state change */
    wait_topic_lock(autotoxes, groupnumber, TOX_GROUP_TOPIC_LOCK_DISABLED);

    /* All peers should be able to change the topic now */
    uint32_t change_count = set_topic_all_peers(rng, autotoxes, NUM_GROUP_TOXES, groupnumber);

    ck_assert_msg(change_count == NUM_GROUP_TOXES, "%u peers changed the topic with topic lock disabled", change_count);

    /* founder silences the last peer he saw join */
    Tox_Err_Group_Mod_Set_Role merr;
    tox_group_mod_set_role(tox0, groupnumber, state0->peer_id, TOX_GROUP_ROLE_OBSERVER, &merr);
    ck_assert_msg(merr == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set %u to observer role: %d", state0->peer_id, merr);

    fprintf(stderr, "Random peer is set to observer\n");

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    /* All peers except one should now be able to change the topic */
    change_count = set_topic_all_peers(rng, autotoxes, NUM_GROUP_TOXES, groupnumber);

    ck_assert_msg(change_count == NUM_GROUP_TOXES - 1, "%u peers changed the topic with a silenced peer", change_count);

    /* Founder enables topic lock and sets topic back to original */
    tox_group_founder_set_topic_lock(tox0, groupnumber, TOX_GROUP_TOPIC_LOCK_ENABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to enable topic lock: %d",
                  lock_set_err);

    fprintf(stderr, "Topic lock enabled\n");

    /* Wait for all peers to get topic lock state change */
    wait_topic_lock(autotoxes, groupnumber, TOX_GROUP_TOPIC_LOCK_ENABLED);

    const bool s3_ret = set_topic(tox0, groupnumber, TOPIC2, TOPIC_LEN2);
    ck_assert_msg(s3_ret, "Founder failed to set topic second time");

    wait_state_topic(autotoxes, groupnumber, TOPIC2, TOPIC_LEN2);

    /* No peer excluding the founder should be able to set the topic */

    change_count = set_topic_all_peers(rng, &autotoxes[1], NUM_GROUP_TOXES - 1, groupnumber);

    ck_assert_msg(change_count == 0, "%u peers changed the topic with topic lock enabled", change_count);

    /* A final check that the topic is unchanged */
    wait_state_topic(autotoxes, groupnumber, TOPIC2, TOPIC_LEN2);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        Tox_Err_Group_Leave err_exit;
        tox_group_leave(autotoxes[i].tox, groupnumber, nullptr, 0, &err_exit);
        ck_assert_msg(err_exit == TOX_ERR_GROUP_LEAVE_OK, "%d", err_exit);
    }

    fprintf(stderr, "All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_topic_test, sizeof(State), &autotest_opts);

    return 0;
}

#undef TOPIC
#undef TOPIC_LEN
#undef TOPIC2
#undef TOPIC_LEN2
#undef NUM_GROUP_TOXES
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef PEER0_NICK
#undef PEER0_NICK_LEN
