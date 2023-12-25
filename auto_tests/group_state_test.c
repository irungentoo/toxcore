/*
 * Tests that we can successfully change the group state and that all peers in the group
 * receive the correct state changes.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "auto_test_support.h"
#include "check_compat.h"

#define NUM_GROUP_TOXES 5

#define PEER_LIMIT_1 NUM_GROUP_TOXES
#define PEER_LIMIT_2 50

#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)

#define GROUP_NAME "The Crystal Palace"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

#define PEER0_NICK "David"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)

typedef struct State {
    size_t  num_peers;
} State;

static bool all_group_peers_connected(const AutoTox *autotoxes, uint32_t tox_count, uint32_t groupnumber,
                                      size_t name_length, uint32_t peer_limit)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        // make sure we got an invite response
        if (tox_group_get_name_size(autotoxes[i].tox, groupnumber, nullptr) != name_length) {
            return false;
        }

        // make sure we got a sync response
        if (tox_group_get_peer_limit(autotoxes[i].tox, groupnumber, nullptr) != peer_limit) {
            return false;
        }

        // make sure we're actually connected
        if (!tox_group_is_connected(autotoxes[i].tox, groupnumber, nullptr)) {
            return false;
        }

        const State *state = (const State *)autotoxes[i].state;

        // make sure all peers are connected to one another
        if (state->num_peers < NUM_GROUP_TOXES - 1) {
            return false;
        }
    }

    return true;
}

static void group_topic_lock_handler(Tox *tox, uint32_t groupnumber, Tox_Group_Topic_Lock topic_lock,
                                     void *user_data)
{
    Tox_Err_Group_State_Queries err;
    Tox_Group_Topic_Lock current_topic_lock = tox_group_get_topic_lock(tox, groupnumber, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(current_topic_lock == topic_lock, "topic locks don't match in callback: %d %d",
                  topic_lock, current_topic_lock);
}

static void group_voice_state_handler(Tox *tox, uint32_t groupnumber, Tox_Group_Voice_State voice_state,
                                      void *user_data)
{
    Tox_Err_Group_State_Queries err;
    Tox_Group_Voice_State current_voice_state = tox_group_get_voice_state(tox, groupnumber, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(current_voice_state == voice_state, "voice states don't match in callback: %d %d",
                  voice_state, current_voice_state);
}

static void group_privacy_state_handler(Tox *tox, uint32_t groupnumber, Tox_Group_Privacy_State privacy_state,
                                        void *user_data)
{
    Tox_Err_Group_State_Queries err;
    Tox_Group_Privacy_State current_pstate = tox_group_get_privacy_state(tox, groupnumber, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(current_pstate == privacy_state, "privacy states don't match in callback");
}

static void group_peer_limit_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, void *user_data)
{
    Tox_Err_Group_State_Queries err;
    uint32_t current_plimit = tox_group_get_peer_limit(tox, groupnumber, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(peer_limit == current_plimit,
                  "Peer limits don't match in callback: %u, %u\n", peer_limit, current_plimit);
}

static void group_password_handler(Tox *tox, uint32_t groupnumber, const uint8_t *password, size_t length,
                                   void *user_data)
{
    Tox_Err_Group_State_Queries err;
    size_t curr_pwlength = tox_group_get_password_size(tox, groupnumber, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert(length == curr_pwlength);

    uint8_t current_password[TOX_GROUP_MAX_PASSWORD_SIZE];
    tox_group_get_password(tox, groupnumber, current_password, &err);

    ck_assert(err == TOX_ERR_GROUP_STATE_QUERIES_OK);
    ck_assert_msg(memcmp(current_password, password, length) == 0,
                  "Passwords don't match: %s, %s", password, current_password);
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;

    ++state->num_peers;
    ck_assert(state->num_peers < NUM_GROUP_TOXES);
}

/* Returns 0 if group state is equal to the state passed to this function.
 * Returns negative integer if state is invalid.
 */
static int check_group_state(const Tox *tox, uint32_t groupnumber, uint32_t peer_limit,
                             Tox_Group_Privacy_State priv_state, Tox_Group_Voice_State voice_state,
                             const uint8_t *password, size_t pass_len, Tox_Group_Topic_Lock topic_lock)
{
    Tox_Err_Group_State_Queries query_err;

    Tox_Group_Privacy_State my_priv_state = tox_group_get_privacy_state(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get privacy state: %d", query_err);

    if (my_priv_state != priv_state) {
        return -1;
    }

    uint32_t my_peer_limit = tox_group_get_peer_limit(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get peer limit: %d", query_err);

    if (my_peer_limit != peer_limit) {
        return -2;
    }

    size_t my_pass_len = tox_group_get_password_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get password size: %d", query_err);

    if (my_pass_len != pass_len) {
        return -5;
    }

    if (password != nullptr && my_pass_len > 0) {
        ck_assert(my_pass_len <= TOX_GROUP_MAX_PASSWORD_SIZE);

        uint8_t my_pass[TOX_GROUP_MAX_PASSWORD_SIZE];
        tox_group_get_password(tox, groupnumber, my_pass, &query_err);
        my_pass[my_pass_len] = 0;
        ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get password: %d", query_err);

        if (memcmp(my_pass, password, my_pass_len) != 0) {
            return -6;
        }
    }

    /* Group name should never change */
    size_t my_gname_len = tox_group_get_name_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get group name size: %d", query_err);

    if (my_gname_len != GROUP_NAME_LEN) {
        return -7;
    }

    ck_assert(my_gname_len <= TOX_GROUP_MAX_GROUP_NAME_LENGTH);

    uint8_t my_gname[TOX_GROUP_MAX_GROUP_NAME_LENGTH];
    tox_group_get_name(tox, groupnumber, my_gname, &query_err);
    my_gname[my_gname_len] = 0;

    if (memcmp(my_gname, (const uint8_t *)GROUP_NAME, my_gname_len) != 0) {
        return -8;
    }

    Tox_Group_Topic_Lock current_topic_lock = tox_group_get_topic_lock(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get topic lock: %d", query_err);

    if (current_topic_lock != topic_lock) {
        return -9;
    }

    Tox_Group_Voice_State current_voice_state = tox_group_get_voice_state(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get voice state: %d", query_err);

    if (current_voice_state != voice_state) {
        return -10;
    }

    return 0;
}

static void set_group_state(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, Tox_Group_Privacy_State priv_state,
                            Tox_Group_Voice_State voice_state, const uint8_t *password, size_t pass_len,
                            Tox_Group_Topic_Lock topic_lock)
{

    Tox_Err_Group_Founder_Set_Peer_Limit limit_set_err;
    tox_group_founder_set_peer_limit(tox, groupnumber, peer_limit, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK, "failed to set peer limit: %d", limit_set_err);

    Tox_Err_Group_Founder_Set_Privacy_State priv_err;
    tox_group_founder_set_privacy_state(tox, groupnumber, priv_state, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK, "failed to set privacy state: %d", priv_err);

    Tox_Err_Group_Founder_Set_Password pass_set_err;
    tox_group_founder_set_password(tox, groupnumber, password, pass_len, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK, "failed to set password: %d", pass_set_err);

    Tox_Err_Group_Founder_Set_Topic_Lock lock_set_err;
    tox_group_founder_set_topic_lock(tox, groupnumber, topic_lock, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to set topic lock: %d",
                  lock_set_err);

    Tox_Err_Group_Founder_Set_Voice_State voice_set_err;
    tox_group_founder_set_voice_state(tox, groupnumber, voice_state, &voice_set_err);
    ck_assert_msg(voice_set_err == TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_OK, "failed to set voice state: %d",
                  voice_set_err);
}

static void group_state_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES >= 3, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_privacy_state(autotoxes[i].tox, group_privacy_state_handler);
        tox_callback_group_peer_limit(autotoxes[i].tox, group_peer_limit_handler);
        tox_callback_group_password(autotoxes[i].tox, group_password_handler);
        tox_callback_group_peer_join(autotoxes[i].tox, group_peer_join_handler);
        tox_callback_group_voice_state(autotoxes[i].tox, group_voice_state_handler);
        tox_callback_group_topic_lock(autotoxes[i].tox, group_topic_lock_handler);
    }

    Tox *tox0 = autotoxes[0].tox;

    /* Tox 0 creates a group and is the founder of a newly created group */
    Tox_Err_Group_New new_err;
    uint32_t groupnum = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN,
                                      (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, &new_err);

    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    /* Founder sets default group state before anyone else joins */
    set_group_state(tox0, groupnum, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, TOX_GROUP_VOICE_STATE_ALL,
                    (const uint8_t *)PASSWORD, PASS_LEN, TOX_GROUP_TOPIC_LOCK_ENABLED);

    /* Founder gets the Chat ID and implicitly shares it publicly */
    Tox_Err_Group_State_Queries id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox0, groupnum, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID and password */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        Tox_Err_Group_Join join_err;
        tox_group_join(autotoxes[i].tox, chat_id, (const uint8_t *)"Test", 4, (const uint8_t *)PASSWORD, PASS_LEN,
                       &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);
    }

    fprintf(stderr, "Peers attempting to join group\n");

    /* Keep checking if all instances have connected to the group until test times out */
    while (!all_group_peers_connected(autotoxes, NUM_GROUP_TOXES, groupnum, GROUP_NAME_LEN, PEER_LIMIT_1)) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    /* Change group state and check that all peers received the changes */
    set_group_state(tox0, groupnum, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, TOX_GROUP_VOICE_STATE_MODERATOR,
                    nullptr, 0, TOX_GROUP_TOPIC_LOCK_DISABLED);

    fprintf(stderr, "Changing state\n");

    while (1) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (check_group_state(autotoxes[i].tox, groupnum, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE,
                                  TOX_GROUP_VOICE_STATE_MODERATOR, nullptr, 0, TOX_GROUP_TOPIC_LOCK_DISABLED) == 0) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            fprintf(stderr, "%u peers successfully received state changes\n", count);
            break;
        }
    }

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        Tox_Err_Group_Leave err_exit;
        tox_group_leave(autotoxes[i].tox, groupnum, nullptr, 0, &err_exit);
        ck_assert_msg(err_exit == TOX_ERR_GROUP_LEAVE_OK, "%d", err_exit);
    }

    fprintf(stderr, "All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_state_test, sizeof(State), &autotest_opts);

    return 0;
}

#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef GROUP_NAME_LEN
#undef GROUP_NAME
#undef PASS_LEN
#undef PASSWORD
#undef PEER_LIMIT_2
#undef PEER_LIMIT_1
#undef NUM_GROUP_TOXES
