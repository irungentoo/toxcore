/*
 * Tests that we can save a groupchat and load a groupchat with the saved data.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "auto_test_support.h"

typedef struct State {
    bool     peer_joined;
} State;

#define NUM_GROUP_TOXES 2
#define GROUP_NAME "The Test Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define TOPIC "They're waiting for you Gordon..."
#define TOPIC_LEN (sizeof(TOPIC) - 1)
#define NEW_PRIV_STATE TOX_GROUP_PRIVACY_STATE_PRIVATE
#define PASSWORD "password123"
#define PASS_LEN (sizeof(PASSWORD) - 1)
#define PEER_LIMIT 69
#define PEER0_NICK "Mike"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) -1)
#define NEW_USER_STATUS TOX_USER_STATUS_BUSY

static void group_invite_handler(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *group_name, size_t group_name_length, void *user_data)
{
    Tox_Err_Group_Invite_Accept err_accept;
    tox_group_invite_accept(tox, friend_number, invite_data, length, (const uint8_t *)"test2", 5,
                            nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);

}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    AutoTox *autotox = (AutoTox *)user_data;
    ck_assert(autotox != nullptr);

    State *state = (State *)autotox->state;
    state->peer_joined = true;
}

/* Checks that group has the same state according to the above defines
 *
 * Returns 0 if state is correct.
 * Returns a value < 0 if state is incorrect.
 */
static int has_correct_group_state(const Tox *tox, uint32_t group_number, const uint8_t *expected_chat_id)
{
    Tox_Err_Group_State_Queries query_err;

    Tox_Group_Privacy_State priv_state = tox_group_get_privacy_state(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (priv_state != NEW_PRIV_STATE) {
        return -1;
    }

    size_t pass_len = tox_group_get_password_size(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    uint8_t password[TOX_GROUP_MAX_PASSWORD_SIZE];
    tox_group_get_password(tox, group_number, password, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (pass_len != PASS_LEN || memcmp(password, PASSWORD, pass_len) != 0) {
        return -2;
    }

    size_t gname_len = tox_group_get_name_size(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    uint8_t group_name[TOX_GROUP_MAX_GROUP_NAME_LENGTH];
    tox_group_get_name(tox, group_number, group_name, &query_err);

    if (gname_len != GROUP_NAME_LEN || memcmp(group_name, GROUP_NAME, gname_len) != 0) {
        return -3;
    }

    if (tox_group_get_peer_limit(tox, group_number, nullptr) != PEER_LIMIT) {
        return -4;
    }

    Tox_Group_Topic_Lock topic_lock = tox_group_get_topic_lock(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (topic_lock != TOX_GROUP_TOPIC_LOCK_DISABLED) {
        return -5;
    }

    Tox_Err_Group_State_Queries id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox, group_number, chat_id, &id_err);

    ck_assert(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (memcmp(chat_id, expected_chat_id, TOX_GROUP_CHAT_ID_SIZE) != 0) {
        return -6;
    }

    return 0;
}

static int has_correct_self_state(const Tox *tox, uint32_t group_number, const uint8_t *expected_self_pk)
{
    Tox_Err_Group_Self_Query sq_err;
    size_t self_length = tox_group_self_get_name_size(tox, group_number, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    uint8_t self_name[TOX_MAX_NAME_LENGTH];
    tox_group_self_get_name(tox, group_number, self_name, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    if (self_length != PEER0_NICK_LEN || memcmp(self_name, PEER0_NICK, self_length) != 0) {
        return -1;
    }

    TOX_USER_STATUS self_status = tox_group_self_get_status(tox, group_number, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    if (self_status != NEW_USER_STATUS) {
        return -2;
    }

    Tox_Group_Role self_role = tox_group_self_get_role(tox, group_number, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    if (self_role != TOX_GROUP_ROLE_FOUNDER) {
        return -3;
    }

    uint8_t self_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];

    tox_group_self_get_public_key(tox, group_number, self_pk, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    if (memcmp(self_pk, expected_self_pk, TOX_GROUP_PEER_PUBLIC_KEY_SIZE) != 0) {
        return -4;
    }

    return 0;
}

static void group_save_test(AutoTox *autotoxes)
{
    ck_assert_msg(NUM_GROUP_TOXES > 1, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_invite(autotoxes[i].tox, group_invite_handler);
        tox_callback_group_peer_join(autotoxes[i].tox, group_peer_join_handler);
    }

    Tox *tox0 = autotoxes[0].tox;

    const State *state0 = (State *)autotoxes[0].state;
    const State *state1 = (State *)autotoxes[1].state;

    Tox_Err_Group_New err_new;
    const uint32_t group_number = tox_group_new(tox0, TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)GROUP_NAME,
                                  GROUP_NAME_LEN, (const uint8_t *)"test", 4, &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    Tox_Err_Group_State_Queries id_err;
    tox_group_get_chat_id(tox0, group_number, chat_id, &id_err);
    ck_assert(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    uint8_t founder_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];

    Tox_Err_Group_Self_Query sq_err;
    tox_group_self_get_public_key(tox0, group_number, founder_pk, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);


    Tox_Err_Group_Invite_Friend err_invite;
    tox_group_invite_friend(tox0, group_number, 0, &err_invite);

    ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);

    while (!state0->peer_joined && !state1->peer_joined) {
        iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);
    }

    printf("tox0 invites tox1 to group\n");

    // change group state
    Tox_Err_Group_Topic_Set top_err;
    tox_group_set_topic(tox0, group_number, (const uint8_t *)TOPIC, TOPIC_LEN, &top_err);
    ck_assert(top_err == TOX_ERR_GROUP_TOPIC_SET_OK);

    Tox_Err_Group_Founder_Set_Topic_Lock lock_set_err;
    tox_group_founder_set_topic_lock(tox0, group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, &lock_set_err);
    ck_assert(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK);

    Tox_Err_Group_Founder_Set_Privacy_State priv_err;
    tox_group_founder_set_privacy_state(tox0, group_number, NEW_PRIV_STATE, &priv_err);
    ck_assert(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK);

    Tox_Err_Group_Founder_Set_Password pass_set_err;
    tox_group_founder_set_password(tox0, group_number, (const uint8_t *)PASSWORD, PASS_LEN, &pass_set_err);
    ck_assert(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK);

    Tox_Err_Group_Founder_Set_Peer_Limit limit_set_err;
    tox_group_founder_set_peer_limit(tox0, group_number, PEER_LIMIT, &limit_set_err);
    ck_assert(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK);

    // change self state
    Tox_Err_Group_Self_Name_Set n_err;
    tox_group_self_set_name(tox0, group_number, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, &n_err);
    ck_assert(n_err == TOX_ERR_GROUP_SELF_NAME_SET_OK);

    Tox_Err_Group_Self_Status_Set s_err;
    tox_group_self_set_status(tox0, group_number, NEW_USER_STATUS, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_STATUS_SET_OK);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    printf("tox0 changes group state\n");

    const size_t save_length = tox_get_savedata_size(tox0);

    uint8_t *save = (uint8_t *)malloc(save_length);

    ck_assert(save != nullptr);

    tox_get_savedata(tox0, save);

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        tox_group_leave(autotoxes[i].tox, group_number, nullptr, 0, nullptr);
    }

    struct Tox_Options *const options = tox_options_new(nullptr);

    ck_assert(options != nullptr);

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    tox_options_set_savedata_data(options, save, save_length);

    Tox *new_tox = tox_new_log(options, nullptr, nullptr);

    ck_assert(new_tox != nullptr);

    iterate_all_wait(autotoxes, NUM_GROUP_TOXES, ITERATION_INTERVAL);

    printf("tox0 saves group and reloads client\n");

    const int group_ret = has_correct_group_state(new_tox, group_number, chat_id);

    ck_assert_msg(group_ret == 0, "incorrect group state: %d", group_ret);

    const int self_ret = has_correct_self_state(new_tox, group_number, founder_pk);

    ck_assert_msg(self_ret == 0, "incorrect self state: %d", self_ret);

    tox_group_leave(new_tox, group_number, nullptr, 0, nullptr);

    free(save);

    tox_options_free(options);

    tox_kill(new_tox);

    printf("All tests passed!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotest_opts = default_run_auto_options();
    autotest_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_save_test, sizeof(State), &autotest_opts);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef TOPIC
#undef TOPIC_LEN
#undef NEW_PRIV_STATE
#undef PASSWORD
#undef PASS_LEN
#undef PEER_LIMIT
#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef NEW_USER_STATUS
