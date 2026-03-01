#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GROUP_NAME "The Test Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define TOPIC "They're waiting for you Gordon..."
#define TOPIC_LEN (sizeof(TOPIC) - 1)
#define NEW_PRIV_STATE TOX_GROUP_PRIVACY_STATE_PRIVATE
#define PASSWORD "password123"
#define PASS_LEN (sizeof(PASSWORD) - 1)
#define PEER_LIMIT 69
#define PEER0_NICK "Mike"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)
#define NEW_USER_STATUS TOX_USER_STATUS_BUSY

typedef struct {
    bool peer_joined;
} State;

static void on_group_invite(const Tox_Event_Group_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    uint32_t friend_number = tox_event_group_invite_get_friend_number(event);
    const uint8_t *invite_data = tox_event_group_invite_get_invite_data(event);
    size_t length = tox_event_group_invite_get_invite_data_length(event);

    tox_group_invite_accept(tox_node_get_tox(self), friend_number, invite_data, length, (const uint8_t *)"Bob", 3, nullptr, 0, nullptr);
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->peer_joined = true;
}

static void check_founder_state(ToxNode *self, uint32_t group_number, const uint8_t *expected_chat_id, const uint8_t *expected_self_pk)
{
    Tox *tox = tox_node_get_tox(self);
    Tox_Err_Group_State_Query query_err;

    // Group state
    ck_assert(tox_group_get_privacy_state(tox, group_number, &query_err) == NEW_PRIV_STATE);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);

    uint8_t password[TOX_GROUP_MAX_PASSWORD_SIZE];
    size_t pass_len = tox_group_get_password_size(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);
    tox_group_get_password(tox, group_number, password, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);
    ck_assert(pass_len == PASS_LEN && memcmp(password, PASSWORD, pass_len) == 0);

    uint8_t gname[TOX_GROUP_MAX_GROUP_NAME_LENGTH];
    size_t gname_len = tox_group_get_name_size(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERY_OK);
    tox_group_get_name(tox, group_number, gname, &query_err);
    ck_assert(gname_len == GROUP_NAME_LEN && memcmp(gname, GROUP_NAME, gname_len) == 0);

    ck_assert(tox_group_get_peer_limit(tox, group_number, nullptr) == PEER_LIMIT);
    ck_assert(tox_group_get_topic_lock(tox, group_number, nullptr) == TOX_GROUP_TOPIC_LOCK_DISABLED);

    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox, group_number, chat_id, nullptr);
    ck_assert(memcmp(chat_id, expected_chat_id, TOX_GROUP_CHAT_ID_SIZE) == 0);

    // Self state
    Tox_Err_Group_Self_Query sq_err;
    uint8_t self_name[TOX_MAX_NAME_LENGTH];
    size_t self_len = tox_group_self_get_name_size(tox, group_number, &sq_err);
    tox_group_self_get_name(tox, group_number, self_name, nullptr);
    ck_assert(self_len == PEER0_NICK_LEN && memcmp(self_name, PEER0_NICK, self_len) == 0);

    ck_assert(tox_group_self_get_status(tox, group_number, nullptr) == NEW_USER_STATUS);
    ck_assert(tox_group_self_get_role(tox, group_number, nullptr) == TOX_GROUP_ROLE_FOUNDER);

    uint8_t self_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_self_get_public_key(tox, group_number, self_pk, nullptr);
    ck_assert(memcmp(self_pk, expected_self_pk, TOX_GROUP_PEER_PUBLIC_KEY_SIZE) == 0);
}

static void founder_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_peer_join(tox_node_get_dispatch(self), on_group_peer_join);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox_Err_Group_New err_new;
    uint32_t group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)"test", 4, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox, group_number, chat_id, nullptr);

    uint8_t founder_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_self_get_public_key(tox, group_number, founder_pk, nullptr);

    tox_group_invite_friend(tox, group_number, 0, nullptr);
    WAIT_UNTIL(state->peer_joined);

    tox_node_log(self, "Bob joined. Changing group state...");
    tox_group_set_topic(tox, group_number, (const uint8_t *)TOPIC, TOPIC_LEN, nullptr);
    tox_group_set_topic_lock(tox, group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, nullptr);
    tox_group_set_privacy_state(tox, group_number, NEW_PRIV_STATE, nullptr);
    tox_group_set_password(tox, group_number, (const uint8_t *)PASSWORD, PASS_LEN, nullptr);
    tox_group_set_peer_limit(tox, group_number, PEER_LIMIT, nullptr);
    tox_group_self_set_name(tox, group_number, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, nullptr);
    tox_group_self_set_status(tox, group_number, NEW_USER_STATUS, nullptr);

    tox_scenario_yield(self);

    tox_node_log(self, "Saving and reloading...");
    tox_node_reload(self);
    tox_node_log(self, "Reloaded.");

    tox_node_wait_for_self_connected(self);
    check_founder_state(self, group_number, chat_id, founder_pk);
    tox_node_log(self, "State verified after reload.");
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_events_callback_group_invite(tox_node_get_dispatch(self), on_group_invite);
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    tox_node_log(self, "Waiting for founder to finish...");
    WAIT_UNTIL(tox_node_is_finished(founder));
    tox_node_log(self, "Founder finished, Bob exiting.");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    State states[2] = {{0}};

    Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_experimental_groups_persistence(opts, true);
    tox_options_set_ipv6_enabled(opts, false);
    tox_options_set_local_discovery_enabled(opts, false);

    ToxNode *alice = tox_scenario_add_node_ex(s, "Alice", founder_script, &states[0], sizeof(State), opts);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &states[1], sizeof(State));
    tox_options_free(opts);

    tox_node_bootstrap(bob, alice);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef PASSWORD
#undef PASS_LEN
#undef PEER_LIMIT
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef TOPIC
#undef TOPIC_LEN
#undef PEER0_NICK
#undef PEER0_NICK_LEN
