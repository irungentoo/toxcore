#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define GROUP_NAME "NASA Headquarters"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define TOPIC "Funny topic here"
#define TOPIC_LEN (sizeof(TOPIC) - 1)
#define PEER0_NICK "Lois"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)
#define PEER0_NICK2 "Terry Davis"
#define PEER0_NICK2_LEN (sizeof(PEER0_NICK2) - 1)
#define PEER1_NICK "Bran"
#define PEER1_NICK_LEN (sizeof(PEER1_NICK) - 1)
#define EXIT_MESSAGE "Goodbye world"
#define EXIT_MESSAGE_LEN (sizeof(EXIT_MESSAGE) - 1)
#define PEER_LIMIT 20

typedef struct {
    uint32_t group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    uint32_t peer_joined_count;
    uint32_t self_joined_count;
    uint32_t peer_exit_count;
    bool peer_nick_updated;
    bool peer_status_updated;
    uint32_t last_peer_id;
    bool is_founder;
    bool synced;
} GroupState;

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->peer_joined_count++;
    state->last_peer_id = tox_event_group_peer_join_get_peer_id(event);
    tox_node_log(self, "Peer joined: %u (total %u)", state->last_peer_id, state->peer_joined_count);
}

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->self_joined_count++;
    tox_node_log(self, "Self joined (total %u)", state->self_joined_count);
}

static void on_group_peer_exit(const Tox_Event_Group_Peer_Exit *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->peer_exit_count++;
    tox_node_log(self, "Peer exited (total %u)", state->peer_exit_count);

    if (state->peer_exit_count == 2) {
        size_t len = tox_event_group_peer_exit_get_part_message_length(event);
        const uint8_t *msg = tox_event_group_peer_exit_get_part_message(event);
        ck_assert(len == EXIT_MESSAGE_LEN);
        ck_assert(memcmp(msg, EXIT_MESSAGE, len) == 0);
    }
}

static void on_group_peer_name(const Tox_Event_Group_Peer_Name *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    size_t len = tox_event_group_peer_name_get_name_length(event);
    const uint8_t *name = tox_event_group_peer_name_get_name(event);
    if (len == PEER0_NICK2_LEN && memcmp(name, PEER0_NICK2, len) == 0) {
        state->peer_nick_updated = true;
    }
}

static void on_group_peer_status(const Tox_Event_Group_Peer_Status *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    if (tox_event_group_peer_status_get_status(event) == TOX_USER_STATUS_BUSY) {
        state->peer_status_updated = true;
    }
}

static void founder_script(ToxNode *self, void *ctx)
{
    GroupState *state = (GroupState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);

    tox_node_log(self, "Waiting for self connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Connected!");

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);
    tox_node_log(self, "Group created: %u", state->group_number);

    tox_group_set_peer_limit(tox, state->group_number, PEER_LIMIT, nullptr);
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)TOPIC, TOPIC_LEN, nullptr);

    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);

    // Signal Peer 1 that group is created
    tox_scenario_barrier_wait(self);

    // Wait for Peer 1 to join
    tox_node_log(self, "Waiting for peer to join...");
    WAIT_UNTIL(state->peer_joined_count == 1);
    tox_node_log(self, "Peer joined!");

    // Sync check
    WAIT_UNTIL(tox_group_is_connected(tox, state->group_number, nullptr));

    // Change name
    tox_group_self_set_name(tox, state->group_number, (const uint8_t *)PEER0_NICK2, PEER0_NICK2_LEN, nullptr);
    // Change status
    tox_group_self_set_status(tox, state->group_number, TOX_USER_STATUS_BUSY, nullptr);

    // Disconnect
    tox_node_log(self, "Disconnecting...");
    tox_group_disconnect(tox, state->group_number, nullptr);

    // Wait some time
    for (int i = 0; i < 50; ++i) {
        tox_scenario_yield(self);
    }

    // Reconnect
    tox_node_log(self, "Reconnecting...");
    tox_group_join(tox, state->chat_id, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, nullptr, 0, nullptr);

    WAIT_UNTIL(tox_group_is_connected(tox, state->group_number, nullptr));

    // Wait for Peer 1 to see us
    for (int i = 0; i < 100; ++i) {
        tox_scenario_yield(self);
    }

    // Leave
    tox_node_log(self, "Leaving with message...");
    tox_group_leave(tox, state->group_number, (const uint8_t *)EXIT_MESSAGE, EXIT_MESSAGE_LEN, nullptr);
}

static void peer1_script(ToxNode *self, void *ctx)
{
    const GroupState *state = (const GroupState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);
    tox_events_callback_group_peer_name(dispatch, on_group_peer_name);
    tox_events_callback_group_peer_status(dispatch, on_group_peer_status);
    tox_events_callback_group_peer_exit(dispatch, on_group_peer_exit);

    tox_node_log(self, "Waiting for self connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Connected!");

    // Wait for Founder to create group and get chat_id
    tox_node_log(self, "Waiting for founder to create group...");
    tox_scenario_barrier_wait(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const GroupState *founder_view = (const GroupState *)tox_node_get_peer_ctx(founder);

    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    memcpy(chat_id, founder_view->chat_id, TOX_GROUP_CHAT_ID_SIZE);
    tox_node_log(self, "Got chat ID from founder!");

    tox_node_log(self, "Joining group...");
    tox_group_join(tox, chat_id, (const uint8_t *)PEER1_NICK, PEER1_NICK_LEN, nullptr, 0, nullptr);

    WAIT_UNTIL(state->self_joined_count == 1);
    WAIT_UNTIL(state->peer_joined_count == 1);
    WAIT_UNTIL(tox_group_is_connected(tox, 0, nullptr));

    WAIT_UNTIL(state->peer_nick_updated);
    WAIT_UNTIL(state->peer_status_updated);

    // Founder will disconnect
    WAIT_UNTIL(state->peer_exit_count == 1);

    // Change status while alone
    tox_group_self_set_status(tox, 0, TOX_USER_STATUS_AWAY, nullptr);

    // Founder will reconnect
    WAIT_UNTIL(state->peer_joined_count == 2);

    // Founder will leave with message
    WAIT_UNTIL(state->peer_exit_count == 2);

    tox_group_leave(tox, 0, nullptr, 0, nullptr);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    GroupState s0 = { .group_number = UINT32_MAX, .is_founder = true };
    GroupState s1 = { .group_number = UINT32_MAX, .is_founder = false };

    ToxNode *n0 = tox_scenario_add_node(s, "Founder", founder_script, &s0, sizeof(GroupState));
    ToxNode *n1 = tox_scenario_add_node(s, "Peer1", peer1_script, &s1, sizeof(GroupState));

    tox_node_bootstrap(n1, n0);
    // Note: No friend add needed for public groups, they find each other via DHT

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef PEER_LIMIT
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef TOPIC
#undef TOPIC_LEN
#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef PEER1_NICK
#undef PEER1_NICK_LEN
