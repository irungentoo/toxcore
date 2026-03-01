#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_PEERS 5
#define GROUP_NAME "The Crystal Palace"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)
#define PEER_LIMIT_1 NUM_PEERS
#define PEER_LIMIT_2 50

typedef struct {
    uint32_t group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    uint32_t peer_count;
    Tox_Group_Privacy_State privacy_state;
    Tox_Group_Voice_State voice_state;
    Tox_Group_Topic_Lock topic_lock;
    uint32_t peer_limit;
    uint8_t password[TOX_GROUP_MAX_PASSWORD_SIZE];
    size_t password_len;
} GroupState;

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->peer_count++;
}

static void on_group_privacy_state(const Tox_Event_Group_Privacy_State *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->privacy_state = tox_event_group_privacy_state_get_privacy_state(event);
}

static void on_group_voice_state(const Tox_Event_Group_Voice_State *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->voice_state = tox_event_group_voice_state_get_voice_state(event);
}

static void on_group_topic_lock(const Tox_Event_Group_Topic_Lock *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->topic_lock = tox_event_group_topic_lock_get_topic_lock(event);
}

static void on_group_peer_limit(const Tox_Event_Group_Peer_Limit *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->peer_limit = tox_event_group_peer_limit_get_peer_limit(event);
}

static void on_group_password(const Tox_Event_Group_Password *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    GroupState *state = (GroupState *)tox_node_get_script_ctx(self);
    state->password_len = tox_event_group_password_get_password_length(event);
    if (state->password_len > 0) {
        memcpy(state->password, tox_event_group_password_get_password(event), state->password_len);
    }
}

static void founder_script(ToxNode *self, void *ctx)
{
    GroupState *state = (GroupState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);

    tox_node_wait_for_self_connected(self);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN,
                                        (const uint8_t *)"Founder", 7, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);
    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);

    tox_group_set_peer_limit(tox, state->group_number, PEER_LIMIT_1, nullptr);
    tox_group_set_privacy_state(tox, state->group_number, TOX_GROUP_PRIVACY_STATE_PUBLIC, nullptr);
    tox_group_set_password(tox, state->group_number, (const uint8_t *)PASSWORD, PASS_LEN, nullptr);
    tox_group_set_topic_lock(tox, state->group_number, TOX_GROUP_TOPIC_LOCK_ENABLED, nullptr);
    tox_group_set_voice_state(tox, state->group_number, TOX_GROUP_VOICE_STATE_ALL, nullptr);

    tox_scenario_barrier_wait(self); // Barrier 1: Founder set initial state

    WAIT_UNTIL(state->peer_count == NUM_PEERS - 1);
    tox_node_log(self, "All peers joined.");

    tox_scenario_barrier_wait(self); // Barrier 2: All peers joined

    tox_node_log(self, "Changing group state...");
    tox_group_set_peer_limit(tox, state->group_number, PEER_LIMIT_2, nullptr);
    tox_group_set_privacy_state(tox, state->group_number, TOX_GROUP_PRIVACY_STATE_PRIVATE, nullptr);
    tox_group_set_password(tox, state->group_number, nullptr, 0, nullptr);
    tox_group_set_topic_lock(tox, state->group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, nullptr);
    tox_group_set_voice_state(tox, state->group_number, TOX_GROUP_VOICE_STATE_MODERATOR, nullptr);

    tox_scenario_barrier_wait(self); // Barrier 3: State changed

    tox_scenario_barrier_wait(self); // Barrier 4: All peers verified state
}

static void peer_script(ToxNode *self, void *ctx)
{
    const GroupState *state = (const GroupState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_privacy_state(dispatch, on_group_privacy_state);
    tox_events_callback_group_voice_state(dispatch, on_group_voice_state);
    tox_events_callback_group_topic_lock(dispatch, on_group_topic_lock);
    tox_events_callback_group_peer_limit(dispatch, on_group_peer_limit);
    tox_events_callback_group_password(dispatch, on_group_password);

    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const GroupState *founder_view = (const GroupState *)tox_node_get_peer_ctx(founder);

    tox_scenario_barrier_wait(self); // Barrier 1: Founder set initial state

    Tox_Err_Group_Join join_err;
    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer", 4, (const uint8_t *)PASSWORD, PASS_LEN, &join_err);
    if (join_err != TOX_ERR_GROUP_JOIN_OK) {
        tox_node_log(self, "tox_group_join failed with error: %s", tox_err_group_join_to_string(join_err));
    }
    ck_assert(join_err == TOX_ERR_GROUP_JOIN_OK);

    WAIT_UNTIL(tox_group_is_connected(tox, 0, nullptr));

    tox_scenario_barrier_wait(self); // Barrier 2: All peers joined

    tox_scenario_barrier_wait(self); // Barrier 3: State changed

    WAIT_UNTIL(state->privacy_state == TOX_GROUP_PRIVACY_STATE_PRIVATE);
    WAIT_UNTIL(state->voice_state == TOX_GROUP_VOICE_STATE_MODERATOR);
    WAIT_UNTIL(state->topic_lock == TOX_GROUP_TOPIC_LOCK_DISABLED);
    WAIT_UNTIL(state->peer_limit == PEER_LIMIT_2);
    WAIT_UNTIL(state->password_len == 0);

    tox_node_log(self, "State verified.");

    tox_scenario_barrier_wait(self); // Barrier 4: All peers verified state
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    GroupState states[NUM_PEERS] = {{0}};

    ToxNode *nodes[NUM_PEERS];
    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(GroupState));
    for (int i = 1; i < NUM_PEERS; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Peer%d", i);
        nodes[i] = tox_scenario_add_node(s, alias, peer_script, &states[i], sizeof(GroupState));
    }

    for (int i = 1; i < NUM_PEERS; ++i) {
        tox_node_bootstrap(nodes[i], nodes[0]);
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef PASSWORD
#undef PASS_LEN
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef NUM_PEERS
