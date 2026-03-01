#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_PEERS 3
#define GROUP_NAME "The Test Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define TOPIC1 "Topic One"
#define TOPIC2 "Topic Two"

typedef struct {
    uint32_t group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    bool chat_id_ready;
    bool connected;
    uint32_t peer_ids[NUM_PEERS];
    uint8_t last_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t last_topic_len;
    Tox_Group_Topic_Lock topic_lock;
    Tox_Group_Role self_role;
} TopicState;

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    state->connected = true;
    state->group_number = tox_event_group_self_join_get_group_number(event);
    state->self_role = tox_group_self_get_role(tox_node_get_tox(self), state->group_number, nullptr);
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);
    uint32_t group_number = tox_event_group_peer_join_get_group_number(event);

    Tox_Err_Group_Peer_Query q_err;
    size_t length = tox_group_peer_get_name_size(tox_node_get_tox(self), group_number, peer_id, &q_err);
    if (q_err == TOX_ERR_GROUP_PEER_QUERY_OK && length > 0) {
        uint8_t name[TOX_MAX_NAME_LENGTH + 1];
        tox_group_peer_get_name(tox_node_get_tox(self), group_number, peer_id, name, &q_err);
        if (q_err == TOX_ERR_GROUP_PEER_QUERY_OK) {
            name[length] = 0;
            if (length >= 4 && memcmp(name, "Peer", 4) == 0) {
                uint32_t idx = (uint32_t)atoi((const char *)name + 4);
                if (idx < NUM_PEERS) {
                    state->peer_ids[idx] = peer_id;
                }
            }
        }
    }
}

static void on_group_topic(const Tox_Event_Group_Topic *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    state->last_topic_len = tox_event_group_topic_get_topic_length(event);
    memcpy(state->last_topic, tox_event_group_topic_get_topic(event), state->last_topic_len);
}

static void on_group_topic_lock(const Tox_Event_Group_Topic_Lock *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    state->topic_lock = tox_event_group_topic_lock_get_topic_lock(event);
}

static void on_group_moderation(const Tox_Event_Group_Moderation *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    Tox_Err_Group_Self_Query err;
    state->self_role = tox_group_self_get_role(tox_node_get_tox(self), state->group_number, &err);
}

static void common_init(ToxNode *self, TopicState *state)
{
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_topic(dispatch, on_group_topic);
    tox_events_callback_group_topic_lock(dispatch, on_group_topic_lock);
    tox_events_callback_group_moderation(dispatch, on_group_moderation);

    for (uint32_t i = 0; i < NUM_PEERS; ++i) {
        state->peer_ids[i] = UINT32_MAX;
    }
    state->topic_lock = TOX_GROUP_TOPIC_LOCK_ENABLED;

    tox_node_wait_for_self_connected(self);
}

static bool topic_is(ToxNode *self, const char *topic)
{
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    size_t len = strlen(topic);
    if (state->last_topic_len == len && memcmp(state->last_topic, topic, len) == 0) {
        return true;
    }

    Tox_Err_Group_State_Query err;
    size_t current_len = tox_group_get_topic_size(tox_node_get_tox(self), state->group_number, &err);
    if (err == TOX_ERR_GROUP_STATE_QUERY_OK && current_len == len) {
        uint8_t current_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        tox_group_get_topic(tox_node_get_tox(self), state->group_number, current_topic, &err);
        if (err == TOX_ERR_GROUP_STATE_QUERY_OK && memcmp(current_topic, topic, len) == 0) {
            state->last_topic_len = current_len;
            memcpy(state->last_topic, current_topic, current_len);
            return true;
        }
    }
    return false;
}

static bool topic_lock_is(ToxNode *self, Tox_Group_Topic_Lock lock)
{
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    if (state->topic_lock == lock) {
        return true;
    }

    Tox_Err_Group_State_Query err;
    Tox_Group_Topic_Lock current_lock = tox_group_get_topic_lock(tox_node_get_tox(self), state->group_number, &err);
    if (err == TOX_ERR_GROUP_STATE_QUERY_OK && current_lock == lock) {
        state->topic_lock = current_lock;
        return true;
    }
    return false;
}

static void founder_script(ToxNode *self, void *ctx)
{
    TopicState *state = (TopicState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)"Peer0", 5, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    state->peer_ids[0] = tox_group_self_get_peer_id(tox, state->group_number, nullptr);

    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);
    state->chat_id_ready = true;

    tox_scenario_barrier_wait(self); // 1: Peers joined
    for (uint32_t i = 1; i < NUM_PEERS; ++i) {
        WAIT_UNTIL(state->peer_ids[i] != UINT32_MAX);
    }
    tox_scenario_barrier_wait(self); // 2: Sync IDs

    // 3: Initial Topic
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)TOPIC1, strlen(TOPIC1), nullptr);
    WAIT_UNTIL(topic_is(self, TOPIC1));
    tox_scenario_barrier_wait(self);

    // 4: Disable topic lock
    tox_group_set_topic_lock(tox, state->group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, nullptr);
    WAIT_UNTIL(topic_lock_is(self, TOX_GROUP_TOPIC_LOCK_DISABLED));
    tox_scenario_barrier_wait(self);

    // 5: Peers changing topic
    tox_scenario_barrier_wait(self); // Peer 1 turn
    WAIT_UNTIL(topic_is(self, "Topic from Peer1"));
    tox_scenario_barrier_wait(self); // Peer 2 turn
    WAIT_UNTIL(topic_is(self, "Topic from Peer2"));

    // 6: Set Peer 2 to Observer
    tox_group_set_role(tox, state->group_number, state->peer_ids[2], TOX_GROUP_ROLE_OBSERVER, nullptr);
    tox_scenario_barrier_wait(self);

    // 7: Peer 1 changes topic, Peer 2 should fail
    tox_scenario_barrier_wait(self); // Peer 1 turn
    WAIT_UNTIL(topic_is(self, "Topic again from Peer1"));
    tox_scenario_barrier_wait(self); // Peer 2 turn (fails)

    // 8: Enable topic lock
    tox_group_set_topic_lock(tox, state->group_number, TOX_GROUP_TOPIC_LOCK_ENABLED, nullptr);
    WAIT_UNTIL(topic_lock_is(self, TOX_GROUP_TOPIC_LOCK_ENABLED));
    tox_scenario_barrier_wait(self);

    // 9: Peer 1 attempts to change topic (fails)
    tox_scenario_barrier_wait(self);

    // 10: Founder changes topic
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)TOPIC2, strlen(TOPIC2), nullptr);
    WAIT_UNTIL(topic_is(self, TOPIC2));
    tox_scenario_barrier_wait(self);
}

static void peer_script(ToxNode *self, void *ctx)
{
    TopicState *state = (TopicState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const TopicState *founder_view = (const TopicState *)tox_node_get_peer_ctx(founder);

    WAIT_UNTIL(founder_view->chat_id_ready);

    char name[16];
    snprintf(name, sizeof(name), "Peer%u", tox_node_get_index(self));
    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)name, strlen(name), nullptr, 0, nullptr);

    WAIT_UNTIL(state->connected);
    state->peer_ids[tox_node_get_index(self)] = tox_group_self_get_peer_id(tox, state->group_number, nullptr);

    tox_scenario_barrier_wait(self); // 1: Joined
    for (uint32_t i = 0; i < NUM_PEERS; ++i) if (i != tox_node_get_index(self)) {
            WAIT_UNTIL(state->peer_ids[i] != UINT32_MAX);
        }
    tox_scenario_barrier_wait(self); // 2: Sync IDs

    // 3: Topic check
    WAIT_UNTIL(topic_is(self, TOPIC1));
    tox_scenario_barrier_wait(self);

    // 4: Disable topic lock
    WAIT_UNTIL(topic_lock_is(self, TOX_GROUP_TOPIC_LOCK_DISABLED));
    tox_scenario_barrier_wait(self);

    // 5: Peers changing topic
    if (tox_node_get_index(self) == 1) {
        tox_group_set_topic(tox, state->group_number, (const uint8_t *)"Topic from Peer1", strlen("Topic from Peer1"), nullptr);
    }
    tox_scenario_barrier_wait(self); // Peer 1 turn
    WAIT_UNTIL(topic_is(self, "Topic from Peer1"));

    if (tox_node_get_index(self) == 2) {
        tox_group_set_topic(tox, state->group_number, (const uint8_t *)"Topic from Peer2", strlen("Topic from Peer2"), nullptr);
    }
    tox_scenario_barrier_wait(self); // Peer 2 turn
    WAIT_UNTIL(topic_is(self, "Topic from Peer2"));

    // 6: Set Peer 2 to Observer
    tox_scenario_barrier_wait(self);
    if (tox_node_get_index(self) == 2) {
        WAIT_UNTIL(state->self_role == TOX_GROUP_ROLE_OBSERVER);
    }

    // 7: Peer 1 changes topic, Peer 2 should fail
    if (tox_node_get_index(self) == 1) {
        tox_group_set_topic(tox, state->group_number, (const uint8_t *)"Topic again from Peer1", strlen("Topic again from Peer1"), nullptr);
    }
    tox_scenario_barrier_wait(self); // Peer 1 turn
    WAIT_UNTIL(topic_is(self, "Topic again from Peer1"));

    if (tox_node_get_index(self) == 2) {
        Tox_Err_Group_Topic_Set err;
        tox_group_set_topic(tox, state->group_number, (const uint8_t *)"Fail topic", 10, &err);
        ck_assert(err == TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS);
    }
    tox_scenario_barrier_wait(self); // Peer 2 turn (fails)

    // 8: Enable topic lock
    WAIT_UNTIL(topic_lock_is(self, TOX_GROUP_TOPIC_LOCK_ENABLED));
    tox_scenario_barrier_wait(self);

    // 9: Peer 1 attempts to change topic (fails)
    if (tox_node_get_index(self) == 1) {
        Tox_Err_Group_Topic_Set err;
        tox_group_set_topic(tox, state->group_number, (const uint8_t *)"Fail topic 2", 12, &err);
        ck_assert(err == TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS);
    }
    tox_scenario_barrier_wait(self);

    // 10: Founder changes topic
    tox_scenario_barrier_wait(self);
    WAIT_UNTIL(topic_is(self, TOPIC2));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    TopicState states[NUM_PEERS] = {0};
    ToxNode *nodes[NUM_PEERS];

    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(TopicState));
    for (uint32_t i = 1; i < NUM_PEERS; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Peer%u", i);
        nodes[i] = tox_scenario_add_node(s, alias, peer_script, &states[i], sizeof(TopicState));
    }

    for (uint32_t i = 0; i < NUM_PEERS; ++i) {
        for (uint32_t j = 0; j < NUM_PEERS; ++j) {
            if (i != j) {
                tox_node_bootstrap(nodes[i], nodes[j]);
                tox_node_friend_add(nodes[i], nodes[j]);
            }
        }
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef TOPIC2
#undef TOPIC1
#undef GROUP_NAME_LEN
#undef GROUP_NAME
#undef NUM_PEERS
