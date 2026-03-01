#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "framework/framework.h"

#define NUM_PEERS      2
#define GROUP_NAME     "Bug Repro Group"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define TOPIC1         "Topic A"
#define TOPIC2         "Topic B"

typedef struct {
    uint32_t group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    bool chat_id_ready;
    bool connected;
    uint32_t peer_ids[NUM_PEERS];
    uint8_t last_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t last_topic_len;
    Tox_Group_Topic_Lock topic_lock;
} TopicState;

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    state->connected = true;
    state->group_number = tox_event_group_self_join_get_group_number(event);
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    TopicState *state = (TopicState *)tox_node_get_script_ctx(self);
    uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);
    uint32_t group_number = tox_event_group_peer_join_get_group_number(event);

    Tox_Err_Group_Peer_Query q_err;
    size_t length
        = tox_group_peer_get_name_size(tox_node_get_tox(self), group_number, peer_id, &q_err);
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
            } else if (length == 7 && memcmp(name, "Founder", 7) == 0) {
                state->peer_ids[0] = peer_id;
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

static void common_init(ToxNode *self, TopicState *state)
{
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_topic(dispatch, on_group_topic);
    tox_events_callback_group_topic_lock(dispatch, on_group_topic_lock);

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
    size_t current_len
        = tox_group_get_topic_size(tox_node_get_tox(self), state->group_number, &err);
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
    Tox_Group_Topic_Lock current_lock
        = tox_group_get_topic_lock(tox_node_get_tox(self), state->group_number, &err);
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
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC,
                                        (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)"Founder", 7, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    state->peer_ids[0] = tox_group_self_get_peer_id(tox, state->group_number, nullptr);
    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);
    state->chat_id_ready = true;

    tox_scenario_barrier_wait(self);  // 1: Joined
    WAIT_UNTIL(state->peer_ids[1] != UINT32_MAX);
    tox_scenario_barrier_wait(self);  // 2: Sync IDs

    // Disable topic lock
    tox_group_set_topic_lock(tox, state->group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, nullptr);
    WAIT_UNTIL(topic_lock_is(self, TOX_GROUP_TOPIC_LOCK_DISABLED));
    tox_scenario_barrier_wait(self);  // 3: Lock disabled

    // Set Topic A
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)TOPIC1, strlen(TOPIC1), nullptr);
    WAIT_UNTIL(topic_is(self, TOPIC1));
    tox_scenario_barrier_wait(self);  // 4: Topic A set

    // Set Topic B
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)TOPIC2, strlen(TOPIC2), nullptr);
    WAIT_UNTIL(topic_is(self, TOPIC2));
    tox_scenario_barrier_wait(self);  // 5: Topic B set

    // Peer 1 will now set Topic A.
    // We expect to REJECT it (stay on Topic B).
    // But if bug exists, we might Accept it (revert to Topic A).

    tox_scenario_barrier_wait(self);  // 6: Peer 1 sets Topic A

    // Verify we have Topic B.
    // Wait a bit to ensure potential network packets arrived.
    uint64_t start = tox_scenario_get_time(tox_node_get_scenario(self));
    while (tox_scenario_get_time(tox_node_get_scenario(self)) - start < 1000) {
        tox_scenario_yield(self);
        if (topic_is(self, TOPIC1)) {
            ck_assert_msg(false, "BUG REPRODUCED: Founder reverted to Topic A!");
        }
    }

    ck_assert_msg(topic_is(self, TOPIC2), "Founder should be on Topic B");
}

static void peer_script(ToxNode *self, void *ctx)
{
    TopicState *state = (TopicState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const TopicState *founder_view = (const TopicState *)tox_node_get_peer_ctx(founder);

    WAIT_UNTIL(founder_view->chat_id_ready);
    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer1", 5, nullptr, 0, nullptr);

    WAIT_UNTIL(state->connected);
    state->peer_ids[1] = tox_group_self_get_peer_id(tox, state->group_number, nullptr);

    tox_scenario_barrier_wait(self);  // 1: Joined
    WAIT_UNTIL(state->peer_ids[0] != UINT32_MAX);
    tox_scenario_barrier_wait(self);  // 2: Sync IDs

    WAIT_UNTIL(topic_lock_is(self, TOX_GROUP_TOPIC_LOCK_DISABLED));
    tox_scenario_barrier_wait(self);  // 3: Lock disabled

    WAIT_UNTIL(topic_is(self, TOPIC1));
    tox_scenario_barrier_wait(self);  // 4: Topic A set

    WAIT_UNTIL(topic_is(self, TOPIC2));
    tox_scenario_barrier_wait(self);  // 5: Topic B set

    // Now we set Topic A.
    // This simulates an old topic being re-broadcast or a malicious/accidental revert.
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)TOPIC1, strlen(TOPIC1), nullptr);

    tox_scenario_barrier_wait(self);  // 6: Peer 1 sets Topic A
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    TopicState states[NUM_PEERS] = {0};
    ToxNode *nodes[NUM_PEERS];

    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(TopicState));
    nodes[1] = tox_scenario_add_node(s, "Peer1", peer_script, &states[1], sizeof(TopicState));

    tox_node_bootstrap(nodes[0], nodes[1]);
    tox_node_friend_add(nodes[0], nodes[1]);

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
