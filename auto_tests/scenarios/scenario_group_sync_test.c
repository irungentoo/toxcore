#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_PEERS 5
#define GROUP_NAME "Sync Test Group"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

typedef struct {
    uint32_t group_number;
    uint32_t peer_count;
    bool connected;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t topic_len;
    uint32_t peers[NUM_PEERS]; // Track peer IDs we've seen
    Tox_Group_Role self_role;
} SyncState;

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    SyncState *state = (SyncState *)tox_node_get_script_ctx(self);
    state->connected = true;
    tox_node_log(self, "Joined group");
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    SyncState *state = (SyncState *)tox_node_get_script_ctx(self);
    uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);

    // Check if it's ourselves
    Tox_Err_Group_Self_Query err_peer;
    uint32_t self_id = tox_group_self_get_peer_id(tox_node_get_tox(self), state->group_number, &err_peer);
    if (err_peer == TOX_ERR_GROUP_SELF_QUERY_OK && peer_id == self_id) {
        return;
    }

    for (uint32_t i = 0; i < state->peer_count; ++i) {
        if (state->peers[i] == peer_id) {
            return;
        }
    }

    if (state->peer_count < NUM_PEERS) {
        tox_node_log(self, "Peer joined: %u", peer_id);
        state->peers[state->peer_count++] = peer_id;
    }
}

static void on_group_topic(const Tox_Event_Group_Topic *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    SyncState *state = (SyncState *)tox_node_get_script_ctx(self);
    state->topic_len = tox_event_group_topic_get_topic_length(event);
    memcpy(state->topic, tox_event_group_topic_get_topic(event), state->topic_len);
    state->topic[state->topic_len] = '\0';
    tox_node_log(self, "Topic updated to: %s", state->topic);
}

static void common_init(ToxNode *self, SyncState *state)
{
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_topic(dispatch, on_group_topic);

    tox_node_log(self, "Waiting for self connection...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected!");
}

static void founder_script(ToxNode *self, void *ctx)
{
    SyncState *state = (SyncState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)"Founder", 7, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);
    state->self_role = TOX_GROUP_ROLE_FOUNDER;

    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);

    // Phase 1: Wait for everyone to join
    tox_scenario_barrier_wait(self); // Barrier 1: Created

    tox_node_log(self, "Waiting for peers to join (current count: %u)...", state->peer_count);
    WAIT_UNTIL(state->peer_count >= NUM_PEERS - 1);
    tox_node_log(self, "All peers joined.");

    // Phase 2: Topic Sync
    tox_group_set_topic_lock(tox, state->group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 2: Lock disabled

    // Everyone spams topic
    tox_node_log(self, "Spamming topic...");
    for (uint32_t i = 0; i < tox_node_get_index(self); ++i) {
        tox_scenario_yield(self);
    }
    char topic[64];
    snprintf(topic, sizeof(topic), "Founder Topic %d", rand());
    bool ok = tox_group_set_topic(tox, state->group_number, (const uint8_t *)topic, strlen(topic), nullptr);
    ck_assert(ok);

    // Manually update state because Tox might not call on_group_topic for self
    state->topic_len = strlen(topic);
    memcpy(state->topic, topic, state->topic_len);
    state->topic[state->topic_len] = '\0';

    tox_scenario_barrier_wait(self); // Barrier 3: Topic spam done

    // Wait for topic convergence
    tox_node_log(self, "Waiting for topic convergence...");
    uint64_t last_log = 0;
    while (1) {
        bool converged = true;
        for (int i = 0; i < NUM_PEERS; ++i) {
            const ToxNode *node = tox_scenario_get_node(tox_node_get_scenario(self), i);
            const SyncState *s_view = (const SyncState *)tox_node_get_peer_ctx(node);
            if (s_view->topic_len != state->topic_len || memcmp(s_view->topic, state->topic, state->topic_len) != 0) {
                converged = false;
                if (tox_scenario_get_time(tox_node_get_scenario(self)) > last_log + 5000) {
                    tox_node_log(self, "Still waiting for %s to converge topic. Expected: %s, Got: %s",
                                 tox_node_get_alias(node), state->topic, s_view->topic);
                }
                break;
            }
        }
        if (converged) {
            break;
        }
        if (tox_scenario_get_time(tox_node_get_scenario(self)) > last_log + 5000) {
            last_log = tox_scenario_get_time(tox_node_get_scenario(self));
        }
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Topics converged!");

    // Phase 3: Role Sync
    // Promote everyone to Moderator
    tox_node_log(self, "Promoting everyone to Moderator...");
    for (uint32_t i = 0; i < state->peer_count; ++i) {
        tox_group_set_role(tox, state->group_number, state->peers[i], TOX_GROUP_ROLE_MODERATOR, nullptr);
    }

    tox_scenario_barrier_wait(self); // Barrier 4: Roles set

    // Wait for role convergence
    tox_node_log(self, "Waiting for role convergence...");
    while (1) {
        bool converged = true;
        for (int i = 0; i < NUM_PEERS; ++i) {
            ToxNode *node = tox_scenario_get_node(tox_node_get_scenario(self), i);
            const SyncState *s_view = (const SyncState *)tox_node_get_peer_ctx(node);

            Tox_Group_Role expected = (i == 0 ? TOX_GROUP_ROLE_FOUNDER : TOX_GROUP_ROLE_MODERATOR);
            if (s_view->self_role != expected) {
                converged = false;
                break;
            }
        }
        if (converged) {
            break;
        }
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Roles converged!");

    tox_scenario_barrier_wait(self); // Barrier 5: Done
}

static void peer_script(ToxNode *self, void *ctx)
{
    SyncState *state = (SyncState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    tox_scenario_barrier_wait(self); // Barrier 1: Created

    const SyncState *founder_view = (const SyncState *)tox_node_get_peer_ctx(founder);

    char name[16];
    snprintf(name, sizeof(name), "Peer%u", tox_node_get_index(self));
    state->group_number = tox_group_join(tox, founder_view->chat_id, (const uint8_t *)name, strlen(name), nullptr, 0, nullptr);
    ck_assert(state->group_number != UINT32_MAX);

    WAIT_UNTIL(state->connected);
    tox_node_log(self, "Joined and connected to group.");

    tox_scenario_barrier_wait(self); // Barrier 2: Lock disabled

    // Spam topic
    for (uint32_t i = 0; i < tox_node_get_index(self); ++i) {
        tox_scenario_yield(self);
    }
    char topic[64];
    snprintf(topic, sizeof(topic), "Peer%u Topic %d", tox_node_get_index(self), rand());
    tox_node_log(self, "Setting topic: %s", topic);
    tox_group_set_topic(tox, state->group_number, (const uint8_t *)topic, strlen(topic), nullptr);

    // Manually update state because Tox might not call on_group_topic for self
    state->topic_len = strlen(topic);
    memcpy(state->topic, topic, state->topic_len);
    state->topic[state->topic_len] = '\0';

    tox_scenario_barrier_wait(self); // Barrier 3: Topic spam done

    // Observe and publish role for Phase 3
    tox_node_log(self, "Waiting for Moderator role...");
    while (tox_scenario_is_running(self)) {
        state->self_role = tox_group_self_get_role(tox, state->group_number, nullptr);
        if (state->self_role == TOX_GROUP_ROLE_MODERATOR) {
            break;
        }
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Got Moderator role!");

    tox_scenario_barrier_wait(self); // Barrier 4: Roles set

    tox_scenario_barrier_wait(self); // Barrier 5: Done
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    SyncState states[NUM_PEERS] = {0};
    ToxNode *nodes[NUM_PEERS];

    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(SyncState));
    static char aliases[NUM_PEERS][16];
    for (int i = 1; i < NUM_PEERS; ++i) {
        snprintf(aliases[i], sizeof(aliases[i]), "Peer%d", i);
        nodes[i] = tox_scenario_add_node(s, aliases[i], peer_script, &states[i], sizeof(SyncState));
    }

    for (int i = 0; i < NUM_PEERS; ++i) {
        for (int j = 0; j < NUM_PEERS; ++j) {
            if (i != j) {
                tox_node_bootstrap(nodes[i], nodes[j]);
            }
        }
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef NUM_PEERS
