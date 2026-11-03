#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

#define NUM_PEERS 3
#define GROUP_NAME "Mod List Group"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
// Long enough for a couple of sync requests.
#define QUIET_MS 30000

typedef struct {
    uint32_t group_number;
    uint32_t peer_count;
    bool created;
    bool connected;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    uint32_t mod_events;
} ModState;

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    state->connected = true;
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    ++state->peer_count;
}

static void on_group_moderation(const Tox_Event_Group_Moderation *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "moderation event %s from %u on %u",
                 tox_group_mod_event_to_string(tox_event_group_moderation_get_mod_type(event)),
                 tox_event_group_moderation_get_source_peer_id(event),
                 tox_event_group_moderation_get_target_peer_id(event));
    ++state->mod_events;
}

static void common_init(ToxNode *self)
{
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_moderation(dispatch, on_group_moderation);
    tox_node_wait_for_self_connected(self);
}

static void stay(ToxNode *self, ModState *state, uint32_t peers)
{
    WAIT_UNTIL(state->peer_count >= peers);
    tox_scenario_barrier_wait(self);
    ToxScenario *s = tox_node_get_scenario(self);
    const uint64_t until = tox_scenario_get_time(s) + QUIET_MS;
    WAIT_UNTIL(tox_scenario_get_time(s) >= until);
    tox_scenario_barrier_wait(self);
}

static void founder_script(ToxNode *self, void *ctx)
{
    ModState *state = (ModState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN,
                                        (const uint8_t *)"Founder", 7, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);
    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);
    state->created = true;

    tox_scenario_barrier_wait(self);
    stay(self, state, NUM_PEERS - 1);
}

static void peer_script(ToxNode *self, void *ctx)
{
    ModState *state = (ModState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self);

    tox_scenario_barrier_wait(self);
    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const ModState *founder_view = (const ModState *)tox_node_get_peer_ctx(founder);
    // The founder's state may not have reached us yet when the barrier opens.
    WAIT_UNTIL(founder_view->created);

    char name[16];
    snprintf(name, sizeof(name), "Peer%u", tox_node_get_index(self));
    Tox_Err_Group_Join err_join;
    state->group_number = tox_group_join(tox, founder_view->chat_id, (const uint8_t *)name, strlen(name), nullptr, 0,
                                         &err_join);
    ck_assert_msg(err_join == TOX_ERR_GROUP_JOIN_OK, "join: %s", tox_err_group_join_to_string(err_join));
    WAIT_UNTIL(state->connected);

    // The peers can't reach each other, so each of them only sees the founder.
    stay(self, state, 1);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    ModState states[NUM_PEERS] = {{0}};
    ToxNode *nodes[NUM_PEERS];

    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(ModState));
    for (uint32_t i = 1; i < NUM_PEERS; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Peer%u", i);
        nodes[i] = tox_scenario_add_node(s, alias, peer_script, &states[i], sizeof(ModState));
        tox_node_bootstrap(nodes[i], nodes[0]);
    }
    tox_scenario_set_link_loss(nodes[1], nodes[2], 100);

    ck_assert(tox_scenario_run(s) == TOX_SCENARIO_DONE);
    uint32_t total = 0;
    for (uint32_t i = 0; i < NUM_PEERS; ++i) {
        total += states[i].mod_events;
    }
    tox_scenario_free(s);
    ck_assert_msg(total == 0, "%u moderation events", total);
    return 0;
}

#undef NUM_PEERS
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef QUIET_MS
