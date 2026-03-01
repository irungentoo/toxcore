#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_PEERS 5
#define GROUP_NAME "Moderation Test Group"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

typedef struct {
    uint32_t group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    bool chat_id_ready;
    uint32_t peer_count;
    bool connected;
    Tox_Group_Role self_role;
    Tox_Group_Voice_State voice_state;
    bool kicked;
    uint32_t peer_ids[NUM_PEERS];    // Map node index to group peer_id
    Tox_Group_Mod_Event last_mod_event;
    uint32_t last_mod_target;
} ModState;

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    state->connected = true;
    uint32_t group_number = tox_event_group_self_join_get_group_number(event);
    uint32_t self_id = tox_group_self_get_peer_id(tox_node_get_tox(self), group_number, nullptr);
    state->self_role = tox_group_self_get_role(tox_node_get_tox(self), group_number, nullptr);
    tox_node_log(self, "Joined group %u (Peer ID: %u) with role %s", group_number, self_id, tox_group_role_to_string(state->self_role));
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    uint32_t group_number = tox_event_group_peer_join_get_group_number(event);
    uint32_t peer_id = tox_event_group_peer_join_get_peer_id(event);

    tox_node_log(self, "Peer %u joined the group", peer_id);
    state->peer_count++;

    Tox_Err_Group_Peer_Query q_err;
    size_t length = tox_group_peer_get_name_size(tox_node_get_tox(self), group_number, peer_id, &q_err);
    if (q_err == TOX_ERR_GROUP_PEER_QUERY_OK && length > 0) {
        uint8_t name[TOX_MAX_NAME_LENGTH];
        tox_group_peer_get_name(tox_node_get_tox(self), group_number, peer_id, name, &q_err);
        if (q_err == TOX_ERR_GROUP_PEER_QUERY_OK) {
            tox_node_log(self, "Peer %u name identified: %.*s", peer_id, (int)length, name);
            if (length == 7 && memcmp(name, "Founder", 7) == 0) {
                state->peer_ids[0] = peer_id;
            } else if (length >= 5 && memcmp(name, "Peer", 4) == 0) {
                int idx = atoi((const char *)name + 4);
                if (idx > 0 && idx < NUM_PEERS) {
                    state->peer_ids[idx] = peer_id;
                }
            }
        }
    }
}

static void on_group_moderation(const Tox_Event_Group_Moderation *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    state->last_mod_event = tox_event_group_moderation_get_mod_type(event);
    state->last_mod_target = tox_event_group_moderation_get_target_peer_id(event);

    Tox_Err_Group_Self_Query err;
    state->self_role = tox_group_self_get_role(tox_node_get_tox(self), state->group_number, &err);

    if (state->last_mod_event == TOX_GROUP_MOD_EVENT_KICK && state->last_mod_target == tox_group_self_get_peer_id(tox_node_get_tox(self), state->group_number, nullptr)) {
        state->kicked = true;
    }

    tox_node_log(self, "Moderation event: %s on peer %u. My role is now %s",
                 tox_group_mod_event_to_string(state->last_mod_event),
                 state->last_mod_target,
                 tox_group_role_to_string(state->self_role));
}

static void on_group_voice_state(const Tox_Event_Group_Voice_State *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    state->voice_state = tox_event_group_voice_state_get_voice_state(event);
    tox_node_log(self, "Voice state updated: %u", state->voice_state);
}

static void common_init(ToxNode *self, ModState *state)
{
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_moderation(dispatch, on_group_moderation);
    tox_events_callback_group_voice_state(dispatch, on_group_voice_state);

    for (int i = 0; i < NUM_PEERS; ++i) {
        state->peer_ids[i] = UINT32_MAX;
    }

    tox_node_log(self, "Waiting for self connection...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected!");
}

static void wait_for_peer_role(ToxNode *self, uint32_t peer_idx, Tox_Group_Role expected_role)
{
    ModState *state = (ModState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Waiting to see Peer %u with role %s", peer_idx, tox_group_role_to_string(expected_role));

    while (tox_scenario_is_running(self)) {
        uint32_t peer_id = state->peer_ids[peer_idx];

        if (peer_id != UINT32_MAX) {
            Tox_Err_Group_Peer_Query err;
            Tox_Group_Role role = tox_group_peer_get_role(tox_node_get_tox(self), state->group_number, peer_id, &err);

            if (err == TOX_ERR_GROUP_PEER_QUERY_OK && role == expected_role) {
                break;
            }
        }

        tox_scenario_yield(self);
    }

    tox_node_log(self, "Peer %u now has role %s", peer_idx, tox_group_role_to_string(expected_role));
}

static void founder_script(ToxNode *self, void *ctx)
{
    ModState *state = (ModState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)"Founder", 7, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    state->self_role = TOX_GROUP_ROLE_FOUNDER;
    state->peer_ids[0] = tox_group_self_get_peer_id(tox, state->group_number, nullptr);

    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);
    state->chat_id_ready = true;

    // Barrier 1: Wait for all peers to join and be seen by everyone
    WAIT_UNTIL(state->peer_count == NUM_PEERS - 1);
    tox_node_log(self, "All peers joined");

    // Wait until we know all peer IDs
    for (int i = 1; i < NUM_PEERS; ++i) {
        WAIT_UNTIL(state->peer_ids[i] != UINT32_MAX);
    }
    tox_node_log(self, "All peer IDs identified");

    tox_scenario_barrier_wait(self); // Barrier 1: Everyone sees everyone

    // Barrier 2: Peer 1 becomes Moderator
    tox_group_set_role(tox, state->group_number, state->peer_ids[1], TOX_GROUP_ROLE_MODERATOR, nullptr);
    wait_for_peer_role(self, 1, TOX_GROUP_ROLE_MODERATOR);
    tox_scenario_barrier_wait(self); // Barrier 2: Everyone sees Peer 1 as Moderator

    // Barrier 3: Peer 2 and 3 become Observer
    tox_group_set_role(tox, state->group_number, state->peer_ids[2], TOX_GROUP_ROLE_OBSERVER, nullptr);
    tox_group_set_role(tox, state->group_number, state->peer_ids[3], TOX_GROUP_ROLE_OBSERVER, nullptr);
    wait_for_peer_role(self, 2, TOX_GROUP_ROLE_OBSERVER);
    wait_for_peer_role(self, 3, TOX_GROUP_ROLE_OBSERVER);
    tox_scenario_barrier_wait(self); // Barrier 3: Everyone sees Peer 2/3 as Observers

    // Barrier 4: Voice State tests
    tox_node_log(self, "Setting voice state to MODERATOR");
    tox_group_set_voice_state(tox, state->group_number, TOX_GROUP_VOICE_STATE_MODERATOR, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 1 set
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 1 done

    tox_node_log(self, "Setting voice state to FOUNDER");
    tox_group_set_voice_state(tox, state->group_number, TOX_GROUP_VOICE_STATE_FOUNDER, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 2 set
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 2 done

    tox_node_log(self, "Setting voice state to ALL");
    tox_group_set_voice_state(tox, state->group_number, TOX_GROUP_VOICE_STATE_ALL, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 3 set
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 3 done

    // Barrier 5: Peer 1 (Mod) promotes Peer 2 back to User
    wait_for_peer_role(self, 2, TOX_GROUP_ROLE_USER);
    tox_scenario_barrier_wait(self); // Barrier 5: Everyone sees Peer 2 as User

    // Barrier 6: Founder promotes Peer 3 to Moderator
    tox_group_set_role(tox, state->group_number, state->peer_ids[3], TOX_GROUP_ROLE_MODERATOR, nullptr);
    wait_for_peer_role(self, 3, TOX_GROUP_ROLE_MODERATOR);
    tox_scenario_barrier_wait(self); // Barrier 6: Everyone sees Peer 3 as Moderator

    // Barrier 7: Moderator (Peer 1) attempts to kick/demote Founder (should fail)
    tox_scenario_barrier_wait(self); // Barrier 7: Founder wait

    // Barrier 8: Founder kicks Moderator (Peer 1)
    tox_group_kick_peer(tox, state->group_number, state->peer_ids[1], nullptr);
    tox_scenario_barrier_wait(self); // Barrier 8: Founder wait

    // Barrier 9: Founder demotes Moderator (Peer 3) to User
    tox_group_set_role(tox, state->group_number, state->peer_ids[3], TOX_GROUP_ROLE_USER, nullptr);
    wait_for_peer_role(self, 3, TOX_GROUP_ROLE_USER);
    tox_scenario_barrier_wait(self); // Barrier 9: Founder wait

    tox_scenario_barrier_wait(self); // Done
}

static void peer_script(ToxNode *self, void *ctx)
{
    ModState *state = (ModState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    common_init(self, state);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const ModState *founder_view = (const ModState *)tox_node_get_peer_ctx(founder);

    while (!founder_view->chat_id_ready) {
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Got chat ID from founder");

    char name[16];
    snprintf(name, sizeof(name), "Peer%u", tox_node_get_index(self));
    Tox_Err_Group_Join err_join;
    state->group_number = tox_group_join(tox, founder_view->chat_id, (const uint8_t *)name, strlen(name), nullptr, 0, &err_join);
    if (state->group_number == UINT32_MAX) {
        tox_node_log(self, "tox_group_join failed with error %u", err_join);
    }
    ck_assert(state->group_number != UINT32_MAX);

    WAIT_UNTIL(state->connected);

    uint32_t self_id = tox_group_self_get_peer_id(tox, state->group_number, nullptr);
    state->peer_ids[tox_node_get_index(self)] = self_id;

    // Barrier 1: Joined
    // Wait until we know all peer IDs
    for (uint32_t i = 0; i < NUM_PEERS; ++i) {
        if (tox_node_get_index(self) != i) {
            WAIT_UNTIL(state->peer_ids[i] != UINT32_MAX);
        }
    }
    tox_scenario_barrier_wait(self); // Barrier 1: Everyone sees everyone

    // Barrier 2: Peer 1 Moderator
    wait_for_peer_role(self, 1, TOX_GROUP_ROLE_MODERATOR);
    tox_scenario_barrier_wait(self); // Barrier 2: Everyone sees Peer 1 as Moderator

    // Barrier 3: Peer 2/3 Observer
    wait_for_peer_role(self, 2, TOX_GROUP_ROLE_OBSERVER);
    wait_for_peer_role(self, 3, TOX_GROUP_ROLE_OBSERVER);
    tox_scenario_barrier_wait(self); // Barrier 3: Everyone sees Peer 2/3 as Observers

    // Barrier 4: Voice State tests
    // Sub-phase 1: MODERATOR
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 1 set
    WAIT_UNTIL(state->voice_state == TOX_GROUP_VOICE_STATE_MODERATOR);
    Tox_Err_Group_Send_Message err_msg;
    tox_group_send_message(tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"hello", 5, &err_msg);
    if (state->self_role == TOX_GROUP_ROLE_MODERATOR || state->self_role == TOX_GROUP_ROLE_FOUNDER) {
        if (err_msg != TOX_ERR_GROUP_SEND_MESSAGE_OK) {
            tox_node_log(self, "Expected OK, got %u. Role: %s", err_msg, tox_group_role_to_string(state->self_role));
        }
        ck_assert(err_msg == TOX_ERR_GROUP_SEND_MESSAGE_OK);
    } else {
        if (err_msg != TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS) {
            tox_node_log(self, "Expected PERMISSIONS, got %u. Role: %s", err_msg, tox_group_role_to_string(state->self_role));
        }
        ck_assert(err_msg == TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
    }
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 1 done

    // Sub-phase 2: FOUNDER
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 2 set
    WAIT_UNTIL(state->voice_state == TOX_GROUP_VOICE_STATE_FOUNDER);
    tox_group_send_message(tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"hello", 5, &err_msg);
    if (state->self_role == TOX_GROUP_ROLE_FOUNDER) {
        ck_assert(err_msg == TOX_ERR_GROUP_SEND_MESSAGE_OK);
    } else {
        ck_assert(err_msg == TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
    }
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 2 done

    // Sub-phase 3: ALL
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 3 set
    WAIT_UNTIL(state->voice_state == TOX_GROUP_VOICE_STATE_ALL);
    tox_group_send_message(tox, state->group_number, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"hello", 5, &err_msg);
    if (state->self_role == TOX_GROUP_ROLE_OBSERVER) {
        ck_assert(err_msg == TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
    } else {
        ck_assert(err_msg == TOX_ERR_GROUP_SEND_MESSAGE_OK);
    }
    tox_scenario_barrier_wait(self); // Barrier 4 Phase 3 done

    // Barrier 5: Peer 1 (Mod) promotes Peer 2 back to User
    if (tox_node_get_index(self) == 1) { // Peer 1
        uint32_t peer2_id = state->peer_ids[2];
        tox_group_set_role(tox, state->group_number, peer2_id, TOX_GROUP_ROLE_USER, nullptr);
    }
    wait_for_peer_role(self, 2, TOX_GROUP_ROLE_USER);
    tox_scenario_barrier_wait(self); // Barrier 5: Everyone sees Peer 2 as User

    // Barrier 6: Founder promotes Peer 3 to Moderator
    wait_for_peer_role(self, 3, TOX_GROUP_ROLE_MODERATOR);
    tox_scenario_barrier_wait(self); // Barrier 6: Everyone sees Peer 3 as Moderator

    // Barrier 7: Moderator (Peer 1) attempts to kick/demote Founder (should fail)
    if (tox_node_get_index(self) == 1) {
        Tox_Err_Group_Kick_Peer err_kick;
        uint32_t founder_peer_id = state->peer_ids[0];
        tox_group_kick_peer(tox, state->group_number, founder_peer_id, &err_kick);
        ck_assert(err_kick != TOX_ERR_GROUP_KICK_PEER_OK);

        Tox_Err_Group_Set_Role err_role;
        tox_group_set_role(tox, state->group_number, founder_peer_id, TOX_GROUP_ROLE_USER, &err_role);
        ck_assert(err_role != TOX_ERR_GROUP_SET_ROLE_OK);
    }
    tox_scenario_barrier_wait(self); // Barrier 7: Everyone wait

    // Barrier 8: Founder kicks Moderator (Peer 1)
    if (tox_node_get_index(self) == 1) {
        WAIT_UNTIL(state->kicked);
        tox_scenario_barrier_wait(self); // Barrier 8: Peer 1 reached (it's kicked)
        return; // Exit script
    }
    tox_scenario_barrier_wait(self); // Barrier 8: Everyone else reached

    // Barrier 9: Founder demotes Moderator (Peer 3) to User
    wait_for_peer_role(self, 3, TOX_GROUP_ROLE_USER);
    tox_scenario_barrier_wait(self); // Barrier 9: Everyone sees Peer 3 as User

    tox_scenario_barrier_wait(self); // Done
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    ToxScenario *s = tox_scenario_new(argc, argv, 300000); // 5 virtual minutes
    ModState states[NUM_PEERS] = {0};
    ToxNode *nodes[NUM_PEERS];

    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(ModState));
    static char aliases[NUM_PEERS][16];
    for (int i = 1; i < NUM_PEERS; ++i) {
        snprintf(aliases[i], sizeof(aliases[i]), "Peer%d", i);
        nodes[i] = tox_scenario_add_node(s, aliases[i], peer_script, &states[i], sizeof(ModState));
    }

    for (int i = 0; i < NUM_PEERS; ++i) {
        for (int j = 0; j < NUM_PEERS; ++j) {
            if (i != j) {
                tox_node_bootstrap(nodes[i], nodes[j]);
                tox_node_friend_add(nodes[i], nodes[j]);
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
