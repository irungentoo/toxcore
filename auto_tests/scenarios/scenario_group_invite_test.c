#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)
#define WRONG_PASS "dadadada"
#define WRONG_PASS_LEN (sizeof(WRONG_PASS) - 1)
#define PEER_LIMIT 1

typedef struct {
    uint32_t group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    bool peer_limit_fail;
    bool password_fail;
    bool connected;
    uint32_t peer_count;
} State;

static void on_group_join_fail(const Tox_Event_Group_Join_Fail *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    Tox_Group_Join_Fail fail_type = tox_event_group_join_fail_get_fail_type(event);

    if (fail_type == TOX_GROUP_JOIN_FAIL_PEER_LIMIT) {
        state->peer_limit_fail = true;
    } else if (fail_type == TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD) {
        state->password_fail = true;
    }
}

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->connected = true;
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->peer_count++;
}

static void founder_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_self_join(dispatch, on_group_self_join);

    tox_node_wait_for_self_connected(self);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"test", 4, (const uint8_t *)"test", 4, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    tox_group_get_chat_id(tox, state->group_number, state->chat_id, nullptr);

    // Phase 1: Peer 1 joins with no password
    tox_scenario_barrier_wait(self); // Barrier 1: Founder created group
    WAIT_UNTIL(state->peer_count == 1);
    tox_node_log(self, "Peer 1 joined.");

    // Phase 2: Set password
    tox_group_set_password(tox, state->group_number, (const uint8_t *)PASSWORD, PASS_LEN, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 2: Founder set password

    // Phase 3: Peer 2 attempts with no password (and fails)
    // Phase 4: Peer 3 attempts with wrong password (and fails)
    tox_scenario_barrier_wait(self); // Barrier 3: Peers 2 and 3 finished attempts

    // Phase 5: Set peer limit
    tox_group_set_peer_limit(tox, state->group_number, PEER_LIMIT, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 4: Founder set peer limit

    // Phase 6: Peer 4 attempts with correct password (and fails due to limit)
    tox_scenario_barrier_wait(self); // Barrier 5: Peer 4 finished attempt

    // Phase 7: Remove password and increase limit
    tox_group_set_password(tox, state->group_number, nullptr, 0, nullptr);
    tox_group_set_peer_limit(tox, state->group_number, 100, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 6: Founder relaxed restrictions

    // Phase 8: Peer 5 joins
    WAIT_UNTIL(state->peer_count >= 2);

    // Phase 9: Set private state
    tox_group_set_privacy_state(tox, state->group_number, TOX_GROUP_PRIVACY_STATE_PRIVATE, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 7: Founder made group private

    // Phase 10: Peer 6 attempts join (and fails because it's private)
    tox_scenario_barrier_wait(self); // Barrier 8: Peer 6 finished wait

    // Phase 11: Make group public again
    tox_group_set_privacy_state(tox, state->group_number, TOX_GROUP_PRIVACY_STATE_PUBLIC, nullptr);
    tox_scenario_barrier_wait(self); // Barrier 9: Founder made group public again

    // Final phase: Everyone leaves
    WAIT_UNTIL(state->peer_count >= 2); // At least Peer 1 and 5 are here
    tox_scenario_barrier_wait(self); // Barrier 10: Ready to leave
    tox_group_leave(tox, state->group_number, nullptr, 0, nullptr);
}

static void peer1_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *founder_view = (const State *)tox_node_get_peer_ctx(founder);
    tox_scenario_barrier_wait(self); // Barrier 1: Founder created group

    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer1", 5, nullptr, 0, nullptr);

    tox_scenario_barrier_wait(self); // Barrier 2
    tox_scenario_barrier_wait(self); // Barrier 3
    tox_scenario_barrier_wait(self); // Barrier 4
    tox_scenario_barrier_wait(self); // Barrier 5
    tox_scenario_barrier_wait(self); // Barrier 6
    tox_scenario_barrier_wait(self); // Barrier 7
    tox_scenario_barrier_wait(self); // Barrier 8
    tox_scenario_barrier_wait(self); // Barrier 9
    tox_scenario_barrier_wait(self); // Barrier 10
    tox_group_leave(tox, 0, nullptr, 0, nullptr);
}

static void peer2_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_join_fail(tox_node_get_dispatch(self), on_group_join_fail);
    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *founder_view = (const State *)tox_node_get_peer_ctx(founder);
    tox_scenario_barrier_wait(self); // 1
    tox_scenario_barrier_wait(self); // 2: Password set

    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer2", 5, nullptr, 0, nullptr);

    WAIT_UNTIL(state->password_fail);
    tox_node_log(self, "Blocked by password as expected.");

    tox_scenario_barrier_wait(self); // 3
    tox_scenario_barrier_wait(self); // 4
    tox_scenario_barrier_wait(self); // 5
    tox_scenario_barrier_wait(self); // 6
    tox_scenario_barrier_wait(self); // 7
    tox_scenario_barrier_wait(self); // 8
    tox_scenario_barrier_wait(self); // 9
    tox_scenario_barrier_wait(self); // 10
}

static void peer3_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_join_fail(tox_node_get_dispatch(self), on_group_join_fail);
    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *founder_view = (const State *)tox_node_get_peer_ctx(founder);
    tox_scenario_barrier_wait(self); // 1
    tox_scenario_barrier_wait(self); // 2

    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer3", 5, (const uint8_t *)WRONG_PASS, WRONG_PASS_LEN, nullptr);

    WAIT_UNTIL(state->password_fail);
    tox_node_log(self, "Blocked by wrong password as expected.");

    tox_scenario_barrier_wait(self); // 3
    tox_scenario_barrier_wait(self); // 4
    tox_scenario_barrier_wait(self); // 5
    tox_scenario_barrier_wait(self); // 6
    tox_scenario_barrier_wait(self); // 7
    tox_scenario_barrier_wait(self); // 8
    tox_scenario_barrier_wait(self); // 9
    tox_scenario_barrier_wait(self); // 10
}

static void peer4_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_join_fail(tox_node_get_dispatch(self), on_group_join_fail);
    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *founder_view = (const State *)tox_node_get_peer_ctx(founder);
    tox_scenario_barrier_wait(self); // 1
    tox_scenario_barrier_wait(self); // 2
    tox_scenario_barrier_wait(self); // 3
    tox_scenario_barrier_wait(self); // 4: Peer limit set

    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer4", 5, (const uint8_t *)PASSWORD, PASS_LEN, nullptr);

    WAIT_UNTIL(state->peer_limit_fail);
    tox_node_log(self, "Blocked by peer limit as expected.");

    tox_scenario_barrier_wait(self); // 5
    tox_scenario_barrier_wait(self); // 6
    tox_scenario_barrier_wait(self); // 7
    tox_scenario_barrier_wait(self); // 8
    tox_scenario_barrier_wait(self); // 9
    tox_scenario_barrier_wait(self); // 10
}

static void peer5_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_self_join(tox_node_get_dispatch(self), on_group_self_join);
    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *founder_view = (const State *)tox_node_get_peer_ctx(founder);
    tox_scenario_barrier_wait(self); // 1
    tox_scenario_barrier_wait(self); // 2
    tox_scenario_barrier_wait(self); // 3
    tox_scenario_barrier_wait(self); // 4
    tox_scenario_barrier_wait(self); // 5
    tox_scenario_barrier_wait(self); // 6: Restrictions relaxed

    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer5", 5, nullptr, 0, nullptr);

    WAIT_UNTIL(state->connected);
    tox_node_log(self, "Joined group.");

    tox_scenario_barrier_wait(self); // 7
    tox_scenario_barrier_wait(self); // 8
    tox_scenario_barrier_wait(self); // 9
    tox_scenario_barrier_wait(self); // 10
    tox_group_leave(tox, 0, nullptr, 0, nullptr);
}

static void peer6_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_self_join(tox_node_get_dispatch(self), on_group_self_join);
    tox_node_wait_for_self_connected(self);

    const ToxNode *founder = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *founder_view = (const State *)tox_node_get_peer_ctx(founder);
    tox_scenario_barrier_wait(self); // 1
    tox_scenario_barrier_wait(self); // 2
    tox_scenario_barrier_wait(self); // 3
    tox_scenario_barrier_wait(self); // 4
    tox_scenario_barrier_wait(self); // 5
    tox_scenario_barrier_wait(self); // 6
    tox_scenario_barrier_wait(self); // 7: Private group

    tox_group_join(tox, founder_view->chat_id, (const uint8_t *)"Peer6", 5, nullptr, 0, nullptr);

    // Wait some time to be sure we are NOT connected
    for (int i = 0; i < 2000 / TOX_SCENARIO_TICK_MS; ++i) {
        ck_assert(!state->connected);
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Could not join private group via chat ID as expected.");

    tox_scenario_barrier_wait(self); // 8
    tox_scenario_barrier_wait(self); // 9
    tox_scenario_barrier_wait(self); // 10
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    State states[7] = {0};

    ToxNode *nodes[7];
    nodes[0] = tox_scenario_add_node(s, "Founder", founder_script, &states[0], sizeof(State));
    nodes[1] = tox_scenario_add_node(s, "Peer1",   peer1_script,   &states[1], sizeof(State));
    nodes[2] = tox_scenario_add_node(s, "Peer2",   peer2_script,   &states[2], sizeof(State));
    nodes[3] = tox_scenario_add_node(s, "Peer3",   peer3_script,   &states[3], sizeof(State));
    nodes[4] = tox_scenario_add_node(s, "Peer4",   peer4_script,   &states[4], sizeof(State));
    nodes[5] = tox_scenario_add_node(s, "Peer5",   peer5_script,   &states[5], sizeof(State));
    nodes[6] = tox_scenario_add_node(s, "Peer6",   peer6_script,   &states[6], sizeof(State));

    for (int i = 1; i < 7; ++i) {
        tox_node_bootstrap(nodes[i], nodes[0]);
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef PASSWORD
#undef PASS_LEN
#undef PEER_LIMIT
