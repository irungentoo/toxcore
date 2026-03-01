#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool connection_status_called;
    Tox_Connection last_status;
} State;

static void on_self_connection_status(const Tox_Event_Self_Connection_Status *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->connection_status_called = true;
    state->last_status = tox_event_self_connection_status_get_connection_status(event);
    tox_node_log(self, "Self connection status: %s", tox_connection_to_string(state->last_status));
}

static void alice_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;

    // Register dispatch callback
    tox_events_callback_self_connection_status(tox_node_get_dispatch(self), on_self_connection_status);

    tox_node_wait_for_self_connected(self);
    ck_assert(state->connection_status_called);
    ck_assert(state->last_status != TOX_CONNECTION_NONE);

    Tox *tox = tox_node_get_tox(self);
    // Test ports
    Tox_Err_Get_Port err_port;
    uint16_t udp_port = tox_self_get_udp_port(tox, &err_port);
    ck_assert(err_port == TOX_ERR_GET_PORT_OK);
    ck_assert(udp_port > 0);
    tox_node_log(self, "UDP Port: %u", udp_port);

    // Friend list test
    tox_node_wait_for_friend_connected(self, 0);
    tox_node_wait_for_friend_connected(self, 1);

    size_t friend_count = tox_self_get_friend_list_size(tox);
    ck_assert(friend_count == 2);

    uint32_t friends[2];
    tox_self_get_friend_list(tox, friends);
    ck_assert(friends[0] == 0);
    ck_assert(friends[1] == 1);

    tox_node_log(self, "Self query tests passed!");
}

static void peer_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    State alice_state = {false, TOX_CONNECTION_NONE};

    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(State));
    tox_scenario_add_node(s, "Bob", peer_script, nullptr, 0);
    tox_scenario_add_node(s, "Charlie", peer_script, nullptr, 0);

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);
    ToxNode *charlie = tox_scenario_get_node(s, 2);

    tox_node_bootstrap(alice, bob);
    tox_node_bootstrap(charlie, bob);

    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);
    tox_node_friend_add(alice, charlie);
    tox_node_friend_add(charlie, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

