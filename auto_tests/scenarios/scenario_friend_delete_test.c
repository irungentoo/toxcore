#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool bob_went_offline;
} AliceState;

static void on_alice_friend_connection_status(const Tox_Event_Friend_Connection_Status *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *state = (AliceState *)tox_node_get_script_ctx(self);

    Tox_Connection status = tox_event_friend_connection_status_get_connection_status(event);
    tox_node_log(self, "Friend connection status changed to %u", status);

    if (status == TOX_CONNECTION_NONE) {
        state->bob_went_offline = true;
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    tox_events_callback_friend_connection_status(tox_node_get_dispatch(self), on_alice_friend_connection_status);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);
    tox_node_log(self, "Connected to Bob. Deleting Bob now...");

    Tox_Err_Friend_Delete err;
    bool success = tox_friend_delete(tox_node_get_tox(self), 0, &err);
    ck_assert(success);
    ck_assert(err == TOX_ERR_FRIEND_DELETE_OK);

    tox_node_log(self, "Bob deleted. Bob should see Alice as offline.");

    // Wait for Bob to finish
    ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    WAIT_UNTIL(tox_node_is_finished(bob));
}

typedef struct {
    bool alice_went_offline;
    bool alice_connected;
} BobState;

static void on_bob_friend_connection_status(const Tox_Event_Friend_Connection_Status *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *state = (BobState *)tox_node_get_script_ctx(self);

    Tox_Connection status = tox_event_friend_connection_status_get_connection_status(event);
    tox_node_log(self, "Friend connection status changed to %u", status);

    if (status != TOX_CONNECTION_NONE) {
        state->alice_connected = true;
    }

    if (status == TOX_CONNECTION_NONE) {
        state->alice_went_offline = true;
    }
}

static void bob_script(ToxNode *self, void *ctx)
{
    const BobState *state = (const BobState *)ctx;
    tox_events_callback_friend_connection_status(tox_node_get_dispatch(self), on_bob_friend_connection_status);

    tox_node_wait_for_self_connected(self);
    WAIT_UNTIL(state->alice_connected);
    tox_node_log(self, "Connected to Alice. Waiting for Alice to delete me...");

    WAIT_UNTIL(state->alice_went_offline);
    tox_node_log(self, "Alice went offline as expected!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    AliceState alice_state = {false};
    BobState bob_state = {false, false};

    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AliceState));
    tox_scenario_add_node(s, "Bob", bob_script, &bob_state, sizeof(BobState));

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
