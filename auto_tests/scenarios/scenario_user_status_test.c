#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    Tox_User_Status last_status;
    bool status_changed;
} BobState;

static void on_friend_status(const Tox_Event_Friend_Status *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *state = (BobState *)tox_node_get_script_ctx(self);

    if (tox_event_friend_status_get_friend_number(event) == 0) {
        state->last_status = tox_event_friend_status_get_status(event);
        state->status_changed = true;
        tox_node_log(self, "Alice changed status to %s", tox_user_status_to_string(state->last_status));
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);

    tox_node_log(self, "Setting status to AWAY");
    tox_self_set_status(tox, TOX_USER_STATUS_AWAY);
    ck_assert(tox_self_get_status(tox) == TOX_USER_STATUS_AWAY);

    // Yield to let the status propagate
    for (int i = 0; i < 20; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Setting status to BUSY");
    tox_self_set_status(tox, TOX_USER_STATUS_BUSY);
    ck_assert(tox_self_get_status(tox) == TOX_USER_STATUS_BUSY);

    for (int i = 0; i < 20; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Setting status back to NONE");
    tox_self_set_status(tox, TOX_USER_STATUS_NONE);
    ck_assert(tox_self_get_status(tox) == TOX_USER_STATUS_NONE);

    ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    WAIT_UNTIL(tox_node_is_finished(bob));
}

static void bob_script(ToxNode *self, void *ctx)
{
    BobState *state = (BobState *)ctx;
    tox_events_callback_friend_status(tox_node_get_dispatch(self), on_friend_status);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_node_log(self, "Waiting for Alice to become AWAY...");
    WAIT_UNTIL(state->status_changed && state->last_status == TOX_USER_STATUS_AWAY);
    state->status_changed = false;

    tox_node_log(self, "Waiting for Alice to become BUSY...");
    WAIT_UNTIL(state->status_changed && state->last_status == TOX_USER_STATUS_BUSY);
    state->status_changed = false;

    tox_node_log(self, "Waiting for Alice to become NONE...");
    WAIT_UNTIL(state->status_changed && state->last_status == TOX_USER_STATUS_NONE);

    tox_node_log(self, "Status propagation verified!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    BobState bob_state = {TOX_USER_STATUS_NONE, false};

    tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
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

