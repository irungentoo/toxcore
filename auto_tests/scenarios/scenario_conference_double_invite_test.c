#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    bool joined;
    uint32_t conference;
} State;

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    if (state->joined) {
        tox_node_log(self, "ERROR! Received second invite for already joined conference");
        return;
    }

    Tox_Err_Conference_Join err;
    state->conference = tox_conference_join(tox_node_get_tox(self),
                                            tox_event_conference_invite_get_friend_number(event),
                                            tox_event_conference_invite_get_cookie(event),
                                            tox_event_conference_invite_get_cookie_length(event),
                                            &err);
    if (err == TOX_ERR_CONFERENCE_JOIN_OK) {
        state->joined = true;
        tox_node_log(self, "Joined conference %u", state->conference);
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    State *state = (State *)ctx;

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Creating conference...");
    Tox_Err_Conference_New err_new;
    state->conference = tox_conference_new(tox, &err_new);
    state->joined = true;

    tox_node_log(self, "Inviting Bob (1st time)...");
    tox_conference_invite(tox, 0, state->conference, nullptr);

    // Wait for Bob to join
    const ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    const State *bob_view = (const State *)tox_node_get_peer_ctx(bob);
    WAIT_UNTIL(bob_view->joined);

    tox_node_log(self, "Inviting Bob (2nd time); should be ignored by Bob's script logic...");
    tox_conference_invite(tox, 0, state->conference, nullptr);

    // Wait some ticks to see if Bob's script logs an error
    for (int i = 0; i < 20; ++i) {
        tox_scenario_yield(self);
    }
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_events_callback_conference_invite(tox_node_get_dispatch(self), on_conference_invite);
    WAIT_UNTIL(tox_node_is_self_connected(self));

    const State *state = (const State *)ctx;
    WAIT_UNTIL(state->joined);

    // Stay alive for Alice's second invite
    for (int i = 0; i < 50; ++i) {
        tox_scenario_yield(self);
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    State s1 = {0}, s2 = {0};

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, &s1, sizeof(State));
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &s2, sizeof(State));

    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    tox_node_bootstrap(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
