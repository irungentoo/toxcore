#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    bool joined;
    uint32_t conference;
    bool friend_in_group;
} State;

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    Tox_Err_Conference_Join err;
    state->conference = tox_conference_join(tox_node_get_tox(self),
                                            tox_event_conference_invite_get_friend_number(event),
                                            tox_event_conference_invite_get_cookie(event),
                                            tox_event_conference_invite_get_cookie_length(event),
                                            &err);
    if (err == TOX_ERR_CONFERENCE_JOIN_OK) {
        state->joined = true;
    }
}

static void on_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    uint32_t count = tox_conference_peer_count(tox_node_get_tox(self), tox_event_conference_peer_list_changed_get_conference_number(event), nullptr);
    state->friend_in_group = (count == 2);
}

static void alice_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    State *state = (State *)ctx;
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_peer_list_changed);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_self_set_name(tox, (const uint8_t *)"Alice", 5, nullptr);

    tox_node_log(self, "Creating conference...");
    Tox_Err_Conference_New err_new;
    state->conference = tox_conference_new(tox, &err_new);
    state->joined = true;

    tox_node_log(self, "Inviting Bob...");
    tox_conference_invite(tox, 0, state->conference, nullptr);

    tox_node_log(self, "Waiting for Bob to join...");
    WAIT_UNTIL(state->friend_in_group);
    tox_node_log(self, "Bob joined!");

    // Wait for Bob to drop out (simulated by Bob finishing)
    tox_node_log(self, "Waiting for Bob to leave...");
    WAIT_UNTIL(!state->friend_in_group);
    tox_node_log(self, "Bob left!");
}

static void bob_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    const State *state = (const State *)ctx;
    tox_events_callback_conference_invite(tox_node_get_dispatch(self), on_conference_invite);
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_peer_list_changed);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_self_set_name(tox, (const uint8_t *)"Bob", 3, nullptr);

    WAIT_UNTIL(state->joined);
    tox_node_log(self, "Joined conference!");

    WAIT_UNTIL(state->friend_in_group);

    // Stay a bit then leave
    for (int i = 0; i < 20; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Leaving conference...");
    tox_conference_delete(tox, state->conference, nullptr);
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
