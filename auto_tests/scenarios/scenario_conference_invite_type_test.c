#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

#include "../../toxcore/tox_private.h"

typedef struct {
    uint32_t invites;
    Tox_Conference_Type type;
} State;

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    ++state->invites;
    state->type = tox_event_conference_invite_get_type(event);
}

static void alice_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    // An invite of a conference type that doesn't exist: the packet ID for
    // conferences' invites (PACKET_ID_INVITE_CONFERENCE), the one for an
    // invite, a conference number, the type, then the conference ID.
    uint8_t invite[1 + 1 + sizeof(uint16_t) + 1 + TOX_CONFERENCE_ID_SIZE] = {96};
    invite[1 + 1 + sizeof(uint16_t)] = 2;
    ck_assert(tox_friend_send_lossless_packet_any_id(tox, 0, invite, sizeof(invite), nullptr));

    Tox_Err_Conference_New err_new;
    const uint32_t conference = tox_conference_new(tox, &err_new);
    ck_assert(err_new == TOX_ERR_CONFERENCE_NEW_OK);
    tox_conference_invite(tox, 0, conference, nullptr);

    const ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    const State *bob_view = (const State *)tox_node_get_peer_ctx(bob);
    WAIT_UNTIL(bob_view->invites > 0);
}

static void bob_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    tox_events_callback_conference_invite(tox_node_get_dispatch(self), on_conference_invite);
    tox_node_wait_for_self_connected(self);

    // Lossless packets arrive in order, so the bad invite came first.
    WAIT_UNTIL(state->invites > 0);
    ck_assert(state->invites == 1);
    ck_assert(state->type == TOX_CONFERENCE_TYPE_TEXT);
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
