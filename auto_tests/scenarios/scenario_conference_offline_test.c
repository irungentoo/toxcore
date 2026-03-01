#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t conf_num;
    bool bob_joined;
} AliceState;

static void alice_on_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *state = (AliceState *)tox_node_get_script_ctx(self);
    uint32_t conf_num = tox_event_conference_peer_list_changed_get_conference_number(event);

    if (conf_num != state->conf_num) {
        return;
    }

    uint32_t count = tox_conference_peer_count(tox_node_get_tox(self), conf_num, nullptr);
    if (count == 2) {
        state->bob_joined = true;
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    AliceState *state = (AliceState *)ctx;
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), alice_on_peer_list_changed);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);
    Tox_Err_Conference_New err_new;
    state->conf_num = tox_conference_new(tox, &err_new);
    ck_assert(err_new == TOX_ERR_CONFERENCE_NEW_OK);

    tox_conference_set_max_offline(tox, state->conf_num, 10, nullptr);

    tox_node_log(self, "Inviting Bob to conference %u", state->conf_num);
    tox_conference_invite(tox, 0, state->conf_num, nullptr);

    WAIT_UNTIL(state->bob_joined);
    tox_node_log(self, "Bob joined. Reloading Alice...");

    tox_node_reload(self);
    tox_node_log(self, "Alice reloaded.");

    // Re-register callback after reload
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), alice_on_peer_list_changed);

    // After reload, we need to get the conference number again
    uint32_t chatlist[1];
    tox_conference_get_chatlist(tox_node_get_tox(self), chatlist);
    state->conf_num = chatlist[0];

    tox_node_log(self, "Checking offline peer list for conference %u...", state->conf_num);

    Tox_Err_Conference_Peer_Query q_err;
    uint32_t offline_count = tox_conference_offline_peer_count(tox_node_get_tox(self), state->conf_num, &q_err);
    ck_assert(q_err == TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    tox_node_log(self, "Offline peer count: %u", offline_count);

    // Bob should be offline now because we just started and haven't connected to him in the conference yet.
    ck_assert(offline_count >= 1);

    tox_node_log(self, "Conference offline peer tests passed!");
}

typedef struct {
    bool invited;
    uint32_t conf_num;
    uint8_t cookie[512];
    size_t cookie_len;
} BobState;

static void bob_on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *state = (BobState *)tox_node_get_script_ctx(self);

    state->invited = true;
    state->cookie_len = tox_event_conference_invite_get_cookie_length(event);
    memcpy(state->cookie, tox_event_conference_invite_get_cookie(event), state->cookie_len);
    tox_node_log(self, "Received conference invite");
}

static void bob_script(ToxNode *self, void *ctx)
{
    const BobState *state = (const BobState *)ctx;
    tox_events_callback_conference_invite(tox_node_get_dispatch(self), bob_on_conference_invite);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    WAIT_UNTIL(state->invited);

    tox_conference_join(tox_node_get_tox(self), 0, state->cookie, state->cookie_len, nullptr);

    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}


int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    AliceState alice_state = {0};
    BobState bob_state = {0};

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
