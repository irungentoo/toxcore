#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t conf_num;
    bool peer_joined;
} AliceState;

static void on_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *state = (AliceState *)tox_node_get_script_ctx(self);
    if (tox_conference_peer_count(tox_node_get_tox(self), state->conf_num, nullptr) == 2) {
        state->peer_joined = true;
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    AliceState *state = (AliceState *)ctx;
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_peer_list_changed);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);
    Tox_Err_Conference_New err_new;
    state->conf_num = tox_conference_new(tox, &err_new);
    ck_assert(err_new == TOX_ERR_CONFERENCE_NEW_OK);

    tox_node_log(self, "Created conference %u", state->conf_num);
    tox_conference_invite(tox, 0, state->conf_num, nullptr);

    WAIT_UNTIL(state->peer_joined);
    tox_node_log(self, "Bob joined. Querying peer info...");

    // Test tox_conference_peer_number_is_ours
    // Our own peer number should be 0 or 1.
    Tox_Err_Conference_Peer_Query q_err;
    bool p0_ours = tox_conference_peer_number_is_ours(tox, state->conf_num, 0, &q_err);
    ck_assert(q_err == TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    bool p1_ours = tox_conference_peer_number_is_ours(tox, state->conf_num, 1, &q_err);
    ck_assert(q_err == TOX_ERR_CONFERENCE_PEER_QUERY_OK);

    ck_assert(p0_ours != p1_ours); // One must be ours, the other must not be.

    uint32_t our_peer_num = p0_ours ? 0 : 1;
    uint32_t bobs_peer_num = p0_ours ? 1 : 0;

    // Test tox_conference_peer_get_public_key
    uint8_t our_pk[TOX_PUBLIC_KEY_SIZE];
    uint8_t our_self_pk[TOX_PUBLIC_KEY_SIZE];
    tox_conference_peer_get_public_key(tox, state->conf_num, our_peer_num, our_pk, nullptr);
    tox_self_get_public_key(tox, our_self_pk);
    ck_assert(memcmp(our_pk, our_self_pk, TOX_PUBLIC_KEY_SIZE) == 0);

    uint8_t bobs_pk[TOX_PUBLIC_KEY_SIZE];
    uint8_t bobs_self_pk[TOX_PUBLIC_KEY_SIZE];
    tox_conference_peer_get_public_key(tox, state->conf_num, bobs_peer_num, bobs_pk, nullptr);

    ToxNode *bob_node = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    tox_self_get_public_key(tox_node_get_tox(bob_node), bobs_self_pk);
    ck_assert(memcmp(bobs_pk, bobs_self_pk, TOX_PUBLIC_KEY_SIZE) == 0);

    // Test tox_conference_get_type
    Tox_Err_Conference_Get_Type gt_err;
    Tox_Conference_Type type = tox_conference_get_type(tox, state->conf_num, &gt_err);
    ck_assert(gt_err == TOX_ERR_CONFERENCE_GET_TYPE_OK);
    ck_assert(type == TOX_CONFERENCE_TYPE_TEXT);

    tox_node_log(self, "Conference query tests passed!");
}

typedef struct {
    bool invited;
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

    AliceState alice_state = {0, false};
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
