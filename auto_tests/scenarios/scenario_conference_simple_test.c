#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    bool joined;
    bool connected;
    uint32_t conference;
    bool received;
    uint32_t peers;
} State;

static void on_conference_connected(const Tox_Event_Conference_Connected *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->connected = true;
    tox_node_log(self, "Connected to conference %u", tox_event_conference_connected_get_conference_number(event));
}

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    tox_node_log(self, "Received conference invite from friend %u", tox_event_conference_invite_get_friend_number(event));
    Tox_Err_Conference_Join err;
    state->conference = tox_conference_join(tox_node_get_tox(self),
                                            tox_event_conference_invite_get_friend_number(event),
                                            tox_event_conference_invite_get_cookie(event),
                                            tox_event_conference_invite_get_cookie_length(event),
                                            &err);
    if (err == TOX_ERR_CONFERENCE_JOIN_OK) {
        state->joined = true;
        tox_node_log(self, "Joined conference %u", state->conference);
    } else {
        tox_node_log(self, "Failed to join conference: %u", err);
    }
}

static void on_conference_message(const Tox_Event_Conference_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    const uint8_t *msg = tox_event_conference_message_get_message(event);
    if (memcmp(msg, "hello!", 6) == 0) {
        state->received = true;
    }
}

static void on_conference_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    state->peers = tox_conference_peer_count(tox_node_get_tox(self), tox_event_conference_peer_list_changed_get_conference_number(event), nullptr);
}

static void tox1_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    State *state = (State *)ctx;
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_conference_peer_list_changed);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Creating conference...");
    Tox_Err_Conference_New err_new;
    state->conference = tox_conference_new(tox, &err_new);
    state->joined = true;

    tox_node_log(self, "Inviting Bob...");
    Tox_Err_Conference_Invite err_inv;
    tox_conference_invite(tox, 0, state->conference, &err_inv);

    WAIT_UNTIL(state->peers == 3);
    tox_node_log(self, "All peers joined!");

    Tox_Err_Conference_Send_Message err_msg;
    tox_conference_send_message(tox, state->conference, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"hello!", 6, &err_msg);
}

static void tox2_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    State *state = (State *)ctx;
    tox_events_callback_conference_connected(tox_node_get_dispatch(self), on_conference_connected);
    tox_events_callback_conference_invite(tox_node_get_dispatch(self), on_conference_invite);
    tox_events_callback_conference_message(tox_node_get_dispatch(self), on_conference_message);
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_conference_peer_list_changed);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Waiting for join...");
    WAIT_UNTIL(state->joined);
    tox_node_log(self, "Joined conference %u. Waiting for connection...", state->conference);
    WAIT_UNTIL(state->connected);
    tox_node_log(self, "Connected. Waiting for Charlie to connect...");

    WAIT_UNTIL(tox_node_is_friend_connected(self, 1));
    tox_node_log(self, "Charlie connected. Inviting Charlie...");

    Tox_Err_Conference_Invite err_inv;
    bool ok = tox_conference_invite(tox, 1, state->conference, &err_inv);
    if (ok) {
        tox_node_log(self, "Successfully invited Charlie");
    } else {
        tox_node_log(self, "Failed to invite Charlie: %u", err_inv);
    }

    WAIT_UNTIL(state->received);
    tox_node_log(self, "Received message!");
}

static void tox3_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    tox_events_callback_conference_invite(tox_node_get_dispatch(self), on_conference_invite);
    tox_events_callback_conference_message(tox_node_get_dispatch(self), on_conference_message);
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_conference_peer_list_changed);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Waiting for message...");
    WAIT_UNTIL(state->received);
    tox_node_log(self, "Received message!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 600000); // 10m virtual timeout
    State s1 = {0}, s2 = {0}, s3 = {0};

    ToxNode *t1 = tox_scenario_add_node(s, "Alice", tox1_script, &s1, sizeof(State));
    ToxNode *t2 = tox_scenario_add_node(s, "Bob", tox2_script, &s2, sizeof(State));
    ToxNode *t3 = tox_scenario_add_node(s, "Charlie", tox3_script, &s3, sizeof(State));

    // t1 <-> t2, t2 <-> t3
    tox_node_friend_add(t1, t2);
    tox_node_friend_add(t2, t1);
    tox_node_friend_add(t2, t3);
    tox_node_friend_add(t3, t2);

    tox_node_bootstrap(t2, t1);
    tox_node_bootstrap(t3, t1); // All bootstrap from Alice
    tox_node_bootstrap(t3, t2);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
