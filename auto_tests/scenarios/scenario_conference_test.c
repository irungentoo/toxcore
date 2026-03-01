#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_PEERS 16
#define GROUP_MESSAGE "Install Gentoo"

typedef struct {
    bool joined;
    bool connected;
    uint32_t conference;
    uint32_t peer_count;
    uint32_t messages_received;
} PeerState;

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    PeerState *state = (PeerState *)tox_node_get_script_ctx(self);

    state->conference = tox_conference_join(tox_node_get_tox(self),
                                            tox_event_conference_invite_get_friend_number(event),
                                            tox_event_conference_invite_get_cookie(event),
                                            tox_event_conference_invite_get_cookie_length(event),
                                            nullptr);
    tox_node_log(self, "Joined conference %u", state->conference);
    state->joined = true;
}

static void on_conference_connected(const Tox_Event_Conference_Connected *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    PeerState *state = (PeerState *)tox_node_get_script_ctx(self);
    state->connected = true;
    tox_node_log(self, "Connected to conference %u", tox_event_conference_connected_get_conference_number(event));
}

static void on_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    PeerState *state = (PeerState *)tox_node_get_script_ctx(self);
    state->peer_count = tox_conference_peer_count(tox_node_get_tox(self), tox_event_conference_peer_list_changed_get_conference_number(event), nullptr);
    tox_node_log(self, "Peer count changed: %u", state->peer_count);
}

static void on_conference_message(const Tox_Event_Conference_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    PeerState *state = (PeerState *)tox_node_get_script_ctx(self);
    const uint8_t *msg = tox_event_conference_message_get_message(event);
    if (memcmp(msg, GROUP_MESSAGE, sizeof(GROUP_MESSAGE) - 1) == 0) {
        state->messages_received++;
        tox_node_log(self, "Received message %u", state->messages_received);
    }
}

static void peer_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    PeerState *state = (PeerState *)ctx;
    uint32_t my_index = tox_node_get_index(self);

    tox_events_callback_conference_invite(tox_node_get_dispatch(self), on_conference_invite);
    tox_events_callback_conference_connected(tox_node_get_dispatch(self), on_conference_connected);
    tox_events_callback_conference_peer_list_changed(tox_node_get_dispatch(self), on_peer_list_changed);
    tox_events_callback_conference_message(tox_node_get_dispatch(self), on_conference_message);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Self connected");

    // Founder (Node 0) creates group
    if (my_index == 0) {
        state->conference = tox_conference_new(tox, nullptr);
        tox_node_log(self, "Created conference %u", state->conference);
        state->joined = true;
        state->connected = true;

        // Invite friend 0 (Node 1)
        WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
        tox_node_log(self, "Friend 0 (Node 1) connected, inviting...");
        tox_conference_invite(tox, 0, state->conference, nullptr);
    } else {
        WAIT_UNTIL(state->joined);
        WAIT_UNTIL(state->connected);

        // Invite next friends if any
        // In linear topology, each node has 2 friends (except ends)
        // We invite friend 1 (the next node in line)
        if (my_index < NUM_PEERS - 1) {
            WAIT_UNTIL(tox_node_is_friend_connected(self, 1));
            tox_node_log(self, "Friend 1 (Node %u) connected, inviting...", my_index + 1);
            Tox_Err_Conference_Invite err;
            if (!tox_conference_invite(tox, 1, state->conference, &err)) {
                tox_node_log(self, "Failed to invite Node %u: %u", my_index + 1, err);
            }
        }
    }

    // Wait for all to join
    WAIT_UNTIL(state->peer_count == NUM_PEERS);
    tox_node_log(self, "All peers joined");

    // One peer sends a message
    if (my_index == 0) {
        tox_node_log(self, "Sending message");
        tox_conference_send_message(tox, state->conference, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)GROUP_MESSAGE, sizeof(GROUP_MESSAGE) - 1, nullptr);
    }

    // Wait for message propagation
    WAIT_UNTIL(state->messages_received > 0);
    tox_node_log(self, "Done");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    PeerState states[NUM_PEERS] = {0};

    ToxNode *nodes[NUM_PEERS];
    for (int i = 0; i < NUM_PEERS; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Peer%d", i);
        nodes[i] = tox_scenario_add_node(s, alias, peer_script, &states[i], sizeof(PeerState));
    }

    // Linear topology
    for (int i = 0; i < NUM_PEERS; ++i) {
        if (i > 0) {
            tox_node_friend_add(nodes[i], nodes[i - 1]);
            tox_node_bootstrap(nodes[i], nodes[i - 1]);
        }
        if (i < NUM_PEERS - 1) {
            tox_node_friend_add(nodes[i], nodes[i + 1]);
        }
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef NUM_PEERS
