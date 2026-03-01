#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint32_t conference;
    bool connected;
    uint32_t peer_count;
    bool n1_should_be_offline;
    bool coordinator_should_be_offline;
} State;

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    state->conference = tox_conference_join(tox_node_get_tox(self),
                                            tox_event_conference_invite_get_friend_number(event),
                                            tox_event_conference_invite_get_cookie(event),
                                            tox_event_conference_invite_get_cookie_length(event),
                                            nullptr);
    tox_node_log(self, "Joined conference %u", state->conference);
}

static void on_conference_connected(const Tox_Event_Conference_Connected *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->connected = true;
    tox_node_log(self, "Connected to conference");
}

static void node_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    const Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_conference_invite(dispatch, on_conference_invite);
    tox_events_callback_conference_connected(dispatch, on_conference_connected);

    tox_node_log(self, "Waiting for self connection...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected to DHT!");

    // Wait for all nodes to be DHT-connected
    for (int i = 0; i < 5; ++i) {
        ToxNode *node = tox_scenario_get_node(tox_node_get_scenario(self), i);
        WAIT_UNTIL(tox_node_is_self_connected(node));
    }
    tox_node_log(self, "All nodes connected to DHT!");

    // Nodes 0, 1, 3, 4 just wait to be invited and connect.
    // Coordination is handled by Node 2 (Founder/Coordinator).

    tox_node_log(self, "Waiting for conference connection...");
    WAIT_UNTIL(state->connected);
    tox_node_log(self, "Connected to conference!");

    // In this test, nodes participate in multiple phases.
    // They just stay alive until the group is fully merged.
    WAIT_UNTIL(tox_conference_peer_count(tox, state->conference, nullptr) == 5);
    tox_node_log(self, "Finished!");
}

static void coordinator_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_conference_invite(dispatch, on_conference_invite);
    tox_events_callback_conference_connected(dispatch, on_conference_connected);

    tox_node_log(self, "Waiting for self connection...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected to DHT!");

    // Wait for all nodes to be DHT-connected
    for (int i = 0; i < 5; ++i) {
        ToxNode *node = tox_scenario_get_node(tox_node_get_scenario(self), i);
        WAIT_UNTIL(tox_node_is_self_connected(node));
    }
    tox_node_log(self, "All nodes connected to DHT!");

    // 1. Create conference
    state->conference = tox_conference_new(tox, nullptr);
    state->connected = true;
    tox_node_log(self, "Created conference %u", state->conference);

    // 2. Invite Node 1
    tox_node_log(self, "Waiting for friend 0 (Node1) to connect...");
    tox_node_wait_for_friend_connected(self, 0); // Node 1 is friend 0
    tox_node_log(self, "Friend 0 (Node1) connected! Inviting...");
    tox_conference_invite(tox, 0, state->conference, nullptr);

    const ToxNode *n1 = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    const State *s1_view = (const State *)tox_node_get_peer_ctx(n1);
    WAIT_UNTIL(s1_view->connected);

    // 3. Node 1 invites Node 0
    // Wait for Node 0 to join conference
    const ToxNode *n0 = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const State *s0_view = (const State *)tox_node_get_peer_ctx(n0);
    tox_node_log(self, "Waiting for Node 0 to join conference...");
    WAIT_UNTIL(s0_view->connected);
    tox_node_log(self, "Node 0 joined!");

    // 4. Split: Node 1 goes offline
    tox_node_log(self, "Splitting group. Node 1 goes offline.");
    state->n1_should_be_offline = true;

    // Wait for Coordinator to see Node 1 is gone (Safe read via mirror)
    tox_node_log(self, "Waiting for Node 1 to be seen as gone from conference...");
    WAIT_UNTIL(tox_conference_peer_count(tox, state->conference, nullptr) == 2); // Only Coordinator and Node 0 left

    // 5. Coordinator invites Node 3
    tox_node_log(self, "Waiting for friend 1 (Node3) to connect...");
    tox_node_wait_for_friend_connected(self, 1); // Node 3 is friend 1
    tox_node_log(self, "Friend 1 (Node3) connected! Inviting...");
    tox_conference_invite(tox, 1, state->conference, nullptr);

    const ToxNode *n3 = tox_scenario_get_node(tox_node_get_scenario(self), 3);
    const State *s3_view = (const State *)tox_node_get_peer_ctx(n3);
    WAIT_UNTIL(s3_view->connected);

    // 6. Node 3 invites Node 4
    const ToxNode *n4 = tox_scenario_get_node(tox_node_get_scenario(self), 4);
    const State *s4_view = (const State *)tox_node_get_peer_ctx(n4);
    tox_node_log(self, "Waiting for Node 4 to join conference...");
    WAIT_UNTIL(s4_view->connected);
    tox_node_log(self, "Node 4 joined!");

    // 7. Coordinator goes offline, Node 1 comes back online
    tox_node_log(self, "Coordinator goes offline, Node 1 comes back online.");
    state->n1_should_be_offline = false;
    tox_node_set_offline(self, true);

    // Wait in offline mode
    for (int i = 0; i < 200; ++i) {
        tox_scenario_yield(self);
    }

    // 8. Node 1 merges groups by inviting Node 3
    // This is handled in Node 1's script after it observes n1_should_be_offline == false.

    // 9. Coordinator comes back online
    tox_node_log(self, "Coming back online.");
    tox_node_set_offline(self, false);

    // Coordinator rejoins
    // In original test: reload and invite again.
    // Here we just re-sync.

    // Wait for all nodes to be in one group
    WAIT_UNTIL(tox_conference_peer_count(tox, state->conference, nullptr) == 5);
    tox_node_log(self, "Group merged successfully!");
}

static void n1_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_conference_invite(dispatch, on_conference_invite);
    tox_events_callback_conference_connected(dispatch, on_conference_connected);

    tox_node_log(self, "Waiting for self connection...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected to DHT!");

    // Wait for all nodes to be DHT-connected
    for (int i = 0; i < 5; ++i) {
        ToxNode *node = tox_scenario_get_node(tox_node_get_scenario(self), i);
        WAIT_UNTIL(tox_node_is_self_connected(node));
    }
    tox_node_log(self, "All nodes connected to DHT!");

    // Phase 1: Wait to join
    tox_node_log(self, "Waiting for conference connection...");
    WAIT_UNTIL(state->connected);
    tox_node_log(self, "Connected to conference!");

    // Phase 2: Invite Node 0
    tox_node_log(self, "Waiting for friend 0 (Node0) to connect...");
    tox_node_wait_for_friend_connected(self, 0); // Node 0 is friend 0
    tox_node_log(self, "Friend 0 (Node0) connected! Inviting...");
    tox_conference_invite(tox, 0, state->conference, nullptr);

    // Phase 3: Split (we will be set offline by Coordinator)
    // Observe coordinator's request for our offline status
    const ToxNode *coordinator = tox_scenario_get_node(tox_node_get_scenario(self), 2);
    const State *coord_view = (const State *)tox_node_get_peer_ctx(coordinator);

    WAIT_UNTIL(coord_view->n1_should_be_offline);
    tox_node_log(self, "Going offline as requested by coordinator.");
    tox_node_set_offline(self, true);

    WAIT_UNTIL(!coord_view->n1_should_be_offline);
    tox_node_log(self, "Coming back online as requested by coordinator.");
    tox_node_set_offline(self, false);

    // Phase 4: Merge groups
    // Node 3 is friend 2 for Node 1
    tox_node_log(self, "Waiting for friend 2 (Node3) to connect...");
    tox_node_wait_for_friend_connected(self, 2);
    tox_node_log(self, "Friend 2 (Node3) connected! Inviting to merge...");
    tox_node_log(self, "Inviting Node 3 to merge groups.");
    tox_conference_invite(tox, 2, state->conference, nullptr);

    WAIT_UNTIL(tox_conference_peer_count(tox, state->conference, nullptr) == 5);
    tox_node_log(self, "Finished!");
}

static void n3_script(ToxNode *self, void *ctx)
{
    const State *state = (const State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_conference_invite(dispatch, on_conference_invite);
    tox_events_callback_conference_connected(dispatch, on_conference_connected);

    tox_node_log(self, "Waiting for self connection...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected to DHT!");

    // Wait for all nodes to be DHT-connected
    for (int i = 0; i < 5; ++i) {
        ToxNode *node = tox_scenario_get_node(tox_node_get_scenario(self), i);
        WAIT_UNTIL(tox_node_is_self_connected(node));
    }
    tox_node_log(self, "All nodes connected to DHT!");

    // Phase 2: Wait to join
    tox_node_log(self, "Waiting for conference connection...");
    WAIT_UNTIL(state->connected);
    tox_node_log(self, "Connected to conference!");

    // Phase 3: Invite Node 4
    // Node 3 invites Node 4 when Coordinator is ready.
    // We can just wait for Node 1 to go offline, which signals the split.
    ToxNode *n1 = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    WAIT_UNTIL(tox_node_is_offline(n1));

    tox_node_log(self, "Waiting for friend 1 (Node4) to connect...");
    tox_node_wait_for_friend_connected(self, 1); // Node 4 is friend 1
    tox_node_log(self, "Friend 1 (Node4) connected! Inviting...");
    tox_conference_invite(tox, 1, state->conference, nullptr);

    WAIT_UNTIL(tox_conference_peer_count(tox, state->conference, nullptr) == 5);
    tox_node_log(self, "Finished!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    State states[5] = {0};
    ToxNode *nodes[5];

    nodes[0] = tox_scenario_add_node(s, "Node0", node_script, &states[0], sizeof(State));
    nodes[1] = tox_scenario_add_node(s, "Node1", n1_script, &states[1], sizeof(State));
    nodes[2] = tox_scenario_add_node(s, "Coordinator", coordinator_script, &states[2], sizeof(State));
    nodes[3] = tox_scenario_add_node(s, "Node3", n3_script, &states[3], sizeof(State));
    nodes[4] = tox_scenario_add_node(s, "Node4", node_script, &states[4], sizeof(State));

    // Topology: 0-1-2-3-4
    tox_node_friend_add(nodes[0], nodes[1]);
    tox_node_friend_add(nodes[1], nodes[0]);
    tox_node_friend_add(nodes[1], nodes[2]);
    tox_node_friend_add(nodes[2], nodes[1]);
    tox_node_friend_add(nodes[2], nodes[3]);
    tox_node_friend_add(nodes[3], nodes[2]);
    tox_node_friend_add(nodes[3], nodes[4]);
    tox_node_friend_add(nodes[4], nodes[3]);

    // Merge connection: 1-3
    tox_node_friend_add(nodes[1], nodes[3]);
    tox_node_friend_add(nodes[3], nodes[1]);

    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 5; ++j) {
            if (i != j) {
                tox_node_bootstrap(nodes[i], nodes[j]);
            }
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
