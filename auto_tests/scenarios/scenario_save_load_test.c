#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define FRIEND_REQUEST_MSG "Gentoo"

static void on_friend_request(const Tox_Event_Friend_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    const uint8_t *msg = tox_event_friend_request_get_message(event);
    size_t len = tox_event_friend_request_get_message_length(event);

    if (len == 7 && memcmp(msg, FRIEND_REQUEST_MSG, 7) == 0) {
        tox_friend_add_norequest(tox_node_get_tox(self), tox_event_friend_request_get_public_key(event), nullptr);
    }
}

static void relay_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));

    ToxScenario *s = tox_node_get_scenario(self);
    bool peers_done = false;
    while (!peers_done && tox_scenario_is_running(self)) {
        peers_done = true;
        for (uint32_t i = 1; i < 3; ++i) {
            if (!tox_node_is_finished(tox_scenario_get_node(s, i))) {
                peers_done = false;
                break;
            }
        }
        if (!peers_done) {
            tox_scenario_yield(self);
        }
    }
}

static void peer_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    uint32_t my_index = tox_node_get_index(self);

    if (my_index == 1) {
        tox_events_callback_friend_request(tox_node_get_dispatch(self), on_friend_request);
    }

    WAIT_UNTIL(tox_node_is_self_connected(self));

    if (my_index == 2) {
        ToxNode *peer1 = tox_scenario_get_node(tox_node_get_scenario(self), 1);
        uint8_t addr[TOX_ADDRESS_SIZE];
        tox_node_get_address(peer1, addr);
        tox_friend_add(tox, addr, (const uint8_t *)FRIEND_REQUEST_MSG, 7, nullptr);
    }

    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to friend");

    // Reload test
    tox_node_log(self, "Reloading...");
    tox_node_reload(self);
    tox_node_log(self, "Reloaded");

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to friend again after reload");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);

    ToxNode *relay = tox_scenario_add_node(s, "Relay", relay_script, nullptr, 0);
    ToxNode *peer1 = tox_scenario_add_node(s, "Peer1", peer_script, nullptr, 0);
    ToxNode *peer2 = tox_scenario_add_node(s, "Peer2", peer_script, nullptr, 0);

    // All peers bootstrap from relay
    tox_node_bootstrap(peer1, relay);
    tox_node_bootstrap(peer2, relay);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
