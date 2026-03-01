#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOSSLESS_PACKET_FILLER 160

static void alice_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    tox_node_log(self, "Waiting for connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Self connected, waiting for friend Bob...");
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to Bob. Connection type: %u", tox_friend_get_connection_status(tox, 0, nullptr));

    const size_t packet_size = tox_max_custom_packet_size();
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    memset(packet, LOSSLESS_PACKET_FILLER, packet_size);

    tox_node_log(self, "Sending lossless packet to Bob (size %zu)...", packet_size);
    Tox_Err_Friend_Custom_Packet err;
    if (tox_friend_send_lossless_packet(tox, 0, packet, packet_size, &err)) {
        tox_node_log(self, "Lossless packet sent successfully!");
    } else {
        tox_node_log(self, "Failed to send lossless packet: %u", err);
    }
    free(packet);
}

static void bob_script(ToxNode *self, void *ctx)
{
    const Tox *tox = tox_node_get_tox(self);
    tox_node_log(self, "Waiting for connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Self connected, waiting for friend Alice...");
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to Alice. Connection type: %u", tox_friend_get_connection_status(tox, 0, nullptr));

    tox_node_log(self, "Waiting for lossless packet from Alice...");
    WAIT_FOR_EVENT(TOX_EVENT_FRIEND_LOSSLESS_PACKET);
    if (tox_scenario_is_running(self)) {
        tox_node_log(self, "Received lossless packet from Alice!");
    } else {
        tox_node_log(self, "Timed out waiting for lossless packet.");
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    tox_node_bootstrap(bob, alice);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
