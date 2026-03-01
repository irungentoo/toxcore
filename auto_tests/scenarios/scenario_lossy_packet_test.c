#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOSSY_PACKET_FILLER 200

static void alice_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    const size_t packet_size = tox_max_custom_packet_size();
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    memset(packet, LOSSY_PACKET_FILLER, packet_size);

    tox_node_log(self, "Sending lossy packet to Bob...");
    tox_friend_send_lossy_packet(tox, 0, packet, packet_size, nullptr);
    free(packet);
}

static void bob_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Waiting for lossy packet from Alice...");
    WAIT_FOR_EVENT(TOX_EVENT_FRIEND_LOSSY_PACKET);
    tox_node_log(self, "Received lossy packet from Alice!");
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
