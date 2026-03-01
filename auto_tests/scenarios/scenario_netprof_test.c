#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "../../toxcore/tox_private.h"

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    for (int i = 0; i < 256; i++) {
        tox_friend_send_message(tox_node_get_tox(self), 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"test", 4, nullptr);
        tox_scenario_yield(self);
    }

    // Wait for Bob to also send his messages and for them to arrive.
    for (int i = 0; i < 100; i++) {
        tox_scenario_yield(self);
    }

    const Tox *tox = tox_node_get_tox(self);
    uint64_t udp_sent = tox_netprof_get_packet_total_count(tox, TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_DIRECTION_SENT);
    uint64_t udp_recv = tox_netprof_get_packet_total_count(tox, TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_DIRECTION_RECV);

    tox_node_log(self, "UDP Sent: %" PRIu64 ", Received: %" PRIu64, udp_sent, udp_recv);

    ck_assert(udp_sent >= 256);
    ck_assert(udp_recv >= 1);
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    for (int i = 0; i < 256; i++) {
        tox_friend_send_message(tox_node_get_tox(self), 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"test", 4, nullptr);
        tox_scenario_yield(self);
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
