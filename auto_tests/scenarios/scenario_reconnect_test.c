#include "framework/framework.h"
#include <stdio.h>

static void alice_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to Bob.");

    // Bob will go offline now.
    tox_node_log(self, "Waiting for Bob to time out...");
    WAIT_UNTIL(!tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Bob timed out as expected.");

    tox_node_log(self, "Waiting for Bob to reconnect...");
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Bob reconnected!");
}

static void bob_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to Alice. Going offline for 40 seconds...");

    tox_node_set_offline(self, true);

    // In our virtual clock, 40 seconds is 40000 / TOX_SCENARIO_TICK_MS ticks.
    for (int i = 0; i < 40000 / TOX_SCENARIO_TICK_MS; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Coming back online.");
    tox_node_set_offline(self, false);

    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Reconnected to Alice!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    tox_node_bootstrap(alice, bob);
    tox_node_bootstrap(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
