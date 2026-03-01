#include "framework/framework.h"
#include <stdio.h>

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_log(self, "Waiting for DHT connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Connected to DHT. Waiting for friend connection...");

    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to Bob!");
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_log(self, "Waiting for DHT connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Connected to DHT. Waiting for friend connection...");

    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
    tox_node_log(self, "Connected to Alice!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000); // 60s virtual timeout

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    tox_node_bootstrap(bob, alice);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    tox_scenario_log(s, "Starting scenario...");
    ToxScenarioStatus res = tox_scenario_run(s);

    if (res == TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Scenario completed successfully!");
    } else {
        tox_scenario_log(s, "Scenario failed with status: %u", res);
    }

    tox_scenario_free(s);
    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}
