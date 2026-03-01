#include "framework/framework.h"
#include <stdio.h>

static void alice_script(ToxNode *self, void *ctx)
{
    ToxScenario *s = tox_node_get_scenario(self);
    ToxNode *bob = tox_scenario_get_node(s, 1);
    // Alice just waits for Bob to finish his bootstrap test
    WAIT_UNTIL(tox_node_is_finished(bob));
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_log(self, "Waiting for DHT connection...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    tox_node_log(self, "Connected to DHT!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 30000);

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    tox_node_bootstrap(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);

    if (res == TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Scenario completed successfully!");
    } else {
        tox_scenario_log(s, "Scenario failed with status: %u", res);
    }

    tox_scenario_free(s);
    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}
