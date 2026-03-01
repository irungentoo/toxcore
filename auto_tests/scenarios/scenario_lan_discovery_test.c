#include "framework/framework.h"
#include <stdio.h>

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_log(self, "Waiting for LAN discovery...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    if (tox_node_is_self_connected(self)) {
        tox_node_log(self, "Discovered network via LAN!");
    } else {
        tox_node_log(self, "Failed to discover network via LAN.");
    }
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_log(self, "Waiting for LAN discovery...");
    WAIT_UNTIL(tox_node_is_self_connected(self));
    if (tox_node_is_self_connected(self)) {
        tox_node_log(self, "Discovered network via LAN!");
    } else {
        tox_node_log(self, "Failed to discover network via LAN.");
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(opts, false);
    tox_options_set_local_discovery_enabled(opts, true);

    // Both nodes have local discovery enabled and NO bootstrap
    tox_scenario_add_node_ex(s, "Alice", alice_script, nullptr, 0, opts);
    tox_scenario_add_node_ex(s, "Bob", bob_script, nullptr, 0, opts);

    tox_options_free(opts);

    tox_scenario_log(s, "Starting scenario (LAN Discovery).");
    ToxScenarioStatus res = tox_scenario_run(s);

    if (res == TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Scenario completed successfully!");
    } else {
        tox_scenario_log(s, "Scenario failed with status: %u", res);
    }

    tox_scenario_free(s);
    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}
