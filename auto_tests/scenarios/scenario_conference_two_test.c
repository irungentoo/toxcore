#include "framework/framework.h"
#include <stdio.h>

static void tox_script(ToxNode *self, void *ctx)
{
    Tox *tox = tox_node_get_tox(self);

    tox_node_log(self, "Creating conference 1...");
    Tox_Err_Conference_New err;
    tox_conference_new(tox, &err);
    if (err != TOX_ERR_CONFERENCE_NEW_OK) {
        tox_node_log(self, "Failed to create conference 1: %u", err);
        return;
    }

    tox_node_log(self, "Creating conference 2...");
    tox_conference_new(tox, &err);
    if (err != TOX_ERR_CONFERENCE_NEW_OK) {
        tox_node_log(self, "Failed to create conference 2: %u", err);
        return;
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    tox_scenario_add_node(s, "Node", tox_script, nullptr, 0);

    // Just run it until completion
    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
