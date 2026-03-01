#include "framework/framework.h"
#include <stdio.h>

static void alice_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Setting typing to true");
    tox_self_set_typing(tox_node_get_tox(self), 0, true, nullptr);

    // Wait some time
    for (int i = 0; i < 10; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Setting typing to false");
    tox_self_set_typing(tox_node_get_tox(self), 0, false, nullptr);
}

static void bob_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Waiting for Alice to start typing...");
    WAIT_UNTIL(tox_node_friend_typing_is(self, 0, true));
    tox_node_log(self, "Alice is typing!");

    tox_node_log(self, "Waiting for Alice to stop typing...");
    WAIT_UNTIL(tox_node_friend_typing_is(self, 0, false));
    tox_node_log(self, "Alice stopped typing.");
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
