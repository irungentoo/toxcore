#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

#define NICKNAME "Gentoo"

static void alice_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Setting name to %s", NICKNAME);
    tox_self_set_name(tox_node_get_tox(self), (const uint8_t *)NICKNAME, sizeof(NICKNAME), nullptr);
}

static void bob_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Waiting for Alice to change name...");
    WAIT_UNTIL(tox_node_friend_name_is(self, 0, (const uint8_t *)NICKNAME, sizeof(NICKNAME)));
    tox_node_log(self, "Alice\'s name is now %s", NICKNAME);
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
