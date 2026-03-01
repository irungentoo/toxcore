#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

#define STATUS_MESSAGE "Installing Gentoo"

static void alice_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Setting status message to %s", STATUS_MESSAGE);
    tox_self_set_status_message(tox_node_get_tox(self), (const uint8_t *)STATUS_MESSAGE, sizeof(STATUS_MESSAGE), nullptr);
}

static void bob_script(ToxNode *self, void *ctx)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    tox_node_log(self, "Waiting for Alice to change status message...");
    WAIT_UNTIL(tox_node_friend_status_message_is(self, 0, (const uint8_t *)STATUS_MESSAGE, sizeof(STATUS_MESSAGE)));
    tox_node_log(self, "Alice\'s status message is now %s", STATUS_MESSAGE);
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
