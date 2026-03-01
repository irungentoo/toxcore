#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_node_log(self, "Sending message to Bob...");
    uint8_t msg[] = "hello";
    Tox_Err_Friend_Send_Message err;
    tox_friend_send_message(tox_node_get_tox(self), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &err);
    ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_node_log(self, "Waiting for message from Alice...");
    WAIT_FOR_EVENT(TOX_EVENT_FRIEND_MESSAGE);
    tox_node_log(self, "Received message!");
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
