#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

#define NUM_MSGS 40000

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    const uint8_t message[] = {0};
    bool errored = false;
    Tox *tox = tox_node_get_tox(self);

    for (uint32_t i = 0; i < NUM_MSGS; i++) {
        Tox_Err_Friend_Send_Message err;
        tox_friend_send_message(tox, 0, TOX_MESSAGE_TYPE_NORMAL, message, sizeof(message), &err);

        if (err != TOX_ERR_FRIEND_SEND_MESSAGE_OK) {
            errored = true;
        }

        if (errored) {
            ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ);
        } else {
            ck_assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
        }
    }

    ck_assert(errored);
    tox_node_log(self, "Success: Send queue overflowed as expected.");
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 30000);
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

#undef NUM_MSGS
