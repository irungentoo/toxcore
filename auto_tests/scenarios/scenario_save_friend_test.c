#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint8_t *name;
    uint8_t *status_message;
    size_t name_len;
    size_t status_len;
} ReferenceData;

static void alice_script(ToxNode *self, void *ctx)
{
    const ReferenceData *ref = (const ReferenceData *)ctx;

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    // Wait for name and status to propagate
    WAIT_UNTIL(tox_node_friend_name_is(self, 0, ref->name, ref->name_len));
    WAIT_UNTIL(tox_node_friend_status_message_is(self, 0, ref->status_message, ref->status_len));
    tox_node_log(self, "Received reference name and status from Bob");

    // Save and Reload
    tox_node_log(self, "Reloading...");
    tox_node_reload(self);
    tox_node_log(self, "Reloaded");

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    // Check if Bob's info is still correct after reload
    ck_assert(tox_node_friend_name_is(self, 0, ref->name, ref->name_len));
    ck_assert(tox_node_friend_status_message_is(self, 0, ref->status_message, ref->status_len));
    tox_node_log(self, "Bob's name and status are still correct after reload");
}

static void bob_script(ToxNode *self, void *ctx)
{
    ReferenceData *ref = (ReferenceData *)ctx;
    Tox *tox = tox_node_get_tox(self);

    tox_self_set_name(tox, ref->name, ref->name_len, nullptr);
    tox_self_set_status_message(tox, ref->status_message, ref->status_len, nullptr);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    // Stay online for Alice
    tox_node_log(self, "Waiting for Alice to finish...");
    while (!tox_node_is_finished(tox_scenario_get_node(tox_node_get_scenario(self), 0))) {
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Alice finished, Bob is done");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);

    ReferenceData ref;
    ref.name_len = tox_max_name_length();
    ref.status_len = tox_max_status_message_length();
    ref.name = (uint8_t *)malloc(ref.name_len);
    ref.status_message = (uint8_t *)malloc(ref.status_len);

    for (size_t i = 0; i < ref.name_len; ++i) {
        ref.name[i] = (uint8_t)(rand() % 256);
    }
    for (size_t i = 0; i < ref.status_len; ++i) {
        ref.status_message[i] = (uint8_t)(rand() % 256);
    }

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, &ref, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &ref, 0);

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
    free(ref.name);
    free(ref.status_message);
    return 0;
}
