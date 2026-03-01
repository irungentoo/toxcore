#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void alice_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox *tox = tox_node_get_tox(self);

    // Test tox_friend_exists
    ck_assert(tox_friend_exists(tox, 0));
    ck_assert(!tox_friend_exists(tox, 1));

    // Test tox_friend_get_public_key
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    Tox_Err_Friend_Get_Public_Key pk_err;
    bool pk_success = tox_friend_get_public_key(tox, 0, pk, &pk_err);
    ck_assert(pk_success);
    ck_assert(pk_err == TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);

    // Test tox_friend_by_public_key
    Tox_Err_Friend_By_Public_Key by_pk_err;
    uint32_t friend_num = tox_friend_by_public_key(tox, pk, &by_pk_err);
    ck_assert(by_pk_err == TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK);
    ck_assert(friend_num == 0);

    // Test tox_friend_get_last_online
    Tox_Err_Friend_Get_Last_Online lo_err;
    uint64_t last_online = tox_friend_get_last_online(tox, 0, &lo_err);
    ck_assert(lo_err == TOX_ERR_FRIEND_GET_LAST_ONLINE_OK);
    // Since they are currently connected, last_online should be recent (non-zero)
    ck_assert(last_online > 0);

    tox_node_log(self, "Friend query tests passed!");
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    // Bob stays connected while Alice runs her tests
    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
