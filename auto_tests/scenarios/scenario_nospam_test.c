#include "framework/framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool nospam_changed;
} AliceState;

static void set_checksum(uint8_t *address)
{
    uint8_t checksum[2] = {0};
    for (int i = 0; i < 36; ++i) {
        checksum[i % 2] ^= address[i];
    }
    address[36] = checksum[0];
    address[37] = checksum[1];
}

static void alice_script(ToxNode *self, void *ctx)
{
    AliceState *state = (AliceState *)ctx;
    tox_node_wait_for_self_connected(self);

    Tox *tox = tox_node_get_tox(self);
    uint32_t old_nospam = tox_self_get_nospam(tox);
    uint32_t new_nospam = old_nospam + 1;

    tox_node_log(self, "Old nospam: %u, setting new nospam: %u", old_nospam, new_nospam);
    tox_self_set_nospam(tox, new_nospam);
    ck_assert(tox_self_get_nospam(tox) == new_nospam);

    // Signal to Bob that we changed nospam
    state->nospam_changed = true;

    tox_node_log(self, "Waiting for friend request from Bob...");
    WAIT_FOR_EVENT(TOX_EVENT_FRIEND_REQUEST);
    tox_node_log(self, "Received friend request from Bob!");
}

static void bob_script(ToxNode *self, void *ctx)
{
    tox_node_wait_for_self_connected(self);

    ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    const AliceState *alice_view = (const AliceState *)tox_node_get_peer_ctx(alice);

    tox_node_log(self, "Waiting for Alice to change nospam...");
    WAIT_UNTIL(alice_view->nospam_changed);

    uint8_t alice_addr[TOX_ADDRESS_SIZE];
    tox_node_get_address(alice, alice_addr);

    // Alice's address in alice_addr is already the NEW one.
    // Manually construct an old address.
    uint8_t old_alice_addr[TOX_ADDRESS_SIZE];
    memcpy(old_alice_addr, alice_addr, TOX_ADDRESS_SIZE);

    uint32_t nospam;
    memcpy(&nospam, old_alice_addr + 32, 4);
    nospam--; // Revert to old nospam
    memcpy(old_alice_addr + 32, &nospam, 4);
    set_checksum(old_alice_addr);

    tox_node_log(self, "Trying to add Alice with OLD nospam...");
    Tox_Err_Friend_Add err;
    uint32_t friend_num = tox_friend_add(tox_node_get_tox(self), old_alice_addr, (const uint8_t *)"Hi", 2, &err);
    ck_assert(err == TOX_ERR_FRIEND_ADD_OK);

    // Wait some time, but not too long.
    for (int i = 0; i < 100; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Deleting Alice and trying with NEW nospam...");
    tox_friend_delete(tox_node_get_tox(self), friend_num, nullptr);

    tox_friend_add(tox_node_get_tox(self), alice_addr, (const uint8_t *)"Hi", 2, &err);
    ck_assert(err == TOX_ERR_FRIEND_ADD_OK);
    tox_node_log(self, "Friend request sent!");
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    AliceState alice_state = {false};
    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AliceState));
    tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(alice, bob);
    tox_node_bootstrap(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
