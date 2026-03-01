#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_TOXES 90
#define NUM_FRIEND_PAIRS 50
#define FR_MESSAGE "Gentoo"

typedef struct {
    uint32_t friend_count;
} State;

static void on_friend_request(const Tox_Event_Friend_Request *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    const uint8_t *msg = tox_event_friend_request_get_message(event);
    size_t len = tox_event_friend_request_get_message_length(event);

    if (len == 6 && memcmp(msg, FR_MESSAGE, 6) == 0) {
        tox_friend_add_norequest(tox_node_get_tox(self), tox_event_friend_request_get_public_key(event), nullptr);
    }
}

static void peer_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    tox_events_callback_friend_request(tox_node_get_dispatch(self), on_friend_request);

    tox_node_wait_for_self_connected(self);

    // Wait until we have the expected number of friends connected
    while (1) {
        uint32_t connected_friends = 0;
        uint32_t total_friends = tox_self_get_friend_list_size(tox_node_get_tox(self));
        for (uint32_t i = 0; i < total_friends; ++i) {
            if (tox_node_is_friend_connected(self, i)) {
                connected_friends++;
            }
        }
        if (connected_friends >= state->friend_count) {
            break;
        }
        tox_scenario_yield(self);
    }

    tox_node_log(self, "All %u friends connected.", state->friend_count);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    State states[NUM_TOXES] = {0};
    ToxNode *nodes[NUM_TOXES];

    for (int i = 0; i < NUM_TOXES; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Tox%d", i);
        nodes[i] = tox_scenario_add_node(s, alias, peer_script, &states[i], sizeof(State));
    }

    for (int i = 0; i < NUM_TOXES; ++i) {
        tox_node_bootstrap(nodes[i], nodes[(i + 1) % NUM_TOXES]);
        tox_node_bootstrap(nodes[(i + 1) % NUM_TOXES], nodes[i]);
    }

    // Generate friend pairs
    for (int i = 0; i < NUM_FRIEND_PAIRS; ++i) {
        int t1, t2;
        do {
            t1 = rand() % NUM_TOXES;
            t2 = rand() % NUM_TOXES;
        } while (t1 == t2);

        uint8_t addr[TOX_ADDRESS_SIZE];
        tox_self_get_address(tox_node_get_tox(nodes[t1]), addr);

        Tox_Err_Friend_Add err;
        tox_friend_add(tox_node_get_tox(nodes[t2]), addr, (const uint8_t *)FR_MESSAGE, 6, &err);
        if (err == TOX_ERR_FRIEND_ADD_OK) {
            states[t1].friend_count++;
            states[t2].friend_count++;

            // Bootstrap off each other
            tox_node_bootstrap(nodes[t2], nodes[t1]);
            tox_node_bootstrap(nodes[t1], nodes[t2]);
        }
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef FR_MESSAGE
#undef NUM_TOXES
#undef NUM_FRIEND_PAIRS
