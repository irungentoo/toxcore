#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_TOXES 40
#define NUM_FRIEND_PAIRS 50
#define FR_MESSAGE "Gentoo"
#define RELAY_TCP_PORT 33448

typedef struct {
    uint32_t expected_friends;
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

    tox_node_log(self, "Waiting for connection to relay...");
    tox_node_wait_for_self_connected(self);
    tox_node_log(self, "Connected. Expected friends: %u", state->expected_friends);

    // Wait until we have the expected number of friends connected via TCP
    uint32_t last_connected = 0;
    while (1) {
        uint32_t connected_friends = 0;
        uint32_t total_friends = tox_self_get_friend_list_size(tox_node_get_tox(self));
        for (uint32_t i = 0; i < total_friends; ++i) {
            if (tox_node_get_friend_connection_status(self, i) == TOX_CONNECTION_TCP) {
                connected_friends++;
            }
        }

        if (connected_friends != last_connected) {
            tox_node_log(self, "Connected friends: %u/%u", connected_friends, state->expected_friends);
            last_connected = connected_friends;
        }

        if (connected_friends >= state->expected_friends) {
            break;
        }
        tox_scenario_yield(self);
    }

    tox_node_log(self, "All %u friends connected via TCP.", state->expected_friends);
}

static void relay_script(ToxNode *self, void *ctx)
{
    (void)ctx;
    ToxScenario *s = tox_node_get_scenario(self);

    while (tox_scenario_is_running(self)) {
        bool all_finished = true;
        for (uint32_t i = 0; i < NUM_TOXES; ++i) {
            ToxNode *peer = tox_scenario_get_node(s, i + 1); // Peers start at index 1
            if (!tox_node_is_finished(peer)) {
                all_finished = false;
                break;
            }
        }
        if (all_finished) {
            break;
        }
        tox_scenario_yield(self);
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);

    struct Tox_Options *opts_relay = tox_options_new(nullptr);
    tox_options_set_tcp_port(opts_relay, RELAY_TCP_PORT);
    ToxNode *relay = tox_scenario_add_node_ex(s, "Relay", relay_script, nullptr, 0, opts_relay);
    tox_options_free(opts_relay);

    uint8_t relay_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox_node_get_tox(relay), relay_dht_id);

    uint16_t relay_tcp_port = tox_self_get_tcp_port(tox_node_get_tox(relay), nullptr);

    State states[NUM_TOXES] = {0};
    ToxNode *nodes[NUM_TOXES];

    struct Tox_Options *opts_peer = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts_peer, false);
    tox_options_set_local_discovery_enabled(opts_peer, false);

    for (int i = 0; i < NUM_TOXES; ++i) {
        char alias[16];
        snprintf(alias, sizeof(alias), "Tox%d", i);
        nodes[i] = tox_scenario_add_node_ex(s, alias, peer_script, &states[i], sizeof(State), opts_peer);

        // All peers use the Relay for TCP and DHT bootstrapping
        tox_add_tcp_relay(tox_node_get_tox(nodes[i]), "127.0.0.1", relay_tcp_port, relay_dht_id, nullptr);
        tox_node_bootstrap(nodes[i], relay);
    }
    tox_options_free(opts_peer);

    struct {
        uint16_t t1;
        uint16_t t2;
    } pairs[NUM_FRIEND_PAIRS];

    // Generate friend pairs
    for (int i = 0; i < NUM_FRIEND_PAIRS; ++i) {
        bool unique;
        do {
            unique = true;
            pairs[i].t1 = rand() % NUM_TOXES;
            pairs[i].t2 = (pairs[i].t1 + rand() % (NUM_TOXES - 1) + 1) % NUM_TOXES;

            // Avoid reciprocal or duplicate pairs
            for (int j = 0; j < i; ++j) {
                if ((pairs[j].t1 == pairs[i].t1 && pairs[j].t2 == pairs[i].t2) ||
                        (pairs[j].t1 == pairs[i].t2 && pairs[j].t2 == pairs[i].t1)) {
                    unique = false;
                    break;
                }
            }
        } while (!unique);

        uint8_t addr[TOX_ADDRESS_SIZE];
        tox_self_get_address(tox_node_get_tox(nodes[pairs[i].t1]), addr);

        Tox_Err_Friend_Add err;
        tox_friend_add(tox_node_get_tox(nodes[pairs[i].t2]), addr, (const uint8_t *)FR_MESSAGE, 6, &err);
        ck_assert(err == TOX_ERR_FRIEND_ADD_OK);

        states[pairs[i].t1].expected_friends++;
        states[pairs[i].t2].expected_friends++;
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
#undef RELAY_TCP_PORT
