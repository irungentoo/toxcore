#include "framework/framework.h"
#include "../../toxcore/tox_private.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_TOXES 30

typedef struct {
    uint8_t  public_key[TOX_DHT_NODE_PUBLIC_KEY_SIZE];
    char     ip[TOX_DHT_NODE_IP_STRING_SIZE];
    uint16_t port;
} Dht_Node;

typedef struct {
    Dht_Node *nodes[NUM_TOXES];
    size_t num_nodes;
    uint8_t public_key_list[NUM_TOXES][TOX_PUBLIC_KEY_SIZE];
} State;

static bool node_crawled(const State *state, const uint8_t *public_key)
{
    for (size_t i = 0; i < state->num_nodes; ++i) {
        if (memcmp(state->nodes[i]->public_key, public_key, TOX_DHT_NODE_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

static void on_dht_nodes_response(const Tox_Event_Dht_Nodes_Response *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);

    const uint8_t *public_key = tox_event_dht_nodes_response_get_public_key(event);
    const char *ip = (const char *)tox_event_dht_nodes_response_get_ip(event);
    const uint16_t port = tox_event_dht_nodes_response_get_port(event);

    if (node_crawled(state, public_key)) {
        return;
    }

    if (state->num_nodes >= NUM_TOXES) {
        return;
    }

    Dht_Node *node = (Dht_Node *)calloc(1, sizeof(Dht_Node));
    ck_assert(node != nullptr);

    memcpy(node->public_key, public_key, TOX_DHT_NODE_PUBLIC_KEY_SIZE);
    snprintf(node->ip, sizeof(node->ip), "%s", ip);
    node->port = port;

    state->nodes[state->num_nodes] = node;
    ++state->num_nodes;

    // ask new node to give us their close nodes to every public key
    for (size_t i = 0; i < NUM_TOXES; ++i) {
        tox_dht_send_nodes_request(tox_node_get_tox(self), public_key, ip, port, state->public_key_list[i], nullptr);
    }
}

static void peer_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    tox_events_callback_dht_nodes_response(tox_node_get_dispatch(self), on_dht_nodes_response);

    // Initial bootstrap: ask the node we bootstrapped from for all other nodes
    // Wait for self connection first
    WAIT_UNTIL(tox_node_is_self_connected(self));

    // After connecting, we should start receiving responses because we bootstrapped
    // but the original test calls tox_dht_send_nodes_request for all nodes.
    // In our case, we bootstrap linearly, so Peer-i bootstraps from Peer-(i-1).
    // Peer-0 doesn't bootstrap from anyone.

    // To kick off crawling, each node can ask its bootstrap source for all nodes.
    uint32_t my_index = tox_node_get_index(self);
    if (my_index > 0) {
        ToxNode *bootstrap_source = tox_scenario_get_node(tox_node_get_scenario(self), my_index - 1);
        uint8_t bs_pk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(tox_node_get_tox(bootstrap_source), bs_pk);

        Tox_Err_Get_Port port_err;
        uint16_t bs_port = tox_self_get_udp_port(tox_node_get_tox(bootstrap_source), &port_err);

        for (size_t i = 0; i < NUM_TOXES; ++i) {
            tox_dht_send_nodes_request(tox_node_get_tox(self), bs_pk, "127.0.0.1", bs_port, state->public_key_list[i], nullptr);
        }
    }

    // Wait until we have crawled all nodes
    uint64_t last_log_time = 0;
    uint64_t last_request_time = 0;
    while (state->num_nodes < NUM_TOXES) {
        tox_scenario_yield(self);
        uint64_t now = tox_scenario_get_time(tox_node_get_scenario(self));

        if (now - last_request_time >= 2000) {
            last_request_time = now;

            // Retry strategy: ask a random known node for missing nodes
            if (state->num_nodes > 0) {
                int idx = rand() % state->num_nodes;
                const Dht_Node *n = state->nodes[idx];
                for (int i = 0; i < NUM_TOXES; ++i) {
                    if (!node_crawled(state, state->public_key_list[i])) {
                        tox_dht_send_nodes_request(tox_node_get_tox(self),
                                                   n->public_key, n->ip, n->port, state->public_key_list[i], nullptr);
                    }
                }
            } else if (my_index > 0) {
                // Fallback: if we haven't found anyone yet, ask bootstrap peer again
                ToxNode *bootstrap_source = tox_scenario_get_node(tox_node_get_scenario(self), my_index - 1);
                uint8_t bs_pk[TOX_PUBLIC_KEY_SIZE];
                tox_self_get_dht_id(tox_node_get_tox(bootstrap_source), bs_pk);
                Tox_Err_Get_Port port_err;
                uint16_t bs_port = tox_self_get_udp_port(tox_node_get_tox(bootstrap_source), &port_err);

                for (int i = 0; i < NUM_TOXES; ++i) {
                    tox_dht_send_nodes_request(tox_node_get_tox(self), bs_pk, "127.0.0.1", bs_port, state->public_key_list[i], nullptr);
                }
            }
        }

        if (now - last_log_time >= 5000) {
            last_log_time = now;
            tox_node_log(self, "Still crawling... found %zu/%d nodes", state->num_nodes, NUM_TOXES);
            if (state->num_nodes < NUM_TOXES) {
                char missing[256] = {0};
                size_t pos = 0;
                for (int i = 0; i < NUM_TOXES; ++i) {
                    if (!node_crawled(state, state->public_key_list[i])) {
                        pos += snprintf(missing + pos, sizeof(missing) - pos, "%d ", i);
                        if (pos >= sizeof(missing) - 1) {
                            break;
                        }
                    }
                }
                tox_node_log(self, "Missing nodes: %s", missing);
            }
        }
    }

    tox_node_log(self, "Finished crawling all %u nodes.", (unsigned int)state->num_nodes);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    State *states = (State *)calloc(NUM_TOXES, sizeof(State));

    ToxNode *nodes[NUM_TOXES];

    for (uint32_t i = 0; i < NUM_TOXES; ++i) {
        char alias[32];
        snprintf(alias, sizeof(alias), "Peer-%u", i);
        nodes[i] = tox_scenario_add_node(s, alias, peer_script, &states[i], sizeof(State));
    }

    // Fill the public_key_list for all nodes
    uint8_t public_keys[NUM_TOXES][TOX_PUBLIC_KEY_SIZE];
    for (uint32_t i = 0; i < NUM_TOXES; ++i) {
        tox_self_get_dht_id(tox_node_get_tox(nodes[i]), public_keys[i]);
    }

    for (uint32_t i = 0; i < NUM_TOXES; ++i) {
        memcpy(states[i].public_key_list, public_keys, sizeof(public_keys));
    }

    // Create a linear graph
    for (uint32_t i = 1; i < NUM_TOXES; ++i) {
        tox_node_bootstrap(nodes[i], nodes[i - 1]);
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %u\n", res);
        return 1;
    }

    for (uint32_t i = 0; i < NUM_TOXES; ++i) {
        for (size_t j = 0; j < states[i].num_nodes; ++j) {
            free(states[i].nodes[j]);
        }
    }

    free(states);
    tox_scenario_free(s);
    return 0;
}

#undef NUM_TOXES
