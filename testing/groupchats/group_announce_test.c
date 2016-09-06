/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/* Basic group announcing testing */

#include "../../toxcore/DHT.h"
#include "../../toxcore/tox.h"
#include "../../toxcore/network.h"
#include "../../toxcore/ping.h"
#include "../../toxcore/util.h"
#include "../../toxcore/group_announce.h"
#include "../../toxcore/Messenger.h"
#include "../misc_tools.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define min(a,b) ((a)>(b)?(b):(a))

/* You can change those but be mindful */
#define PEERCOUNT       20

typedef struct Peer {
    uint32_t index;
    Mono_Time *mono_time;
    Messenger *tox;
    uint8_t pk[EXT_PUBLIC_KEY];
    uint8_t sk[EXT_SECRET_KEY];
} Peer;


static void idle_cycle(Peer *peers, int peercount, void *userdata)
{
    for (int i = 0; i < peercount; ++i) {
        do_messenger(peers[i].tox, userdata);
    }
}

static void idle_n_secs(int n, Peer *peers, int peercount, void *userdata)
{
    for (int i = 0; i < n * 1000; i += 50) { /* msecs */
        idle_cycle(peers, peercount, userdata);
        c_sleep(500); /* millis */
    }
}

static void bootstrap(Peer *peers)
{
    IP_Port *root;
    int32_t count = net_getipport("localhost", &root, TOX_SOCK_DGRAM);
    assert(count != -1);

    for (int i = 0; i < PEERCOUNT; ++i) {
        Messenger *target = peers[i >= (PEERCOUNT - 1) ? 0 : i + 1].tox;
        uint16_t bootstrap_port = net_port(dht_get_net(target->dht));
        const uint8_t *bootstrap_key = dht_get_self_public_key(target->dht);

        for (int32_t ip = 0; ip < count; ++ip) {
            root[ip].port = bootstrap_port;
            dht_bootstrap(peers[i].tox->dht, root[ip], bootstrap_key);
        }
    }

    net_freeipport(root);
}

static void basicannouncetest(void)
{
    Peer peers[PEERCOUNT];

    Messenger_Options options = {0};
    options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    options.port_range[0] = 33445;
    options.port_range[1] = 33545;

    printf("DHT public keys:\n");

    for (int i = 0; i < PEERCOUNT; ++i) {
        options.log_callback = (logger_cb *)print_debug_log;
        options.log_context = peers[i].tox;
        options.log_user_data = &peers[i].index;

        peers[i].index = i + 1;
        peers[i].mono_time = mono_time_new();
        peers[i].tox = new_messenger(peers[i].mono_time, &options, nullptr);
        create_extended_keypair(peers[i].pk, peers[i].sk);
        printf("%s, %d\n", id_toa(dht_get_self_public_key(peers[i].tox->dht)), i);
    }

    printf("Bootstrapping everybody from each other\n");
    bootstrap(peers);

    printf("Waiting until every Tox is connected\n");

    for (;;) {
        idle_cycle(peers, PEERCOUNT, nullptr);

        int numconnected = 0;

        for (int i = 0; i < PEERCOUNT; ++i) {
            numconnected += dht_isconnected(peers[i].tox->dht);
        }

        if (numconnected == PEERCOUNT * min(PEERCOUNT - 1, LCLIENT_LIST)) {
            break;
        }

        /* TODO: busy wait might be slightly more efficient here */
        c_sleep(500); /* millis */
    }

    printf("Network is connected\n");

    uint8_t group_pk[EXT_PUBLIC_KEY];
    uint8_t group_sk[EXT_SECRET_KEY];

    create_extended_keypair(group_pk, group_sk);

    int res;
    printf("Sending announce requests\n");
    res = gca_send_announce_request(peers[0].tox->group_handler->announce, peers[0].pk,
                                    peers[0].sk, group_pk);
    printf("Announced node: %s\n", id_toa(peers[0].pk));


    printf("Number of sent announce requests %d\n", res);
    idle_n_secs(10, peers, PEERCOUNT, nullptr);

    printf("Sending get announced nodes requests\n");
    res = gca_send_get_nodes_request(peers[1].tox->group_handler->announce, peers[1].pk,
                                     peers[1].sk, group_pk);
    printf("Number of sent get announced nodes requests %d\n", res);
    idle_n_secs(10, peers, PEERCOUNT, nullptr);

    printf("Getting announced nodes\n");

    GC_Announce_Node nodes[10 * 4];
    int num_nodes = gca_get_requested_nodes(peers[1].tox->group_handler->announce, group_pk, nodes);

    printf("Number of announced nodes %d\n", num_nodes);

    for (int i = 0; i < num_nodes; ++i) {
        printf("Announced node: %s\n", id_toa(nodes[i].public_key));
    }
}

int main(void)
{
    basicannouncetest();
    return 0;
}
