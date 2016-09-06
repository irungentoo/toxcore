/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/* Basic group chats testing */

#include "../../toxcore/DHT.h"
#include "../../toxcore/network.h"
#include "../../toxcore/ping.h"
#include "../../toxcore/util.h"
#include "../../toxcore/Messenger.h"
#include "../misc_tools.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#define PEERCOUNT       20

static void on_group_peer_join(Messenger *m, uint32_t groupnumber, uint32_t peernumber, void *userdata)
{
    GC_Chat *ct = gc_get_group(m->group_handler, groupnumber);
    printf("Number of peers in the chat: %u\n", ct->numpeers);
}

int main(int argc, char *argv[])
{
    /* Set ip to IPv6 loopback. TODO: IPv4 fallback? */
    IP localhost;
    ip_init(&localhost, 1);
    localhost.ip.v6.uint8[15] = 1;
    Messenger_Options options = {0};
    options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;

    uint32_t index[PEERCOUNT];
    Mono_Time *mono_times[PEERCOUNT];
    Messenger *tox[PEERCOUNT];
    Mono_Time *mono_time = mono_time_new();
    Messenger *chat = new_messenger(mono_time, &options, nullptr);
    assert(chat != nullptr);

    for (int i = 0; i < PEERCOUNT; ++i) {
        options.log_callback = (logger_cb *)print_debug_log;
        options.log_context = tox[i];
        options.log_user_data = &index[i];

        index[i] = i + 1;
        mono_times[i] = mono_time_new();
        tox[i] = new_messenger(mono_times[i], &options, nullptr);
        assert(tox[i] != nullptr);
    }

    printf("%s\n", id_toa(dht_get_self_public_key(tox[0]->dht)));
    IP_Port ip_port;
    ip_copy(&ip_port.ip, &localhost);
    ip_port.port = net_port(dht_get_net(tox[0]->dht));
    char buf[IP_NTOA_LEN];
    printf("%s\n", ip_ntoa(&ip_port.ip, buf, sizeof(buf)));
    printf("%d\n", ip_port.port);

    printf("Bootstrapping from node\n");

    for (int i = 1; i < PEERCOUNT; ++i) {
        dht_bootstrap(tox[0]->dht, ip_port, dht_get_self_public_key(tox[0]->dht));
    }

    dht_bootstrap(chat->dht, ip_port, dht_get_self_public_key(tox[0]->dht));

    printf("Waiting until every Tox is connected\n");

    while (true) {
        for (int i = 0; i < PEERCOUNT; ++i) {
            do_messenger(tox[i], nullptr);
        }

        do_messenger(chat, nullptr);

        int numconnected = 0;

        for (int i = 0; i < PEERCOUNT; ++i) {
            numconnected += dht_isconnected(tox[i]->dht);
        }

#if 0
        printf("%d\n", numconnected);
#endif

        if (numconnected > PEERCOUNT * min_s32(PEERCOUNT - 1, LCLIENT_LIST)) {
            break;
        }

        /* TODO: busy wait might be slightly more efficient here */
        c_sleep(50); /* millis */
    }

    printf("Network is connected\n");

    chat->group_handler = new_dht_groupchats(chat);
    int groupnumber = gc_group_add(chat->group_handler, 0, (const uint8_t *)"Test", 4);

    if (groupnumber < 0) {
        printf("Cannot create group\n");
    }

    GC_Chat *ct = gc_get_group(chat->group_handler, groupnumber);
    printf("CHAT ENC: %s\n CHAT SIG: %s\n", id_toa(get_enc_key(ct->chat_public_key)),
           id_toa(get_sig_pk(ct->chat_public_key)));

    gc_callback_peer_join(chat, on_group_peer_join, nullptr);

    while (true) {
        for (int i = 0; i < PEERCOUNT; ++i) {
            do_messenger(tox[i], nullptr);
        }

        do_messenger(chat, nullptr);
        c_sleep(500); /* millis */
    }
}
