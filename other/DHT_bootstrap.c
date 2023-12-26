/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * DHT bootstrap
 *
 * A simple DHT boostrap node for tox.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/DHT.h"
#include "../toxcore/LAN_discovery.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/group_announce.h"
#include "../toxcore/group_onion_announce.h"
#include "../toxcore/logger.h"
#include "../toxcore/mem.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/onion.h"
#include "../toxcore/onion_announce.h"
#include "../toxcore/tox.h"

#define TCP_RELAY_ENABLED

#ifdef TCP_RELAY_ENABLED
#include "../toxcore/TCP_server.h"
#endif

#include "../testing/misc_tools.h"

#define DHT_NODE_EXTRA_PACKETS

#ifdef DHT_NODE_EXTRA_PACKETS
#include "./bootstrap_node_packets.h"

#ifndef DAEMON_VERSION_NUMBER
#define DAEMON_VERSION_NUMBER (1000000000UL + TOX_VERSION_MAJOR*1000000UL + TOX_VERSION_MINOR*1000UL + TOX_VERSION_PATCH*1UL)
#endif

static const char *motd_str = ""; //Change this to anything within 256 bytes(but 96 bytes maximum prefered)
#endif

#define PORT 33445


static bool manage_keys(DHT *dht)
{
    enum { KEYS_SIZE = CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE };
    uint8_t keys[KEYS_SIZE];

    FILE *keys_file = fopen("key", "rb");

    if (keys_file != nullptr) {
        /* If file was opened successfully -- load keys,
           otherwise save new keys */
        size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (read_size != KEYS_SIZE) {
            printf("Error while reading the key file\nExiting.\n");
            fclose(keys_file);
            return false;
        }

        dht_set_self_public_key(dht, keys);
        dht_set_self_secret_key(dht, keys + CRYPTO_PUBLIC_KEY_SIZE);
        printf("Keys loaded successfully.\n");
    } else {
        memcpy(keys, dht_get_self_public_key(dht), CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(keys + CRYPTO_PUBLIC_KEY_SIZE, dht_get_self_secret_key(dht), CRYPTO_SECRET_KEY_SIZE);
        keys_file = fopen("key", "wb");

        if (keys_file == nullptr) {
            printf("Error opening key file in write mode.\nKeys will not be saved.\n");
            return false;
        }

        if (fwrite(keys, sizeof(uint8_t), KEYS_SIZE, keys_file) != KEYS_SIZE) {
            printf("Error while writing the key file.\nExiting.\n");
            fclose(keys_file);
            return false;
        }

        printf("Keys saved successfully.\n");
    }

    fclose(keys_file);
    return true;
}

static const char *strlevel(Logger_Level level)
{
    switch (level) {
        case LOGGER_LEVEL_TRACE:
            return "TRACE";

        case LOGGER_LEVEL_DEBUG:
            return "DEBUG";

        case LOGGER_LEVEL_INFO:
            return "INFO";

        case LOGGER_LEVEL_WARNING:
            return "WARNING";

        case LOGGER_LEVEL_ERROR:
            return "ERROR";

        default:
            return "<unknown>";
    }
}

static void print_log(void *context, Logger_Level level, const char *file, int line,
                      const char *func, const char *message, void *userdata)
{
    fprintf(stderr, "[%s] %s:%d(%s) %s\n", strlevel(level), file, line, func, message);
}

int main(int argc, char *argv[])
{
    if (argc == 2 && !tox_strncasecmp(argv[1], "-h", 3)) {
        printf("Usage (connected)  : %s [--ipv4|--ipv6] IP PORT KEY\n", argv[0]);
        printf("Usage (unconnected): %s [--ipv4|--ipv6]\n", argv[0]);
        return 0;
    }

    /* let user override default by cmdline */
    bool ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        return 1;
    }

    /* Initialize networking -
       Bind to ip 0.0.0.0 / [::] : PORT */
    IP ip;
    ip_init(&ip, ipv6enabled);

    Logger *logger = logger_new();

    if (MIN_LOGGER_LEVEL <= LOGGER_LEVEL_DEBUG) {
        logger_callback_log(logger, print_log, nullptr, nullptr);
    }

    const Random *rng = system_random();
    const Network *ns = system_network();
    const Memory *mem = system_memory();

    Mono_Time *mono_time = mono_time_new(mem, nullptr, nullptr);
    const uint16_t start_port = PORT;
    const uint16_t end_port = start_port + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM);
    DHT *dht = new_dht(logger, mem, rng, ns, mono_time, new_networking_ex(logger, mem, ns, &ip, start_port, end_port, nullptr), true, true);
    Onion *onion = new_onion(logger, mem, mono_time, rng, dht);
    Forwarding *forwarding = new_forwarding(logger, rng, mono_time, dht);
    GC_Announces_List *gc_announces_list = new_gca_list();
    Onion_Announce *onion_a = new_onion_announce(logger, mem, rng, mono_time, dht);

#ifdef DHT_NODE_EXTRA_PACKETS
    bootstrap_set_callbacks(dht_get_net(dht), (uint32_t)DAEMON_VERSION_NUMBER, (const uint8_t *) motd_str, strlen(motd_str)+1);
#endif

    if (!(onion && forwarding && onion_a)) {
        printf("Something failed to initialize.\n");
        return 1;
    }

    gca_onion_init(gc_announces_list, onion_a);

    perror("Initialization");

    if (!manage_keys(dht)) {
        return 1;
    }
    printf("Public key: ");

#ifdef TCP_RELAY_ENABLED
#define NUM_PORTS 3
    uint16_t ports[NUM_PORTS] = {443, 3389, PORT};
    TCP_Server *tcp_s = new_tcp_server(logger, mem, rng, ns, ipv6enabled, NUM_PORTS, ports, dht_get_self_secret_key(dht), onion, forwarding);

    if (tcp_s == nullptr) {
        printf("TCP server failed to initialize.\n");
        return 1;
    }

#endif

    const char *const public_id_filename = "PUBLIC_ID.txt";
    FILE *file = fopen(public_id_filename, "w");

    if (file == nullptr) {
        printf("Could not open file \"%s\" for writing. Exiting...\n", public_id_filename);
        return 1;
    }

    for (uint32_t i = 0; i < 32; ++i) {
        const uint8_t *const self_public_key = dht_get_self_public_key(dht);
        printf("%02X", self_public_key[i]);
        fprintf(file, "%02X", self_public_key[i]);
    }

    fclose(file);

    printf("\n");
    printf("Port: %u\n", net_ntohs(net_port(dht_get_net(dht))));

    if (argc > argvoffset + 3) {
        printf("Trying to bootstrap into the network...\n");

        const long int port_conv = strtol(argv[argvoffset + 2], nullptr, 10);

        if (port_conv <= 0 || port_conv > UINT16_MAX) {
            printf("Failed to convert \"%s\" into a valid port. Exiting...\n", argv[argvoffset + 2]);
            return 1;
        }

        const uint16_t port = net_htons((uint16_t)port_conv);

        uint8_t *bootstrap_key = hex_string_to_bin(argv[argvoffset + 3]);
        int res = dht_bootstrap_from_address(dht, argv[argvoffset + 1],
                                             ipv6enabled, port, bootstrap_key);
        free(bootstrap_key);

        if (!res) {
            printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
            return 1;
        }
    }

    int is_waiting_for_dht_connection = 1;

    uint64_t last_lan_discovery = 0;
    const Broadcast_Info *broadcast = lan_discovery_init(ns);

    while (1) {
        mono_time_update(mono_time);

        if (is_waiting_for_dht_connection && dht_isconnected(dht)) {
            printf("Connected to other bootstrap node successfully.\n");
            is_waiting_for_dht_connection = 0;
        }

        do_dht(dht);

        if (mono_time_is_timeout(mono_time, last_lan_discovery, is_waiting_for_dht_connection ? 5 : LAN_DISCOVERY_INTERVAL)) {
            lan_discovery_send(dht_get_net(dht), broadcast, dht_get_self_public_key(dht), net_htons(PORT));
            last_lan_discovery = mono_time_get(mono_time);
        }

#ifdef TCP_RELAY_ENABLED
        do_tcp_server(tcp_s, mono_time);
#endif
        networking_poll(dht_get_net(dht), nullptr);

        c_sleep(1);
    }
}
