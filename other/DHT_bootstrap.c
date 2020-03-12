/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * DHT bootstrap
 *
 * A simple DHT boostrap node for tox.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/DHT.h"
#include "../toxcore/LAN_discovery.h"
#include "../toxcore/friend_requests.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#define TCP_RELAY_ENABLED

#ifdef TCP_RELAY_ENABLED
#include "../toxcore/TCP_server.h"
#endif

#include "../testing/misc_tools.h"

#ifdef DHT_NODE_EXTRA_PACKETS
#include "./bootstrap_node_packets.h"

#define DHT_VERSION_NUMBER 1
#define DHT_MOTD "This is a test motd"
#endif

#define PORT 33445


static void manage_keys(DHT *dht)
{
    enum { KEYS_SIZE = CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE };
    uint8_t keys[KEYS_SIZE];

    FILE *keys_file = fopen("key", "r");

    if (keys_file != nullptr) {
        /* If file was opened successfully -- load keys,
           otherwise save new keys */
        size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (read_size != KEYS_SIZE) {
            printf("Error while reading the key file\nExiting.\n");
            exit(1);
        }

        dht_set_self_public_key(dht, keys);
        dht_set_self_secret_key(dht, keys + CRYPTO_PUBLIC_KEY_SIZE);
        printf("Keys loaded successfully.\n");
    } else {
        memcpy(keys, dht_get_self_public_key(dht), CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(keys + CRYPTO_PUBLIC_KEY_SIZE, dht_get_self_secret_key(dht), CRYPTO_SECRET_KEY_SIZE);
        keys_file = fopen("key", "w");

        if (keys_file == nullptr) {
            printf("Error opening key file in write mode.\nKeys will not be saved.\n");
            return;
        }

        if (fwrite(keys, sizeof(uint8_t), KEYS_SIZE, keys_file) != KEYS_SIZE) {
            printf("Error while writing the key file.\nExiting.\n");
            exit(1);
        }

        printf("Keys saved successfully.\n");
    }

    fclose(keys_file);
}

static void print_log(void *context, Logger_Level level, const char *file, int line,
                      const char *func, const char *message, void *userdata)
{
    const char *strlevel;

    switch (level) {
        case LOGGER_LEVEL_TRACE:
            strlevel = "TRACE";
            break;

        case LOGGER_LEVEL_DEBUG:
            strlevel = "DEBUG";
            break;

        case LOGGER_LEVEL_INFO:
            strlevel = "INFO";
            break;

        case LOGGER_LEVEL_WARNING:
            strlevel = "WARNING";
            break;

        case LOGGER_LEVEL_ERROR:
            strlevel = "ERROR";
            break;

        default:
            strlevel = "<unknown>";
            break;
    }

    fprintf(stderr, "[%s] %s:%d(%s) %s\n", strlevel, file, line, func, message);
}

int main(int argc, char *argv[])
{
    if (argc == 2 && !tox_strncasecmp(argv[1], "-h", 3)) {
        printf("Usage (connected)  : %s [--ipv4|--ipv6] IP PORT KEY\n", argv[0]);
        printf("Usage (unconnected): %s [--ipv4|--ipv6]\n", argv[0]);
        exit(0);
    }

    /* let user override default by cmdline */
    bool ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        exit(1);
    }

    /* Initialize networking -
       Bind to ip 0.0.0.0 / [::] : PORT */
    IP ip;
    ip_init(&ip, ipv6enabled);

    Logger *logger = logger_new();

    if (MIN_LOGGER_LEVEL == LOGGER_LEVEL_TRACE || MIN_LOGGER_LEVEL == LOGGER_LEVEL_DEBUG) {
        logger_callback_log(logger, print_log, nullptr, nullptr);
    }

    Mono_Time *mono_time = mono_time_new();
    DHT *dht = new_dht(logger, mono_time, new_networking(logger, ip, PORT), true);
    Onion *onion = new_onion(mono_time, dht);
    Onion_Announce *onion_a = new_onion_announce(mono_time, dht);

#ifdef DHT_NODE_EXTRA_PACKETS
    bootstrap_set_callbacks(dht_get_net(dht), DHT_VERSION_NUMBER, DHT_MOTD, sizeof(DHT_MOTD));
#endif

    if (!(onion && onion_a)) {
        printf("Something failed to initialize.\n");
        exit(1);
    }

    perror("Initialization");

    manage_keys(dht);
    printf("Public key: ");
    uint32_t i;

#ifdef TCP_RELAY_ENABLED
#define NUM_PORTS 3
    uint16_t ports[NUM_PORTS] = {443, 3389, PORT};
    TCP_Server *tcp_s = new_TCP_server(ipv6enabled, NUM_PORTS, ports, dht_get_self_secret_key(dht), onion);

    if (tcp_s == nullptr) {
        printf("TCP server failed to initialize.\n");
        exit(1);
    }

#endif

    const char *const public_id_filename = "PUBLIC_ID.txt";
    FILE *file = fopen(public_id_filename, "w");

    if (file == nullptr) {
        printf("Could not open file \"%s\" for writing. Exiting...\n", public_id_filename);
        exit(1);
    }

    for (i = 0; i < 32; i++) {
        const uint8_t *const self_public_key = dht_get_self_public_key(dht);
        printf("%02X", self_public_key[i]);
        fprintf(file, "%02X", self_public_key[i]);
    }

    fclose(file);

    printf("\n");
    printf("Port: %u\n", net_ntohs(net_port(dht_get_net(dht))));

    if (argc > argvoffset + 3) {
        printf("Trying to bootstrap into the network...\n");
        uint16_t port = net_htons(atoi(argv[argvoffset + 2]));
        uint8_t *bootstrap_key = hex_string_to_bin(argv[argvoffset + 3]);
        int res = dht_bootstrap_from_address(dht, argv[argvoffset + 1],
                                             ipv6enabled, port, bootstrap_key);
        free(bootstrap_key);

        if (!res) {
            printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
            exit(1);
        }
    }

    int is_waiting_for_dht_connection = 1;

    uint64_t last_LANdiscovery = 0;
    lan_discovery_init(dht);

    while (1) {
        mono_time_update(mono_time);

        if (is_waiting_for_dht_connection && dht_isconnected(dht)) {
            printf("Connected to other bootstrap node successfully.\n");
            is_waiting_for_dht_connection = 0;
        }

        do_dht(dht);

        if (mono_time_is_timeout(mono_time, last_LANdiscovery, is_waiting_for_dht_connection ? 5 : LAN_DISCOVERY_INTERVAL)) {
            lan_discovery_send(net_htons(PORT), dht);
            last_LANdiscovery = mono_time_get(mono_time);
        }

#ifdef TCP_RELAY_ENABLED
        do_TCP_server(tcp_s, mono_time);
#endif
        networking_poll(dht_get_net(dht), nullptr);

        c_sleep(1);
    }
}
