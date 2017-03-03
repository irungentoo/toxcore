/*
 * DHT bootstrap
 *
 * A simple DHT boostrap node for tox.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _XOPEN_SOURCE 600

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../toxcore/DHT.h"
#include "../toxcore/friend_requests.h"
#include "../toxcore/LAN_discovery.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#define TCP_RELAY_ENABLED

#ifdef TCP_RELAY_ENABLED
#include "../toxcore/TCP_server.h"
#endif

#include "../testing/misc_tools.c"

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

    if (keys_file != NULL) {
        /* If file was opened successfully -- load keys,
           otherwise save new keys */
        size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);

        if (read_size != KEYS_SIZE) {
            printf("Error while reading the key file\nExiting.\n");
            exit(1);
        }

        memcpy(dht->self_public_key, keys, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(dht->self_secret_key, keys + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_SECRET_KEY_SIZE);
        printf("Keys loaded successfully.\n");
    } else {
        memcpy(keys, dht->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(keys + CRYPTO_PUBLIC_KEY_SIZE, dht->self_secret_key, CRYPTO_SECRET_KEY_SIZE);
        keys_file = fopen("key", "w");

        if (keys_file == NULL) {
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

int main(int argc, char *argv[])
{
    if (argc == 2 && !tox_strncasecmp(argv[1], "-h", 3)) {
        printf("Usage (connected)  : %s [--ipv4|--ipv6] IP PORT KEY\n", argv[0]);
        printf("Usage (unconnected): %s [--ipv4|--ipv6]\n", argv[0]);
        exit(0);
    }

    /* let user override default by cmdline */
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        exit(1);
    }

    /* Initialize networking -
       Bind to ip 0.0.0.0 / [::] : PORT */
    IP ip;
    ip_init(&ip, ipv6enabled);

    DHT *dht = new_DHT(NULL, new_networking(NULL, ip, PORT), true);
    Onion *onion = new_onion(dht);
    Onion_Announce *onion_a = new_onion_announce(dht);

#ifdef DHT_NODE_EXTRA_PACKETS
    bootstrap_set_callbacks(dht->net, DHT_VERSION_NUMBER, DHT_MOTD, sizeof(DHT_MOTD));
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
    TCP_Server *tcp_s = new_TCP_server(ipv6enabled, NUM_PORTS, ports, dht->self_secret_key, onion);

    if (tcp_s == NULL) {
        printf("TCP server failed to initialize.\n");
        exit(1);
    }

#endif

    FILE *file;
    file = fopen("PUBLIC_ID.txt", "w");

    for (i = 0; i < 32; i++) {
        printf("%02hhX", dht->self_public_key[i]);
        fprintf(file, "%02hhX", dht->self_public_key[i]);
    }

    fclose(file);

    printf("\n");
    printf("Port: %u\n", net_ntohs(dht->net->port));

    if (argc > argvoffset + 3) {
        printf("Trying to bootstrap into the network...\n");
        uint16_t port = net_htons(atoi(argv[argvoffset + 2]));
        uint8_t *bootstrap_key = hex_string_to_bin(argv[argvoffset + 3]);
        int res = DHT_bootstrap_from_address(dht, argv[argvoffset + 1],
                                             ipv6enabled, port, bootstrap_key);
        free(bootstrap_key);

        if (!res) {
            printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
            exit(1);
        }
    }

    int is_waiting_for_dht_connection = 1;

    uint64_t last_LANdiscovery = 0;
    LANdiscovery_init(dht);

    while (1) {
        if (is_waiting_for_dht_connection && DHT_isconnected(dht)) {
            printf("Connected to other bootstrap node successfully.\n");
            is_waiting_for_dht_connection = 0;
        }

        do_DHT(dht);

        if (is_timeout(last_LANdiscovery, is_waiting_for_dht_connection ? 5 : LAN_DISCOVERY_INTERVAL)) {
            send_LANdiscovery(net_htons(PORT), dht);
            last_LANdiscovery = unix_time();
        }

#ifdef TCP_RELAY_ENABLED
        do_TCP_server(tcp_s);
#endif
        networking_poll(dht->net, NULL);

        c_sleep(1);
    }
}
