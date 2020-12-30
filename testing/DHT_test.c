/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/* DHT test
 * A file with a main that runs our DHT for testing.
 *
 * Compile with: gcc -O2 -Wall -D VANILLA_NACL -o test ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/Messenger.c ../nacl/build/${HOSTNAME%.*}/lib/amd64/{cpucycles.o,libnacl.a,randombytes.o} DHT_test.c
 *
 * Command line arguments are the ip, port and public key of a node.
 * EX: ./test 127.0.0.1 33445 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 *
 * The test will then ask you for the id (in hex format) of the friend you wish to add
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <arpa/inet.h>
#endif

#include "../toxcore/DHT.h"
#include "../toxcore/friend_requests.h"
#include "../toxcore/mono_time.h"
#include "misc_tools.h"

#define PORT 33445

static const uint8_t zeroes_cid[CRYPTO_PUBLIC_KEY_SIZE] = {0};

static void print_client_id(const uint8_t *public_key)
{
    uint32_t j;

    for (j = 0; j < CRYPTO_PUBLIC_KEY_SIZE; j++) {
        printf("%02X", public_key[j]);
    }
}

static void print_assoc(const IPPTsPng *assoc, uint8_t ours)
{
    const IP_Port *ipp = &assoc->ip_port;
    char ip_str[IP_NTOA_LEN];
    printf("\nIP: %s Port: %u", ip_ntoa(&ipp->ip, ip_str, sizeof(ip_str)), net_ntohs(ipp->port));
    printf("\nTimestamp: %llu", (long long unsigned int) assoc->timestamp);
    printf("\nLast pinged: %llu\n", (long long unsigned int) assoc->last_pinged);

    ipp = &assoc->ret_ip_port;

    if (ours) {
        printf("OUR IP: %s Port: %u\n", ip_ntoa(&ipp->ip, ip_str, sizeof(ip_str)), net_ntohs(ipp->port));
    } else {
        printf("RET IP: %s Port: %u\n", ip_ntoa(&ipp->ip, ip_str, sizeof(ip_str)), net_ntohs(ipp->port));
    }

    printf("Timestamp: %llu\n", (long long unsigned int) assoc->ret_timestamp);
}

static void print_clientlist(DHT *dht)
{
    uint32_t i;
    printf("___________________CLOSE________________________________\n");

    for (i = 0; i < LCLIENT_LIST; i++) {
        const Client_data *client = dht_get_close_client(dht, i);

        if (public_key_cmp(client->public_key, zeroes_cid) == 0) {
            continue;
        }

        printf("ClientID: ");
        print_client_id(client->public_key);

        print_assoc(&client->assoc4, 1);
        print_assoc(&client->assoc6, 1);
    }
}

static void print_friendlist(DHT *dht)
{
    uint32_t i, k;
    IP_Port p_ip;
    printf("_________________FRIENDS__________________________________\n");

    for (k = 0; k < dht_get_num_friends(dht); k++) {
        printf("FRIEND %u\n", k);
        printf("ID: ");

        print_client_id(dht_get_friend_public_key(dht, k));

        int friendok = dht_getfriendip(dht, dht_get_friend_public_key(dht, k), &p_ip);
        char ip_str[IP_NTOA_LEN];
        printf("\nIP: %s:%u (%d)", ip_ntoa(&p_ip.ip, ip_str, sizeof(ip_str)), net_ntohs(p_ip.port), friendok);

        printf("\nCLIENTS IN LIST:\n\n");

        for (i = 0; i < MAX_FRIEND_CLIENTS; i++) {
            const Client_data *client = dht_friend_client(dht_get_friend(dht, k), i);

            if (public_key_cmp(client->public_key, zeroes_cid) == 0) {
                continue;
            }

            printf("ClientID: ");
            print_client_id(client->public_key);

            print_assoc(&client->assoc4, 0);
            print_assoc(&client->assoc6, 0);
        }
    }
}

#if 0 /* TODO(slvr): */
static void printpacket(uint8_t *data, uint32_t length, IP_Port ip_port)
{
    uint32_t i;
    printf("UNHANDLED PACKET RECEIVED\nLENGTH:%u\nCONTENTS:\n", length);
    printf("--------------------BEGIN-----------------------------\n");

    for (i = 0; i < length; i++) {
        if (data[i] < 16) {
            printf("0");
        }

        printf("%X", data[i]);
    }

    printf("\n--------------------END-----------------------------\n\n\n");
}
#endif

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Usage: %s [--ipv4|--ipv6] ip port public_key\n", argv[0]);
        exit(0);
    }

    /* let user override default by cmdline */
    bool ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        exit(1);
    }

    //memcpy(self_client_id, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 32);
    /* initialize networking */
    /* bind to ip 0.0.0.0:PORT */
    IP ip;
    ip_init(&ip, ipv6enabled);

    Mono_Time *const mono_time = mono_time_new();
    Logger *const logger = logger_new();
    DHT *dht = new_dht(logger, mono_time, new_networking(logger, ip, PORT), true);
    printf("OUR ID: ");

    for (uint32_t i = 0; i < 32; i++) {
        const uint8_t *const self_public_key = dht_get_self_public_key(dht);

        if (self_public_key[i] < 16) {
            printf("0");
        }

        printf("%X", self_public_key[i]);
    }

    char temp_id[128];
    printf("\nEnter the public_key of the friend you wish to add (32 bytes HEX format):\n");

    if (!fgets(temp_id, sizeof(temp_id), stdin)) {
        exit(0);
    }

    if ((strlen(temp_id) > 0) && (temp_id[strlen(temp_id) - 1] == '\n')) {
        temp_id[strlen(temp_id) - 1] = '\0';
    }

    uint8_t *bin_id = hex_string_to_bin(temp_id);
    dht_addfriend(dht, bin_id, nullptr, nullptr, 0, nullptr);
    free(bin_id);

    perror("Initialization");

    uint16_t port = net_htons(atoi(argv[argvoffset + 2]));
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = dht_bootstrap_from_address(dht, argv[argvoffset + 1], ipv6enabled, port, binary_string);
    free(binary_string);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        return 1;
    }

#if 0 /* TODO(slvr): */
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
#endif

    while (1) {
        mono_time_update(mono_time);

        do_dht(dht);

#if 0 /* TODO(slvr): */

        while (receivepacket(&ip_port, data, &length) != -1) {
            if (dht_handlepacket(data, length, ip_port) && friendreq_handlepacket(data, length, ip_port)) {
                //unhandled packet
                printpacket(data, length, ip_port);
            } else {
                printf("Received handled packet with length: %u\n", length);
            }
        }

#endif
        networking_poll(dht_get_net(dht), nullptr);

        print_clientlist(dht);
        print_friendlist(dht);
        c_sleep(300);
    }
}
