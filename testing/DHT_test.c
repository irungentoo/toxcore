/* DHT test
 * A file with a main that runs our DHT for testing.
 *
 * Compile with: gcc -O2 -Wall -D VANILLA_NACL -o test ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/Messenger.c ../nacl/build/${HOSTNAME%.*}/lib/amd64/{cpucycles.o,libnacl.a,randombytes.o} DHT_test.c
 *
 * Command line arguments are the ip, port and public key of a node.
 * EX: ./test 127.0.0.1 33445 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 *
 * The test will then ask you for the id (in hex format) of the friend you wish to add
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

//#include "../core/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/friend_requests.h"
#include "misc_tools.c"

#include <string.h>

//Sleep function (x = milliseconds)
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

#define PORT 33445

uint8_t zeroes_cid[CLIENT_ID_SIZE];

void print_client_id(uint8_t *client_id)
{
    uint32_t j;

    for (j = 0; j < CLIENT_ID_SIZE; j++) {
        printf("%02hhX", client_id[j]);
    }
}

void print_hardening(Hardening *h)
{
    printf("Hardening:\n");
    printf("routes_requests_ok: %hhu\n", h->routes_requests_ok);
    printf("routes_requests_timestamp: %llu\n", (long long unsigned int)h->routes_requests_timestamp);
    printf("routes_requests_pingedid: ");
    print_client_id(h->routes_requests_pingedid);
    printf("\nsend_nodes_ok: %hhu\n", h->send_nodes_ok);
    printf("send_nodes_timestamp: %llu\n", (long long unsigned int)h->send_nodes_timestamp);
    printf("send_nodes_pingedid: ");
    print_client_id(h->send_nodes_pingedid);
    printf("\ntesting_requests: %hhu\n", h->testing_requests);
    printf("testing_timestamp: %llu\n", (long long unsigned int)h->testing_timestamp);
    printf("testing_pingedid: ");
    print_client_id(h->testing_pingedid);
    printf("\n\n");
}

void print_assoc(IPPTsPng *assoc, uint8_t ours)
{
    IP_Port *ipp = &assoc->ip_port;
    printf("\nIP: %s Port: %u", ip_ntoa(&ipp->ip), ntohs(ipp->port));
    printf("\nTimestamp: %llu", (long long unsigned int) assoc->timestamp);
    printf("\nLast pinged: %llu\n", (long long unsigned int) assoc->last_pinged);

    ipp = &assoc->ret_ip_port;

    if (ours)
        printf("OUR IP: %s Port: %u\n", ip_ntoa(&ipp->ip), ntohs(ipp->port));
    else
        printf("RET IP: %s Port: %u\n", ip_ntoa(&ipp->ip), ntohs(ipp->port));

    printf("Timestamp: %llu\n", (long long unsigned int) assoc->ret_timestamp);
    print_hardening(&assoc->hardening);

}

void print_clientlist(DHT *dht)
{
    uint32_t i;
    printf("___________________CLOSE________________________________\n");

    for (i = 0; i < LCLIENT_LIST; i++) {
        Client_data *client = &dht->close_clientlist[i];

        if (memcmp(client->client_id, zeroes_cid, CLIENT_ID_SIZE) == 0)
            continue;

        printf("ClientID: ");
        print_client_id(client->client_id);

        print_assoc(&client->assoc4, 1);
        print_assoc(&client->assoc6, 1);
    }
}

void print_friendlist(DHT *dht)
{
    uint32_t i, k;
    IP_Port p_ip;
    printf("_________________FRIENDS__________________________________\n");

    for (k = 0; k < dht->num_friends; k++) {
        printf("FRIEND %u\n", k);
        printf("ID: ");

        print_client_id(dht->friends_list[k].client_id);

        int friendok = DHT_getfriendip(dht, dht->friends_list[k].client_id, &p_ip);
        printf("\nIP: %s:%u (%d)", ip_ntoa(&p_ip.ip), ntohs(p_ip.port), friendok);

        printf("\nCLIENTS IN LIST:\n\n");

        for (i = 0; i < MAX_FRIEND_CLIENTS; i++) {
            Client_data *client = &dht->friends_list[k].client_list[i];

            if (memcmp(client->client_id, zeroes_cid, CLIENT_ID_SIZE) == 0)
                continue;

            printf("ClientID: ");
            print_client_id(client->client_id);

            print_assoc(&client->assoc4, 0);
            print_assoc(&client->assoc6, 0);
        }
    }
}

void printpacket(uint8_t *data, uint32_t length, IP_Port ip_port)
{
    uint32_t i;
    printf("UNHANDLED PACKET RECEIVED\nLENGTH:%u\nCONTENTS:\n", length);
    printf("--------------------BEGIN-----------------------------\n");

    for (i = 0; i < length; i++) {
        if (data[i] < 16)
            printf("0");

        printf("%hhX", data[i]);
    }

    printf("\n--------------------END-----------------------------\n\n\n");
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Usage: %s [--ipv4|--ipv6] ip port public_key\n", argv[0]);
        exit(0);
    }

    /* let user override default by cmdline */
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0)
        exit(1);

    //memcpy(self_client_id, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 32);
    /* initialize networking */
    /* bind to ip 0.0.0.0:PORT */
    IP ip;
    ip_init(&ip, ipv6enabled);

    DHT *dht = new_DHT(new_networking(ip, PORT));
    printf("OUR ID: ");
    uint32_t i;

    for (i = 0; i < 32; i++) {
        if (dht->self_public_key[i] < 16)
            printf("0");

        printf("%hhX", dht->self_public_key[i]);
    }

    char temp_id[128];
    printf("\nEnter the client_id of the friend you wish to add (32 bytes HEX format):\n");

    if (!fgets(temp_id, sizeof(temp_id), stdin))
        exit(0);

    if ((strlen(temp_id) > 0) && (temp_id[strlen(temp_id) - 1] == '\n'))
        temp_id[strlen(temp_id) - 1] = '\0';

    uint8_t *bin_id = hex_string_to_bin(temp_id);
    DHT_addfriend(dht, bin_id);
    free(bin_id);

    perror("Initialization");

    uint16_t port = htons(atoi(argv[argvoffset + 2]));
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = DHT_bootstrap_from_address(dht, argv[argvoffset + 1], ipv6enabled, port, binary_string);
    free(binary_string);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        return 1;
    }

    /*
        IP_Port ip_port;
        uint8_t data[MAX_UDP_PACKET_SIZE];
        uint32_t length;
    */

    while (1) {

        do_DHT(dht);

        /* slvrTODO:
                while(receivepacket(&ip_port, data, &length) != -1) {
                    if(DHT_handlepacket(data, length, ip_port) && friendreq_handlepacket(data, length, ip_port)) {
                        //unhandled packet
                        printpacket(data, length, ip_port);
                    } else {
                        printf("Received handled packet with length: %u\n", length);
                    }
                }
        */
        networking_poll(dht->net);

        print_clientlist(dht);
        print_friendlist(dht);
        c_sleep(300);
    }

    return 0;
}
