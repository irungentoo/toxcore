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

//#include "../core/network.h"
#include "../toxcore/DHT.h"
#include "../toxcore/friend_requests.h"
#include "misc_tools.c"

#include <string.h>

//Sleep function (x = milliseconds)
#ifdef WIN32

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

#define PORT 33445

void print_clientlist(DHT *dht)
{
    uint32_t i, j;
    IP_Port p_ip;
    printf("___________________CLOSE________________________________\n");

    for (i = 0; i < LCLIENT_LIST; i++) {
        printf("ClientID: ");

        for (j = 0; j < CLIENT_ID_SIZE; j++) {
            printf("%02hhX", dht->close_clientlist[i].client_id[j]);
        }

        p_ip = dht->close_clientlist[i].ip_port;
        printf("\nIP: %u.%u.%u.%u Port: %u", p_ip.ip.uint8[0], p_ip.ip.uint8[1], p_ip.ip.uint8[2], p_ip.ip.uint8[3],
               ntohs(p_ip.port));
        printf("\nTimestamp: %llu", (long long unsigned int) dht->close_clientlist[i].timestamp);
        printf("\nLast pinged: %llu\n", (long long unsigned int) dht->close_clientlist[i].last_pinged);
        p_ip = dht->close_clientlist[i].ret_ip_port;
        printf("OUR IP: %u.%u.%u.%u Port: %u\n", p_ip.ip.uint8[0], p_ip.ip.uint8[1], p_ip.ip.uint8[2], p_ip.ip.uint8[3],
               ntohs(p_ip.port));
        printf("Timestamp: %llu\n", (long long unsigned int) dht->close_clientlist[i].ret_timestamp);
    }
}

void print_friendlist(DHT *dht)
{
    uint32_t i, j, k;
    IP_Port p_ip;
    printf("_________________FRIENDS__________________________________\n");

    for (k = 0; k < dht->num_friends; k++) {
        printf("FRIEND %u\n", k);
        printf("ID: ");

        for (j = 0; j < CLIENT_ID_SIZE; j++) {
            printf("%c", dht->friends_list[k].client_id[j]);
        }

        p_ip = DHT_getfriendip(dht, dht->friends_list[k].client_id);
        printf("\nIP: %u.%u.%u.%u:%u", p_ip.ip.uint8[0], p_ip.ip.uint8[1], p_ip.ip.uint8[2], p_ip.ip.uint8[3],
               ntohs(p_ip.port));

        printf("\nCLIENTS IN LIST:\n\n");

        for (i = 0; i < MAX_FRIEND_CLIENTS; i++) {
            printf("ClientID: ");

            for (j = 0; j < CLIENT_ID_SIZE; j++) {
                if (dht->friends_list[k].client_list[i].client_id[j] < 16)
                    printf("0");

                printf("%hhX", dht->friends_list[k].client_list[i].client_id[j]);
            }

            p_ip = dht->friends_list[k].client_list[i].ip_port;
            printf("\nIP: %u.%u.%u.%u:%u", p_ip.ip.uint8[0], p_ip.ip.uint8[1], p_ip.ip.uint8[2], p_ip.ip.uint8[3],
                   ntohs(p_ip.port));
            printf("\nTimestamp: %llu", (long long unsigned int) dht->friends_list[k].client_list[i].timestamp);
            printf("\nLast pinged: %llu\n", (long long unsigned int) dht->friends_list[k].client_list[i].last_pinged);
            p_ip = dht->friends_list[k].client_list[i].ret_ip_port;
            printf("ret IP: %u.%u.%u.%u:%u\n", p_ip.ip.uint8[0], p_ip.ip.uint8[1], p_ip.ip.uint8[2], p_ip.ip.uint8[3],
                   ntohs(p_ip.port));
            printf("Timestamp: %llu\n", (long long unsigned int)dht->friends_list[k].client_list[i].ret_timestamp);
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
    //memcpy(self_client_id, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 32);
    /* initialize networking */
    /* bind to ip 0.0.0.0:PORT */
    IP ip;
    ip.uint32 = 0;

    DHT *dht = new_DHT(new_net_crypto(new_networking(ip, PORT)));

    if (argc < 4) {
        printf("usage %s ip port public_key\n", argv[0]);
        exit(0);
    }

    new_keys(dht->c);
    printf("OUR ID: ");
    uint32_t i;

    for (i = 0; i < 32; i++) {
        if (dht->c->self_public_key[i] < 16)
            printf("0");

        printf("%hhX", dht->c->self_public_key[i]);
    }

    char temp_id[128];
    printf("\nEnter the client_id of the friend you wish to add (32 bytes HEX format):\n");

    if (scanf("%s", temp_id) != 1)
        exit(0);

    DHT_addfriend(dht, hex_string_to_bin(temp_id));


    perror("Initialization");
    IP_Port bootstrap_ip_port;
    bootstrap_ip_port.port = htons(atoi(argv[2]));
    /* bootstrap_ip_port.ip.c[0] = 127;
     * bootstrap_ip_port.ip.c[1] = 0;
     * bootstrap_ip_port.ip.c[2] = 0;
     * bootstrap_ip_port.ip.c[3] = 1; */
    bootstrap_ip_port.ip.uint32 = inet_addr(argv[1]);
    DHT_bootstrap(dht, bootstrap_ip_port, hex_string_to_bin(argv[3]));

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
        networking_poll(dht->c->lossless_udp->net);

        print_clientlist(dht);
        print_friendlist(dht);
        c_sleep(300);
    }

    return 0;
}
