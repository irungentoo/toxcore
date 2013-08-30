/* DHT boostrap
 *
 * A simple DHT boostrap server for tox.
 *
 * Build commands (use one or the other):
 *                gcc -O2 -Wall -D VANILLA_NACL -o bootstrap_server ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/Messenger.c ../core/DHT.c ../core/friend_requests.c ../nacl/build/${HOSTNAME%.*}/lib/amd64/{cpucycles.o,libnacl.a,randombytes.o} DHT_bootstrap.c
 *
 *                gcc -O2 -Wall -o bootstrap_server ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/Messenger.c ../core/DHT.c ../core/friend_requests.c -lsodium DHT_bootstrap.c
 *
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

#include "../toxcore/DHT.h"
#include "../toxcore/friend_requests.h"
#include "../testing/misc_tools.c"

/* Sleep function (x = milliseconds) */
#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define PORT 33445



void manage_keys(DHT *dht)
{
    const uint32_t KEYS_SIZE = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
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

        load_keys(dht->c, keys);
        printf("Keys loaded successfully.\n");
    } else {
        new_keys(dht->c);
        save_keys(dht->c, keys);
        keys_file = fopen("key", "w");

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
    /* Initialize networking -
       Bind to ip 0.0.0.0:PORT */
    IP ip;
    ip.uint32 = 0;
    DHT *dht = new_DHT(new_net_crypto(new_networking(ip, PORT)));
    manage_keys(dht);
    printf("Public key: ");
    uint32_t i;

    FILE *file;
    file = fopen("PUBLIC_ID.txt", "w");

    for (i = 0; i < 32; i++) {
        if (dht->c->self_public_key[i] < 16)
            printf("0");

        printf("%hhX", dht->c->self_public_key[i]);
        fprintf(file, "%hhX", dht->c->self_public_key[i]);
    }

    fclose(file);

    printf("\n");
    printf("Port: %u\n", PORT);

    perror("Initialization.");

    if (argc > 3) {
        printf("Trying to bootstrap into the network...\n");
        IP_Port bootstrap_info;
        bootstrap_info.ip.uint32 = inet_addr(argv[1]);
        bootstrap_info.port = htons(atoi(argv[2]));
        uint8_t *bootstrap_key = hex_string_to_bin(argv[3]);
        DHT_bootstrap(dht, bootstrap_info, bootstrap_key);
        free(bootstrap_key);
    }

    int is_waiting_for_dht_connection = 1;

    while (1) {
        if (is_waiting_for_dht_connection && DHT_isconnected(dht)) {
            printf("Connected to other bootstrap server successfully.\n");
            is_waiting_for_dht_connection = 0;
        }

        do_DHT(dht);

        networking_poll(dht->c->lossless_udp->net);

        c_sleep(1);
    }

    return 0;
}
