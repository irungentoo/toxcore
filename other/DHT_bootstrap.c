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

#include "../core/DHT.h"
#include "../core/friend_requests.h"
#include "../core/misc_tools.h"

//Sleep function (x = milliseconds)
#ifdef WIN32
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define PORT 33445



void manage_keys()
{
    const uint32_t KEYS_SIZE = crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint8_t keys[KEYS_SIZE];

    FILE *keys_file = fopen("key", "r");
    if (keys_file != NULL) {
        //if file was opened successfully -- load keys
        size_t read_size = fread(keys, sizeof(uint8_t), KEYS_SIZE, keys_file);
        if (read_size != KEYS_SIZE) {
            printf("Error while reading the key file\nExiting.\n");
            exit(1);
        }
        load_keys(keys);
        printf("Keys loaded successfully\n");
    } else {
        //otherwise save new keys
        new_keys();
        save_keys(keys);
        keys_file = fopen("key", "w");
        if (fwrite(keys, sizeof(uint8_t), KEYS_SIZE, keys_file) != KEYS_SIZE) {
            printf("Error while writing the key file.\nExiting.\n");
            exit(1);
        }
        printf("Keys saved successfully\n");
    }

    fclose(keys_file);
}

int main(int argc, char *argv[])
{
    manage_keys();
    printf("Public key: ");
    uint32_t i;
    for(i = 0; i < 32; i++)
    {
        if(self_public_key[i] < 16)
            printf("0");
        printf("%hhX",self_public_key[i]);
    }
    printf("\n");
    printf("Port: %u\n", PORT);
    //initialize networking
    //bind to ip 0.0.0.0:PORT
    IP ip;
    ip.i = 0;
    init_networking(ip, PORT);

    perror("Initialization");

    if (argc > 3) {
        printf("Trying to bootstrap into the network...\n");
        IP_Port bootstrap_info;
        bootstrap_info.ip.i = inet_addr(argv[1]);
        bootstrap_info.port = htons(atoi(argv[2]));
        uint8_t *bootstrap_key = hex_string_to_bin(argv[3]);
        DHT_bootstrap(bootstrap_info, bootstrap_key);
        free(bootstrap_key);
    }

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    int is_waiting_for_dht_connection = 1;
    while(1)
    {
        if (is_waiting_for_dht_connection && DHT_isconnected())
        {
            printf("Connected to other bootstrap server successfully.\n");
            is_waiting_for_dht_connection = 0;
        }
        doDHT();

        while(receivepacket(&ip_port, data, &length) != -1)
        {
            DHT_handlepacket(data, length, ip_port);
            friendreq_handlepacket(data, length, ip_port);
        }
        c_sleep(1);
    }
    shutdown_networking();
    return 0;
}
