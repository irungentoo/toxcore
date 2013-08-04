/* Messenger test
 * 
 * This program adds a friend and accepts all friend requests with the proper message.
 * 
 * It tries sending a message to the added friend.
 * 
 * If it recieves a message from a friend it replies back.
 * 
 * 
 * This is how I compile it: gcc -O2 -Wall -D VANILLA_NACL -o test ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/messenger.c ../core/state.c ../core/friends.c ../core/DHT.c ../nacl/build/${HOSTNAME%.*}/lib/amd64/{cpucycles.o,libnacl.a,randombytes.o} Messenger_test.c
 *
 * 
 * Command line arguments are the ip, port and public_key of a node (for bootstrapping).
 * 
 * EX: ./test 127.0.0.1 33445 CDCFD319CE3460824B33BE58FD86B8941C9585181D8FBD7C79C5721D7C2E9F7C
 * 
 * Or the argument can be the path to the save file.
 * 
 * EX: ./test Save.bak
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

#include "../core/messenger.h"
#include "../core/state.h"
#include "misc_tools.h"

#ifdef WIN32

#define c_sleep(x) Sleep(1*x)

#else
#include <unistd.h>
#include <arpa/inet.h>
#define c_sleep(x) usleep(1000*x)

#endif

void print_request(uint8_t * public_key, uint8_t * data, uint16_t length)
{
    printf("Friend request recieved from: \n");
    printf("ClientID: ");
    uint32_t j;
    for(j = 0; j < 32; j++)
    {
        if(public_key[j] < 16)
            printf("0");
        printf("%hhX", public_key[j]);
    }
    printf("\nOf length: %u with data: %s \n", length, data);
    
    if(length != sizeof("Install Gentoo"))
    {
        return;
    }
    if(memcmp(data , "Install Gentoo", sizeof("Install Gentoo")) == 0 )
    //if the request contained the message of peace the person is obviously a friend so we add him.
    {
        printf("Friend request accepted.\n");
        add_friend_norequest(public_key);
    }
}

void print_message(int friendnumber, uint8_t * string, uint16_t length)
{
    printf("Message with length %u recieved from %u: %s \n", length, friendnumber, string);
    send_message(friendnumber, (uint8_t*)"Test1", 6);
}

int main(int argc, char *argv[])
{
    if (argc < 4 && argc != 2) {
        printf("usage %s ip port public_key (of the DHT bootstrap node)\n or\n %s Save.bak\n", argv[0], argv[0]);
        exit(0);
    }
    init_tox();
    if(argc > 3) {
        IP_Port bootstrap_ip_port;
        bootstrap_ip_port.port = htons(atoi(argv[2]));
        bootstrap_ip_port.ip.i = inet_addr(argv[1]);
        DHT_bootstrap(bootstrap_ip_port, hex_string_to_bin(argv[3]));
    } else {
        FILE *file = fopen(argv[1], "rb");
        if ( file==NULL ){return 1;}
        int read;
        uint8_t buffer[128000];
        read = fread(buffer, 1, 128000, file);
        printf("Messenger loaded: %i\n", load_tox_state(buffer, read));
        fclose(file);
        
    }

    friend_add_request_callback(print_request);
    message_receive_callback(print_message);
    
    printf("OUR ID: ");
    uint32_t i;
    for(i = 0; i < 32; i++) {
        if(self_public_key[i] < 16)
            printf("0");
        printf("%hhX",self_public_key[i]);
    }
    
    set_self_name((uint8_t *)"Anon", 5);
    
    char temp_id[128];
    printf("\nEnter the client_id of the friend you wish to add (32 bytes HEX format):\n");
    if(scanf("%s", temp_id) != 1) {
        return 1;
    }
    int num = add_friend(hex_string_to_bin(temp_id), (uint8_t*)"Install Gentoo", sizeof("Install Gentoo"));
    
    perror("Initialization");

    while(1) {
        uint8_t name[128];
        get_friend_name(num, name);
        printf("%s\n", name);
        
        send_message(num, (uint8_t*)"Test", 5);
        process_tox();
        c_sleep(30);
        FILE *file = fopen("Save.bak", "wb");
        if ( file==NULL ){return 1;}
        uint8_t * buffer = malloc(tox_state_size());
        save_tox_state(buffer);
        fwrite(buffer, 1, tox_state_size(), file);
        free(buffer);
        fclose(file);
    }  
}
