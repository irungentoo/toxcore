/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/* Messenger test
 *
 * This program adds a friend and accepts all friend requests with the proper message.
 *
 * It tries sending a message to the added friend.
 *
 * If it receives a message from a friend it replies back.
 *
 *
 * This is how I compile it: gcc -O2 -Wall -o test ../core/Lossless_UDP.c ../core/network.c ../core/net_crypto.c ../core/Messenger.c ../core/DHT.c Messenger_test.c -lsodium
 *
 *
 * Command line arguments are the ip, port and public_key of a node (for bootstrapping).
 *
 * EX: ./test 127.0.0.1 33445 CDCFD319CE3460824B33BE58FD86B8941C9585181D8FBD7C79C5721D7C2E9F7C
 *
 * Or the argument can be the path to the save file.
 *
 * EX: ./test Save.bak
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <arpa/inet.h>
#endif

#include "../toxcore/Messenger.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/mono_time.h"
#include "misc_tools.h"

static void print_message(Messenger *m, uint32_t friendnumber, unsigned int type, const uint8_t *string, size_t length,
                          void *userdata)
{
    printf("Message with length %u received from %u: %s \n", (unsigned)length, friendnumber, string);
    m_send_message_generic(m, friendnumber, type, (const uint8_t *)"Test1", 6, nullptr);
}

/* TODO(irungentoo): needed as print_request has to match the interface expected by
 * networking_requesthandler and so cannot take a Messenger * */
static Messenger *m;

static void print_request(Messenger *m2, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    printf("Friend request received from: \n");
    printf("ClientID: ");
    uint32_t j;

    for (j = 0; j < 32; j++) {
        if (public_key[j] < 16) {
            printf("0");
        }

        printf("%hhX", public_key[j]);
    }

    printf("\nOf length: %u with data: %s \n", (unsigned)length, data);

    if (length != sizeof("Install Gentoo")) {
        return;
    }

    if (memcmp(data, "Install Gentoo", sizeof("Install Gentoo")) == 0)
        //if the request contained the message of peace the person is obviously a friend so we add him.
    {
        printf("Friend request accepted.\n");
        m_addfriend_norequest(m2, public_key);
    }
}

int main(int argc, char *argv[])
{
    /* let user override default by cmdline */
    bool ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0) {
        exit(1);
    }

    /* with optional --ipvx, now it can be 1-4 arguments... */
    if (argc != argvoffset + 4) {
        printf("Usage: %s [--ipv4|--ipv6] ip port public_key (of the DHT bootstrap node)\n", argv[0]);
        exit(0);
    }

    const Memory *mem = os_memory();
    Mono_Time *const mono_time = mono_time_new(mem, nullptr, nullptr);

    if (mono_time == nullptr) {
        fputs("Failed to allocate monotonic timer datastructure\n", stderr);
        exit(0);
    }

    Messenger_Options options = {0};
    options.ipv6enabled = ipv6enabled;
    Messenger_Error err;
    m = new_messenger(mono_time, mem, os_random(), os_network(), &options, &err);

    if (!m) {
        fprintf(stderr, "Failed to allocate messenger datastructure: %d\n", err);
        exit(0);
    }

    if (argc == argvoffset + 4) {
        const long int port_conv = strtol(argv[argvoffset + 2], nullptr, 10);

        if (port_conv <= 0 || port_conv > UINT16_MAX) {
            printf("Failed to convert \"%s\" into a valid port. Exiting...\n", argv[argvoffset + 2]);
            exit(1);
        }

        const uint16_t port = net_htons((uint16_t)port_conv);
        uint8_t *bootstrap_key = hex_string_to_bin(argv[argvoffset + 3]);
        bool res = dht_bootstrap_from_address(m->dht, argv[argvoffset + 1],
                                              ipv6enabled, port, bootstrap_key);
        free(bootstrap_key);

        if (!res) {
            printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
            exit(1);
        }
    }

    m_callback_friendrequest(m, print_request);
    m_callback_friendmessage(m, print_message);

    printf("OUR ID: ");
    uint32_t i;
    uint8_t address[FRIEND_ADDRESS_SIZE];
    getaddress(m, address);

    for (i = 0; i < FRIEND_ADDRESS_SIZE; i++) {
        if (address[i] < 16) {
            printf("0");
        }

        printf("%hhX", address[i]);
    }

    setname(m, (const uint8_t *)"Anon", 5);

    char temp_hex_id[128];
    printf("\nEnter the address of the friend you wish to add (38 bytes HEX format):\n");

    if (!fgets(temp_hex_id, sizeof(temp_hex_id), stdin)) {
        exit(0);
    }

    if ((strlen(temp_hex_id) > 0) && (temp_hex_id[strlen(temp_hex_id) - 1] == '\n')) {
        temp_hex_id[strlen(temp_hex_id) - 1] = '\0';
    }

    uint8_t *bin_id = hex_string_to_bin(temp_hex_id);
    const int num = m_addfriend(m, bin_id, (const uint8_t *)"Install Gentoo", sizeof("Install Gentoo"));
    free(bin_id);

    perror("Initialization");

    while (1) {
        mono_time_update(mono_time);

        uint8_t name[128];
        const char *const filename = "Save.bak";
        getname(m, num, name);
        printf("%s\n", name);

        m_send_message_generic(m, num, MESSAGE_NORMAL, (const uint8_t *)"Test", 5, nullptr);
        do_messenger(m, nullptr);
        c_sleep(30);
        FILE *file = fopen(filename, "wb");

        if (file == nullptr) {
            printf("Failed to open file %s\n", filename);
            kill_messenger(m);
            return 1;
        }

        uint8_t *buffer = (uint8_t *)malloc(messenger_size(m));

        if (buffer == nullptr) {
            fputs("Failed to allocate memory\n", stderr);
            fclose(file);
            kill_messenger(m);
            return 1;
        }

        messenger_save(m, buffer);
        const size_t write_result = fwrite(buffer, 1, messenger_size(m), file);

        if (write_result < messenger_size(m)) {
            free(buffer);
            fclose(file);
            kill_messenger(m);
            return 1;
        }

        free(buffer);
        fclose(file);
    }
}
