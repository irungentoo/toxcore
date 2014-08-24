/* Tox Shell
 *
 * Proof of concept ssh like server software using tox.
 *
 * Command line arguments are the ip, port and public_key of a node (for bootstrapping).
 *
 * EX: ./test 127.0.0.1 33445 CDCFD319CE3460824B33BE58FD86B8941C9585181D8FBD7C79C5721D7C2E9F7C
 *
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include "../toxcore/tox.h"
#include "misc_tools.c"

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <util.h>
#elif defined(__FreeBSD__)
#include <libutil.h>
#else
#include <pty.h>
#endif
#include <unistd.h>
#include <fcntl.h>

#define c_sleep(x) usleep(1000*x)

void print_online(Tox *tox, int friendnumber, uint8_t status, void *userdata)
{
    if (status == 1)
        printf("\nOther went online.\n");
    else
        printf("\nOther went offline.\n");
}

void print_message(Tox *tox, int friendnumber, const uint8_t *string, uint16_t length, void *userdata)
{
    int master = *((int *)userdata);
    write(master, string, length);
    write(master, "\n", 1);
}

int main(int argc, char *argv[])
{
    uint8_t ipv6enabled = TOX_ENABLE_IPV6_DEFAULT; /* x */
    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &ipv6enabled);

    if (argvoffset < 0)
        exit(1);

    /* with optional --ipvx, now it can be 1-4 arguments... */
    if ((argc != argvoffset + 2) && (argc != argvoffset + 4)) {
        printf("Usage: %s [--ipv4|--ipv6] ip port public_key (of the DHT bootstrap node)\n", argv[0]);
        exit(0);
    }

    int *master = malloc(sizeof(int));
    int ret = forkpty(master, NULL, NULL, NULL);

    if (ret == -1) {
        printf("fork failed\n");
        return 1;
    }

    if (ret == 0) {
        execl("/bin/sh", "sh", NULL);
        return 0;
    }

    int flags = fcntl(*master, F_GETFL, 0);
    int r = fcntl(*master, F_SETFL, flags | O_NONBLOCK);

    if (r < 0) {
        printf("error setting flags\n");
    }

    Tox *tox = tox_new(0);
    tox_callback_connection_status(tox, print_online, NULL);
    tox_callback_friend_message(tox, print_message, master);


    uint16_t port = atoi(argv[argvoffset + 2]);
    unsigned char *binary_string = hex_string_to_bin(argv[argvoffset + 3]);
    int res = tox_bootstrap_from_address(tox, argv[argvoffset + 1], port, binary_string);
    free(binary_string);

    if (!res) {
        printf("Failed to convert \"%s\" into an IP address. Exiting...\n", argv[argvoffset + 1]);
        exit(1);
    }

    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(tox, address);
    uint32_t i;

    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++) {
        printf("%02X", address[i]);
    }

    char temp_id[128];
    printf("\nEnter the address of the other id you want to sync with (38 bytes HEX format):\n");

    if (scanf("%s", temp_id) != 1) {
        return 1;
    }

    uint8_t *bin_id = hex_string_to_bin(temp_id);
    int num = tox_add_friend(tox, bin_id, (uint8_t *)"Install Gentoo", sizeof("Install Gentoo"));
    free(bin_id);

    if (num < 0) {
        printf("\nSomething went wrong when adding friend.\n");
        return 1;
    }

    uint8_t notconnected = 1;

    while (1) {
        if (tox_isconnected(tox) && notconnected) {
            printf("\nDHT connected.\n");
            notconnected = 0;
        }

        while (tox_get_friend_connection_status(tox, num) == 1) {
            uint8_t buf[TOX_MAX_MESSAGE_LENGTH];
            ret = read(*master, buf, sizeof(buf));

            if (ret <= 0)
                break;

            tox_send_message(tox, num, buf, ret);
        }

        tox_do(tox);
        c_sleep(1);
    }

    return 0;
}
