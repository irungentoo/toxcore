/* nTox.h
 *
 *Textual frontend for Tox.
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

#ifndef NTOX_H
#define NTOX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ncurses.h>
#include <curses.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include "../core/tox.h"

#define STRING_LENGTH 256
#define HISTORY 50
#define PUB_KEY_BYTES 32

/*
  resolve_addr():
    address should represent IPv4 or a hostname with A record

    returns a data in network byte order that can be used to set IP.i or IP_Port.ip.i
    returns 0 on failure

    TODO: Fix ipv6 support
*/

uint32_t resolve_addr(const char *address)
{
    struct addrinfo *server = NULL;
    struct addrinfo  hints;
    int              rc;
    uint32_t         addr;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;    // IPv4 only right now.
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    rc = getaddrinfo(address, "echo", &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    // IPv4 records only..
    if (server->ai_family != AF_INET) {
        freeaddrinfo(server);
        return 0;
    }


    addr = ((struct sockaddr_in *)server->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(server);
    return addr;
}

void new_lines(char *line);
void line_eval(Tox *m, char *line);
void wrap(char output[STRING_LENGTH], char input[STRING_LENGTH], int line_width) ;
int count_lines(char *string) ;
char *appender(char *str, const char c);
void do_refresh();

#endif
