/*
* TCP_server.h -- Implementation of the TCP relay server part of Tox.
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

#include "net_crypto.h"

#define TCP_MAX_BACKLOG 128

#define MAX_PACKET_SIZE 8192

#define MAX_INCOMMING_CONNECTIONS 32

#define TCP_SERVER_HANDSHAKE_SIZE (crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES)
#define TCP_CLIENT_HANDSHAKE_SIZE (crypto_box_PUBLICKEYBYTES + TCP_SERVER_HANDSHAKE_SIZE)

enum {
    TCP_STATUS_NO_STATUS,
    TCP_STATUS_CONNECTED,
    TCP_STATUS_UNCONFIRMED,
    TCP_STATUS_CONFIRMED,
};

typedef struct {
    uint8_t status;
    sock_t  sock;
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t recv_nonce[crypto_box_NONCEBYTES]; /* Nonce of received packets. */
    uint8_t sent_nonce[crypto_box_NONCEBYTES]; /* Nonce of sent packets. */
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    uint16_t next_packet_length;
} TCP_Secure_Connection;

typedef struct {
    sock_t *socks_listening;
    unsigned int num_listening_socks;

    TCP_Secure_Connection incomming_connection_queue[MAX_INCOMMING_CONNECTIONS];
} TCP_Server;

/* Create new TCP server instance.
 */
TCP_Server *new_TCP_server(uint8_t ipv6_enabled, uint16_t num_sockets, uint16_t *ports);

/* Run the TCP_server
 */
void do_TCP_server(TCP_Server *TCP_server);

/* Kill the TCP server
 */
void kill_TCP_server(TCP_Server *TCP_server);
