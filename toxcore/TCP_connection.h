/* TCP_connection.h
 *
 * Handles TCP relay connections between two Tox clients.
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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

#ifndef TCP_CONNECTION_H
#define TCP_CONNECTION_H

#include "TCP_client.h"

#define TCP_CONN_NONE 0
#define TCP_CONN_VALID 1
#define TCP_CONN_CONNECTED 2

#define TCP_CONNECTIONS_STATUS_NONE 0
#define TCP_CONNECTIONS_STATUS_REGISTERED 1
#define TCP_CONNECTIONS_STATUS_ONLINE 2

#define MAX_FRIEND_TCP_CONNECTIONS 4


typedef struct {
    uint8_t status;
    uint8_t public_key[crypto_box_PUBLICKEYBYTES]; /* The dht public key of the peer */

    struct {
        uint32_t tcp_connection;
        unsigned int status;
        unsigned int connection_id;
    } connections[MAX_FRIEND_TCP_CONNECTIONS];

    int id; /* id used in callbacks. */
} TCP_Connection_to;

typedef struct {
    uint8_t status;
    TCP_Client_Connection *connection;
    uint32_t lock_count;
} TCP_con;

typedef struct {
    DHT *dht;

    TCP_Connection_to *connections;
    uint32_t connections_length; /* Length of connections array. */

    TCP_con *tcp_connections;
    uint32_t tcp_connections_length; /* Length of tcp_connections array. */

    int (*tcp_data_callback)(void *object, int id, const uint8_t *data, uint16_t length);
    void *tcp_data_callback_object;

    int (*tcp_oob_callback)(void *object, const uint8_t *public_key, const uint8_t *relay_pk, const uint8_t *data,
                            uint16_t length);
    void *tcp_oob_callback_object;

    int (*tcp_onion_callback)(void *object, const uint8_t *data, uint16_t length);
    void *tcp_onion_callback_object;

    TCP_Proxy_Info proxy_info;
} TCP_Connections;



TCP_Connections *new_tcp_connections(DHT *dht);
void do_tcp_connections(TCP_Connections *tcp_c);
void kill_tcp_connections(TCP_Connections *tcp_c);

#endif

