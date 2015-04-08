/* TCP_connection.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "TCP_connection.h"

/* Set the size of the array to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
#define realloc_tox_array(array, element_size, num, temp_pointer) (num ? (temp_pointer = realloc(array, num * element_size), temp_pointer ? (array = temp_pointer, 0) : (-1) ) : (free(array), array = NULL, 0))


/* return 1 if the connections_number is not valid.
 * return 0 if the connections_number is valid.
 */
static _Bool connections_number_not_valid(const TCP_Connections *tcp_c, int connections_number)
{
    if ((unsigned int)connections_number >= tcp_c->connections_length)
        return 1;

    if (tcp_c->connections == NULL)
        return 1;

    if (tcp_c->connections[connections_number].status == TCP_CONN_STATUS_NONE)
        return 1;

    return 0;
}

/* return 1 if the tcp_connections_number is not valid.
 * return 0 if the tcp_connections_number is valid.
 */
static _Bool tcp_connections_number_not_valid(const TCP_Connections *tcp_c, int tcp_connections_number)
{
    if ((unsigned int)tcp_connections_number >= tcp_c->tcp_connections_length)
        return 1;

    if (tcp_c->tcp_connections == NULL)
        return 1;

    if (tcp_c->tcp_connections[tcp_connections_number].status == TCP_CONN_STATUS_NONE)
        return 1;

    return 0;
}

/* Create a new empty connection.
 *
 * return -1 on failure.
 * return connections_number on success.
 */
static int create_connection(TCP_Connections *tcp_c)
{
    uint32_t i;

    for (i = 0; i < tcp_c->connections_length; ++i) {
        if (tcp_c->connections[i].status == TCP_CONN_STATUS_NONE)
            return i;
    }

    int id = -1;

    TCP_Connection_to *temp_pointer;

    if (realloc_tox_array(tcp_c->connections, sizeof(TCP_Connection_to), tcp_c->connections_length + 1,
                          temp_pointer) == 0) {
        id = tcp_c->connections_length;
        ++tcp_c->connections_length;
        memset(&(tcp_c->connections[id]), 0, sizeof(TCP_Connection_to));
    }

    return id;
}

/* Create a new empty tcp connection.
 *
 * return -1 on failure.
 * return tcp_connections_number on success.
 */
static int create_tcp_connection(TCP_Connections *tcp_c)
{
    uint32_t i;

    for (i = 0; i < tcp_c->tcp_connections_length; ++i) {
        if (tcp_c->tcp_connections[i].status == TCP_CONN_STATUS_NONE)
            return i;
    }

    int id = -1;

    TCP_con *temp_pointer;

    if (realloc_tox_array(tcp_c->tcp_connections, sizeof(TCP_con), tcp_c->tcp_connections_length + 1, temp_pointer) == 0) {
        id = tcp_c->tcp_connections_length;
        ++tcp_c->tcp_connections_length;
        memset(&(tcp_c->tcp_connections[id]), 0, sizeof(TCP_con));
    }

    return id;
}

/* Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_connection(TCP_Connections *tcp_c, int connections_number)
{
    if (connections_number_not_valid(tcp_c, connections_number))
        return -1;

    uint32_t i;
    memset(&(tcp_c->connections[connections_number]), 0 , sizeof(TCP_Connection_to));

    for (i = tcp_c->connections_length; i != 0; --i) {
        if (tcp_c->connections[i - 1].status != TCP_CONN_STATUS_NONE)
            break;
    }

    if (tcp_c->connections_length != i) {
        tcp_c->connections_length = i;
        TCP_Connection_to *temp_pointer;
        realloc_tox_array(tcp_c->connections, sizeof(TCP_Connection_to), tcp_c->connections_length, temp_pointer);
    }

    return 0;
}

/* Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_tcp_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    if (tcp_connections_number_not_valid(tcp_c, tcp_connections_number))
        return -1;

    uint32_t i;
    memset(&(tcp_c->tcp_connections[tcp_connections_number]), 0 , sizeof(TCP_con));

    for (i = tcp_c->tcp_connections_length; i != 0; --i) {
        if (tcp_c->tcp_connections[i - 1].status != TCP_CONN_STATUS_NONE)
            break;
    }

    if (tcp_c->tcp_connections_length != i) {
        tcp_c->tcp_connections_length = i;
        TCP_con *temp_pointer;
        realloc_tox_array(tcp_c->tcp_connections, sizeof(TCP_con), tcp_c->tcp_connections_length, temp_pointer);
    }

    return 0;
}

TCP_Connections *new_tcp_connections(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    TCP_Connections *temp = calloc(1, sizeof(TCP_Connections));

    if (temp == NULL)
        return NULL;

    temp->dht = dht;
    return temp;
}

void do_tcp_connections(TCP_Connections *tcp_c)
{

}

void kill_tcp_connections(TCP_Connections *tcp_c)
{
    free(tcp_c);
}


