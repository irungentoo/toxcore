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

/* NOTE: only used by TCP_con */
#define TCP_CONN_CONNECTED 2

/* Connection is not connected but can be quickly reconnected in case it is needed. */
#define TCP_CONN_SLEEPING 3

#define TCP_CONNECTIONS_STATUS_NONE 0
#define TCP_CONNECTIONS_STATUS_REGISTERED 1
#define TCP_CONNECTIONS_STATUS_ONLINE 2

#define MAX_FRIEND_TCP_CONNECTIONS 6

/* Time until connection to friend gets killed (if it doesn't get locked withing that time) */
#define TCP_CONNECTION_ANNOUNCE_TIMEOUT (TCP_CONNECTION_TIMEOUT)

/* The amount of recommended connections for each friend
   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2) */
#define RECOMMENDED_FRIEND_TCP_CONNECTIONS (MAX_FRIEND_TCP_CONNECTIONS / 2)

/* Number of TCP connections used for onion purposes. */
#define NUM_ONION_TCP_CONNECTIONS RECOMMENDED_FRIEND_TCP_CONNECTIONS

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
    uint64_t connected_time;
    uint32_t lock_count;
    uint32_t sleep_count;
    _Bool onion;

    /* Only used when connection is sleeping. */
    IP_Port ip_port;
    uint8_t relay_pk[crypto_box_PUBLICKEYBYTES];
    _Bool unsleep; /* set to 1 to unsleep connection. */
} TCP_con;

typedef struct {
    DHT *dht;

    TCP_Connection_to *connections;
    uint32_t connections_length; /* Length of connections array. */

    TCP_con *tcp_connections;
    uint32_t tcp_connections_length; /* Length of tcp_connections array. */

    int (*tcp_data_callback)(void *object, int id, const uint8_t *data, uint16_t length);
    void *tcp_data_callback_object;

    int (*tcp_oob_callback)(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                            const uint8_t *data, uint16_t length);
    void *tcp_oob_callback_object;

    int (*tcp_onion_callback)(void *object, const uint8_t *data, uint16_t length);
    void *tcp_onion_callback_object;

    TCP_Proxy_Info proxy_info;

    _Bool onion_status;
    uint16_t onion_num_conns;
} TCP_Connections;

/* Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_packet_tcp_connection(TCP_Connections *tcp_c, int connections_number, const uint8_t *packet, uint16_t length);

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO: This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_onion_conn_number(TCP_Connections *tcp_c);

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_onion_request(TCP_Connections *tcp_c, unsigned int tcp_connections_number, const uint8_t *data,
                           uint16_t length);

/* Set if we want TCP_connection to allocate some connection for onion use.
 *
 * If status is 1, allocate some connections. if status is 0, don't.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_onion_status(TCP_Connections *tcp_c, _Bool status);

/* Send an oob packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_oob_packet(TCP_Connections *tcp_c, unsigned int tcp_connections_number, const uint8_t *public_key,
                        const uint8_t *packet, uint16_t length);

/* Set the callback for TCP data packets.
 */
void set_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_data_callback)(void *object, int id,
                                        const uint8_t *data, uint16_t length), void *object);

/* Set the callback for TCP onion packets.
 */
void set_onion_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_onion_callback)(void *object,
        const uint8_t *data, uint16_t length), void *object);

/* Set the callback for TCP oob data packets.
 */
void set_oob_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_oob_callback)(void *object,
        const uint8_t *public_key, unsigned int tcp_connections_number, const uint8_t *data, uint16_t length), void *object);

/* Create a new TCP connection to public_key.
 *
 * id is the id in the callbacks for that connection.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
int new_tcp_connection_to(TCP_Connections *tcp_c, const uint8_t *public_key, int id);

/* return 0 on success.
 * return -1 on failure.
 */
int kill_tcp_connection_to(TCP_Connections *tcp_c, int connections_number);

/* Set connection status.
 *
 * status of 1 means we are using the connection.
 * status of 0 means we are not using it.
 *
 * Unused tcp connections will be disconnected from but kept in case they are needed.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_to_status(TCP_Connections *tcp_c, int connections_number, _Bool status);

/* return number of online tcp relays tied to the connection on success.
 * return 0 on failure.
 */
unsigned int tcp_connection_to_online_tcp_relays(TCP_Connections *tcp_c, int connections_number);

/* Add a TCP relay tied to a connection.
 *
 * NOTE: This can only be used during the tcp_oob_callback.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_number_relay_connection(TCP_Connections *tcp_c, int connections_number,
                                    unsigned int tcp_connections_number);

/* Add a TCP relay tied to a connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_connection(TCP_Connections *tcp_c, int connections_number, IP_Port ip_port, const uint8_t *relay_pk);

/* Add a TCP relay to the instance.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_global(TCP_Connections *tcp_c, IP_Port ip_port, const uint8_t *relay_pk);

/* Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int tcp_copy_connected_relays(TCP_Connections *tcp_c, Node_format *tcp_relays, uint16_t max_num);

TCP_Connections *new_tcp_connections(DHT *dht, TCP_Proxy_Info *proxy_info);
void do_tcp_connections(TCP_Connections *tcp_c);
void kill_tcp_connections(TCP_Connections *tcp_c);

#endif

