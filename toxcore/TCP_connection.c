/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * Handles TCP relay connections between two Tox clients.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "TCP_connection.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "mono_time.h"
#include "util.h"


struct TCP_Connections {
    Mono_Time *mono_time;
    DHT *dht;

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];

    TCP_Connection_to *connections;
    uint32_t connections_length; /* Length of connections array. */

    TCP_con *tcp_connections;
    uint32_t tcp_connections_length; /* Length of tcp_connections array. */

    tcp_data_cb *tcp_data_callback;
    void *tcp_data_callback_object;

    tcp_oob_cb *tcp_oob_callback;
    void *tcp_oob_callback_object;

    tcp_onion_cb *tcp_onion_callback;
    void *tcp_onion_callback_object;

    TCP_Proxy_Info proxy_info;

    bool onion_status;
    uint16_t onion_num_conns;
};


const uint8_t *tcp_connections_public_key(const TCP_Connections *tcp_c)
{
    return tcp_c->self_public_key;
}


/* Set the size of the array to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_TCP_Connection_to(TCP_Connection_to **array, size_t num)
{
    if (!num) {
        free(*array);
        *array = nullptr;
        return 0;
    }

    TCP_Connection_to *temp_pointer =
        (TCP_Connection_to *)realloc(*array, num * sizeof(TCP_Connection_to));

    if (!temp_pointer) {
        return -1;
    }

    *array = temp_pointer;

    return 0;
}

static int realloc_TCP_con(TCP_con **array, size_t num)
{
    if (!num) {
        free(*array);
        *array = nullptr;
        return 0;
    }

    TCP_con *temp_pointer = (TCP_con *)realloc(*array, num * sizeof(TCP_con));

    if (!temp_pointer) {
        return -1;
    }

    *array = temp_pointer;

    return 0;
}


/**
 * Return true if the connections_number is valid.
 */
static bool connections_number_is_valid(const TCP_Connections *tcp_c, int connections_number)
{
    if ((unsigned int)connections_number >= tcp_c->connections_length) {
        return false;
    }

    if (tcp_c->connections == nullptr) {
        return false;
    }

    if (tcp_c->connections[connections_number].status == TCP_CONN_NONE) {
        return false;
    }

    return true;
}

/**
 * Return true if the tcp_connections_number is valid.
 */
static bool tcp_connections_number_is_valid(const TCP_Connections *tcp_c, int tcp_connections_number)
{
    if ((uint32_t)tcp_connections_number >= tcp_c->tcp_connections_length) {
        return false;
    }

    if (tcp_c->tcp_connections == nullptr) {
        return false;
    }

    if (tcp_c->tcp_connections[tcp_connections_number].status == TCP_CONN_NONE) {
        return false;
    }

    return true;
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
        if (tcp_c->connections[i].status == TCP_CONN_NONE) {
            return i;
        }
    }

    int id = -1;

    if (realloc_TCP_Connection_to(&tcp_c->connections, tcp_c->connections_length + 1) == 0) {
        id = tcp_c->connections_length;
        ++tcp_c->connections_length;
        memset(&tcp_c->connections[id], 0, sizeof(TCP_Connection_to));
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
    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        if (tcp_c->tcp_connections[i].status == TCP_CONN_NONE) {
            return i;
        }
    }

    int id = -1;

    if (realloc_TCP_con(&tcp_c->tcp_connections, tcp_c->tcp_connections_length + 1) == 0) {
        id = tcp_c->tcp_connections_length;
        ++tcp_c->tcp_connections_length;
        memset(&tcp_c->tcp_connections[id], 0, sizeof(TCP_con));
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
    if (!connections_number_is_valid(tcp_c, connections_number)) {
        return -1;
    }

    uint32_t i;
    memset(&tcp_c->connections[connections_number], 0, sizeof(TCP_Connection_to));

    for (i = tcp_c->connections_length; i != 0; --i) {
        if (tcp_c->connections[i - 1].status != TCP_CONN_NONE) {
            break;
        }
    }

    if (tcp_c->connections_length != i) {
        tcp_c->connections_length = i;
        realloc_TCP_Connection_to(&tcp_c->connections, tcp_c->connections_length);
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
    if (!tcp_connections_number_is_valid(tcp_c, tcp_connections_number)) {
        return -1;
    }

    memset(&tcp_c->tcp_connections[tcp_connections_number], 0, sizeof(TCP_con));

    uint32_t i;

    for (i = tcp_c->tcp_connections_length; i != 0; --i) {
        if (tcp_c->tcp_connections[i - 1].status != TCP_CONN_NONE) {
            break;
        }
    }

    if (tcp_c->tcp_connections_length != i) {
        tcp_c->tcp_connections_length = i;
        realloc_TCP_con(&tcp_c->tcp_connections, tcp_c->tcp_connections_length);
    }

    return 0;
}

static TCP_Connection_to *get_connection(const TCP_Connections *tcp_c, int connections_number)
{
    if (!connections_number_is_valid(tcp_c, connections_number)) {
        return nullptr;
    }

    return &tcp_c->connections[connections_number];
}

static TCP_con *get_tcp_connection(const TCP_Connections *tcp_c, int tcp_connections_number)
{
    if (!tcp_connections_number_is_valid(tcp_c, tcp_connections_number)) {
        return nullptr;
    }

    return &tcp_c->tcp_connections[tcp_connections_number];
}

/* Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_packet_tcp_connection(TCP_Connections *tcp_c, int connections_number, const uint8_t *packet, uint16_t length)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (!con_to) {
        return -1;
    }

    // TODO(irungentoo): detect and kill bad relays.
    // TODO(irungentoo): thread safety?
    unsigned int i;
    int ret = -1;

    bool limit_reached = 0;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
        uint8_t status = con_to->connections[i].status;
        uint8_t connection_id = con_to->connections[i].connection_id;

        if (tcp_con_num && status == TCP_CONNECTIONS_STATUS_ONLINE) {
            tcp_con_num -= 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_con_num);

            if (!tcp_con) {
                continue;
            }

            ret = send_data(tcp_con->connection, connection_id, packet, length);

            if (ret == 0) {
                limit_reached = 1;
            }

            if (ret == 1) {
                break;
            }
        }
    }

    if (ret == 1) {
        return 0;
    }

    if (!limit_reached) {
        ret = 0;

        /* Send oob packets to all relays tied to the connection. */
        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
            uint8_t status = con_to->connections[i].status;

            if (tcp_con_num && status == TCP_CONNECTIONS_STATUS_REGISTERED) {
                tcp_con_num -= 1;
                TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_con_num);

                if (!tcp_con) {
                    continue;
                }

                if (send_oob_packet(tcp_con->connection, con_to->public_key, packet, length) == 1) {
                    ret += 1;
                }
            }
        }

        if (ret >= 1) {
            return 0;
        }

        return -1;
    }

    return -1;
}

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO(irungentoo): This number is just the index of an array that the elements
 * can change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_onion_conn_number(TCP_Connections *tcp_c)
{
    const uint32_t r = random_u32();

    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        uint32_t index = ((i + r) % tcp_c->tcp_connections_length);

        if (tcp_c->tcp_connections[index].onion && tcp_c->tcp_connections[index].status == TCP_CONN_CONNECTED) {
            return index;
        }
    }

    return -1;
}

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_onion_request(TCP_Connections *tcp_c, uint32_t tcp_connections_number, const uint8_t *data,
                           uint16_t length)
{
    if (tcp_connections_number >= tcp_c->tcp_connections_length) {
        return -1;
    }

    if (tcp_c->tcp_connections[tcp_connections_number].status == TCP_CONN_CONNECTED) {
        int ret = send_onion_request(tcp_c->tcp_connections[tcp_connections_number].connection, data, length);

        if (ret == 1) {
            return 0;
        }
    }

    return -1;
}

/* Send an oob packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_oob_packet(TCP_Connections *tcp_c, unsigned int tcp_connections_number, const uint8_t *public_key,
                        const uint8_t *packet, uint16_t length)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (tcp_con->status != TCP_CONN_CONNECTED) {
        return -1;
    }

    int ret = send_oob_packet(tcp_con->connection, public_key, packet, length);

    if (ret == 1) {
        return 0;
    }

    return -1;
}

/* Set the callback for TCP data packets.
 */
void set_packet_tcp_connection_callback(TCP_Connections *tcp_c, tcp_data_cb *tcp_data_callback, void *object)
{
    tcp_c->tcp_data_callback = tcp_data_callback;
    tcp_c->tcp_data_callback_object = object;
}

/* Set the callback for TCP onion packets.
 */
void set_oob_packet_tcp_connection_callback(TCP_Connections *tcp_c, tcp_oob_cb *tcp_oob_callback, void *object)
{
    tcp_c->tcp_oob_callback = tcp_oob_callback;
    tcp_c->tcp_oob_callback_object = object;
}

/* Set the callback for TCP oob data packets.
 */
void set_onion_packet_tcp_connection_callback(TCP_Connections *tcp_c, tcp_onion_cb *tcp_onion_callback, void *object)
{
    tcp_c->tcp_onion_callback = tcp_onion_callback;
    tcp_c->tcp_onion_callback_object = object;
}


/* Find the TCP connection with public_key.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
static int find_tcp_connection_to(TCP_Connections *tcp_c, const uint8_t *public_key)
{
    unsigned int i;

    for (i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            if (public_key_cmp(con_to->public_key, public_key) == 0) {
                return i;
            }
        }
    }

    return -1;
}

/* Find the TCP connection to a relay with relay_pk.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
static int find_tcp_connection_relay(TCP_Connections *tcp_c, const uint8_t *relay_pk)
{
    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con) {
            if (tcp_con->status == TCP_CONN_SLEEPING) {
                if (public_key_cmp(tcp_con->relay_pk, relay_pk) == 0) {
                    return i;
                }
            } else {
                if (public_key_cmp(tcp_con_public_key(tcp_con->connection), relay_pk) == 0) {
                    return i;
                }
            }
        }
    }

    return -1;
}

/* Create a new TCP connection to public_key.
 *
 * public_key must be the counterpart to the secret key that the other peer used with new_tcp_connections().
 *
 * id is the id in the callbacks for that connection.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
int new_tcp_connection_to(TCP_Connections *tcp_c, const uint8_t *public_key, int id)
{
    if (find_tcp_connection_to(tcp_c, public_key) != -1) {
        return -1;
    }

    int connections_number = create_connection(tcp_c);

    if (connections_number == -1) {
        return -1;
    }

    TCP_Connection_to *con_to = &tcp_c->connections[connections_number];

    con_to->status = TCP_CONN_VALID;
    memcpy(con_to->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    con_to->id = id;

    return connections_number;
}

/* return 0 on success.
 * return -1 on failure.
 */
int kill_tcp_connection_to(TCP_Connections *tcp_c, int connections_number)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (!con_to) {
        return -1;
    }

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection) {
            unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

            if (!tcp_con) {
                continue;
            }

            if (tcp_con->status == TCP_CONN_CONNECTED) {
                send_disconnect_request(tcp_con->connection, con_to->connections[i].connection_id);
            }

            if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                --tcp_con->lock_count;

                if (con_to->status == TCP_CONN_SLEEPING) {
                    --tcp_con->sleep_count;
                }
            }
        }
    }

    return wipe_connection(tcp_c, connections_number);
}

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
int set_tcp_connection_to_status(TCP_Connections *tcp_c, int connections_number, bool status)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (!con_to) {
        return -1;
    }

    if (status) {
        /* Connection is unsleeping. */
        if (con_to->status != TCP_CONN_SLEEPING) {
            return -1;
        }

        unsigned int i;

        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            if (con_to->connections[i].tcp_connection) {
                unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
                TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

                if (!tcp_con) {
                    continue;
                }

                if (tcp_con->status == TCP_CONN_SLEEPING) {
                    tcp_con->unsleep = 1;
                }
            }
        }

        con_to->status = TCP_CONN_VALID;
        return 0;
    }

    /* Connection is going to sleep. */
    if (con_to->status != TCP_CONN_VALID) {
        return -1;
    }

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection) {
            unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

            if (!tcp_con) {
                continue;
            }

            if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                ++tcp_con->sleep_count;
            }
        }
    }

    con_to->status = TCP_CONN_SLEEPING;
    return 0;
}

static bool tcp_connection_in_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
            return 1;
        }
    }

    return 0;
}

/* return index on success.
 * return -1 on failure.
 */
static int add_tcp_connection_to_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    unsigned int i;

    if (tcp_connection_in_conn(con_to, tcp_connections_number)) {
        return -1;
    }

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == 0) {
            con_to->connections[i].tcp_connection = tcp_connections_number + 1;
            con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
            con_to->connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/* return index on success.
 * return -1 on failure.
 */
static int rm_tcp_connection_from_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
            con_to->connections[i].tcp_connection = 0;
            con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
            con_to->connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/* return number of online connections on success.
 * return -1 on failure.
 */
static unsigned int online_tcp_connection_from_conn(TCP_Connection_to *con_to)
{
    unsigned int count = 0;

    for (unsigned int i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection) {
            if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                ++count;
            }
        }
    }

    return count;
}

/* return index on success.
 * return -1 on failure.
 */
static int set_tcp_connection_status(TCP_Connection_to *con_to, unsigned int tcp_connections_number,
                                     unsigned int status, uint8_t connection_id)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {

            if (con_to->connections[i].status == status) {
                return -1;
            }

            con_to->connections[i].status = status;
            con_to->connections[i].connection_id = connection_id;
            return i;
        }
    }

    return -1;
}

/* Kill a TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static int kill_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    unsigned int i;

    for (i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            rm_tcp_connection_from_conn(con_to, tcp_connections_number);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
    }

    kill_TCP_connection(tcp_con->connection);

    return wipe_tcp_connection(tcp_c, tcp_connections_number);
}

static int reconnect_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (tcp_con->status == TCP_CONN_SLEEPING) {
        return -1;
    }

    IP_Port ip_port = tcp_con_ip_port(tcp_con->connection);
    uint8_t relay_pk[CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(relay_pk, tcp_con_public_key(tcp_con->connection), CRYPTO_PUBLIC_KEY_SIZE);
    kill_TCP_connection(tcp_con->connection);
    tcp_con->connection = new_TCP_connection(tcp_c->mono_time, ip_port, relay_pk, tcp_c->self_public_key,
                          tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (!tcp_con->connection) {
        kill_tcp_relay_connection(tcp_c, tcp_connections_number);
        return -1;
    }

    unsigned int i;

    for (i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_NONE, 0);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
        tcp_con->onion = 0;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCP_CONN_VALID;
    tcp_con->unsleep = 0;

    return 0;
}

static int sleep_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (tcp_con->status != TCP_CONN_CONNECTED) {
        return -1;
    }

    if (tcp_con->lock_count != tcp_con->sleep_count) {
        return -1;
    }

    tcp_con->ip_port = tcp_con_ip_port(tcp_con->connection);
    memcpy(tcp_con->relay_pk, tcp_con_public_key(tcp_con->connection), CRYPTO_PUBLIC_KEY_SIZE);

    kill_TCP_connection(tcp_con->connection);
    tcp_con->connection = nullptr;

    unsigned int i;

    for (i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_NONE, 0);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
        tcp_con->onion = 0;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCP_CONN_SLEEPING;
    tcp_con->unsleep = 0;

    return 0;
}

static int unsleep_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (tcp_con->status != TCP_CONN_SLEEPING) {
        return -1;
    }

    tcp_con->connection = new_TCP_connection(tcp_c->mono_time, tcp_con->ip_port, tcp_con->relay_pk, tcp_c->self_public_key,
                          tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (!tcp_con->connection) {
        kill_tcp_relay_connection(tcp_c, tcp_connections_number);
        return -1;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCP_CONN_VALID;
    tcp_con->unsleep = 0;
    return 0;
}

/* Send a TCP routing request.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static int send_tcp_relay_routing_request(TCP_Connections *tcp_c, int tcp_connections_number, uint8_t *public_key)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (tcp_con->status == TCP_CONN_SLEEPING) {
        return -1;
    }

    if (send_routing_request(tcp_con->connection, public_key) != 1) {
        return -1;
    }

    return 0;
}

static int tcp_response_callback(void *object, uint8_t connection_id, const uint8_t *public_key)
{
    TCP_Client_Connection *tcp_client_con = (TCP_Client_Connection *)object;
    TCP_Connections *tcp_c = (TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    int connections_number = find_tcp_connection_to(tcp_c, public_key);

    if (connections_number == -1) {
        return -1;
    }

    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
        return -1;
    }

    if (set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_REGISTERED, connection_id) == -1) {
        return -1;
    }

    set_tcp_connection_number(tcp_con->connection, connection_id, connections_number);

    return 0;
}

static int tcp_status_callback(void *object, uint32_t number, uint8_t connection_id, uint8_t status)
{
    TCP_Client_Connection *tcp_client_con = (TCP_Client_Connection *)object;
    TCP_Connections *tcp_c = (TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);
    TCP_Connection_to *con_to = get_connection(tcp_c, number);

    if (!con_to || !tcp_con) {
        return -1;
    }

    if (status == 1) {
        if (set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_REGISTERED, connection_id) == -1) {
            return -1;
        }

        --tcp_con->lock_count;

        if (con_to->status == TCP_CONN_SLEEPING) {
            --tcp_con->sleep_count;
        }
    } else if (status == 2) {
        if (set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_ONLINE, connection_id) == -1) {
            return -1;
        }

        ++tcp_con->lock_count;

        if (con_to->status == TCP_CONN_SLEEPING) {
            ++tcp_con->sleep_count;
        }
    }

    return 0;
}

static int tcp_conn_data_callback(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data,
                                  uint16_t length, void *userdata)
{
    if (length == 0) {
        return -1;
    }

    TCP_Client_Connection *tcp_client_con = (TCP_Client_Connection *)object;
    TCP_Connections *tcp_c = (TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    TCP_Connection_to *con_to = get_connection(tcp_c, number);

    if (!con_to) {
        return -1;
    }

    if (tcp_c->tcp_data_callback) {
        tcp_c->tcp_data_callback(tcp_c->tcp_data_callback_object, con_to->id, data, length, userdata);
    }

    return 0;
}

static int tcp_conn_oob_callback(void *object, const uint8_t *public_key, const uint8_t *data, uint16_t length,
                                 void *userdata)
{
    if (length == 0) {
        return -1;
    }

    TCP_Client_Connection *tcp_client_con = (TCP_Client_Connection *)object;
    TCP_Connections *tcp_c = (TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    /* TODO(irungentoo): optimize */
    int connections_number = find_tcp_connection_to(tcp_c, public_key);

    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to && tcp_connection_in_conn(con_to, tcp_connections_number)) {
        return tcp_conn_data_callback(object, connections_number, 0, data, length, userdata);
    }

    if (tcp_c->tcp_oob_callback) {
        tcp_c->tcp_oob_callback(tcp_c->tcp_oob_callback_object, public_key, tcp_connections_number, data, length, userdata);
    }

    return 0;
}

static int tcp_onion_callback(void *object, const uint8_t *data, uint16_t length, void *userdata)
{
    TCP_Connections *tcp_c = (TCP_Connections *)object;

    if (tcp_c->tcp_onion_callback) {
        tcp_c->tcp_onion_callback(tcp_c->tcp_onion_callback_object, data, length, userdata);
    }

    return 0;
}

/* Set callbacks for the TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static int tcp_relay_set_callbacks(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    TCP_Client_Connection *con = tcp_con->connection;

    tcp_con_set_custom_object(con, tcp_c);
    tcp_con_set_custom_uint(con, tcp_connections_number);
    onion_response_handler(con, &tcp_onion_callback, tcp_c);
    routing_response_handler(con, &tcp_response_callback, con);
    routing_status_handler(con, &tcp_status_callback, con);
    routing_data_handler(con, &tcp_conn_data_callback, con);
    oob_data_handler(con, &tcp_conn_oob_callback, con);

    return 0;
}

static int tcp_relay_on_online(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    unsigned int sent = 0;

    for (unsigned int i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            if (tcp_connection_in_conn(con_to, tcp_connections_number)) {
                if (send_tcp_relay_routing_request(tcp_c, tcp_connections_number, con_to->public_key) == 0) {
                    ++sent;
                }
            }
        }
    }

    tcp_relay_set_callbacks(tcp_c, tcp_connections_number);
    tcp_con->status = TCP_CONN_CONNECTED;

    /* If this connection isn't used by any connection, we don't need to wait for them to come online. */
    if (sent) {
        tcp_con->connected_time = mono_time_get(tcp_c->mono_time);
    } else {
        tcp_con->connected_time = 0;
    }

    if (tcp_c->onion_status && tcp_c->onion_num_conns < NUM_ONION_TCP_CONNECTIONS) {
        tcp_con->onion = 1;
        ++tcp_c->onion_num_conns;
    }

    return 0;
}

static int add_tcp_relay_instance(TCP_Connections *tcp_c, IP_Port ip_port, const uint8_t *relay_pk)
{
    if (net_family_is_tcp_ipv4(ip_port.ip.family)) {
        ip_port.ip.family = net_family_ipv4;
    } else if (net_family_is_tcp_ipv6(ip_port.ip.family)) {
        ip_port.ip.family = net_family_ipv6;
    }

    if (!net_family_is_ipv4(ip_port.ip.family) && !net_family_is_ipv6(ip_port.ip.family)) {
        return -1;
    }

    int tcp_connections_number = create_tcp_connection(tcp_c);

    if (tcp_connections_number == -1) {
        return -1;
    }

    TCP_con *tcp_con = &tcp_c->tcp_connections[tcp_connections_number];

    tcp_con->connection = new_TCP_connection(tcp_c->mono_time, ip_port, relay_pk, tcp_c->self_public_key,
                          tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (!tcp_con->connection) {
        return -1;
    }

    tcp_con->status = TCP_CONN_VALID;

    return tcp_connections_number;
}

/* Add a TCP relay to the TCP_Connections instance.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_global(TCP_Connections *tcp_c, IP_Port ip_port, const uint8_t *relay_pk)
{
    int tcp_connections_number = find_tcp_connection_relay(tcp_c, relay_pk);

    if (tcp_connections_number != -1) {
        return -1;
    }

    if (add_tcp_relay_instance(tcp_c, ip_port, relay_pk) == -1) {
        return -1;
    }

    return 0;
}

/* Add a TCP relay tied to a connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_number_relay_connection(TCP_Connections *tcp_c, int connections_number, unsigned int tcp_connections_number)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (!con_to) {
        return -1;
    }

    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (con_to->status != TCP_CONN_SLEEPING && tcp_con->status == TCP_CONN_SLEEPING) {
        tcp_con->unsleep = 1;
    }

    if (add_tcp_connection_to_conn(con_to, tcp_connections_number) == -1) {
        return -1;
    }

    if (tcp_con->status == TCP_CONN_CONNECTED) {
        if (send_tcp_relay_routing_request(tcp_c, tcp_connections_number, con_to->public_key) == 0) {
            tcp_con->connected_time = mono_time_get(tcp_c->mono_time);
        }
    }

    return 0;
}

/* Add a TCP relay tied to a connection.
 *
 * This should be called with the same relay by two peers who want to create a TCP connection with each other.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_connection(TCP_Connections *tcp_c, int connections_number, IP_Port ip_port, const uint8_t *relay_pk)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (!con_to) {
        return -1;
    }

    int tcp_connections_number = find_tcp_connection_relay(tcp_c, relay_pk);

    if (tcp_connections_number != -1) {
        return add_tcp_number_relay_connection(tcp_c, connections_number, tcp_connections_number);
    }

    if (online_tcp_connection_from_conn(con_to) >= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
        return -1;
    }

    tcp_connections_number = add_tcp_relay_instance(tcp_c, ip_port, relay_pk);

    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con) {
        return -1;
    }

    if (add_tcp_connection_to_conn(con_to, tcp_connections_number) == -1) {
        return -1;
    }

    return 0;
}

/* return number of online tcp relays tied to the connection on success.
 * return 0 on failure.
 */
unsigned int tcp_connection_to_online_tcp_relays(TCP_Connections *tcp_c, int connections_number)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (!con_to) {
        return 0;
    }

    return online_tcp_connection_from_conn(con_to);
}

/* Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
uint32_t tcp_copy_connected_relays(TCP_Connections *tcp_c, Node_format *tcp_relays, uint16_t max_num)
{
    const uint32_t r = random_u32();
    uint32_t copied = 0;

    for (uint32_t i = 0; (i < tcp_c->tcp_connections_length) && (copied < max_num); ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, (i + r) % tcp_c->tcp_connections_length);

        if (!tcp_con) {
            continue;
        }

        if (tcp_con->status == TCP_CONN_CONNECTED) {
            memcpy(tcp_relays[copied].public_key, tcp_con_public_key(tcp_con->connection), CRYPTO_PUBLIC_KEY_SIZE);
            tcp_relays[copied].ip_port = tcp_con_ip_port(tcp_con->connection);

            Family *const family = &tcp_relays[copied].ip_port.ip.family;

            if (net_family_is_ipv4(*family)) {
                *family = net_family_tcp_ipv4;
            } else if (net_family_is_ipv6(*family)) {
                *family = net_family_tcp_ipv6;
            }

            ++copied;
        }
    }

    return copied;
}

/* Set if we want TCP_connection to allocate some connection for onion use.
 *
 * If status is 1, allocate some connections. if status is 0, don't.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_onion_status(TCP_Connections *tcp_c, bool status)
{
    if (tcp_c->onion_status == status) {
        return -1;
    }

    if (status) {
        for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
            TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

            if (tcp_con) {
                if (tcp_con->status == TCP_CONN_CONNECTED && !tcp_con->onion) {
                    ++tcp_c->onion_num_conns;
                    tcp_con->onion = 1;
                }
            }

            if (tcp_c->onion_num_conns >= NUM_ONION_TCP_CONNECTIONS) {
                break;
            }
        }

        if (tcp_c->onion_num_conns < NUM_ONION_TCP_CONNECTIONS) {
            unsigned int wakeup = NUM_ONION_TCP_CONNECTIONS - tcp_c->onion_num_conns;

            for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
                TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

                if (tcp_con) {
                    if (tcp_con->status == TCP_CONN_SLEEPING) {
                        tcp_con->unsleep = 1;
                    }
                }

                if (!wakeup) {
                    break;
                }
            }
        }

        tcp_c->onion_status = 1;
    } else {
        for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
            TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

            if (tcp_con) {
                if (tcp_con->onion) {
                    --tcp_c->onion_num_conns;
                    tcp_con->onion = 0;
                }
            }
        }

        tcp_c->onion_status = 0;
    }

    return 0;
}

/* Returns a new TCP_Connections object associated with the secret_key.
 *
 * In order for others to connect to this instance new_tcp_connection_to() must be called with the
 * public_key associated with secret_key.
 *
 * Returns NULL on failure.
 */
TCP_Connections *new_tcp_connections(Mono_Time *mono_time, const uint8_t *secret_key, TCP_Proxy_Info *proxy_info)
{
    if (secret_key == nullptr) {
        return nullptr;
    }

    TCP_Connections *temp = (TCP_Connections *)calloc(1, sizeof(TCP_Connections));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->mono_time = mono_time;

    memcpy(temp->self_secret_key, secret_key, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(temp->self_public_key, temp->self_secret_key);
    temp->proxy_info = *proxy_info;

    return temp;
}

static void do_tcp_conns(const Logger *logger, TCP_Connections *tcp_c, void *userdata)
{
    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con == nullptr) {
            continue;
        }

        if (tcp_con->status != TCP_CONN_SLEEPING) {
            do_TCP_connection(logger, tcp_c->mono_time, tcp_con->connection, userdata);

            /* callbacks can change TCP connection address. */
            tcp_con = get_tcp_connection(tcp_c, i);

            // Make sure the TCP connection wasn't dropped in any of the callbacks.
            assert(tcp_con != nullptr);

            if (tcp_con_status(tcp_con->connection) == TCP_CLIENT_DISCONNECTED) {
                if (tcp_con->status == TCP_CONN_CONNECTED) {
                    reconnect_tcp_relay_connection(tcp_c, i);
                } else {
                    kill_tcp_relay_connection(tcp_c, i);
                }

                continue;
            }

            if (tcp_con->status == TCP_CONN_VALID && tcp_con_status(tcp_con->connection) == TCP_CLIENT_CONFIRMED) {
                tcp_relay_on_online(tcp_c, i);
            }

            if (tcp_con->status == TCP_CONN_CONNECTED && !tcp_con->onion && tcp_con->lock_count
                    && tcp_con->lock_count == tcp_con->sleep_count
                    && mono_time_is_timeout(tcp_c->mono_time, tcp_con->connected_time, TCP_CONNECTION_ANNOUNCE_TIMEOUT)) {
                sleep_tcp_relay_connection(tcp_c, i);
            }
        }

        if (tcp_con->status == TCP_CONN_SLEEPING && tcp_con->unsleep) {
            unsleep_tcp_relay_connection(tcp_c, i);
        }
    }
}

static void kill_nonused_tcp(TCP_Connections *tcp_c)
{
    if (tcp_c->tcp_connections_length == 0) {
        return;
    }

    uint32_t num_online = 0;
    uint32_t num_kill = 0;
    VLA(unsigned int, to_kill, tcp_c->tcp_connections_length);

    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con) {
            if (tcp_con->status == TCP_CONN_CONNECTED) {
                if (!tcp_con->onion && !tcp_con->lock_count
                        && mono_time_is_timeout(tcp_c->mono_time, tcp_con->connected_time, TCP_CONNECTION_ANNOUNCE_TIMEOUT)) {
                    to_kill[num_kill] = i;
                    ++num_kill;
                }

                ++num_online;
            }
        }
    }

    if (num_online <= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
        return;
    }

    uint32_t n = num_online - RECOMMENDED_FRIEND_TCP_CONNECTIONS;

    if (n < num_kill) {
        num_kill = n;
    }

    for (uint32_t i = 0; i < num_kill; ++i) {
        kill_tcp_relay_connection(tcp_c, to_kill[i]);
    }
}

void do_tcp_connections(const Logger *logger, TCP_Connections *tcp_c, void *userdata)
{
    do_tcp_conns(logger, tcp_c, userdata);
    kill_nonused_tcp(tcp_c);
}

void kill_tcp_connections(TCP_Connections *tcp_c)
{
    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        kill_TCP_connection(tcp_c->tcp_connections[i].connection);
    }

    free(tcp_c->tcp_connections);
    free(tcp_c->connections);
    free(tcp_c);
}
