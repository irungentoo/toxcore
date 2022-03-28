/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Handles TCP relay connections between two Tox clients.
 */
#include "TCP_connection.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "TCP_client.h"
#include "ccompat.h"
#include "mono_time.h"
#include "util.h"

struct TCP_Connections {
    const Logger *logger;
    const Random *rng;
    Mono_Time *mono_time;
    const Network *ns;
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

    forwarded_response_cb *tcp_forwarded_response_callback;
    void *tcp_forwarded_response_callback_object;

    TCP_Proxy_Info proxy_info;

    bool onion_status;
    uint16_t onion_num_conns;
};


static const TCP_Connection_to empty_tcp_connection_to = {0};
static const TCP_con empty_tcp_con = {0};


const uint8_t *tcp_connections_public_key(const TCP_Connections *tcp_c)
{
    return tcp_c->self_public_key;
}


uint32_t tcp_connections_count(const TCP_Connections *tcp_c)
{
    return tcp_c->tcp_connections_length;
}

/** @brief Set the size of the array to num.
 *
 * @retval -1 if realloc fails.
 * @retval 0 if it succeeds.
 */
non_null()
static int realloc_TCP_Connection_to(TCP_Connection_to **array, size_t num)
{
    if (num == 0) {
        free(*array);
        *array = nullptr;
        return 0;
    }

    TCP_Connection_to *temp_pointer =
        (TCP_Connection_to *)realloc(*array, num * sizeof(TCP_Connection_to));

    if (temp_pointer == nullptr) {
        return -1;
    }

    *array = temp_pointer;

    return 0;
}

non_null()
static int realloc_TCP_con(TCP_con **array, size_t num)
{
    if (num == 0) {
        free(*array);
        *array = nullptr;
        return 0;
    }

    TCP_con *temp_pointer = (TCP_con *)realloc(*array, num * sizeof(TCP_con));

    if (temp_pointer == nullptr) {
        return -1;
    }

    *array = temp_pointer;

    return 0;
}


/**
 * Return true if the connections_number is valid.
 */
non_null()
static bool connections_number_is_valid(const TCP_Connections *tcp_c, int connections_number)
{
    if ((unsigned int)connections_number >= tcp_c->connections_length) {
        return false;
    }

    if (tcp_c->connections == nullptr) {
        return false;
    }

    return tcp_c->connections[connections_number].status != TCP_CONN_NONE;
}

/**
 * Return true if the tcp_connections_number is valid.
 */
non_null()
static bool tcp_connections_number_is_valid(const TCP_Connections *tcp_c, int tcp_connections_number)
{
    if ((uint32_t)tcp_connections_number >= tcp_c->tcp_connections_length) {
        return false;
    }

    if (tcp_c->tcp_connections == nullptr) {
        return false;
    }

    return tcp_c->tcp_connections[tcp_connections_number].status != TCP_CONN_NONE;
}

/** @brief Create a new empty connection.
 *
 * return -1 on failure.
 * return connections_number on success.
 */
non_null()
static int create_connection(TCP_Connections *tcp_c)
{
    for (uint32_t i = 0; i < tcp_c->connections_length; ++i) {
        if (tcp_c->connections[i].status == TCP_CONN_NONE) {
            return i;
        }
    }

    int id = -1;

    if (realloc_TCP_Connection_to(&tcp_c->connections, tcp_c->connections_length + 1) == 0) {
        id = tcp_c->connections_length;
        ++tcp_c->connections_length;
        tcp_c->connections[id] = empty_tcp_connection_to;
    }

    return id;
}

/** @brief Create a new empty tcp connection.
 *
 * return -1 on failure.
 * return tcp_connections_number on success.
 */
non_null()
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
        tcp_c->tcp_connections[id] = empty_tcp_con;
    }

    return id;
}

/** @brief Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
non_null()
static int wipe_connection(TCP_Connections *tcp_c, int connections_number)
{
    if (!connections_number_is_valid(tcp_c, connections_number)) {
        return -1;
    }

    uint32_t i;
    tcp_c->connections[connections_number] = empty_tcp_connection_to;

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

/** @brief Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
non_null()
static int wipe_tcp_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    if (!tcp_connections_number_is_valid(tcp_c, tcp_connections_number)) {
        return -1;
    }

    tcp_c->tcp_connections[tcp_connections_number] = empty_tcp_con;

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

non_null()
static TCP_Connection_to *get_connection(const TCP_Connections *tcp_c, int connections_number)
{
    if (!connections_number_is_valid(tcp_c, connections_number)) {
        return nullptr;
    }

    return &tcp_c->connections[connections_number];
}

non_null()
static TCP_con *get_tcp_connection(const TCP_Connections *tcp_c, int tcp_connections_number)
{
    if (!tcp_connections_number_is_valid(tcp_c, tcp_connections_number)) {
        return nullptr;
    }

    return &tcp_c->tcp_connections[tcp_connections_number];
}

/** Returns the number of connected TCP relays */
uint32_t tcp_connected_relays_count(const TCP_Connections *tcp_c)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < tcp_connections_count(tcp_c); ++i) {
        const TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con == nullptr) {
            continue;
        }

        if (tcp_con->status == TCP_CONN_CONNECTED) {
            ++count;
        }
    }

    return count;
}

/** @brief Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_packet_tcp_connection(const TCP_Connections *tcp_c, int connections_number, const uint8_t *packet,
                               uint16_t length)
{
    const TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
        return -1;
    }

    // TODO(irungentoo): detect and kill bad relays.
    // TODO(irungentoo): thread safety?
    int ret = -1;

    bool limit_reached = false;

    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
        const uint8_t status = con_to->connections[i].status;
        const uint8_t connection_id = con_to->connections[i].connection_id;

        if (tcp_con_num > 0 && status == TCP_CONNECTIONS_STATUS_ONLINE) {
            tcp_con_num -= 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_con_num);

            if (tcp_con == nullptr) {
                continue;
            }

            ret = send_data(tcp_c->logger, tcp_con->connection, connection_id, packet, length);

            if (ret == 0) {
                limit_reached = true;
            }

            if (ret == 1) {
                break;
            }
        }
    }

    if (ret == 1) {
        return 0;
    }

    if (limit_reached) {
        return -1;
    }

    bool sent_any = false;

    /* Send oob packets to all relays tied to the connection. */
    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
        const uint8_t status = con_to->connections[i].status;

        if (tcp_con_num > 0 && status == TCP_CONNECTIONS_STATUS_REGISTERED) {
            tcp_con_num -= 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_con_num);

            if (tcp_con == nullptr) {
                continue;
            }

            if (send_oob_packet(tcp_c->logger, tcp_con->connection, con_to->public_key, packet, length) == 1) {
                sent_any = true;
            }
        }
    }

    return sent_any ? 0 : -1;
}

/** @brief Return a TCP connection number for use in send_tcp_onion_request.
 *
 * TODO(irungentoo): This number is just the index of an array that the elements
 * can change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_onion_conn_number(const TCP_Connections *tcp_c)
{
    const uint32_t r = random_u32(tcp_c->rng);

    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        const uint32_t index = (i + r) % tcp_c->tcp_connections_length;

        if (tcp_c->tcp_connections[index].onion && tcp_c->tcp_connections[index].status == TCP_CONN_CONNECTED) {
            return index;
        }
    }

    return -1;
}

/** @brief Return TCP connection number of active TCP connection with ip_port.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
non_null()
static int get_conn_number_by_ip_port(TCP_Connections *tcp_c, const IP_Port *ip_port)
{
    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        const IP_Port conn_ip_port = tcp_con_ip_port(tcp_c->tcp_connections[i].connection);

        if (ipport_equal(ip_port, &conn_ip_port) &&
                tcp_c->tcp_connections[i].status == TCP_CONN_CONNECTED) {
            return i;
        }
    }

    return -1;
}

/** @brief Put IP_Port of a random onion TCP connection in ip_port.
 *
 * return true on success.
 * return false on failure.
 */
bool tcp_get_random_conn_ip_port(const TCP_Connections *tcp_c, IP_Port *ip_port)
{
    const int index = get_random_tcp_onion_conn_number(tcp_c);

    if (index == -1) {
        return false;
    }

    *ip_port = tcp_con_ip_port(tcp_c->tcp_connections[index].connection);
    return true;
}

/** @brief Send an onion packet via the TCP relay corresponding to tcp_connections_number.
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
        const int ret = send_onion_request(tcp_c->logger, tcp_c->tcp_connections[tcp_connections_number].connection, data,
                                           length);

        if (ret == 1) {
            return 0;
        }
    }

    return -1;
}

/* Send a forward request to the TCP relay with IP_Port tcp_forwarder,
 * requesting to forward data via a chain of dht nodes starting with dht_node.
 * A chain_length of 0 means that dht_node is the final destination of data.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_forward_request(const Logger *logger, TCP_Connections *tcp_c, const IP_Port *tcp_forwarder,
                             const IP_Port *dht_node,
                             const uint8_t *chain_keys, uint16_t chain_length,
                             const uint8_t *data, uint16_t data_length)
{
    const int index = get_conn_number_by_ip_port(tcp_c, tcp_forwarder);

    if (index == -1) {
        return -1;
    }

    if (chain_length == 0) {
        return send_forward_request_tcp(logger, tcp_c->tcp_connections[index].connection, dht_node, data,
                                        data_length) == 1 ? 0 : -1;
    }

    const uint16_t len = forward_chain_packet_size(chain_length, data_length);
    VLA(uint8_t, packet, len);

    return create_forward_chain_packet(chain_keys, chain_length, data, data_length, packet)
           && send_forward_request_tcp(logger, tcp_c->tcp_connections[index].connection, dht_node, packet, len) == 1 ? 0 : -1;
}

/** @brief Send an oob packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_oob_packet(const TCP_Connections *tcp_c, unsigned int tcp_connections_number,
                        const uint8_t *public_key, const uint8_t *packet, uint16_t length)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    if (tcp_con->status != TCP_CONN_CONNECTED) {
        return -1;
    }

    const int ret = send_oob_packet(tcp_c->logger, tcp_con->connection, public_key, packet, length);

    if (ret == 1) {
        return 0;
    }

    return -1;
}

non_null()
static int find_tcp_connection_relay(const TCP_Connections *tcp_c, const uint8_t *relay_pk);

/** @brief Send an oob packet via the TCP relay corresponding to relay_pk.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_oob_packet_using_relay(const TCP_Connections *tcp_c, const uint8_t *relay_pk, const uint8_t *public_key,
                                    const uint8_t *packet, uint16_t length)
{
    const int tcp_con_number = find_tcp_connection_relay(tcp_c, relay_pk);

    if (tcp_con_number < 0) {
        return -1;
    }

    return tcp_send_oob_packet(tcp_c, tcp_con_number, public_key, packet, length);
}

/** @brief Set the callback for TCP data packets. */
void set_packet_tcp_connection_callback(TCP_Connections *tcp_c, tcp_data_cb *tcp_data_callback, void *object)
{
    tcp_c->tcp_data_callback = tcp_data_callback;
    tcp_c->tcp_data_callback_object = object;
}

/** @brief Set the callback for TCP oob data packets. */
void set_oob_packet_tcp_connection_callback(TCP_Connections *tcp_c, tcp_oob_cb *tcp_oob_callback, void *object)
{
    tcp_c->tcp_oob_callback = tcp_oob_callback;
    tcp_c->tcp_oob_callback_object = object;
}

/** @brief Set the callback for TCP onion packets. */
void set_onion_packet_tcp_connection_callback(TCP_Connections *tcp_c, tcp_onion_cb *tcp_onion_callback, void *object)
{
    tcp_c->tcp_onion_callback = tcp_onion_callback;
    tcp_c->tcp_onion_callback_object = object;
}

/** @brief Set the callback for TCP forwarding packets. */
void set_forwarding_packet_tcp_connection_callback(TCP_Connections *tcp_c,
        forwarded_response_cb *tcp_forwarded_response_callback,
        void *object)
{
    tcp_c->tcp_forwarded_response_callback = tcp_forwarded_response_callback;
    tcp_c->tcp_forwarded_response_callback_object = object;
}

/** @brief Encode tcp_connections_number as a custom ip_port.
 *
 * return ip_port.
 */
IP_Port tcp_connections_number_to_ip_port(unsigned int tcp_connections_number)
{
    IP_Port ip_port = {{{0}}};
    ip_port.ip.family = net_family_tcp_server();
    ip_port.ip.ip.v6.uint32[0] = tcp_connections_number;
    return ip_port;
}

/** @brief Decode ip_port created by tcp_connections_number_to_ip_port to tcp_connections_number.
 *
 * return true on success.
 * return false if ip_port is invalid.
 */
bool ip_port_to_tcp_connections_number(const IP_Port *ip_port, unsigned int *tcp_connections_number)
{
    *tcp_connections_number = ip_port->ip.ip.v6.uint32[0];
    return net_family_is_tcp_server(ip_port->ip.family);
}

/** @brief Find the TCP connection with public_key.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
non_null()
static int find_tcp_connection_to(const TCP_Connections *tcp_c, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < tcp_c->connections_length; ++i) {
        const TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to != nullptr) {
            if (pk_equal(con_to->public_key, public_key)) {
                return i;
            }
        }
    }

    return -1;
}

/** @brief Find the TCP connection to a relay with relay_pk.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
static int find_tcp_connection_relay(const TCP_Connections *tcp_c, const uint8_t *relay_pk)
{
    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        const TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con != nullptr) {
            if (tcp_con->status == TCP_CONN_SLEEPING) {
                if (pk_equal(tcp_con->relay_pk, relay_pk)) {
                    return i;
                }
            } else {
                if (pk_equal(tcp_con_public_key(tcp_con->connection), relay_pk)) {
                    return i;
                }
            }
        }
    }

    return -1;
}

/** @brief Create a new TCP connection to public_key.
 *
 * public_key must be the counterpart to the secret key that the other peer used with `new_tcp_connections()`.
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

    const int connections_number = create_connection(tcp_c);

    if (connections_number == -1) {
        return -1;
    }

    TCP_Connection_to *con_to = &tcp_c->connections[connections_number];

    con_to->status = TCP_CONN_VALID;
    memcpy(con_to->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    con_to->id = id;

    return connections_number;
}

/**
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int kill_tcp_connection_to(TCP_Connections *tcp_c, int connections_number)
{
    const TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
        return -1;
    }

    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection > 0) {
            const unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

            if (tcp_con == nullptr) {
                continue;
            }

            if (tcp_con->status == TCP_CONN_CONNECTED) {
                send_disconnect_request(tcp_c->logger, tcp_con->connection, con_to->connections[i].connection_id);
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

/** @brief Set connection status.
 *
 * status of 1 means we are using the connection.
 * status of 0 means we are not using it.
 *
 * Unused tcp connections will be disconnected from but kept in case they are needed.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_to_status(const TCP_Connections *tcp_c, int connections_number, bool status)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
        return -1;
    }

    if (status) {
        /* Connection is unsleeping. */
        if (con_to->status != TCP_CONN_SLEEPING) {
            return -1;
        }

        for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            if (con_to->connections[i].tcp_connection > 0) {
                const unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
                TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

                if (tcp_con == nullptr) {
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

    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection > 0) {
            unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
            TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

            if (tcp_con == nullptr) {
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

non_null()
static bool tcp_connection_in_conn(const TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
            return true;
        }
    }

    return false;
}

/**
 * @return index on success.
 * @retval -1 on failure.
 */
non_null()
static int add_tcp_connection_to_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    if (tcp_connection_in_conn(con_to, tcp_connections_number)) {
        return -1;
    }

    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == 0) {
            con_to->connections[i].tcp_connection = tcp_connections_number + 1;
            con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
            con_to->connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/**
 * @return index on success.
 * @retval -1 on failure.
 */
non_null()
static int rm_tcp_connection_from_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
            con_to->connections[i].tcp_connection = 0;
            con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
            con_to->connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/**
 * @return number of online connections on success.
 * @retval -1 on failure.
 */
non_null()
static uint32_t online_tcp_connection_from_conn(const TCP_Connection_to *con_to)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection > 0) {
            if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                ++count;
            }
        }
    }

    return count;
}

/**
 * @return index on success.
 * @retval -1 on failure.
 */
non_null()
static int set_tcp_connection_status(TCP_Connection_to *con_to, unsigned int tcp_connections_number,
                                     uint8_t status,
                                     uint8_t connection_id)
{
    for (uint32_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
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

/** @brief Kill a TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int kill_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    for (uint32_t i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to != nullptr) {
            rm_tcp_connection_from_conn(con_to, tcp_connections_number);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
    }

    kill_TCP_connection(tcp_con->connection);

    return wipe_tcp_connection(tcp_c, tcp_connections_number);
}

non_null()
static int reconnect_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    if (tcp_con->status == TCP_CONN_SLEEPING) {
        return -1;
    }

    IP_Port ip_port = tcp_con_ip_port(tcp_con->connection);
    uint8_t relay_pk[CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(relay_pk, tcp_con_public_key(tcp_con->connection), CRYPTO_PUBLIC_KEY_SIZE);
    kill_TCP_connection(tcp_con->connection);
    tcp_con->connection = new_TCP_connection(tcp_c->logger, tcp_c->mono_time, tcp_c->rng, tcp_c->ns, &ip_port, relay_pk, tcp_c->self_public_key, tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (tcp_con->connection == nullptr) {
        kill_tcp_relay_connection(tcp_c, tcp_connections_number);
        return -1;
    }

    for (uint32_t i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to != nullptr) {
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

non_null()
static int sleep_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
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

    for (uint32_t i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to != nullptr) {
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

non_null()
static int unsleep_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    if (tcp_con->status != TCP_CONN_SLEEPING) {
        return -1;
    }

    tcp_con->connection = new_TCP_connection(
            tcp_c->logger, tcp_c->mono_time, tcp_c->rng, tcp_c->ns, &tcp_con->ip_port,
            tcp_con->relay_pk, tcp_c->self_public_key, tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (tcp_con->connection == nullptr) {
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

/** @brief Send a TCP routing request.
 *
 * return 0 on success.
 * return -1 on failure.
 */
non_null()
static int send_tcp_relay_routing_request(const TCP_Connections *tcp_c, int tcp_connections_number,
        const uint8_t *public_key)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    if (tcp_con->status == TCP_CONN_SLEEPING) {
        return -1;
    }

    if (send_routing_request(tcp_c->logger, tcp_con->connection, public_key) != 1) {
        return -1;
    }

    return 0;
}

non_null()
static int tcp_response_callback(void *object, uint8_t connection_id, const uint8_t *public_key)
{
    TCP_Client_Connection *tcp_client_con = (TCP_Client_Connection *)object;
    const TCP_Connections *tcp_c = (const TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    const unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    const int connections_number = find_tcp_connection_to(tcp_c, public_key);

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

non_null()
static int tcp_status_callback(void *object, uint32_t number, uint8_t connection_id, uint8_t status)
{
    const TCP_Client_Connection *tcp_client_con = (const TCP_Client_Connection *)object;
    const TCP_Connections *tcp_c = (const TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    const unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);
    TCP_Connection_to *con_to = get_connection(tcp_c, number);

    if (con_to == nullptr || tcp_con == nullptr) {
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

non_null(1, 4) nullable(6)
static int tcp_conn_data_callback(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data,
                                  uint16_t length, void *userdata)
{
    if (length == 0) {
        return -1;
    }

    const TCP_Client_Connection *tcp_client_con = (TCP_Client_Connection *)object;
    TCP_Connections *tcp_c = (TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    const unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    const TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    const TCP_Connection_to *con_to = get_connection(tcp_c, number);

    if (con_to == nullptr) {
        return -1;
    }

    if (tcp_c->tcp_data_callback != nullptr) {
        tcp_c->tcp_data_callback(tcp_c->tcp_data_callback_object, con_to->id, data, length, userdata);
    }

    return 0;
}

non_null()
static int tcp_conn_oob_callback(void *object, const uint8_t *public_key, const uint8_t *data, uint16_t length,
                                 void *userdata)
{
    if (length == 0) {
        return -1;
    }

    const TCP_Client_Connection *tcp_client_con = (const TCP_Client_Connection *)object;
    TCP_Connections *tcp_c = (TCP_Connections *)tcp_con_custom_object(tcp_client_con);

    const unsigned int tcp_connections_number = tcp_con_custom_uint(tcp_client_con);
    const TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    /* TODO(irungentoo): optimize */
    const int connections_number = find_tcp_connection_to(tcp_c, public_key);

    const TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to != nullptr && tcp_connection_in_conn(con_to, tcp_connections_number)) {
        return tcp_conn_data_callback(object, connections_number, 0, data, length, userdata);
    }

    if (tcp_c->tcp_oob_callback != nullptr) {
        tcp_c->tcp_oob_callback(tcp_c->tcp_oob_callback_object, public_key, tcp_connections_number, data, length, userdata);
    }

    return 0;
}

non_null()
static int tcp_onion_callback(void *object, const uint8_t *data, uint16_t length, void *userdata)
{
    TCP_Connections *tcp_c = (TCP_Connections *)object;

    if (tcp_c->tcp_onion_callback != nullptr) {
        tcp_c->tcp_onion_callback(tcp_c->tcp_onion_callback_object, data, length, userdata);
    }

    return 0;
}

non_null()
static void tcp_forwarding_callback(void *object, const uint8_t *data, uint16_t length, void *userdata)
{
    TCP_Connections *tcp_c = (TCP_Connections *)object;

    if (tcp_c->tcp_forwarded_response_callback != nullptr) {
        tcp_c->tcp_forwarded_response_callback(tcp_c->tcp_forwarded_response_callback_object, data, length, userdata);
    }
}

/** @brief Set callbacks for the TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
non_null()
static int tcp_relay_set_callbacks(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    TCP_Client_Connection *con = tcp_con->connection;

    tcp_con_set_custom_object(con, tcp_c);
    tcp_con_set_custom_uint(con, tcp_connections_number);
    onion_response_handler(con, &tcp_onion_callback, tcp_c);
    forwarding_handler(con, &tcp_forwarding_callback, tcp_c);
    routing_response_handler(con, &tcp_response_callback, con);
    routing_status_handler(con, &tcp_status_callback, con);
    routing_data_handler(con, &tcp_conn_data_callback, con);
    oob_data_handler(con, &tcp_conn_oob_callback, con);

    return 0;
}

non_null()
static int tcp_relay_on_online(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    bool sent_any = false;

    for (uint32_t i = 0; i < tcp_c->connections_length; ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to != nullptr) {
            if (tcp_connection_in_conn(con_to, tcp_connections_number)) {
                if (send_tcp_relay_routing_request(tcp_c, tcp_connections_number, con_to->public_key) == 0) {
                    sent_any = true;
                }
            }
        }
    }

    tcp_relay_set_callbacks(tcp_c, tcp_connections_number);
    tcp_con->status = TCP_CONN_CONNECTED;

    /* If this connection isn't used by any connection, we don't need to wait for them to come online. */
    if (sent_any) {
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

non_null()
static int add_tcp_relay_instance(TCP_Connections *tcp_c, const IP_Port *ip_port, const uint8_t *relay_pk)
{
    IP_Port ipp_copy = *ip_port;

    if (net_family_is_tcp_ipv4(ipp_copy.ip.family)) {
        ipp_copy.ip.family = net_family_ipv4();
    } else if (net_family_is_tcp_ipv6(ipp_copy.ip.family)) {
        ipp_copy.ip.family = net_family_ipv6();
    }

    if (!net_family_is_ipv4(ipp_copy.ip.family) && !net_family_is_ipv6(ipp_copy.ip.family)) {
        return -1;
    }

    const int tcp_connections_number = create_tcp_connection(tcp_c);

    if (tcp_connections_number == -1) {
        return -1;
    }

    TCP_con *tcp_con = &tcp_c->tcp_connections[tcp_connections_number];

    tcp_con->connection = new_TCP_connection(
            tcp_c->logger, tcp_c->mono_time, tcp_c->rng, tcp_c->ns, &ipp_copy,
            relay_pk, tcp_c->self_public_key, tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (tcp_con->connection == nullptr) {
        return -1;
    }

    tcp_con->status = TCP_CONN_VALID;

    return tcp_connections_number;
}

/** @brief Add a TCP relay to the TCP_Connections instance.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_global(TCP_Connections *tcp_c, const IP_Port *ip_port, const uint8_t *relay_pk)
{
    const int tcp_connections_number = find_tcp_connection_relay(tcp_c, relay_pk);

    if (tcp_connections_number != -1) {
        return -1;
    }

    if (add_tcp_relay_instance(tcp_c, ip_port, relay_pk) == -1) {
        return -1;
    }

    return 0;
}

/** @brief Add a TCP relay tied to a connection.
 *
 * NOTE: This can only be used during the tcp_oob_callback.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_number_relay_connection(const TCP_Connections *tcp_c, int connections_number,
                                    unsigned int tcp_connections_number)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
        return -1;
    }

    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
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

/** @brief Add a TCP relay tied to a connection.
 *
 * This should be called with the same relay by two peers who want to create a TCP connection with each other.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_connection(TCP_Connections *tcp_c, int connections_number, const IP_Port *ip_port,
                             const uint8_t *relay_pk)
{
    TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
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

    const TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (tcp_con == nullptr) {
        return -1;
    }

    if (add_tcp_connection_to_conn(con_to, tcp_connections_number) == -1) {
        return -1;
    }

    return 0;
}

/**
 * @return number of online tcp relays tied to the connection on success.
 * @retval 0 on failure.
 */
uint32_t tcp_connection_to_online_tcp_relays(const TCP_Connections *tcp_c, int connections_number)
{
    const TCP_Connection_to *con_to = get_connection(tcp_c, connections_number);

    if (con_to == nullptr) {
        return 0;
    }

    return online_tcp_connection_from_conn(con_to);
}

/** @brief Copies the tcp relay from tcp connections designated by `idx` to `tcp_relay`.
 *
 * Returns true if the relay was successfully copied.
 * Returns false if the connection index is invalid, or if the relay is not connected.
 */
non_null()
static bool copy_tcp_relay_conn(const TCP_Connections *tcp_c, Node_format *tcp_relay, uint16_t idx)
{
    const TCP_con *tcp_con = get_tcp_connection(tcp_c, idx);

    if (tcp_con == nullptr) {
        return false;
    }

    if (tcp_con->status != TCP_CONN_CONNECTED) {
        return false;
    }

    memcpy(tcp_relay->public_key, tcp_con_public_key(tcp_con->connection), CRYPTO_PUBLIC_KEY_SIZE);
    tcp_relay->ip_port = tcp_con_ip_port(tcp_con->connection);

    Family *const family = &tcp_relay->ip_port.ip.family;

    if (net_family_is_ipv4(*family)) {
        *family = net_family_tcp_ipv4();
    } else if (net_family_is_ipv6(*family)) {
        *family = net_family_tcp_ipv6();
    }

    return true;
}

/** @brief Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
 *
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
uint32_t tcp_copy_connected_relays(const TCP_Connections *tcp_c, Node_format *tcp_relays, uint16_t max_num)
{
    const uint32_t r = random_u32(tcp_c->rng);
    uint32_t copied = 0;

    for (uint32_t i = 0; (i < tcp_c->tcp_connections_length) && (copied < max_num); ++i) {
        const uint16_t idx = (i + r) % tcp_c->tcp_connections_length;

        if (copy_tcp_relay_conn(tcp_c, &tcp_relays[copied], idx)) {
            ++copied;
        }
    }

    return copied;
}

uint32_t tcp_copy_connected_relays_index(const TCP_Connections *tcp_c, Node_format *tcp_relays, uint16_t max_num,
        uint32_t idx)
{
    if (tcp_c->tcp_connections_length == 0) {
        return 0;
    }

    uint32_t copied = 0;
    const uint16_t num_to_copy = min_u16(max_num, tcp_c->tcp_connections_length);
    const uint16_t start = idx % tcp_c->tcp_connections_length;
    const uint16_t end = (start + num_to_copy) % tcp_c->tcp_connections_length;

    for (uint16_t i = start; i != end; i = (i + 1) % tcp_c->tcp_connections_length) {
        if (copy_tcp_relay_conn(tcp_c, &tcp_relays[copied], i)) {
            ++copied;
        }
    }

    return copied;
}

/** @brief Set if we want TCP_connection to allocate some connection for onion use.
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

            if (tcp_con != nullptr) {
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
            const unsigned int wakeup = NUM_ONION_TCP_CONNECTIONS - tcp_c->onion_num_conns;

            for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
                TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

                if (tcp_con != nullptr) {
                    if (tcp_con->status == TCP_CONN_SLEEPING) {
                        tcp_con->unsleep = 1;
                    }
                }

                if (wakeup == 0) {
                    break;
                }
            }
        }

        tcp_c->onion_status = 1;
    } else {
        for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
            TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

            if (tcp_con != nullptr) {
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

/** @brief Returns a new TCP_Connections object associated with the secret_key.
 *
 * In order for others to connect to this instance `new_tcp_connection_to()` must be called with the
 * public_key associated with secret_key.
 *
 * Returns NULL on failure.
 */
TCP_Connections *new_tcp_connections(
        const Logger *logger, const Random *rng, const Network *ns, Mono_Time *mono_time, const uint8_t *secret_key,
        const TCP_Proxy_Info *proxy_info)
{
    if (secret_key == nullptr) {
        return nullptr;
    }

    TCP_Connections *temp = (TCP_Connections *)calloc(1, sizeof(TCP_Connections));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->logger = logger;
    temp->rng = rng;
    temp->mono_time = mono_time;
    temp->ns = ns;

    memcpy(temp->self_secret_key, secret_key, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(temp->self_public_key, temp->self_secret_key);
    temp->proxy_info = *proxy_info;

    return temp;
}

non_null(1, 2) nullable(3)
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

            if (tcp_con->status == TCP_CONN_CONNECTED
                    && !tcp_con->onion && tcp_con->lock_count > 0
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

non_null()
static void kill_nonused_tcp(TCP_Connections *tcp_c)
{
    if (tcp_c->tcp_connections_length <= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
        return;
    }

    const uint32_t num_online = tcp_connected_relays_count(tcp_c);

    if (num_online <= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
        return;
    }

    const uint32_t max_kill_count = num_online - RECOMMENDED_FRIEND_TCP_CONNECTIONS;
    uint32_t kill_count = 0;

    for (uint32_t i = 0; i < tcp_c->tcp_connections_length && kill_count < max_kill_count; ++i) {
        const TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con == nullptr) {
            continue;
        }

        if (tcp_con->status == TCP_CONN_CONNECTED) {
            if (tcp_con->onion || tcp_con->lock_count > 0) {  // connection is in use so we skip it
                continue;
            }

            if (mono_time_is_timeout(tcp_c->mono_time, tcp_con->connected_time, TCP_CONNECTION_ANNOUNCE_TIMEOUT)) {
                kill_tcp_relay_connection(tcp_c, i);
                ++kill_count;
            }
        }
    }
}

void do_tcp_connections(const Logger *logger, TCP_Connections *tcp_c, void *userdata)
{
    do_tcp_conns(logger, tcp_c, userdata);
    kill_nonused_tcp(tcp_c);
}

void kill_tcp_connections(TCP_Connections *tcp_c)
{
    if (tcp_c == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < tcp_c->tcp_connections_length; ++i) {
        kill_TCP_connection(tcp_c->tcp_connections[i].connection);
    }

    crypto_memzero(tcp_c->self_secret_key, sizeof(tcp_c->self_secret_key));

    free(tcp_c->tcp_connections);
    free(tcp_c->connections);
    free(tcp_c);
}
