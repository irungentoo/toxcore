/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay server part of Tox.
 */
#include "TCP_server.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif

#ifdef TCP_SERVER_USE_EPOLL
#include <sys/epoll.h>
#include <unistd.h>
#endif

#include "TCP_common.h"
#include "ccompat.h"
#include "list.h"
#include "mono_time.h"
#include "util.h"

#ifdef TCP_SERVER_USE_EPOLL
#define TCP_SOCKET_LISTENING 0
#define TCP_SOCKET_INCOMING 1
#define TCP_SOCKET_UNCONFIRMED 2
#define TCP_SOCKET_CONFIRMED 3
#endif

typedef struct TCP_Secure_Conn {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint32_t index;
    // TODO(iphydf): Add an enum for this (same as in TCP_client.c, probably).
    uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
    uint8_t other_id;
} TCP_Secure_Conn;

typedef struct TCP_Secure_Connection {
    TCP_Connection con;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint16_t next_packet_length;
    TCP_Secure_Conn connections[NUM_CLIENT_CONNECTIONS];
    uint8_t status;

    uint64_t identifier;

    uint64_t last_pinged;
    uint64_t ping_id;
} TCP_Secure_Connection;


struct TCP_Server {
    const Logger *logger;
    const Random *rng;
    const Network *ns;
    Onion *onion;
    Forwarding *forwarding;

#ifdef TCP_SERVER_USE_EPOLL
    int efd;
    uint64_t last_run_pinged;
#endif
    Socket *socks_listening;
    unsigned int num_listening_socks;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE];
    TCP_Secure_Connection incoming_connection_queue[MAX_INCOMING_CONNECTIONS];
    uint16_t incoming_connection_queue_index;
    TCP_Secure_Connection unconfirmed_connection_queue[MAX_INCOMING_CONNECTIONS];
    uint16_t unconfirmed_connection_queue_index;

    TCP_Secure_Connection *accepted_connection_array;
    uint32_t size_accepted_connections;
    uint32_t num_accepted_connections;

    uint64_t counter;

    BS_List accepted_key_list;
};

const uint8_t *tcp_server_public_key(const TCP_Server *tcp_server)
{
    return tcp_server->public_key;
}

size_t tcp_server_listen_count(const TCP_Server *tcp_server)
{
    return tcp_server->num_listening_socks;
}

/** This is needed to compile on Android below API 21 */
#ifdef TCP_SERVER_USE_EPOLL
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
#endif

/** @brief Increase the size of the connection list
 *
 * @retval -1 on failure
 * @retval 0 on success.
 */
non_null()
static int alloc_new_connections(TCP_Server *tcp_server, uint32_t num)
{
    const uint32_t new_size = tcp_server->size_accepted_connections + num;

    if (new_size < tcp_server->size_accepted_connections) {
        return -1;
    }

    TCP_Secure_Connection *new_connections = (TCP_Secure_Connection *)realloc(
                tcp_server->accepted_connection_array,
                new_size * sizeof(TCP_Secure_Connection));

    if (new_connections == nullptr) {
        return -1;
    }

    const uint32_t old_size = tcp_server->size_accepted_connections;
    const uint32_t size_new_entries = num * sizeof(TCP_Secure_Connection);
    memset(new_connections + old_size, 0, size_new_entries);

    tcp_server->accepted_connection_array = new_connections;
    tcp_server->size_accepted_connections = new_size;
    return 0;
}

non_null()
static void wipe_secure_connection(TCP_Secure_Connection *con)
{
    if (con->status != 0) {
        wipe_priority_list(con->con.priority_queue_start);
        crypto_memzero(con, sizeof(TCP_Secure_Connection));
    }
}

non_null()
static void move_secure_connection(TCP_Secure_Connection *con_new, TCP_Secure_Connection *con_old)
{
    *con_new = *con_old;
    crypto_memzero(con_old, sizeof(TCP_Secure_Connection));
}

non_null()
static void free_accepted_connection_array(TCP_Server *tcp_server)
{
    if (tcp_server->accepted_connection_array == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < tcp_server->size_accepted_connections; ++i) {
        wipe_secure_connection(&tcp_server->accepted_connection_array[i]);
    }

    free(tcp_server->accepted_connection_array);
    tcp_server->accepted_connection_array = nullptr;
    tcp_server->size_accepted_connections = 0;
}

/** 
 * @return index corresponding to connection with peer on success
 * @retval -1 on failure.
 */
non_null()
static int get_TCP_connection_index(const TCP_Server *tcp_server, const uint8_t *public_key)
{
    return bs_list_find(&tcp_server->accepted_key_list, public_key);
}


non_null()
static int kill_accepted(TCP_Server *tcp_server, int index);

/** @brief Add accepted TCP connection to the list.
 *
 * @return index on success
 * @retval -1 on failure
 */
non_null()
static int add_accepted(TCP_Server *tcp_server, const Mono_Time *mono_time, TCP_Secure_Connection *con)
{
    int index = get_TCP_connection_index(tcp_server, con->public_key);

    if (index != -1) { /* If an old connection to the same public key exists, kill it. */
        kill_accepted(tcp_server, index);
        index = -1;
    }

    if (tcp_server->size_accepted_connections == tcp_server->num_accepted_connections) {
        if (alloc_new_connections(tcp_server, 4) == -1) {
            return -1;
        }

        index = tcp_server->num_accepted_connections;
    } else {
        for (uint32_t i = tcp_server->size_accepted_connections; i != 0; --i) {
            if (tcp_server->accepted_connection_array[i - 1].status == TCP_STATUS_NO_STATUS) {
                index = i - 1;
                break;
            }
        }
    }

    if (index == -1) {
        LOGGER_ERROR(tcp_server->logger, "FAIL index is -1");
        return -1;
    }

    if (!bs_list_add(&tcp_server->accepted_key_list, con->public_key, index)) {
        return -1;
    }

    move_secure_connection(&tcp_server->accepted_connection_array[index], con);

    tcp_server->accepted_connection_array[index].status = TCP_STATUS_CONFIRMED;
    ++tcp_server->num_accepted_connections;
    tcp_server->accepted_connection_array[index].identifier = ++tcp_server->counter;
    tcp_server->accepted_connection_array[index].last_pinged = mono_time_get(mono_time);
    tcp_server->accepted_connection_array[index].ping_id = 0;

    return index;
}

/** @brief Delete accepted connection from list.
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
non_null()
static int del_accepted(TCP_Server *tcp_server, int index)
{
    if ((uint32_t)index >= tcp_server->size_accepted_connections) {
        return -1;
    }

    if (tcp_server->accepted_connection_array[index].status == TCP_STATUS_NO_STATUS) {
        return -1;
    }

    if (!bs_list_remove(&tcp_server->accepted_key_list, tcp_server->accepted_connection_array[index].public_key, index)) {
        return -1;
    }

    wipe_secure_connection(&tcp_server->accepted_connection_array[index]);
    --tcp_server->num_accepted_connections;

    if (tcp_server->num_accepted_connections == 0) {
        free_accepted_connection_array(tcp_server);
    }

    return 0;
}

/** Kill a TCP_Secure_Connection */
non_null()
static void kill_TCP_secure_connection(TCP_Secure_Connection *con)
{
    kill_sock(con->con.ns, con->con.sock);
    wipe_secure_connection(con);
}

non_null()
static int rm_connection_index(TCP_Server *tcp_server, TCP_Secure_Connection *con, uint8_t con_number);

/** @brief Kill an accepted TCP_Secure_Connection
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int kill_accepted(TCP_Server *tcp_server, int index)
{
    if ((uint32_t)index >= tcp_server->size_accepted_connections) {
        return -1;
    }

    for (uint32_t i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        rm_connection_index(tcp_server, &tcp_server->accepted_connection_array[index], i);
    }

    const Socket sock = tcp_server->accepted_connection_array[index].con.sock;

    if (del_accepted(tcp_server, index) != 0) {
        return -1;
    }

    kill_sock(tcp_server->ns, sock);
    return 0;
}

/**
 * @retval 1 if everything went well.
 * @retval -1 if the connection must be killed.
 */
non_null()
static int handle_TCP_handshake(const Logger *logger, TCP_Secure_Connection *con, const uint8_t *data, uint16_t length,
                                const uint8_t *self_secret_key)
{
    if (length != TCP_CLIENT_HANDSHAKE_SIZE) {
        LOGGER_ERROR(logger, "invalid handshake length: %d != %d", length, TCP_CLIENT_HANDSHAKE_SIZE);
        return -1;
    }

    if (con->status != TCP_STATUS_CONNECTED) {
        LOGGER_ERROR(logger, "TCP connection %u not connected", (unsigned int)con->identifier);
        return -1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(data, self_secret_key, shared_key);
    uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
    int len = decrypt_data_symmetric(shared_key, data + CRYPTO_PUBLIC_KEY_SIZE,
                                     data + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE, plain);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE) {
        LOGGER_ERROR(logger, "invalid TCP handshake decrypted length: %d != %d", len, TCP_HANDSHAKE_PLAIN_SIZE);
        crypto_memzero(shared_key, sizeof(shared_key));
        return -1;
    }

    memcpy(con->public_key, data, CRYPTO_PUBLIC_KEY_SIZE);
    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t resp_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_new_keypair(con->con.rng, resp_plain, temp_secret_key);
    random_nonce(con->con.rng, con->con.sent_nonce);
    memcpy(resp_plain + CRYPTO_PUBLIC_KEY_SIZE, con->con.sent_nonce, CRYPTO_NONCE_SIZE);
    memcpy(con->recv_nonce, plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    random_nonce(con->con.rng, response);

    len = encrypt_data_symmetric(shared_key, response, resp_plain, TCP_HANDSHAKE_PLAIN_SIZE,
                                 response + CRYPTO_NONCE_SIZE);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return -1;
    }

    IP_Port ipp = {{{0}}};

    if (TCP_SERVER_HANDSHAKE_SIZE != net_send(con->con.ns, logger, con->con.sock, response, TCP_SERVER_HANDSHAKE_SIZE, &ipp)) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return -1;
    }

    encrypt_precompute(plain, temp_secret_key, con->con.shared_key);
    con->status = TCP_STATUS_UNCONFIRMED;

    crypto_memzero(shared_key, sizeof(shared_key));

    return 1;
}

/**
 * @retval 1 if connection handshake was handled correctly.
 * @retval 0 if we didn't get it yet.
 * @retval -1 if the connection must be killed.
 */
non_null()
static int read_connection_handshake(const Logger *logger, TCP_Secure_Connection *con, const uint8_t *self_secret_key)
{
    uint8_t data[TCP_CLIENT_HANDSHAKE_SIZE];
    const int len = read_TCP_packet(logger, con->con.ns, con->con.sock, data, TCP_CLIENT_HANDSHAKE_SIZE, &con->con.ip_port);

    if (len == -1) {
        LOGGER_TRACE(logger, "connection handshake is not ready yet");
        return 0;
    }

    return handle_TCP_handshake(logger, con, data, len, self_secret_key);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
static int send_routing_response(const Logger *logger, TCP_Secure_Connection *con, uint8_t rpid,
                                 const uint8_t *public_key)
{
    uint8_t data[1 + 1 + CRYPTO_PUBLIC_KEY_SIZE];
    data[0] = TCP_PACKET_ROUTING_RESPONSE;
    data[1] = rpid;
    memcpy(data + 2, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    return write_packet_TCP_secure_connection(logger, &con->con, data, sizeof(data), true);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
static int send_connect_notification(const Logger *logger, TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_CONNECTION_NOTIFICATION, (uint8_t)(id + NUM_RESERVED_PORTS)};
    return write_packet_TCP_secure_connection(logger, &con->con, data, sizeof(data), true);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
static int send_disconnect_notification(const Logger *logger, TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_DISCONNECT_NOTIFICATION, (uint8_t)(id + NUM_RESERVED_PORTS)};
    return write_packet_TCP_secure_connection(logger, &con->con, data, sizeof(data), true);
}

/**
 * @retval 0 on success.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
static int handle_TCP_routing_req(TCP_Server *tcp_server, uint32_t con_id, const uint8_t *public_key)
{
    uint32_t index = -1;
    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    /* If person tries to cennect to himself we deny the request*/
    if (pk_equal(con->public_key, public_key)) {
        if (send_routing_response(tcp_server->logger, con, 0, public_key) == -1) {
            return -1;
        }

        return 0;
    }

    for (uint32_t i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        if (con->connections[i].status != 0) {
            if (pk_equal(public_key, con->connections[i].public_key)) {
                if (send_routing_response(tcp_server->logger, con, i + NUM_RESERVED_PORTS, public_key) == -1) {
                    return -1;
                }

                return 0;
            }
        } else if (index == (uint32_t) -1) {
            index = i;
        }
    }

    if (index == (uint32_t) -1) {
        if (send_routing_response(tcp_server->logger, con, 0, public_key) == -1) {
            return -1;
        }

        return 0;
    }

    const int ret = send_routing_response(tcp_server->logger, con, index + NUM_RESERVED_PORTS, public_key);

    if (ret == 0) {
        return 0;
    }

    if (ret == -1) {
        return -1;
    }

    con->connections[index].status = 1;
    memcpy(con->connections[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    const int other_index = get_TCP_connection_index(tcp_server, public_key);

    if (other_index != -1) {
        uint32_t other_id = -1;
        TCP_Secure_Connection *other_conn = &tcp_server->accepted_connection_array[other_index];

        for (uint32_t i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
            if (other_conn->connections[i].status == 1
                    && pk_equal(other_conn->connections[i].public_key, con->public_key)) {
                other_id = i;
                break;
            }
        }

        if (other_id != (uint32_t) -1) {
            con->connections[index].status = 2;
            con->connections[index].index = other_index;
            con->connections[index].other_id = other_id;
            other_conn->connections[other_id].status = 2;
            other_conn->connections[other_id].index = con_id;
            other_conn->connections[other_id].other_id = index;
            // TODO(irungentoo): return values?
            send_connect_notification(tcp_server->logger, con, index);
            send_connect_notification(tcp_server->logger, other_conn, other_id);
        }
    }

    return 0;
}

/**
 * @retval 0 on success.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
static int handle_TCP_oob_send(TCP_Server *tcp_server, uint32_t con_id, const uint8_t *public_key, const uint8_t *data,
                               uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH) {
        return -1;
    }

    const TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    const int other_index = get_TCP_connection_index(tcp_server, public_key);

    if (other_index != -1) {
        VLA(uint8_t, resp_packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + length);
        resp_packet[0] = TCP_PACKET_OOB_RECV;
        memcpy(resp_packet + 1, con->public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(resp_packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length);
        write_packet_TCP_secure_connection(tcp_server->logger, &tcp_server->accepted_connection_array[other_index].con,
                                           resp_packet, SIZEOF_VLA(resp_packet), false);
    }

    return 0;
}

/** @brief Remove connection with con_number from the connections array of con.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int rm_connection_index(TCP_Server *tcp_server, TCP_Secure_Connection *con, uint8_t con_number)
{
    if (con_number >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    if (con->connections[con_number].status != 0) {
        if (con->connections[con_number].status == 2) {
            const uint32_t index = con->connections[con_number].index;
            const uint8_t other_id = con->connections[con_number].other_id;

            if (index >= tcp_server->size_accepted_connections) {
                return -1;
            }

            tcp_server->accepted_connection_array[index].connections[other_id].other_id = 0;
            tcp_server->accepted_connection_array[index].connections[other_id].index = 0;
            tcp_server->accepted_connection_array[index].connections[other_id].status = 1;
            // TODO(irungentoo): return values?
            send_disconnect_notification(tcp_server->logger, &tcp_server->accepted_connection_array[index], other_id);
        }

        con->connections[con_number].index = 0;
        con->connections[con_number].other_id = 0;
        con->connections[con_number].status = 0;
        return 0;
    }

    return -1;
}

/** @brief Encode con_id and identifier as a custom IP_Port.
 *
 * @return ip_port.
 */
static IP_Port con_id_to_ip_port(uint32_t con_id, uint64_t identifier)
{
    IP_Port ip_port = {{{0}}};
    ip_port.ip.family = net_family_tcp_client();
    ip_port.ip.ip.v6.uint32[0] = con_id;
    ip_port.ip.ip.v6.uint64[1] = identifier;
    return ip_port;

}

/** @brief Decode ip_port created by con_id_to_ip_port to con_id.
 *
 * @retval true on success.
 * @retval false if ip_port is invalid.
 */
non_null()
static bool ip_port_to_con_id(const TCP_Server *tcp_server, const IP_Port *ip_port, uint32_t *con_id)
{
    *con_id = ip_port->ip.ip.v6.uint32[0];

    return net_family_is_tcp_client(ip_port->ip.family) &&
           *con_id < tcp_server->size_accepted_connections &&
           tcp_server->accepted_connection_array[*con_id].identifier == ip_port->ip.ip.v6.uint64[1];
}

non_null()
static int handle_onion_recv_1(void *object, const IP_Port *dest, const uint8_t *data, uint16_t length)
{
    TCP_Server *tcp_server = (TCP_Server *)object;
    uint32_t index;

    if (!ip_port_to_con_id(tcp_server, dest, &index)) {
        return 1;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[index];

    VLA(uint8_t, packet, 1 + length);
    memcpy(packet + 1, data, length);
    packet[0] = TCP_PACKET_ONION_RESPONSE;

    if (write_packet_TCP_secure_connection(tcp_server->logger, &con->con, packet, SIZEOF_VLA(packet), false) != 1) {
        return 1;
    }

    return 0;
}

non_null()
static bool handle_forward_reply_tcp(void *object, const uint8_t *sendback_data, uint16_t sendback_data_len,
                                     const uint8_t *data, uint16_t length)
{
    TCP_Server *tcp_server = (TCP_Server *)object;

    if (sendback_data_len != 1 + sizeof(uint32_t) + sizeof(uint64_t)) {
        return false;
    }

    if (*sendback_data != SENDBACK_TCP) {
        return false;
    }

    uint32_t con_id;
    uint64_t identifier;
    net_unpack_u32(sendback_data + 1, &con_id);
    net_unpack_u64(sendback_data + 1 + sizeof(uint32_t), &identifier);

    if (con_id >= tcp_server->size_accepted_connections) {
        return false;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    if (con->identifier != identifier) {
        return false;
    }

    VLA(uint8_t, packet, 1 + length);
    memcpy(packet + 1, data, length);
    packet[0] = TCP_PACKET_FORWARDING;

    return write_packet_TCP_secure_connection(tcp_server->logger, &con->con, packet, SIZEOF_VLA(packet), false) == 1;
}

/**
 * @retval 0 on success
 * @retval -1 on failure
 */
non_null()
static int handle_TCP_packet(TCP_Server *tcp_server, uint32_t con_id, const uint8_t *data, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    TCP_Secure_Connection *const con = &tcp_server->accepted_connection_array[con_id];

    switch (data[0]) {
        case TCP_PACKET_ROUTING_REQUEST: {
            if (length != 1 + CRYPTO_PUBLIC_KEY_SIZE) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling routing request for %d", con_id);
            return handle_TCP_routing_req(tcp_server, con_id, data + 1);
        }

        case TCP_PACKET_CONNECTION_NOTIFICATION: {
            if (length != 2) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling connection notification for %d", con_id);
            break;
        }

        case TCP_PACKET_DISCONNECT_NOTIFICATION: {
            if (length != 2) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling disconnect notification for %d", con_id);
            return rm_connection_index(tcp_server, con, data[1] - NUM_RESERVED_PORTS);
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t)) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling ping for %d", con_id);

            uint8_t response[1 + sizeof(uint64_t)];
            response[0] = TCP_PACKET_PONG;
            memcpy(response + 1, data + 1, sizeof(uint64_t));
            write_packet_TCP_secure_connection(tcp_server->logger, &con->con, response, sizeof(response), true);
            return 0;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t)) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling pong for %d", con_id);

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));

            if (ping_id != 0) {
                if (ping_id == con->ping_id) {
                    con->ping_id = 0;
                }

                return 0;
            }

            return -1;
        }

        case TCP_PACKET_OOB_SEND: {
            if (length <= 1 + CRYPTO_PUBLIC_KEY_SIZE) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling oob send for %d", con_id);

            return handle_TCP_oob_send(tcp_server, con_id, data + 1, data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                       length - (1 + CRYPTO_PUBLIC_KEY_SIZE));
        }

        case TCP_PACKET_ONION_REQUEST: {
            LOGGER_TRACE(tcp_server->logger, "handling onion request for %d", con_id);

            if (tcp_server->onion != nullptr) {
                if (length <= 1 + CRYPTO_NONCE_SIZE + ONION_SEND_BASE * 2) {
                    return -1;
                }

                IP_Port source = con_id_to_ip_port(con_id, con->identifier);
                onion_send_1(tcp_server->onion, data + 1 + CRYPTO_NONCE_SIZE, length - (1 + CRYPTO_NONCE_SIZE), &source,
                             data + 1);
            }

            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {
            LOGGER_TRACE(tcp_server->logger, "handling onion response for %d", con_id);
            return -1;
        }

        case TCP_PACKET_FORWARD_REQUEST: {
            if (tcp_server->forwarding == nullptr) {
                return -1;
            }

            const uint16_t sendback_data_len = 1 + sizeof(uint32_t) + sizeof(uint64_t);
            uint8_t sendback_data[1 + sizeof(uint32_t) + sizeof(uint64_t)];
            sendback_data[0] = SENDBACK_TCP;
            net_pack_u32(sendback_data + 1, con_id);
            net_pack_u64(sendback_data + 1 + sizeof(uint32_t), con->identifier);

            IP_Port dest;
            const int ipport_length = unpack_ip_port(&dest, data + 1, length - 1, false);

            if (ipport_length == -1) {
                return -1;
            }

            const uint8_t *const forward_data = data + (1 + ipport_length);
            const uint16_t forward_data_len = length - (1 + ipport_length);

            if (forward_data_len > MAX_FORWARD_DATA_SIZE) {
                return -1;
            }

            send_forwarding(tcp_server->forwarding, &dest, sendback_data, sendback_data_len, forward_data, forward_data_len);
            return 0;
        }

        case TCP_PACKET_FORWARDING: {
            return -1;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS) {
                return -1;
            }

            const uint8_t c_id = data[0] - NUM_RESERVED_PORTS;
            LOGGER_TRACE(tcp_server->logger, "handling packet id %d for %d", c_id, con_id);

            if (c_id >= NUM_CLIENT_CONNECTIONS) {
                return -1;
            }

            if (con->connections[c_id].status == 0) {
                return -1;
            }

            if (con->connections[c_id].status != 2) {
                return 0;
            }

            const uint32_t index = con->connections[c_id].index;
            const uint8_t other_c_id = con->connections[c_id].other_id + NUM_RESERVED_PORTS;
            VLA(uint8_t, new_data, length);
            memcpy(new_data, data, length);
            new_data[0] = other_c_id;
            const int ret = write_packet_TCP_secure_connection(tcp_server->logger,
                            &tcp_server->accepted_connection_array[index].con, new_data, length, false);

            if (ret == -1) {
                return -1;
            }

            return 0;
        }
    }

    return 0;
}


non_null()
static int confirm_TCP_connection(TCP_Server *tcp_server, const Mono_Time *mono_time, TCP_Secure_Connection *con,
                                  const uint8_t *data, uint16_t length)
{
    const int index = add_accepted(tcp_server, mono_time, con);

    if (index == -1) {
        LOGGER_DEBUG(tcp_server->logger, "dropping connection %u: not accepted", (unsigned int)con->identifier);
        kill_TCP_secure_connection(con);
        return -1;
    }

    wipe_secure_connection(con);

    if (handle_TCP_packet(tcp_server, index, data, length) == -1) {
        LOGGER_DEBUG(tcp_server->logger, "dropping connection %u: data packet (len=%d) not handled",
                     (unsigned int)con->identifier, length);
        kill_accepted(tcp_server, index);
        return -1;
    }

    return index;
}

/**
 * @return index on success
 * @retval -1 on failure
 */
non_null()
static int accept_connection(TCP_Server *tcp_server, Socket sock)
{
    if (!sock_valid(sock)) {
        return -1;
    }

    if (!set_socket_nonblock(tcp_server->ns, sock)) {
        kill_sock(tcp_server->ns, sock);
        return -1;
    }

    if (!set_socket_nosigpipe(tcp_server->ns, sock)) {
        kill_sock(tcp_server->ns, sock);
        return -1;
    }

    const uint16_t index = tcp_server->incoming_connection_queue_index % MAX_INCOMING_CONNECTIONS;

    TCP_Secure_Connection *conn = &tcp_server->incoming_connection_queue[index];

    if (conn->status != TCP_STATUS_NO_STATUS) {
        LOGGER_DEBUG(tcp_server->logger, "connection %d dropped before accepting", index);
        kill_TCP_secure_connection(conn);
    }

    conn->status = TCP_STATUS_CONNECTED;
    conn->con.ns = tcp_server->ns;
    conn->con.rng = tcp_server->rng;
    conn->con.sock = sock;
    conn->next_packet_length = 0;

    ++tcp_server->incoming_connection_queue_index;
    return index;
}

non_null()
static Socket new_listening_TCP_socket(const Logger *logger, const Network *ns, Family family, uint16_t port)
{
    const Socket sock = net_socket(ns, family, TOX_SOCK_STREAM, TOX_PROTO_TCP);

    if (!sock_valid(sock)) {
        LOGGER_ERROR(logger, "TCP socket creation failed (family = %d)", family.value);
        return net_invalid_socket;
    }

    bool ok = set_socket_nonblock(ns, sock);

    if (ok && net_family_is_ipv6(family)) {
        ok = set_socket_dualstack(ns, sock);
    }

    if (ok) {
        ok = set_socket_reuseaddr(ns, sock);
    }

    ok = ok && bind_to_port(ns, sock, family, port) && (net_listen(ns, sock, TCP_MAX_BACKLOG) == 0);

    if (!ok) {
        char *const error = net_new_strerror(net_error());
        LOGGER_WARNING(logger, "could not bind to TCP port %d (family = %d): %s",
                       port, family.value, error != nullptr ? error : "(null)");
        net_kill_strerror(error);
        kill_sock(ns, sock);
        return net_invalid_socket;
    }

    LOGGER_DEBUG(logger, "successfully bound to TCP port %d", port);
    return sock;
}

TCP_Server *new_TCP_server(const Logger *logger, const Random *rng, const Network *ns,
                           bool ipv6_enabled, uint16_t num_sockets,
                           const uint16_t *ports, const uint8_t *secret_key, Onion *onion, Forwarding *forwarding)
{
    if (num_sockets == 0 || ports == nullptr) {
        LOGGER_ERROR(logger, "no sockets");
        return nullptr;
    }

    if (ns == nullptr) {
        LOGGER_ERROR(logger, "NULL network");
        return nullptr;
    }

    TCP_Server *temp = (TCP_Server *)calloc(1, sizeof(TCP_Server));

    if (temp == nullptr) {
        LOGGER_ERROR(logger, "TCP server allocation failed");
        return nullptr;
    }

    temp->logger = logger;
    temp->ns = ns;
    temp->rng = rng;

    temp->socks_listening = (Socket *)calloc(num_sockets, sizeof(Socket));

    if (temp->socks_listening == nullptr) {
        LOGGER_ERROR(logger, "socket allocation failed");
        free(temp);
        return nullptr;
    }

#ifdef TCP_SERVER_USE_EPOLL
    temp->efd = epoll_create(8);

    if (temp->efd == -1) {
        LOGGER_ERROR(logger, "epoll initialisation failed");
        free(temp->socks_listening);
        free(temp);
        return nullptr;
    }

#endif

    const Family family = ipv6_enabled ? net_family_ipv6() : net_family_ipv4();

    for (uint32_t i = 0; i < num_sockets; ++i) {
        const Socket sock = new_listening_TCP_socket(logger, ns, family, ports[i]);

        if (!sock_valid(sock)) {
            continue;
        }

#ifdef TCP_SERVER_USE_EPOLL
        struct epoll_event ev;

        ev.events = EPOLLIN | EPOLLET;
        ev.data.u64 = sock.sock | ((uint64_t)TCP_SOCKET_LISTENING << 32);

        if (epoll_ctl(temp->efd, EPOLL_CTL_ADD, sock.sock, &ev) == -1) {
            continue;
        }

#endif

        temp->socks_listening[temp->num_listening_socks] = sock;
        ++temp->num_listening_socks;
    }

    if (temp->num_listening_socks == 0) {
        free(temp->socks_listening);
        free(temp);
        return nullptr;
    }

    if (onion != nullptr) {
        temp->onion = onion;
        set_callback_handle_recv_1(onion, &handle_onion_recv_1, temp);
    }

    if (forwarding != nullptr) {
        temp->forwarding = forwarding;
        set_callback_forward_reply(forwarding, &handle_forward_reply_tcp, temp);
    }

    memcpy(temp->secret_key, secret_key, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(temp->public_key, temp->secret_key);

    bs_list_init(&temp->accepted_key_list, CRYPTO_PUBLIC_KEY_SIZE, 8);

    return temp;
}

#ifndef TCP_SERVER_USE_EPOLL
non_null()
static void do_TCP_accept_new(TCP_Server *tcp_server)
{
    for (uint32_t i = 0; i < tcp_server->num_listening_socks; ++i) {
        Socket sock;

        do {
            sock = net_accept(tcp_server->ns, tcp_server->socks_listening[i]);
        } while (accept_connection(tcp_server, sock) != -1);
    }
}
#endif

non_null()
static int do_incoming(TCP_Server *tcp_server, uint32_t i)
{
    TCP_Secure_Connection *const conn = &tcp_server->incoming_connection_queue[i];

    if (conn->status != TCP_STATUS_CONNECTED) {
        return -1;
    }

    LOGGER_TRACE(tcp_server->logger, "handling incoming TCP connection %d", i);

    const int ret = read_connection_handshake(tcp_server->logger, conn, tcp_server->secret_key);

    if (ret == -1) {
        LOGGER_TRACE(tcp_server->logger, "incoming connection %d dropped due to failed handshake", i);
        kill_TCP_secure_connection(conn);
        return -1;
    }

    if (ret != 1) {
        return -1;
    }

    const int index_new = tcp_server->unconfirmed_connection_queue_index % MAX_INCOMING_CONNECTIONS;
    TCP_Secure_Connection *conn_old = conn;
    TCP_Secure_Connection *conn_new = &tcp_server->unconfirmed_connection_queue[index_new];

    if (conn_new->status != TCP_STATUS_NO_STATUS) {
        LOGGER_ERROR(tcp_server->logger, "incoming connection %d would overwrite existing", i);
        kill_TCP_secure_connection(conn_new);
    }

    move_secure_connection(conn_new, conn_old);
    ++tcp_server->unconfirmed_connection_queue_index;

    return index_new;
}

non_null()
static int do_unconfirmed(TCP_Server *tcp_server, const Mono_Time *mono_time, uint32_t i)
{
    TCP_Secure_Connection *const conn = &tcp_server->unconfirmed_connection_queue[i];

    if (conn->status != TCP_STATUS_UNCONFIRMED) {
        return -1;
    }

    LOGGER_TRACE(tcp_server->logger, "handling unconfirmed TCP connection %d", i);

    uint8_t packet[MAX_PACKET_SIZE];
    const int len = read_packet_TCP_secure_connection(tcp_server->logger, conn->con.ns, conn->con.sock, &conn->next_packet_length, conn->con.shared_key, conn->recv_nonce, packet, sizeof(packet), &conn->con.ip_port);

    if (len == 0) {
        return -1;
    }

    if (len == -1) {
        kill_TCP_secure_connection(conn);
        return -1;
    }

    return confirm_TCP_connection(tcp_server, mono_time, conn, packet, len);
}

non_null()
static bool tcp_process_secure_packet(TCP_Server *tcp_server, uint32_t i)
{
    TCP_Secure_Connection *const conn = &tcp_server->accepted_connection_array[i];

    uint8_t packet[MAX_PACKET_SIZE];
    const int len = read_packet_TCP_secure_connection(tcp_server->logger, conn->con.ns, conn->con.sock, &conn->next_packet_length, conn->con.shared_key, conn->recv_nonce, packet, sizeof(packet), &conn->con.ip_port);
    LOGGER_TRACE(tcp_server->logger, "processing packet for %d: %d", i, len);

    if (len == 0) {
        return false;
    }

    if (len == -1) {
        kill_accepted(tcp_server, i);
        return false;
    }

    if (handle_TCP_packet(tcp_server, i, packet, len) == -1) {
        LOGGER_TRACE(tcp_server->logger, "dropping connection %d: data packet (len=%d) not handled", i, len);
        kill_accepted(tcp_server, i);
        return false;
    }

    return true;
}

non_null()
static void do_confirmed_recv(TCP_Server *tcp_server, uint32_t i)
{
    while (tcp_process_secure_packet(tcp_server, i)) {
        // Keep reading until an error occurs or there is no more data to read.
        continue;
    }
}

#ifndef TCP_SERVER_USE_EPOLL
non_null()
static void do_TCP_incoming(TCP_Server *tcp_server)
{
    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        do_incoming(tcp_server, i);
    }
}

non_null()
static void do_TCP_unconfirmed(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        do_unconfirmed(tcp_server, mono_time, i);
    }
}
#endif

non_null()
static void do_TCP_confirmed(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
#ifdef TCP_SERVER_USE_EPOLL

    if (tcp_server->last_run_pinged == mono_time_get(mono_time)) {
        return;
    }

    tcp_server->last_run_pinged = mono_time_get(mono_time);
#endif

    for (uint32_t i = 0; i < tcp_server->size_accepted_connections; ++i) {
        TCP_Secure_Connection *conn = &tcp_server->accepted_connection_array[i];

        if (conn->status != TCP_STATUS_CONFIRMED) {
            continue;
        }

        if (mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_FREQUENCY)) {
            uint8_t ping[1 + sizeof(uint64_t)];
            ping[0] = TCP_PACKET_PING;
            uint64_t ping_id = random_u64(conn->con.rng);

            if (ping_id == 0) {
                ++ping_id;
            }

            memcpy(ping + 1, &ping_id, sizeof(uint64_t));
            const int ret = write_packet_TCP_secure_connection(tcp_server->logger, &conn->con, ping, sizeof(ping), true);

            if (ret == 1) {
                conn->last_pinged = mono_time_get(mono_time);
                conn->ping_id = ping_id;
            } else {
                if (mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_FREQUENCY + TCP_PING_TIMEOUT)) {
                    kill_accepted(tcp_server, i);
                    continue;
                }
            }
        }

        if (conn->ping_id != 0 && mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_TIMEOUT)) {
            kill_accepted(tcp_server, i);
            continue;
        }

        send_pending_data(tcp_server->logger, &conn->con);

#ifndef TCP_SERVER_USE_EPOLL

        do_confirmed_recv(tcp_server, i);

#endif
    }
}

#ifdef TCP_SERVER_USE_EPOLL
non_null()
static bool tcp_epoll_process(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
#define MAX_EVENTS 16
    struct epoll_event events[MAX_EVENTS];
    const int nfds = epoll_wait(tcp_server->efd, events, MAX_EVENTS, 0);
#undef MAX_EVENTS

    for (int n = 0; n < nfds; ++n) {
        const Socket sock = {(int)(events[n].data.u64 & 0xFFFFFFFF)};
        const int status = (events[n].data.u64 >> 32) & 0xFF;
        const int index = events[n].data.u64 >> 40;

        if ((events[n].events & EPOLLERR) != 0 || (events[n].events & EPOLLHUP) != 0 || (events[n].events & EPOLLRDHUP) != 0) {
            switch (status) {
                case TCP_SOCKET_LISTENING: {
                    // should never happen
                    LOGGER_ERROR(tcp_server->logger, "connection %d was in listening state", index);
                    break;
                }

                case TCP_SOCKET_INCOMING: {
                    LOGGER_TRACE(tcp_server->logger, "incoming connection %d dropped", index);
                    kill_TCP_secure_connection(&tcp_server->incoming_connection_queue[index]);
                    break;
                }

                case TCP_SOCKET_UNCONFIRMED: {
                    LOGGER_TRACE(tcp_server->logger, "unconfirmed connection %d dropped", index);
                    kill_TCP_secure_connection(&tcp_server->unconfirmed_connection_queue[index]);
                    break;
                }

                case TCP_SOCKET_CONFIRMED: {
                    LOGGER_TRACE(tcp_server->logger, "confirmed connection %d dropped", index);
                    kill_accepted(tcp_server, index);
                    break;
                }
            }

            continue;
        }


        if ((events[n].events & EPOLLIN) == 0) {
            continue;
        }

        switch (status) {
            case TCP_SOCKET_LISTENING: {
                // socket is from socks_listening, accept connection
                while (true) {
                    const Socket sock_new = net_accept(tcp_server->ns, sock);

                    if (!sock_valid(sock_new)) {
                        break;
                    }

                    const int index_new = accept_connection(tcp_server, sock_new);

                    if (index_new == -1) {
                        continue;
                    }

                    struct epoll_event ev;

                    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;

                    ev.data.u64 = sock_new.sock | ((uint64_t)TCP_SOCKET_INCOMING << 32) | ((uint64_t)index_new << 40);

                    if (epoll_ctl(tcp_server->efd, EPOLL_CTL_ADD, sock_new.sock, &ev) == -1) {
                        LOGGER_DEBUG(tcp_server->logger, "new connection %d was dropped due to epoll error %d", index, net_error());
                        kill_TCP_secure_connection(&tcp_server->incoming_connection_queue[index_new]);
                        continue;
                    }
                }

                break;
            }

            case TCP_SOCKET_INCOMING: {
                const int index_new = do_incoming(tcp_server, index);

                if (index_new != -1) {
                    LOGGER_TRACE(tcp_server->logger, "incoming connection %d was accepted as %d", index, index_new);
                    events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    events[n].data.u64 = sock.sock | ((uint64_t)TCP_SOCKET_UNCONFIRMED << 32) | ((uint64_t)index_new << 40);

                    if (epoll_ctl(tcp_server->efd, EPOLL_CTL_MOD, sock.sock, &events[n]) == -1) {
                        LOGGER_DEBUG(tcp_server->logger, "incoming connection %d was dropped due to epoll error %d", index, net_error());
                        kill_TCP_secure_connection(&tcp_server->unconfirmed_connection_queue[index_new]);
                        break;
                    }
                }

                break;
            }

            case TCP_SOCKET_UNCONFIRMED: {
                const int index_new = do_unconfirmed(tcp_server, mono_time, index);

                if (index_new != -1) {
                    LOGGER_TRACE(tcp_server->logger, "unconfirmed connection %d was confirmed as %d", index, index_new);
                    events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    events[n].data.u64 = sock.sock | ((uint64_t)TCP_SOCKET_CONFIRMED << 32) | ((uint64_t)index_new << 40);

                    if (epoll_ctl(tcp_server->efd, EPOLL_CTL_MOD, sock.sock, &events[n]) == -1) {
                        // remove from confirmed connections
                        LOGGER_DEBUG(tcp_server->logger, "unconfirmed connection %d was dropped due to epoll error %d", index, net_error());
                        kill_accepted(tcp_server, index_new);
                        break;
                    }
                }

                break;
            }

            case TCP_SOCKET_CONFIRMED: {
                do_confirmed_recv(tcp_server, index);
                break;
            }
        }
    }

    return nfds > 0;
}

non_null()
static void do_TCP_epoll(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
    while (tcp_epoll_process(tcp_server, mono_time)) {
        // Keep processing packets until there are no more FDs ready for reading.
        continue;
    }
}
#endif

void do_TCP_server(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
#ifdef TCP_SERVER_USE_EPOLL
    do_TCP_epoll(tcp_server, mono_time);

#else
    do_TCP_accept_new(tcp_server);
    do_TCP_incoming(tcp_server);
    do_TCP_unconfirmed(tcp_server, mono_time);
#endif

    do_TCP_confirmed(tcp_server, mono_time);
}

void kill_TCP_server(TCP_Server *tcp_server)
{
    if (tcp_server == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < tcp_server->num_listening_socks; ++i) {
        kill_sock(tcp_server->ns, tcp_server->socks_listening[i]);
    }

    if (tcp_server->onion != nullptr) {
        set_callback_handle_recv_1(tcp_server->onion, nullptr, nullptr);
    }

    if (tcp_server->forwarding != nullptr) {
        set_callback_forward_reply(tcp_server->forwarding, nullptr, nullptr);
    }

    bs_list_free(&tcp_server->accepted_key_list);

#ifdef TCP_SERVER_USE_EPOLL
    close(tcp_server->efd);
#endif

    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        wipe_secure_connection(&tcp_server->incoming_connection_queue[i]);
        wipe_secure_connection(&tcp_server->unconfirmed_connection_queue[i]);
    }

    free_accepted_connection_array(tcp_server);

    crypto_memzero(tcp_server->secret_key, sizeof(tcp_server->secret_key));

    free(tcp_server->socks_listening);
    free(tcp_server);
}
