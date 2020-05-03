/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/*
 * Implementation of the TCP relay server part of Tox.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
    Socket sock;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint16_t next_packet_length;
    TCP_Secure_Conn connections[NUM_CLIENT_CONNECTIONS];
    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint8_t status;
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    TCP_Priority_List *priority_queue_start;
    TCP_Priority_List *priority_queue_end;

    uint64_t identifier;

    uint64_t last_pinged;
    uint64_t ping_id;
} TCP_Secure_Connection;


struct TCP_Server {
    const Logger *logger;
    Onion *onion;

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

/* This is needed to compile on Android below API 21
 */
#ifdef TCP_SERVER_USE_EPOLL
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
#endif

/* Increase the size of the connection list
 *
 *  return -1 on failure
 *  return 0 on success.
 */
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

void wipe_priority_list(TCP_Priority_List *p)
{
    while (p) {
        TCP_Priority_List *pp = p;
        p = p->next;
        free(pp);
    }
}

static void wipe_secure_connection(TCP_Secure_Connection *con)
{
    if (con->status) {
        wipe_priority_list(con->priority_queue_start);
        crypto_memzero(con, sizeof(TCP_Secure_Connection));
    }
}

static void move_secure_connection(TCP_Secure_Connection *con_new, TCP_Secure_Connection *con_old)
{
    memcpy(con_new, con_old, sizeof(TCP_Secure_Connection));
    crypto_memzero(con_old, sizeof(TCP_Secure_Connection));
}

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

/* return index corresponding to connection with peer on success
 * return -1 on failure.
 */
static int get_TCP_connection_index(const TCP_Server *tcp_server, const uint8_t *public_key)
{
    return bs_list_find(&tcp_server->accepted_key_list, public_key);
}


static int kill_accepted(TCP_Server *tcp_server, int index);

/* Add accepted TCP connection to the list.
 *
 * return index on success
 * return -1 on failure
 */
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
        uint32_t i;

        for (i = tcp_server->size_accepted_connections; i != 0; --i) {
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

/* Delete accepted connection from list.
 *
 * return 0 on success
 * return -1 on failure
 */
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

/* Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return -1 on failure.
 */
uint16_t read_TCP_length(const Logger *logger, Socket sock)
{
    const unsigned int count = net_socket_data_recv_buffer(sock);

    if (count >= sizeof(uint16_t)) {
        uint16_t length;
        const int len = net_recv(sock, &length, sizeof(uint16_t));

        if (len != sizeof(uint16_t)) {
            LOGGER_ERROR(logger, "FAIL recv packet");
            return 0;
        }

        length = net_ntohs(length);

        if (length > MAX_PACKET_SIZE) {
            return -1;
        }

        return length;
    }

    return 0;
}

/* Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
int read_TCP_packet(const Logger *logger, Socket sock, uint8_t *data, uint16_t length)
{
    unsigned int count = net_socket_data_recv_buffer(sock);

    if (count >= length) {
        const int len = net_recv(sock, data, length);

        if (len != length) {
            LOGGER_ERROR(logger, "FAIL recv packet");
            return -1;
        }

        return len;
    }

    return -1;
}

/* return length of received packet on success.
 * return 0 if could not read any packet.
 * return -1 on failure (connection must be killed).
 */
int read_packet_TCP_secure_connection(const Logger *logger, Socket sock, uint16_t *next_packet_length,
                                      const uint8_t *shared_key, uint8_t *recv_nonce, uint8_t *data, uint16_t max_len)
{
    if (*next_packet_length == 0) {
        uint16_t len = read_TCP_length(logger, sock);

        if (len == (uint16_t) -1) {
            return -1;
        }

        if (len == 0) {
            return 0;
        }

        *next_packet_length = len;
    }

    if (max_len + CRYPTO_MAC_SIZE < *next_packet_length) {
        return -1;
    }

    VLA(uint8_t, data_encrypted, *next_packet_length);
    int len_packet = read_TCP_packet(logger, sock, data_encrypted, *next_packet_length);

    if (len_packet != *next_packet_length) {
        return 0;
    }

    *next_packet_length = 0;

    int len = decrypt_data_symmetric(shared_key, recv_nonce, data_encrypted, len_packet, data);

    if (len + CRYPTO_MAC_SIZE != len_packet) {
        return -1;
    }

    increment_nonce(recv_nonce);

    return len;
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
static int send_pending_data_nonpriority(TCP_Secure_Connection *con)
{
    if (con->last_packet_length == 0) {
        return 0;
    }

    const uint16_t left = con->last_packet_length - con->last_packet_sent;
    const int len = net_send(con->sock, con->last_packet + con->last_packet_sent, left);

    if (len <= 0) {
        return -1;
    }

    if (len == left) {
        con->last_packet_length = 0;
        con->last_packet_sent = 0;
        return 0;
    }

    con->last_packet_sent += len;
    return -1;
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
static int send_pending_data(TCP_Secure_Connection *con)
{
    /* finish sending current non-priority packet */
    if (send_pending_data_nonpriority(con) == -1) {
        return -1;
    }

    TCP_Priority_List *p = con->priority_queue_start;

    while (p) {
        const uint16_t left = p->size - p->sent;
        const int len = net_send(con->sock, p->data + p->sent, left);

        if (len != left) {
            if (len > 0) {
                p->sent += len;
            }

            break;
        }

        TCP_Priority_List *pp = p;
        p = p->next;
        free(pp);
    }

    con->priority_queue_start = p;

    if (!p) {
        con->priority_queue_end = nullptr;
        return 0;
    }

    return -1;
}

/* return 0 on failure (only if malloc fails)
 * return 1 on success
 */
static bool add_priority(TCP_Secure_Connection *con, const uint8_t *packet, uint16_t size, uint16_t sent)
{
    TCP_Priority_List *p = con->priority_queue_end;
    TCP_Priority_List *new_list = (TCP_Priority_List *)malloc(sizeof(TCP_Priority_List) + size);

    if (!new_list) {
        return 0;
    }

    new_list->next = nullptr;
    new_list->size = size;
    new_list->sent = sent;
    memcpy(new_list->data, packet, size);

    if (p) {
        p->next = new_list;
    } else {
        con->priority_queue_start = new_list;
    }

    con->priority_queue_end = new_list;
    return 1;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int write_packet_TCP_secure_connection(TCP_Secure_Connection *con, const uint8_t *data, uint16_t length,
        bool priority)
{
    if (length + CRYPTO_MAC_SIZE > MAX_PACKET_SIZE) {
        return -1;
    }

    bool sendpriority = 1;

    if (send_pending_data(con) == -1) {
        if (priority) {
            sendpriority = 0;
        } else {
            return 0;
        }
    }

    VLA(uint8_t, packet, sizeof(uint16_t) + length + CRYPTO_MAC_SIZE);

    const uint16_t c_length = net_htons(length + CRYPTO_MAC_SIZE);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (SIZEOF_VLA(packet) - sizeof(uint16_t))) {
        return -1;
    }

    if (priority) {
        len = sendpriority ? net_send(con->sock, packet, SIZEOF_VLA(packet)) : 0;

        if (len <= 0) {
            len = 0;
        }

        increment_nonce(con->sent_nonce);

        if ((unsigned int)len == SIZEOF_VLA(packet)) {
            return 1;
        }

        return add_priority(con, packet, SIZEOF_VLA(packet), len);
    }

    len = net_send(con->sock, packet, SIZEOF_VLA(packet));

    if (len <= 0) {
        return 0;
    }

    increment_nonce(con->sent_nonce);

    if ((unsigned int)len == SIZEOF_VLA(packet)) {
        return 1;
    }

    memcpy(con->last_packet, packet, SIZEOF_VLA(packet));
    con->last_packet_length = SIZEOF_VLA(packet);
    con->last_packet_sent = len;
    return 1;
}

/* Kill a TCP_Secure_Connection
 */
static void kill_TCP_secure_connection(TCP_Secure_Connection *con)
{
    kill_sock(con->sock);
    wipe_secure_connection(con);
}

static int rm_connection_index(TCP_Server *tcp_server, TCP_Secure_Connection *con, uint8_t con_number);

/* Kill an accepted TCP_Secure_Connection
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int kill_accepted(TCP_Server *tcp_server, int index)
{
    if ((uint32_t)index >= tcp_server->size_accepted_connections) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        rm_connection_index(tcp_server, &tcp_server->accepted_connection_array[index], i);
    }

    Socket sock = tcp_server->accepted_connection_array[index].sock;

    if (del_accepted(tcp_server, index) != 0) {
        return -1;
    }

    kill_sock(sock);
    return 0;
}

/* return 1 if everything went well.
 * return -1 if the connection must be killed.
 */
static int handle_TCP_handshake(TCP_Secure_Connection *con, const uint8_t *data, uint16_t length,
                                const uint8_t *self_secret_key)
{
    if (length != TCP_CLIENT_HANDSHAKE_SIZE) {
        return -1;
    }

    if (con->status != TCP_STATUS_CONNECTED) {
        return -1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(data, self_secret_key, shared_key);
    uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
    int len = decrypt_data_symmetric(shared_key, data + CRYPTO_PUBLIC_KEY_SIZE,
                                     data + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE, plain);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE) {
        return -1;
    }

    memcpy(con->public_key, data, CRYPTO_PUBLIC_KEY_SIZE);
    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t resp_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_new_keypair(resp_plain, temp_secret_key);
    random_nonce(con->sent_nonce);
    memcpy(resp_plain + CRYPTO_PUBLIC_KEY_SIZE, con->sent_nonce, CRYPTO_NONCE_SIZE);
    memcpy(con->recv_nonce, plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    random_nonce(response);

    len = encrypt_data_symmetric(shared_key, response, resp_plain, TCP_HANDSHAKE_PLAIN_SIZE,
                                 response + CRYPTO_NONCE_SIZE);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        return -1;
    }

    if (TCP_SERVER_HANDSHAKE_SIZE != net_send(con->sock, response, TCP_SERVER_HANDSHAKE_SIZE)) {
        return -1;
    }

    encrypt_precompute(plain, temp_secret_key, con->shared_key);
    con->status = TCP_STATUS_UNCONFIRMED;
    return 1;
}

/* return 1 if connection handshake was handled correctly.
 * return 0 if we didn't get it yet.
 * return -1 if the connection must be killed.
 */
static int read_connection_handshake(const Logger *logger, TCP_Secure_Connection *con, const uint8_t *self_secret_key)
{
    uint8_t data[TCP_CLIENT_HANDSHAKE_SIZE];
    const int len = read_TCP_packet(logger, con->sock, data, TCP_CLIENT_HANDSHAKE_SIZE);

    if (len != -1) {
        return handle_TCP_handshake(con, data, len, self_secret_key);
    }

    return 0;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_routing_response(TCP_Secure_Connection *con, uint8_t rpid, const uint8_t *public_key)
{
    uint8_t data[1 + 1 + CRYPTO_PUBLIC_KEY_SIZE];
    data[0] = TCP_PACKET_ROUTING_RESPONSE;
    data[1] = rpid;
    memcpy(data + 2, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    return write_packet_TCP_secure_connection(con, data, sizeof(data), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_connect_notification(TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_CONNECTION_NOTIFICATION, (uint8_t)(id + NUM_RESERVED_PORTS)};
    return write_packet_TCP_secure_connection(con, data, sizeof(data), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_disconnect_notification(TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_DISCONNECT_NOTIFICATION, (uint8_t)(id + NUM_RESERVED_PORTS)};
    return write_packet_TCP_secure_connection(con, data, sizeof(data), 1);
}

/* return 0 on success.
 * return -1 on failure (connection must be killed).
 */
static int handle_TCP_routing_req(TCP_Server *tcp_server, uint32_t con_id, const uint8_t *public_key)
{
    uint32_t i;
    uint32_t index = -1;
    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    /* If person tries to cennect to himself we deny the request*/
    if (public_key_cmp(con->public_key, public_key) == 0) {
        if (send_routing_response(con, 0, public_key) == -1) {
            return -1;
        }

        return 0;
    }

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        if (con->connections[i].status != 0) {
            if (public_key_cmp(public_key, con->connections[i].public_key) == 0) {
                if (send_routing_response(con, i + NUM_RESERVED_PORTS, public_key) == -1) {
                    return -1;
                }

                return 0;
            }
        } else if (index == (uint32_t) -1) {
            index = i;
        }
    }

    if (index == (uint32_t) -1) {
        if (send_routing_response(con, 0, public_key) == -1) {
            return -1;
        }

        return 0;
    }

    int ret = send_routing_response(con, index + NUM_RESERVED_PORTS, public_key);

    if (ret == 0) {
        return 0;
    }

    if (ret == -1) {
        return -1;
    }

    con->connections[index].status = 1;
    memcpy(con->connections[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    int other_index = get_TCP_connection_index(tcp_server, public_key);

    if (other_index != -1) {
        uint32_t other_id = -1;
        TCP_Secure_Connection *other_conn = &tcp_server->accepted_connection_array[other_index];

        for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
            if (other_conn->connections[i].status == 1
                    && public_key_cmp(other_conn->connections[i].public_key, con->public_key) == 0) {
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
            send_connect_notification(con, index);
            send_connect_notification(other_conn, other_id);
        }
    }

    return 0;
}

/* return 0 on success.
 * return -1 on failure (connection must be killed).
 */
static int handle_TCP_oob_send(TCP_Server *tcp_server, uint32_t con_id, const uint8_t *public_key, const uint8_t *data,
                               uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH) {
        return -1;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    int other_index = get_TCP_connection_index(tcp_server, public_key);

    if (other_index != -1) {
        VLA(uint8_t, resp_packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + length);
        resp_packet[0] = TCP_PACKET_OOB_RECV;
        memcpy(resp_packet + 1, con->public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(resp_packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length);
        write_packet_TCP_secure_connection(&tcp_server->accepted_connection_array[other_index], resp_packet,
                                           SIZEOF_VLA(resp_packet), 0);
    }

    return 0;
}

/* Remove connection with con_number from the connections array of con.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int rm_connection_index(TCP_Server *tcp_server, TCP_Secure_Connection *con, uint8_t con_number)
{
    if (con_number >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    if (con->connections[con_number].status) {
        uint32_t index = con->connections[con_number].index;
        uint8_t other_id = con->connections[con_number].other_id;

        if (con->connections[con_number].status == 2) {

            if (index >= tcp_server->size_accepted_connections) {
                return -1;
            }

            tcp_server->accepted_connection_array[index].connections[other_id].other_id = 0;
            tcp_server->accepted_connection_array[index].connections[other_id].index = 0;
            tcp_server->accepted_connection_array[index].connections[other_id].status = 1;
            // TODO(irungentoo): return values?
            send_disconnect_notification(&tcp_server->accepted_connection_array[index], other_id);
        }

        con->connections[con_number].index = 0;
        con->connections[con_number].other_id = 0;
        con->connections[con_number].status = 0;
        return 0;
    }

    return -1;
}

static int handle_onion_recv_1(void *object, IP_Port dest, const uint8_t *data, uint16_t length)
{
    TCP_Server *tcp_server = (TCP_Server *)object;
    uint32_t index = dest.ip.ip.v6.uint32[0];

    if (index >= tcp_server->size_accepted_connections) {
        return 1;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[index];

    if (con->identifier != dest.ip.ip.v6.uint64[1]) {
        return 1;
    }

    VLA(uint8_t, packet, 1 + length);
    memcpy(packet + 1, data, length);
    packet[0] = TCP_PACKET_ONION_RESPONSE;

    if (write_packet_TCP_secure_connection(con, packet, SIZEOF_VLA(packet), 0) != 1) {
        return 1;
    }

    return 0;
}

/* return 0 on success
 * return -1 on failure
 */
static int handle_TCP_packet(TCP_Server *tcp_server, uint32_t con_id, const uint8_t *data, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    switch (data[0]) {
        case TCP_PACKET_ROUTING_REQUEST: {
            if (length != 1 + CRYPTO_PUBLIC_KEY_SIZE) {
                return -1;
            }

            return handle_TCP_routing_req(tcp_server, con_id, data + 1);
        }

        case TCP_PACKET_CONNECTION_NOTIFICATION: {
            if (length != 2) {
                return -1;
            }

            break;
        }

        case TCP_PACKET_DISCONNECT_NOTIFICATION: {
            if (length != 2) {
                return -1;
            }

            return rm_connection_index(tcp_server, con, data[1] - NUM_RESERVED_PORTS);
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t)) {
                return -1;
            }

            uint8_t response[1 + sizeof(uint64_t)];
            response[0] = TCP_PACKET_PONG;
            memcpy(response + 1, data + 1, sizeof(uint64_t));
            write_packet_TCP_secure_connection(con, response, sizeof(response), 1);
            return 0;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t)) {
                return -1;
            }

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));

            if (ping_id) {
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

            return handle_TCP_oob_send(tcp_server, con_id, data + 1, data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                       length - (1 + CRYPTO_PUBLIC_KEY_SIZE));
        }

        case TCP_PACKET_ONION_REQUEST: {
            if (tcp_server->onion) {
                if (length <= 1 + CRYPTO_NONCE_SIZE + ONION_SEND_BASE * 2) {
                    return -1;
                }

                IP_Port source;
                source.port = 0;  // dummy initialise
                source.ip.family = net_family_tcp_onion;
                source.ip.ip.v6.uint32[0] = con_id;
                source.ip.ip.v6.uint32[1] = 0;
                source.ip.ip.v6.uint64[1] = con->identifier;
                onion_send_1(tcp_server->onion, data + 1 + CRYPTO_NONCE_SIZE, length - (1 + CRYPTO_NONCE_SIZE), source,
                             data + 1);
            }

            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {
            return -1;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS) {
                return -1;
            }

            uint8_t c_id = data[0] - NUM_RESERVED_PORTS;

            if (c_id >= NUM_CLIENT_CONNECTIONS) {
                return -1;
            }

            if (con->connections[c_id].status == 0) {
                return -1;
            }

            if (con->connections[c_id].status != 2) {
                return 0;
            }

            uint32_t index = con->connections[c_id].index;
            uint8_t other_c_id = con->connections[c_id].other_id + NUM_RESERVED_PORTS;
            VLA(uint8_t, new_data, length);
            memcpy(new_data, data, length);
            new_data[0] = other_c_id;
            int ret = write_packet_TCP_secure_connection(&tcp_server->accepted_connection_array[index], new_data, length, 0);

            if (ret == -1) {
                return -1;
            }

            return 0;
        }
    }

    return 0;
}


static int confirm_TCP_connection(TCP_Server *tcp_server, const Mono_Time *mono_time, TCP_Secure_Connection *con,
                                  const uint8_t *data,
                                  uint16_t length)
{
    int index = add_accepted(tcp_server, mono_time, con);

    if (index == -1) {
        kill_TCP_secure_connection(con);
        return -1;
    }

    wipe_secure_connection(con);

    if (handle_TCP_packet(tcp_server, index, data, length) == -1) {
        kill_accepted(tcp_server, index);
        return -1;
    }

    return index;
}

/* return index on success
 * return -1 on failure
 */
static int accept_connection(TCP_Server *tcp_server, Socket sock)
{
    if (!sock_valid(sock)) {
        return -1;
    }

    if (!set_socket_nonblock(sock)) {
        kill_sock(sock);
        return -1;
    }

    if (!set_socket_nosigpipe(sock)) {
        kill_sock(sock);
        return -1;
    }

    uint16_t index = tcp_server->incoming_connection_queue_index % MAX_INCOMING_CONNECTIONS;

    TCP_Secure_Connection *conn = &tcp_server->incoming_connection_queue[index];

    if (conn->status != TCP_STATUS_NO_STATUS) {
        kill_TCP_secure_connection(conn);
    }

    conn->status = TCP_STATUS_CONNECTED;
    conn->sock = sock;
    conn->next_packet_length = 0;

    ++tcp_server->incoming_connection_queue_index;
    return index;
}

static Socket new_listening_TCP_socket(Family family, uint16_t port)
{
    Socket sock = net_socket(family, TOX_SOCK_STREAM, TOX_PROTO_TCP);

    if (!sock_valid(sock)) {
        return net_invalid_socket;
    }

    int ok = set_socket_nonblock(sock);

    if (ok && net_family_is_ipv6(family)) {
        ok = set_socket_dualstack(sock);
    }

    if (ok) {
        ok = set_socket_reuseaddr(sock);
    }

    ok = ok && bind_to_port(sock, family, port) && (net_listen(sock, TCP_MAX_BACKLOG) == 0);

    if (!ok) {
        kill_sock(sock);
        return net_invalid_socket;
    }

    return sock;
}

TCP_Server *new_TCP_server(const Logger *logger, uint8_t ipv6_enabled, uint16_t num_sockets, const uint16_t *ports,
                           const uint8_t *secret_key, Onion *onion)
{
    if (num_sockets == 0 || ports == nullptr) {
        return nullptr;
    }

    if (networking_at_startup() != 0) {
        return nullptr;
    }

    TCP_Server *temp = (TCP_Server *)calloc(1, sizeof(TCP_Server));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->logger = logger;

    temp->socks_listening = (Socket *)calloc(num_sockets, sizeof(Socket));

    if (temp->socks_listening == nullptr) {
        free(temp);
        return nullptr;
    }

#ifdef TCP_SERVER_USE_EPOLL
    temp->efd = epoll_create(8);

    if (temp->efd == -1) {
        free(temp->socks_listening);
        free(temp);
        return nullptr;
    }

#endif

    const Family family = ipv6_enabled ? net_family_ipv6 : net_family_ipv4;

    uint32_t i;
#ifdef TCP_SERVER_USE_EPOLL
    struct epoll_event ev;
#endif

    for (i = 0; i < num_sockets; ++i) {
        Socket sock = new_listening_TCP_socket(family, ports[i]);

        if (sock_valid(sock)) {
#ifdef TCP_SERVER_USE_EPOLL
            ev.events = EPOLLIN | EPOLLET;
            ev.data.u64 = sock.socket | ((uint64_t)TCP_SOCKET_LISTENING << 32);

            if (epoll_ctl(temp->efd, EPOLL_CTL_ADD, sock.socket, &ev) == -1) {
                continue;
            }

#endif

            temp->socks_listening[temp->num_listening_socks] = sock;
            ++temp->num_listening_socks;
        }
    }

    if (temp->num_listening_socks == 0) {
        free(temp->socks_listening);
        free(temp);
        return nullptr;
    }

    if (onion) {
        temp->onion = onion;
        set_callback_handle_recv_1(onion, &handle_onion_recv_1, temp);
    }

    memcpy(temp->secret_key, secret_key, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(temp->public_key, temp->secret_key);

    bs_list_init(&temp->accepted_key_list, CRYPTO_PUBLIC_KEY_SIZE, 8);

    return temp;
}

#ifndef TCP_SERVER_USE_EPOLL
static void do_TCP_accept_new(TCP_Server *tcp_server)
{
    uint32_t i;

    for (i = 0; i < tcp_server->num_listening_socks; ++i) {
        Socket sock;

        do {
            sock = net_accept(tcp_server->socks_listening[i]);
        } while (accept_connection(tcp_server, sock) != -1);
    }
}
#endif

static int do_incoming(TCP_Server *tcp_server, uint32_t i)
{
    if (tcp_server->incoming_connection_queue[i].status != TCP_STATUS_CONNECTED) {
        return -1;
    }

    int ret = read_connection_handshake(tcp_server->logger, &tcp_server->incoming_connection_queue[i],
                                        tcp_server->secret_key);

    if (ret == -1) {
        kill_TCP_secure_connection(&tcp_server->incoming_connection_queue[i]);
    } else if (ret == 1) {
        int index_new = tcp_server->unconfirmed_connection_queue_index % MAX_INCOMING_CONNECTIONS;
        TCP_Secure_Connection *conn_old = &tcp_server->incoming_connection_queue[i];
        TCP_Secure_Connection *conn_new = &tcp_server->unconfirmed_connection_queue[index_new];

        if (conn_new->status != TCP_STATUS_NO_STATUS) {
            kill_TCP_secure_connection(conn_new);
        }

        move_secure_connection(conn_new, conn_old);
        ++tcp_server->unconfirmed_connection_queue_index;

        return index_new;
    }

    return -1;
}

static int do_unconfirmed(TCP_Server *tcp_server, const Mono_Time *mono_time, uint32_t i)
{
    TCP_Secure_Connection *conn = &tcp_server->unconfirmed_connection_queue[i];

    if (conn->status != TCP_STATUS_UNCONFIRMED) {
        return -1;
    }

    uint8_t packet[MAX_PACKET_SIZE];
    int len = read_packet_TCP_secure_connection(tcp_server->logger, conn->sock, &conn->next_packet_length, conn->shared_key,
              conn->recv_nonce, packet, sizeof(packet));

    if (len == 0) {
        return -1;
    }

    if (len == -1) {
        kill_TCP_secure_connection(conn);
        return -1;
    }

    return confirm_TCP_connection(tcp_server, mono_time, conn, packet, len);
}

static bool tcp_process_secure_packet(TCP_Server *tcp_server, uint32_t i)
{
    TCP_Secure_Connection *const conn = &tcp_server->accepted_connection_array[i];

    uint8_t packet[MAX_PACKET_SIZE];
    int len = read_packet_TCP_secure_connection(tcp_server->logger, conn->sock, &conn->next_packet_length, conn->shared_key,
              conn->recv_nonce, packet, sizeof(packet));

    if (len == 0) {
        return false;
    }

    if (len == -1) {
        kill_accepted(tcp_server, i);
        return false;
    }

    if (handle_TCP_packet(tcp_server, i, packet, len) == -1) {
        kill_accepted(tcp_server, i);
        return false;
    }

    return true;
}

static void do_confirmed_recv(TCP_Server *tcp_server, uint32_t i)
{
    while (tcp_process_secure_packet(tcp_server, i)) {
        // Keep reading until an error occurs or there is no more data to read.
        continue;
    }
}

#ifndef TCP_SERVER_USE_EPOLL
static void do_TCP_incoming(TCP_Server *tcp_server)
{
    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        do_incoming(tcp_server, i);
    }
}

static void do_TCP_unconfirmed(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        do_unconfirmed(tcp_server, mono_time, i);
    }
}
#endif

static void do_TCP_confirmed(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
#ifdef TCP_SERVER_USE_EPOLL

    if (tcp_server->last_run_pinged == mono_time_get(mono_time)) {
        return;
    }

    tcp_server->last_run_pinged = mono_time_get(mono_time);
#endif
    uint32_t i;

    for (i = 0; i < tcp_server->size_accepted_connections; ++i) {
        TCP_Secure_Connection *conn = &tcp_server->accepted_connection_array[i];

        if (conn->status != TCP_STATUS_CONFIRMED) {
            continue;
        }

        if (mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_FREQUENCY)) {
            uint8_t ping[1 + sizeof(uint64_t)];
            ping[0] = TCP_PACKET_PING;
            uint64_t ping_id = random_u64();

            if (!ping_id) {
                ++ping_id;
            }

            memcpy(ping + 1, &ping_id, sizeof(uint64_t));
            int ret = write_packet_TCP_secure_connection(conn, ping, sizeof(ping), 1);

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

        if (conn->ping_id && mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_TIMEOUT)) {
            kill_accepted(tcp_server, i);
            continue;
        }

        send_pending_data(conn);

#ifndef TCP_SERVER_USE_EPOLL

        do_confirmed_recv(tcp_server, i);

#endif
    }
}

#ifdef TCP_SERVER_USE_EPOLL
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

        if ((events[n].events & EPOLLERR) || (events[n].events & EPOLLHUP) || (events[n].events & EPOLLRDHUP)) {
            switch (status) {
                case TCP_SOCKET_LISTENING: {
                    // should never happen
                    break;
                }

                case TCP_SOCKET_INCOMING: {
                    kill_TCP_secure_connection(&tcp_server->incoming_connection_queue[index]);
                    break;
                }

                case TCP_SOCKET_UNCONFIRMED: {
                    kill_TCP_secure_connection(&tcp_server->unconfirmed_connection_queue[index]);
                    break;
                }

                case TCP_SOCKET_CONFIRMED: {
                    kill_accepted(tcp_server, index);
                    break;
                }
            }

            continue;
        }


        if (!(events[n].events & EPOLLIN)) {
            continue;
        }

        switch (status) {
            case TCP_SOCKET_LISTENING: {
                // socket is from socks_listening, accept connection
                while (1) {
                    Socket sock_new = net_accept(sock);

                    if (!sock_valid(sock_new)) {
                        break;
                    }

                    int index_new = accept_connection(tcp_server, sock_new);

                    if (index_new == -1) {
                        continue;
                    }

                    struct epoll_event ev;

                    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP;

                    ev.data.u64 = sock_new.socket | ((uint64_t)TCP_SOCKET_INCOMING << 32) | ((uint64_t)index_new << 40);

                    if (epoll_ctl(tcp_server->efd, EPOLL_CTL_ADD, sock_new.socket, &ev) == -1) {
                        kill_TCP_secure_connection(&tcp_server->incoming_connection_queue[index_new]);
                        continue;
                    }
                }

                break;
            }

            case TCP_SOCKET_INCOMING: {
                const int index_new = do_incoming(tcp_server, index);

                if (index_new != -1) {
                    events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    events[n].data.u64 = sock.socket | ((uint64_t)TCP_SOCKET_UNCONFIRMED << 32) | ((uint64_t)index_new << 40);

                    if (epoll_ctl(tcp_server->efd, EPOLL_CTL_MOD, sock.socket, &events[n]) == -1) {
                        kill_TCP_secure_connection(&tcp_server->unconfirmed_connection_queue[index_new]);
                        break;
                    }
                }

                break;
            }

            case TCP_SOCKET_UNCONFIRMED: {
                const int index_new = do_unconfirmed(tcp_server, mono_time, index);

                if (index_new != -1) {
                    events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                    events[n].data.u64 = sock.socket | ((uint64_t)TCP_SOCKET_CONFIRMED << 32) | ((uint64_t)index_new << 40);

                    if (epoll_ctl(tcp_server->efd, EPOLL_CTL_MOD, sock.socket, &events[n]) == -1) {
                        // remove from confirmed connections
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

static void do_TCP_epoll(TCP_Server *tcp_server, const Mono_Time *mono_time)
{
    while (tcp_epoll_process(tcp_server, mono_time)) {
        // Keep processing packets until there are no more FDs ready for reading.
        continue;
    }
}
#endif

void do_TCP_server(TCP_Server *tcp_server, Mono_Time *mono_time)
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
    for (uint32_t i = 0; i < tcp_server->num_listening_socks; ++i) {
        kill_sock(tcp_server->socks_listening[i]);
    }

    if (tcp_server->onion) {
        set_callback_handle_recv_1(tcp_server->onion, nullptr, nullptr);
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

    free(tcp_server->socks_listening);
    free(tcp_server);
}
