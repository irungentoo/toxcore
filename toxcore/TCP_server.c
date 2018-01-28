/*
 * Implementation of the TCP relay server part of Tox.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2014 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "TCP_server.h"

#include "util.h"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif

typedef struct TCP_Secure_Connection {
    Socket sock;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint16_t next_packet_length;
    struct {
        uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
        uint32_t index;
        uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
        uint8_t other_id;
    } connections[NUM_CLIENT_CONNECTIONS];
    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint8_t status;
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    TCP_Priority_List *priority_queue_start, *priority_queue_end;

    uint64_t identifier;

    uint64_t last_pinged;
    uint64_t ping_id;
} TCP_Secure_Connection;


struct TCP_Server {
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

    BS_LIST accepted_key_list;
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
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif

/* Set the size of the connection list to numfriends.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_connection(TCP_Server *TCP_server, uint32_t num)
{
    if (num == 0) {
        free(TCP_server->accepted_connection_array);
        TCP_server->accepted_connection_array = nullptr;
        TCP_server->size_accepted_connections = 0;
        return 0;
    }

    if (num == TCP_server->size_accepted_connections) {
        return 0;
    }

    TCP_Secure_Connection *new_connections = (TCP_Secure_Connection *)realloc(
                TCP_server->accepted_connection_array,
                num * sizeof(TCP_Secure_Connection));

    if (new_connections == nullptr) {
        return -1;
    }

    if (num > TCP_server->size_accepted_connections) {
        uint32_t old_size = TCP_server->size_accepted_connections;
        uint32_t size_new_entries = (num - old_size) * sizeof(TCP_Secure_Connection);
        memset(new_connections + old_size, 0, size_new_entries);
    }

    TCP_server->accepted_connection_array = new_connections;
    TCP_server->size_accepted_connections = num;
    return 0;
}

/* return index corresponding to connection with peer on success
 * return -1 on failure.
 */
static int get_TCP_connection_index(const TCP_Server *TCP_server, const uint8_t *public_key)
{
    return bs_list_find(&TCP_server->accepted_key_list, public_key);
}


static int kill_accepted(TCP_Server *TCP_server, int index);

/* Add accepted TCP connection to the list.
 *
 * return index on success
 * return -1 on failure
 */
static int add_accepted(TCP_Server *TCP_server, const TCP_Secure_Connection *con)
{
    int index = get_TCP_connection_index(TCP_server, con->public_key);

    if (index != -1) { /* If an old connection to the same public key exists, kill it. */
        kill_accepted(TCP_server, index);
        index = -1;
    }

    if (TCP_server->size_accepted_connections == TCP_server->num_accepted_connections) {
        if (realloc_connection(TCP_server, TCP_server->size_accepted_connections + 4) == -1) {
            return -1;
        }

        index = TCP_server->num_accepted_connections;
    } else {
        uint32_t i;

        for (i = TCP_server->size_accepted_connections; i != 0; --i) {
            if (TCP_server->accepted_connection_array[i - 1].status == TCP_STATUS_NO_STATUS) {
                index = i - 1;
                break;
            }
        }
    }

    if (index == -1) {
        fprintf(stderr, "FAIL index is -1\n");
        return -1;
    }

    if (!bs_list_add(&TCP_server->accepted_key_list, con->public_key, index)) {
        return -1;
    }

    memcpy(&TCP_server->accepted_connection_array[index], con, sizeof(TCP_Secure_Connection));
    TCP_server->accepted_connection_array[index].status = TCP_STATUS_CONFIRMED;
    ++TCP_server->num_accepted_connections;
    TCP_server->accepted_connection_array[index].identifier = ++TCP_server->counter;
    TCP_server->accepted_connection_array[index].last_pinged = unix_time();
    TCP_server->accepted_connection_array[index].ping_id = 0;

    return index;
}

/* Delete accepted connection from list.
 *
 * return 0 on success
 * return -1 on failure
 */
static int del_accepted(TCP_Server *TCP_server, int index)
{
    if ((uint32_t)index >= TCP_server->size_accepted_connections) {
        return -1;
    }

    if (TCP_server->accepted_connection_array[index].status == TCP_STATUS_NO_STATUS) {
        return -1;
    }

    if (!bs_list_remove(&TCP_server->accepted_key_list, TCP_server->accepted_connection_array[index].public_key, index)) {
        return -1;
    }

    crypto_memzero(&TCP_server->accepted_connection_array[index], sizeof(TCP_Secure_Connection));
    --TCP_server->num_accepted_connections;

    if (TCP_server->num_accepted_connections == 0) {
        realloc_connection(TCP_server, 0);
    }

    return 0;
}

/* return the amount of data in the tcp recv buffer.
 * return 0 on failure.
 */
unsigned int TCP_socket_data_recv_buffer(Socket sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    unsigned long count = 0;
    ioctlsocket(sock, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock, FIONREAD, &count);
#endif

    return count;
}

/* Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return ~0 on failure.
 */
uint16_t read_TCP_length(Socket sock)
{
    unsigned int count = TCP_socket_data_recv_buffer(sock);

    if (count >= sizeof(uint16_t)) {
        uint16_t length;
        int len = recv(sock, (char *)&length, sizeof(uint16_t), MSG_NOSIGNAL);

        if (len != sizeof(uint16_t)) {
            fprintf(stderr, "FAIL recv packet\n");
            return 0;
        }

        length = net_ntohs(length);

        if (length > MAX_PACKET_SIZE) {
            return ~0;
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
int read_TCP_packet(Socket sock, uint8_t *data, uint16_t length)
{
    unsigned int count = TCP_socket_data_recv_buffer(sock);

    if (count >= length) {
        int len = recv(sock, (char *)data, length, MSG_NOSIGNAL);

        if (len != length) {
            fprintf(stderr, "FAIL recv packet\n");
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
int read_packet_TCP_secure_connection(Socket sock, uint16_t *next_packet_length, const uint8_t *shared_key,
                                      uint8_t *recv_nonce, uint8_t *data, uint16_t max_len)
{
    if (*next_packet_length == 0) {
        uint16_t len = read_TCP_length(sock);

        if (len == (uint16_t)~0) {
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
    int len_packet = read_TCP_packet(sock, data_encrypted, *next_packet_length);

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

    uint16_t left = con->last_packet_length - con->last_packet_sent;
    int len = send(con->sock, (const char *)(con->last_packet + con->last_packet_sent), left, MSG_NOSIGNAL);

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
        uint16_t left = p->size - p->sent;
        int len = send(con->sock, (const char *)(p->data + p->sent), left, MSG_NOSIGNAL);

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

    uint16_t c_length = net_htons(length + CRYPTO_MAC_SIZE);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (SIZEOF_VLA(packet) - sizeof(uint16_t))) {
        return -1;
    }

    if (priority) {
        len = sendpriority ? send(con->sock, (const char *)packet, SIZEOF_VLA(packet), MSG_NOSIGNAL) : 0;

        if (len <= 0) {
            len = 0;
        }

        increment_nonce(con->sent_nonce);

        if ((unsigned int)len == SIZEOF_VLA(packet)) {
            return 1;
        }

        return add_priority(con, packet, SIZEOF_VLA(packet), len);
    }

    len = send(con->sock, (const char *)packet, SIZEOF_VLA(packet), MSG_NOSIGNAL);

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
    crypto_memzero(con, sizeof(TCP_Secure_Connection));
}

static int rm_connection_index(TCP_Server *TCP_server, TCP_Secure_Connection *con, uint8_t con_number);

/* Kill an accepted TCP_Secure_Connection
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int kill_accepted(TCP_Server *TCP_server, int index)
{
    if ((uint32_t)index >= TCP_server->size_accepted_connections) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        rm_connection_index(TCP_server, &TCP_server->accepted_connection_array[index], i);
    }

    Socket sock = TCP_server->accepted_connection_array[index].sock;

    if (del_accepted(TCP_server, index) != 0) {
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

    if (TCP_SERVER_HANDSHAKE_SIZE != send(con->sock, (const char *)response, TCP_SERVER_HANDSHAKE_SIZE, MSG_NOSIGNAL)) {
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
static int read_connection_handshake(TCP_Secure_Connection *con, const uint8_t *self_secret_key)
{
    uint8_t data[TCP_CLIENT_HANDSHAKE_SIZE];
    int len = 0;

    if ((len = read_TCP_packet(con->sock, data, TCP_CLIENT_HANDSHAKE_SIZE)) != -1) {
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
static int handle_TCP_routing_req(TCP_Server *TCP_server, uint32_t con_id, const uint8_t *public_key)
{
    uint32_t i;
    uint32_t index = ~0;
    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[con_id];

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
        } else if (index == (uint32_t)~0) {
            index = i;
        }
    }

    if (index == (uint32_t)~0) {
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
    int other_index = get_TCP_connection_index(TCP_server, public_key);

    if (other_index != -1) {
        uint32_t other_id = ~0;
        TCP_Secure_Connection *other_conn = &TCP_server->accepted_connection_array[other_index];

        for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
            if (other_conn->connections[i].status == 1
                    && public_key_cmp(other_conn->connections[i].public_key, con->public_key) == 0) {
                other_id = i;
                break;
            }
        }

        if (other_id != (uint32_t)~0) {
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
static int handle_TCP_oob_send(TCP_Server *TCP_server, uint32_t con_id, const uint8_t *public_key, const uint8_t *data,
                               uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH) {
        return -1;
    }

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[con_id];

    int other_index = get_TCP_connection_index(TCP_server, public_key);

    if (other_index != -1) {
        VLA(uint8_t, resp_packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + length);
        resp_packet[0] = TCP_PACKET_OOB_RECV;
        memcpy(resp_packet + 1, con->public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(resp_packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length);
        write_packet_TCP_secure_connection(&TCP_server->accepted_connection_array[other_index], resp_packet,
                                           SIZEOF_VLA(resp_packet), 0);
    }

    return 0;
}

/* Remove connection with con_number from the connections array of con.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int rm_connection_index(TCP_Server *TCP_server, TCP_Secure_Connection *con, uint8_t con_number)
{
    if (con_number >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    if (con->connections[con_number].status) {
        uint32_t index = con->connections[con_number].index;
        uint8_t other_id = con->connections[con_number].other_id;

        if (con->connections[con_number].status == 2) {

            if (index >= TCP_server->size_accepted_connections) {
                return -1;
            }

            TCP_server->accepted_connection_array[index].connections[other_id].other_id = 0;
            TCP_server->accepted_connection_array[index].connections[other_id].index = 0;
            TCP_server->accepted_connection_array[index].connections[other_id].status = 1;
            // TODO(irungentoo): return values?
            send_disconnect_notification(&TCP_server->accepted_connection_array[index], other_id);
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
    TCP_Server *TCP_server = (TCP_Server *)object;
    uint32_t index = dest.ip.ip6.uint32[0];

    if (index >= TCP_server->size_accepted_connections) {
        return 1;
    }

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[index];

    if (con->identifier != dest.ip.ip6.uint64[1]) {
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
static int handle_TCP_packet(TCP_Server *TCP_server, uint32_t con_id, const uint8_t *data, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[con_id];

    switch (data[0]) {
        case TCP_PACKET_ROUTING_REQUEST: {
            if (length != 1 + CRYPTO_PUBLIC_KEY_SIZE) {
                return -1;
            }

            return handle_TCP_routing_req(TCP_server, con_id, data + 1);
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

            return rm_connection_index(TCP_server, con, data[1] - NUM_RESERVED_PORTS);
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

            return handle_TCP_oob_send(TCP_server, con_id, data + 1, data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                       length - (1 + CRYPTO_PUBLIC_KEY_SIZE));
        }

        case TCP_PACKET_ONION_REQUEST: {
            if (TCP_server->onion) {
                if (length <= 1 + CRYPTO_NONCE_SIZE + ONION_SEND_BASE * 2) {
                    return -1;
                }

                IP_Port source;
                source.port = 0;  // dummy initialise
                source.ip.family = TCP_ONION_FAMILY;
                source.ip.ip6.uint32[0] = con_id;
                source.ip.ip6.uint32[1] = 0;
                source.ip.ip6.uint64[1] = con->identifier;
                onion_send_1(TCP_server->onion, data + 1 + CRYPTO_NONCE_SIZE, length - (1 + CRYPTO_NONCE_SIZE), source,
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
            int ret = write_packet_TCP_secure_connection(&TCP_server->accepted_connection_array[index], new_data, length, 0);

            if (ret == -1) {
                return -1;
            }

            return 0;
        }
    }

    return 0;
}


static int confirm_TCP_connection(TCP_Server *TCP_server, TCP_Secure_Connection *con, const uint8_t *data,
                                  uint16_t length)
{
    int index = add_accepted(TCP_server, con);

    if (index == -1) {
        kill_TCP_secure_connection(con);
        return -1;
    }

    crypto_memzero(con, sizeof(TCP_Secure_Connection));

    if (handle_TCP_packet(TCP_server, index, data, length) == -1) {
        kill_accepted(TCP_server, index);
        return -1;
    }

    return index;
}

/* return index on success
 * return -1 on failure
 */
static int accept_connection(TCP_Server *TCP_server, Socket sock)
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

    uint16_t index = TCP_server->incoming_connection_queue_index % MAX_INCOMING_CONNECTIONS;

    TCP_Secure_Connection *conn = &TCP_server->incoming_connection_queue[index];

    if (conn->status != TCP_STATUS_NO_STATUS) {
        kill_TCP_secure_connection(conn);
    }

    conn->status = TCP_STATUS_CONNECTED;
    conn->sock = sock;
    conn->next_packet_length = 0;

    ++TCP_server->incoming_connection_queue_index;
    return index;
}

static Socket new_listening_TCP_socket(int family, uint16_t port)
{
    Socket sock = net_socket(family, TOX_SOCK_STREAM, TOX_PROTO_TCP);

    if (!sock_valid(sock)) {
        return ~0;
    }

    int ok = set_socket_nonblock(sock);

    if (ok && family == TOX_AF_INET6) {
        ok = set_socket_dualstack(sock);
    }

    if (ok) {
        ok = set_socket_reuseaddr(sock);
    }

    ok = ok && bind_to_port(sock, family, port) && (listen(sock, TCP_MAX_BACKLOG) == 0);

    if (!ok) {
        kill_sock(sock);
        return ~0;
    }

    return sock;
}

TCP_Server *new_TCP_server(uint8_t ipv6_enabled, uint16_t num_sockets, const uint16_t *ports, const uint8_t *secret_key,
                           Onion *onion)
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

    uint8_t family;

    if (ipv6_enabled) {
        family = TOX_AF_INET6;
    } else {
        family = TOX_AF_INET;
    }

    uint32_t i;
#ifdef TCP_SERVER_USE_EPOLL
    struct epoll_event ev;
#endif

    for (i = 0; i < num_sockets; ++i) {
        Socket sock = new_listening_TCP_socket(family, ports[i]);

        if (sock_valid(sock)) {
#ifdef TCP_SERVER_USE_EPOLL
            ev.events = EPOLLIN | EPOLLET;
            ev.data.u64 = sock | ((uint64_t)TCP_SOCKET_LISTENING << 32);

            if (epoll_ctl(temp->efd, EPOLL_CTL_ADD, sock, &ev) == -1) {
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

static void do_TCP_accept_new(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < TCP_server->num_listening_socks; ++i) {
        struct sockaddr_storage addr;
        socklen_t addrlen = sizeof(addr);
        Socket sock;

        do {
            sock = accept(TCP_server->socks_listening[i], (struct sockaddr *)&addr, &addrlen);
        } while (accept_connection(TCP_server, sock) != -1);
    }
}

static int do_incoming(TCP_Server *TCP_server, uint32_t i)
{
    if (TCP_server->incoming_connection_queue[i].status != TCP_STATUS_CONNECTED) {
        return -1;
    }

    int ret = read_connection_handshake(&TCP_server->incoming_connection_queue[i], TCP_server->secret_key);

    if (ret == -1) {
        kill_TCP_secure_connection(&TCP_server->incoming_connection_queue[i]);
    } else if (ret == 1) {
        int index_new = TCP_server->unconfirmed_connection_queue_index % MAX_INCOMING_CONNECTIONS;
        TCP_Secure_Connection *conn_old = &TCP_server->incoming_connection_queue[i];
        TCP_Secure_Connection *conn_new = &TCP_server->unconfirmed_connection_queue[index_new];

        if (conn_new->status != TCP_STATUS_NO_STATUS) {
            kill_TCP_secure_connection(conn_new);
        }

        memcpy(conn_new, conn_old, sizeof(TCP_Secure_Connection));
        crypto_memzero(conn_old, sizeof(TCP_Secure_Connection));
        ++TCP_server->unconfirmed_connection_queue_index;

        return index_new;
    }

    return -1;
}

static int do_unconfirmed(TCP_Server *TCP_server, uint32_t i)
{
    TCP_Secure_Connection *conn = &TCP_server->unconfirmed_connection_queue[i];

    if (conn->status != TCP_STATUS_UNCONFIRMED) {
        return -1;
    }

    uint8_t packet[MAX_PACKET_SIZE];
    int len = read_packet_TCP_secure_connection(conn->sock, &conn->next_packet_length, conn->shared_key, conn->recv_nonce,
              packet, sizeof(packet));

    if (len == 0) {
        return -1;
    }

    if (len == -1) {
        kill_TCP_secure_connection(conn);
        return -1;
    }

    return confirm_TCP_connection(TCP_server, conn, packet, len);
}

static void do_confirmed_recv(TCP_Server *TCP_server, uint32_t i)
{
    TCP_Secure_Connection *conn = &TCP_server->accepted_connection_array[i];

    uint8_t packet[MAX_PACKET_SIZE];
    int len;

    while ((len = read_packet_TCP_secure_connection(conn->sock, &conn->next_packet_length, conn->shared_key,
                  conn->recv_nonce, packet, sizeof(packet)))) {
        if (len == -1) {
            kill_accepted(TCP_server, i);
            break;
        }

        if (handle_TCP_packet(TCP_server, i, packet, len) == -1) {
            kill_accepted(TCP_server, i);
            break;
        }
    }
}

static void do_TCP_incoming(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        do_incoming(TCP_server, i);
    }
}

static void do_TCP_unconfirmed(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        do_unconfirmed(TCP_server, i);
    }
}

static void do_TCP_confirmed(TCP_Server *TCP_server)
{
#ifdef TCP_SERVER_USE_EPOLL

    if (TCP_server->last_run_pinged == unix_time()) {
        return;
    }

    TCP_server->last_run_pinged = unix_time();
#endif
    uint32_t i;

    for (i = 0; i < TCP_server->size_accepted_connections; ++i) {
        TCP_Secure_Connection *conn = &TCP_server->accepted_connection_array[i];

        if (conn->status != TCP_STATUS_CONFIRMED) {
            continue;
        }

        if (is_timeout(conn->last_pinged, TCP_PING_FREQUENCY)) {
            uint8_t ping[1 + sizeof(uint64_t)];
            ping[0] = TCP_PACKET_PING;
            uint64_t ping_id = random_u64();

            if (!ping_id) {
                ++ping_id;
            }

            memcpy(ping + 1, &ping_id, sizeof(uint64_t));
            int ret = write_packet_TCP_secure_connection(conn, ping, sizeof(ping), 1);

            if (ret == 1) {
                conn->last_pinged = unix_time();
                conn->ping_id = ping_id;
            } else {
                if (is_timeout(conn->last_pinged, TCP_PING_FREQUENCY + TCP_PING_TIMEOUT)) {
                    kill_accepted(TCP_server, i);
                    continue;
                }
            }
        }

        if (conn->ping_id && is_timeout(conn->last_pinged, TCP_PING_TIMEOUT)) {
            kill_accepted(TCP_server, i);
            continue;
        }

        send_pending_data(conn);

#ifndef TCP_SERVER_USE_EPOLL

        do_confirmed_recv(TCP_server, i);

#endif
    }
}

#ifdef TCP_SERVER_USE_EPOLL
static void do_TCP_epoll(TCP_Server *TCP_server)
{
#define MAX_EVENTS 16
    struct epoll_event events[MAX_EVENTS];
    int nfds;

    while ((nfds = epoll_wait(TCP_server->efd, events, MAX_EVENTS, 0)) > 0) {
        int n;

        for (n = 0; n < nfds; ++n) {
            Socket sock = events[n].data.u64 & 0xFFFFFFFF;
            int status = (events[n].data.u64 >> 32) & 0xFF, index = (events[n].data.u64 >> 40);

            if ((events[n].events & EPOLLERR) || (events[n].events & EPOLLHUP) || (events[n].events & EPOLLRDHUP)) {
                switch (status) {
                    case TCP_SOCKET_LISTENING: {
                        //should never happen
                        break;
                    }

                    case TCP_SOCKET_INCOMING: {
                        kill_TCP_secure_connection(&TCP_server->incoming_connection_queue[index]);
                        break;
                    }

                    case TCP_SOCKET_UNCONFIRMED: {
                        kill_TCP_secure_connection(&TCP_server->unconfirmed_connection_queue[index]);
                        break;
                    }

                    case TCP_SOCKET_CONFIRMED: {
                        kill_accepted(TCP_server, index);
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
                    //socket is from socks_listening, accept connection
                    struct sockaddr_storage addr;
                    socklen_t addrlen = sizeof(addr);

                    while (1) {
                        Socket sock_new = accept(sock, (struct sockaddr *)&addr, &addrlen);

                        if (!sock_valid(sock_new)) {
                            break;
                        }

                        int index_new = accept_connection(TCP_server, sock_new);

                        if (index_new == -1) {
                            continue;
                        }

                        struct epoll_event ev = {
                            .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
                            .data.u64 = sock_new | ((uint64_t)TCP_SOCKET_INCOMING << 32) | ((uint64_t)index_new << 40)
                        };

                        if (epoll_ctl(TCP_server->efd, EPOLL_CTL_ADD, sock_new, &ev) == -1) {
                            kill_TCP_secure_connection(&TCP_server->incoming_connection_queue[index_new]);
                            continue;
                        }
                    }

                    break;
                }

                case TCP_SOCKET_INCOMING: {
                    int index_new;

                    if ((index_new = do_incoming(TCP_server, index)) != -1) {
                        events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                        events[n].data.u64 = sock | ((uint64_t)TCP_SOCKET_UNCONFIRMED << 32) | ((uint64_t)index_new << 40);

                        if (epoll_ctl(TCP_server->efd, EPOLL_CTL_MOD, sock, &events[n]) == -1) {
                            kill_TCP_secure_connection(&TCP_server->unconfirmed_connection_queue[index_new]);
                            break;
                        }
                    }

                    break;
                }

                case TCP_SOCKET_UNCONFIRMED: {
                    int index_new;

                    if ((index_new = do_unconfirmed(TCP_server, index)) != -1) {
                        events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                        events[n].data.u64 = sock | ((uint64_t)TCP_SOCKET_CONFIRMED << 32) | ((uint64_t)index_new << 40);

                        if (epoll_ctl(TCP_server->efd, EPOLL_CTL_MOD, sock, &events[n]) == -1) {
                            //remove from confirmed connections
                            kill_accepted(TCP_server, index_new);
                            break;
                        }
                    }

                    break;
                }

                case TCP_SOCKET_CONFIRMED: {
                    do_confirmed_recv(TCP_server, index);
                    break;
                }
            }
        }
    }

#undef MAX_EVENTS
}
#endif

void do_TCP_server(TCP_Server *TCP_server)
{
    unix_time_update();

#ifdef TCP_SERVER_USE_EPOLL
    do_TCP_epoll(TCP_server);

#else
    do_TCP_accept_new(TCP_server);
    do_TCP_incoming(TCP_server);
    do_TCP_unconfirmed(TCP_server);
#endif

    do_TCP_confirmed(TCP_server);
}

void kill_TCP_server(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < TCP_server->num_listening_socks; ++i) {
        kill_sock(TCP_server->socks_listening[i]);
    }

    if (TCP_server->onion) {
        set_callback_handle_recv_1(TCP_server->onion, nullptr, nullptr);
    }

    bs_list_free(&TCP_server->accepted_key_list);

#ifdef TCP_SERVER_USE_EPOLL
    close(TCP_server->efd);
#endif

    free(TCP_server->socks_listening);
    free(TCP_server->accepted_connection_array);
    free(TCP_server);
}
