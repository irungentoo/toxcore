/*
* TCP_server.c -- Implementation of the TCP relay server part of Tox.
*
*  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include "TCP_server.h"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif

#include "util.h"

/* return 1 on success
 * return 0 on failure
 */
static int bind_to_port(sock_t sock, int family, uint16_t port)
{
    struct sockaddr_storage addr = {0};
    size_t addrsize;

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
    } else {
        return 0;
    }

    return (bind(sock, (struct sockaddr *)&addr, addrsize) == 0);
}

/* Set the size of the connection list to numfriends.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_connection(TCP_Server *TCP_server, uint32_t num)
{
    if (num == 0) {
        free(TCP_server->accepted_connection_array);
        TCP_server->accepted_connection_array = NULL;
        TCP_server->size_accepted_connections = 0;
        return 0;
    }

    if (num == TCP_server->size_accepted_connections) {
        return 0;
    }

    TCP_Secure_Connection *new_connections = realloc(TCP_server->accepted_connection_array,
            num * sizeof(TCP_Secure_Connection));

    if (new_connections == NULL)
        return -1;

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
        if (realloc_connection(TCP_server, TCP_server->size_accepted_connections + 4) == -1)
            return -1;

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

    if (!bs_list_add(&TCP_server->accepted_key_list, con->public_key, index))
        return -1;

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
    if ((uint32_t)index >= TCP_server->size_accepted_connections)
        return -1;

    if (TCP_server->accepted_connection_array[index].status == TCP_STATUS_NO_STATUS)
        return -1;

    if (!bs_list_remove(&TCP_server->accepted_key_list, TCP_server->accepted_connection_array[index].public_key, index))
        return -1;

    memset(&TCP_server->accepted_connection_array[index], 0, sizeof(TCP_Secure_Connection));
    --TCP_server->num_accepted_connections;

    if (TCP_server->num_accepted_connections == 0)
        realloc_connection(TCP_server, 0);

    return 0;
}

/* return the amount of data in the tcp recv buffer.
 * return 0 on failure.
 */
unsigned int TCP_socket_data_recv_buffer(sock_t sock)
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
uint16_t read_TCP_length(sock_t sock)
{
    unsigned int count = TCP_socket_data_recv_buffer(sock);

    if (count >= sizeof(uint16_t)) {
        uint16_t length;
        int len = recv(sock, (uint8_t *)&length, sizeof(uint16_t), MSG_NOSIGNAL);

        if (len != sizeof(uint16_t)) {
            fprintf(stderr, "FAIL recv packet\n");
            return 0;
        }

        length = ntohs(length);

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
int read_TCP_packet(sock_t sock, uint8_t *data, uint16_t length)
{
    unsigned int count = TCP_socket_data_recv_buffer(sock);

    if (count >= length) {
        int len = recv(sock, data, length, MSG_NOSIGNAL);

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
int read_packet_TCP_secure_connection(sock_t sock, uint16_t *next_packet_length, const uint8_t *shared_key,
                                      uint8_t *recv_nonce, uint8_t *data, uint16_t max_len)
{
    if (*next_packet_length == 0) {
        uint16_t len = read_TCP_length(sock);

        if (len == (uint16_t)~0)
            return -1;

        if (len == 0)
            return 0;

        *next_packet_length = len;
    }

    if (max_len + crypto_box_MACBYTES < *next_packet_length)
        return -1;

    uint8_t data_encrypted[*next_packet_length];
    int len_packet = read_TCP_packet(sock, data_encrypted, *next_packet_length);

    if (len_packet != *next_packet_length)
        return 0;

    *next_packet_length = 0;

    int len = decrypt_data_symmetric(shared_key, recv_nonce, data_encrypted, len_packet, data);

    if (len + crypto_box_MACBYTES != len_packet)
        return -1;

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
    int len = send(con->sock, con->last_packet + con->last_packet_sent, left, MSG_NOSIGNAL);

    if (len <= 0)
        return -1;

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
        int len = send(con->sock, p->data + p->sent, left, MSG_NOSIGNAL);

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
        con->priority_queue_end = NULL;
        return 0;
    }

    return -1;
}

/* return 0 on failure (only if malloc fails)
 * return 1 on success
 */
static _Bool add_priority(TCP_Secure_Connection *con, const uint8_t *packet, uint16_t size, uint16_t sent)
{
    TCP_Priority_List *p = con->priority_queue_end, *new;
    new = malloc(sizeof(TCP_Priority_List) + size);

    if (!new) {
        return 0;
    }

    new->next = NULL;
    new->size = size;
    new->sent = sent;
    memcpy(new->data, packet, size);

    if (p) {
        p->next = new;
    } else {
        con->priority_queue_start = new;
    }

    con->priority_queue_end = new;
    return 1;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int write_packet_TCP_secure_connection(TCP_Secure_Connection *con, const uint8_t *data, uint16_t length,
        _Bool priority)
{
    if (length + crypto_box_MACBYTES > MAX_PACKET_SIZE)
        return -1;

    _Bool sendpriority = 1;

    if (send_pending_data(con) == -1) {
        if (priority) {
            sendpriority = 0;
        } else {
            return 0;
        }
    }

    uint8_t packet[sizeof(uint16_t) + length + crypto_box_MACBYTES];

    uint16_t c_length = htons(length + crypto_box_MACBYTES);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (sizeof(packet) - sizeof(uint16_t)))
        return -1;

    if (priority) {
        len = sendpriority ? send(con->sock, packet, sizeof(packet), MSG_NOSIGNAL) : 0;

        if (len <= 0) {
            len = 0;
        }

        increment_nonce(con->sent_nonce);

        if ((unsigned int)len == sizeof(packet)) {
            return 1;
        }

        return add_priority(con, packet, sizeof(packet), len);
    }

    len = send(con->sock, packet, sizeof(packet), MSG_NOSIGNAL);

    if (len <= 0)
        return 0;

    increment_nonce(con->sent_nonce);

    if ((unsigned int)len == sizeof(packet))
        return 1;

    memcpy(con->last_packet, packet, sizeof(packet));
    con->last_packet_length = sizeof(packet);
    con->last_packet_sent = len;
    return 1;
}

/* Kill a TCP_Secure_Connection
 */
static void kill_TCP_connection(TCP_Secure_Connection *con)
{
    kill_sock(con->sock);
    memset(con, 0, sizeof(TCP_Secure_Connection));
}

static int rm_connection_index(TCP_Server *TCP_server, TCP_Secure_Connection *con, uint8_t con_number);

/* Kill an accepted TCP_Secure_Connection
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int kill_accepted(TCP_Server *TCP_server, int index)
{
    if ((uint32_t)index >= TCP_server->size_accepted_connections)
        return -1;

    uint32_t i;

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        rm_connection_index(TCP_server, &TCP_server->accepted_connection_array[index], i);
    }

    sock_t sock = TCP_server->accepted_connection_array[index].sock;

    if (del_accepted(TCP_server, index) != 0)
        return -1;

    kill_sock(sock);
    return 0;
}

/* return 1 if everything went well.
 * return -1 if the connection must be killed.
 */
static int handle_TCP_handshake(TCP_Secure_Connection *con, const uint8_t *data, uint16_t length,
                                const uint8_t *self_secret_key)
{
    if (length != TCP_CLIENT_HANDSHAKE_SIZE)
        return -1;

    if (con->status != TCP_STATUS_CONNECTED)
        return -1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(data, self_secret_key, shared_key);
    uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
    int len = decrypt_data_symmetric(shared_key, data + crypto_box_PUBLICKEYBYTES,
                                     data + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, TCP_HANDSHAKE_PLAIN_SIZE + crypto_box_MACBYTES, plain);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE)
        return -1;

    memcpy(con->public_key, data, crypto_box_PUBLICKEYBYTES);
    uint8_t temp_secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t resp_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_box_keypair(resp_plain, temp_secret_key);
    random_nonce(con->sent_nonce);
    memcpy(resp_plain + crypto_box_PUBLICKEYBYTES, con->sent_nonce, crypto_box_NONCEBYTES);
    memcpy(con->recv_nonce, plain + crypto_box_PUBLICKEYBYTES, crypto_box_NONCEBYTES);

    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    new_nonce(response);

    len = encrypt_data_symmetric(shared_key, response, resp_plain, TCP_HANDSHAKE_PLAIN_SIZE,
                                 response + crypto_box_NONCEBYTES);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE + crypto_box_MACBYTES)
        return -1;

    if (TCP_SERVER_HANDSHAKE_SIZE != send(con->sock, response, TCP_SERVER_HANDSHAKE_SIZE, MSG_NOSIGNAL))
        return -1;

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
    uint8_t data[1 + 1 + crypto_box_PUBLICKEYBYTES];
    data[0] = TCP_PACKET_ROUTING_RESPONSE;
    data[1] = rpid;
    memcpy(data + 2, public_key, crypto_box_PUBLICKEYBYTES);

    return write_packet_TCP_secure_connection(con, data, sizeof(data), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_connect_notification(TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_CONNECTION_NOTIFICATION, id + NUM_RESERVED_PORTS};
    return write_packet_TCP_secure_connection(con, data, sizeof(data), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_disconnect_notification(TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_DISCONNECT_NOTIFICATION, id + NUM_RESERVED_PORTS};
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
    if (memcmp(con->public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0) {
        if (send_routing_response(con, 0, public_key) == -1)
            return -1;

        return 0;
    }

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        if (con->connections[i].status != 0) {
            if (memcmp(public_key, con->connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0) {
                if (send_routing_response(con, i + NUM_RESERVED_PORTS, public_key) == -1) {
                    return -1;
                } else {
                    return 0;
                }
            }
        } else if (index == (uint32_t)~0) {
            index = i;
        }
    }

    if (index == (uint32_t)~0) {
        if (send_routing_response(con, 0, public_key) == -1)
            return -1;

        return 0;
    }

    int ret = send_routing_response(con, index + NUM_RESERVED_PORTS, public_key);

    if (ret == 0)
        return 0;

    if (ret == -1)
        return -1;

    con->connections[index].status = 1;
    memcpy(con->connections[index].public_key, public_key, crypto_box_PUBLICKEYBYTES);
    int other_index = get_TCP_connection_index(TCP_server, public_key);

    if (other_index != -1) {
        uint32_t other_id = ~0;
        TCP_Secure_Connection *other_conn = &TCP_server->accepted_connection_array[other_index];

        for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
            if (other_conn->connections[i].status == 1
                    && memcmp(other_conn->connections[i].public_key, con->public_key, crypto_box_PUBLICKEYBYTES) == 0) {
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
            //TODO: return values?
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
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH)
        return -1;

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[con_id];

    int other_index = get_TCP_connection_index(TCP_server, public_key);

    if (other_index != -1) {
        uint8_t resp_packet[1 + crypto_box_PUBLICKEYBYTES + length];
        resp_packet[0] = TCP_PACKET_OOB_RECV;
        memcpy(resp_packet + 1, con->public_key, crypto_box_PUBLICKEYBYTES);
        memcpy(resp_packet + 1 + crypto_box_PUBLICKEYBYTES, data, length);
        write_packet_TCP_secure_connection(&TCP_server->accepted_connection_array[other_index], resp_packet,
                                           sizeof(resp_packet), 0);
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
    if (con_number >= NUM_CLIENT_CONNECTIONS)
        return -1;

    if (con->connections[con_number].status) {
        uint32_t index = con->connections[con_number].index;
        uint8_t other_id = con->connections[con_number].other_id;

        if (con->connections[con_number].status == 2) {

            if (index >= TCP_server->size_accepted_connections)
                return -1;

            TCP_server->accepted_connection_array[index].connections[other_id].other_id = 0;
            TCP_server->accepted_connection_array[index].connections[other_id].index = 0;
            TCP_server->accepted_connection_array[index].connections[other_id].status = 1;
            //TODO: return values?
            send_disconnect_notification(&TCP_server->accepted_connection_array[index], other_id);
        }

        con->connections[con_number].index = 0;
        con->connections[con_number].other_id = 0;
        con->connections[con_number].status = 0;
        return 0;
    } else {
        return -1;
    }
}

static int handle_onion_recv_1(void *object, IP_Port dest, const uint8_t *data, uint16_t length)
{
    TCP_Server *TCP_server = object;
    uint32_t index = dest.ip.ip6.uint32[0];

    if (index >= TCP_server->size_accepted_connections)
        return 1;

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[index];

    if (con->identifier != dest.ip.ip6.uint64[1])
        return 1;

    uint8_t packet[1 + length];
    memcpy(packet + 1, data, length);
    packet[0] = TCP_PACKET_ONION_RESPONSE;

    if (write_packet_TCP_secure_connection(con, packet, sizeof(packet), 0) != 1)
        return 1;

    return 0;
}

/* return 0 on success
 * return -1 on failure
 */
static int handle_TCP_packet(TCP_Server *TCP_server, uint32_t con_id, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[con_id];

    switch (data[0]) {
        case TCP_PACKET_ROUTING_REQUEST: {
            if (length != 1 + crypto_box_PUBLICKEYBYTES)
                return -1;

            return handle_TCP_routing_req(TCP_server, con_id, data + 1);
        }

        case TCP_PACKET_CONNECTION_NOTIFICATION: {
            if (length != 2)
                return -1;

            break;
        }

        case TCP_PACKET_DISCONNECT_NOTIFICATION: {
            if (length != 2)
                return -1;

            return rm_connection_index(TCP_server, con, data[1] - NUM_RESERVED_PORTS);
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            uint8_t response[1 + sizeof(uint64_t)];
            response[0] = TCP_PACKET_PONG;
            memcpy(response + 1, data + 1, sizeof(uint64_t));
            write_packet_TCP_secure_connection(con, response, sizeof(response), 1);
            return 0;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));

            if (ping_id) {
                if (ping_id == con->ping_id) {
                    con->ping_id = 0;
                }

                return 0;
            } else {
                return -1;
            }
        }

        case TCP_PACKET_OOB_SEND: {
            if (length <= 1 + crypto_box_PUBLICKEYBYTES)
                return -1;

            return handle_TCP_oob_send(TCP_server, con_id, data + 1, data + 1 + crypto_box_PUBLICKEYBYTES,
                                       length - (1 + crypto_box_PUBLICKEYBYTES));
        }

        case TCP_PACKET_ONION_REQUEST: {
            if (TCP_server->onion) {
                if (length <= 1 + crypto_box_NONCEBYTES + ONION_SEND_BASE * 2)
                    return -1;

                IP_Port source;
                source.port = 0;  // dummy initialise
                source.ip.family = TCP_ONION_FAMILY;
                source.ip.ip6.uint32[0] = con_id;
                source.ip.ip6.uint32[1] = 0;
                source.ip.ip6.uint64[1] = con->identifier;
                onion_send_1(TCP_server->onion, data + 1 + crypto_box_NONCEBYTES, length - (1 + crypto_box_NONCEBYTES), source,
                             data + 1);
            }

            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {
            return -1;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS)
                return -1;

            uint8_t c_id = data[0] - NUM_RESERVED_PORTS;

            if (c_id >= NUM_CLIENT_CONNECTIONS)
                return -1;

            if (con->connections[c_id].status == 0)
                return -1;

            if (con->connections[c_id].status != 2)
                return 0;

            uint32_t index = con->connections[c_id].index;
            uint8_t other_c_id = con->connections[c_id].other_id + NUM_RESERVED_PORTS;
            uint8_t new_data[length];
            memcpy(new_data, data, length);
            new_data[0] = other_c_id;
            int ret = write_packet_TCP_secure_connection(&TCP_server->accepted_connection_array[index], new_data, length, 0);

            if (ret == -1)
                return -1;

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
        kill_TCP_connection(con);
        return -1;
    }

    memset(con, 0, sizeof(TCP_Secure_Connection));

    if (handle_TCP_packet(TCP_server, index, data, length) == -1) {
        kill_accepted(TCP_server, index);
        return -1;
    }

    return index;
}

/* return index on success
 * return -1 on failure
 */
static int accept_connection(TCP_Server *TCP_server, sock_t sock)
{
    if (!sock_valid(sock))
        return -1;

    if (!set_socket_nonblock(sock)) {
        kill_sock(sock);
        return -1;
    }

    if (!set_socket_nosigpipe(sock)) {
        kill_sock(sock);
        return -1;
    }

    uint16_t index = TCP_server->incomming_connection_queue_index % MAX_INCOMMING_CONNECTIONS;

    TCP_Secure_Connection *conn = &TCP_server->incomming_connection_queue[index];

    if (conn->status != TCP_STATUS_NO_STATUS)
        kill_TCP_connection(conn);

    conn->status = TCP_STATUS_CONNECTED;
    conn->sock = sock;
    conn->next_packet_length = 0;

    ++TCP_server->incomming_connection_queue_index;
    return index;
}

static sock_t new_listening_TCP_socket(int family, uint16_t port)
{
    sock_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if (!sock_valid(sock)) {
        return ~0;
    }

    int ok = set_socket_nonblock(sock);

    if (ok && family == AF_INET6) {
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

TCP_Server *new_TCP_server(uint8_t ipv6_enabled, uint16_t num_sockets, const uint16_t *ports, const uint8_t *public_key,
                           const uint8_t *secret_key, Onion *onion)
{
    if (num_sockets == 0 || ports == NULL)
        return NULL;

    if (networking_at_startup() != 0) {
        return NULL;
    }

    TCP_Server *temp = calloc(1, sizeof(TCP_Server));

    if (temp == NULL)
        return NULL;

    temp->socks_listening = calloc(num_sockets, sizeof(sock_t));

    if (temp->socks_listening == NULL) {
        free(temp);
        return NULL;
    }

#ifdef TCP_SERVER_USE_EPOLL
    temp->efd = epoll_create(8);

    if (temp->efd == -1) {
        free(temp->socks_listening);
        free(temp);
        return NULL;
    }

#endif

    uint8_t family;

    if (ipv6_enabled) {
        family = AF_INET6;
    } else {
        family = AF_INET;
    }

    uint32_t i;
#ifdef TCP_SERVER_USE_EPOLL
    struct epoll_event ev;
#endif

    for (i = 0; i < num_sockets; ++i) {
        sock_t sock = new_listening_TCP_socket(family, ports[i]);

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
        return NULL;
    }

    if (onion) {
        temp->onion = onion;
        set_callback_handle_recv_1(onion, &handle_onion_recv_1, temp);
    }

    memcpy(temp->public_key, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp->secret_key, secret_key, crypto_box_SECRETKEYBYTES);

    bs_list_init(&temp->accepted_key_list, crypto_box_PUBLICKEYBYTES, 8);

    return temp;
}

static void do_TCP_accept_new(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < TCP_server->num_listening_socks; ++i) {
        struct sockaddr_storage addr;
        unsigned int addrlen = sizeof(addr);
        sock_t sock;

        do {
            sock = accept(TCP_server->socks_listening[i], (struct sockaddr *)&addr, &addrlen);
        } while (accept_connection(TCP_server, sock) != -1);
    }
}

static int do_incoming(TCP_Server *TCP_server, uint32_t i)
{
    if (TCP_server->incomming_connection_queue[i].status != TCP_STATUS_CONNECTED)
        return -1;

    int ret = read_connection_handshake(&TCP_server->incomming_connection_queue[i], TCP_server->secret_key);

    if (ret == -1) {
        kill_TCP_connection(&TCP_server->incomming_connection_queue[i]);
    } else if (ret == 1) {
        int index_new = TCP_server->unconfirmed_connection_queue_index % MAX_INCOMMING_CONNECTIONS;
        TCP_Secure_Connection *conn_old = &TCP_server->incomming_connection_queue[i];
        TCP_Secure_Connection *conn_new = &TCP_server->unconfirmed_connection_queue[index_new];

        if (conn_new->status != TCP_STATUS_NO_STATUS)
            kill_TCP_connection(conn_new);

        memcpy(conn_new, conn_old, sizeof(TCP_Secure_Connection));
        memset(conn_old, 0, sizeof(TCP_Secure_Connection));
        ++TCP_server->unconfirmed_connection_queue_index;

        return index_new;
    }

    return -1;
}

static int do_unconfirmed(TCP_Server *TCP_server, uint32_t i)
{
    TCP_Secure_Connection *conn = &TCP_server->unconfirmed_connection_queue[i];

    if (conn->status != TCP_STATUS_UNCONFIRMED)
        return -1;

    uint8_t packet[MAX_PACKET_SIZE];
    int len = read_packet_TCP_secure_connection(conn->sock, &conn->next_packet_length, conn->shared_key, conn->recv_nonce,
              packet, sizeof(packet));

    if (len == 0) {
        return -1;
    } else if (len == -1) {
        kill_TCP_connection(conn);
        return -1;
    } else {
        return confirm_TCP_connection(TCP_server, conn, packet, len);
    }
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

static void do_TCP_incomming(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMMING_CONNECTIONS; ++i) {
        do_incoming(TCP_server, i);
    }
}

static void do_TCP_unconfirmed(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMMING_CONNECTIONS; ++i) {
        do_unconfirmed(TCP_server, i);
    }
}

static void do_TCP_confirmed(TCP_Server *TCP_server)
{
#ifdef TCP_SERVER_USE_EPOLL

    if (TCP_server->last_run_pinged == unix_time())
        return;

    TCP_server->last_run_pinged = unix_time();
#endif
    uint32_t i;

    for (i = 0; i < TCP_server->size_accepted_connections; ++i) {
        TCP_Secure_Connection *conn = &TCP_server->accepted_connection_array[i];

        if (conn->status != TCP_STATUS_CONFIRMED)
            continue;

        if (is_timeout(conn->last_pinged, TCP_PING_FREQUENCY)) {
            uint8_t ping[1 + sizeof(uint64_t)];
            ping[0] = TCP_PACKET_PING;
            uint64_t ping_id = random_64b();

            if (!ping_id)
                ++ping_id;

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
            sock_t sock = events[n].data.u64 & 0xFFFFFFFF;
            int status = (events[n].data.u64 >> 32) & 0xFF, index = (events[n].data.u64 >> 40);

            if ((events[n].events & EPOLLERR) || (events[n].events & EPOLLHUP) || (events[n].events & EPOLLRDHUP)) {
                switch (status) {
                    case TCP_SOCKET_LISTENING: {
                        //should never happen
                        break;
                    }

                    case TCP_SOCKET_INCOMING: {
                        kill_TCP_connection(&TCP_server->incomming_connection_queue[index]);
                        break;
                    }

                    case TCP_SOCKET_UNCONFIRMED: {
                        kill_TCP_connection(&TCP_server->unconfirmed_connection_queue[index]);
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
                    unsigned int addrlen = sizeof(addr);

                    while (1) {
                        sock_t sock_new = accept(sock, (struct sockaddr *)&addr, &addrlen);

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
                            kill_TCP_connection(&TCP_server->incomming_connection_queue[index_new]);
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
                            kill_TCP_connection(&TCP_server->unconfirmed_connection_queue[index_new]);
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
    do_TCP_incomming(TCP_server);
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
        set_callback_handle_recv_1(TCP_server->onion, NULL, NULL);
    }

    bs_list_free(&TCP_server->accepted_key_list);

#ifdef TCP_SERVER_USE_EPOLL
    close(TCP_server->efd);
#endif

    free(TCP_server->socks_listening);
    free(TCP_server->accepted_connection_array);
    free(TCP_server);
}
