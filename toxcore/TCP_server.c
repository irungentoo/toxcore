/*
* TCP_server.c -- Implementation of the TCP relay server part of Tox.
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

#include "TCP_server.h"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif

/* return 1 if valid
 * return 0 if not valid
 */
static int sock_valid(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

    if (sock == INVALID_SOCKET) {
#else

    if (sock < 0) {
#endif
        return 0;
    }

    return 1;
}

static void kill_sock(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

/* return 1 on success
 * return 0 on failure
 */
static int set_nonblock(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
#else
    return (fcntl(sock, F_SETFL, O_NONBLOCK, 1) == 0);
#endif
}

/* return 1 on success
 * return 0 on failure
 */
static int set_dualstack(sock_t sock)
{
    char ipv6only = 0;
    socklen_t optsize = sizeof(ipv6only);
    int res = getsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, &optsize);

    if ((res == 0) && (ipv6only == 0))
        return 1;

    ipv6only = 0;
    return (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) == 0);
}

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

    TCP_Secure_Connection *new_connections = realloc(TCP_server->accepted_connection_array,
            num * sizeof(TCP_Secure_Connection));

    if (new_connections == NULL)
        return -1;

    TCP_server->accepted_connection_array = new_connections;
    TCP_server->size_accepted_connections = num;
    return 0;
}

/* Add accepted TCP connection to the list.
 *
 * return index on success
 * return -1 on failure
 */
static int add_accepted(TCP_Server *TCP_server, TCP_Secure_Connection *con)
{
    int index = -1;

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

    memcpy(&TCP_server->accepted_connection_array[index], con, sizeof(TCP_Secure_Connection));
    TCP_server->accepted_connection_array[index].status = TCP_STATUS_CONFIRMED;
    ++TCP_server->num_accepted_connections;
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

    memset(&TCP_server->accepted_connection_array[index], 0, sizeof(TCP_Secure_Connection));
    --TCP_server->num_accepted_connections;

    if (TCP_server->num_accepted_connections == 0)
        realloc_connection(TCP_server, 0);

    return 0;
}

/* return index corresponding to connection with peer on success
 * return -1 on failure.
 */
static int get_TCP_connection_index(TCP_Server *TCP_server, uint8_t *public_key)
{
    //TODO optimize this function.
    uint32_t i;

    for (i = 0; i < TCP_server->size_accepted_connections; ++i) {
        if (memcmp(TCP_server->accepted_connection_array[i].public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0)
            return i;
    }

    return -1;
}

/* return length on success
 * return 0 if nothing has been read from socket.
 * return ~0 on failure.
 */
static uint16_t read_length(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    unsigned long count = 0;
    ioctlsocket(sock, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock, FIONREAD, &count);
#endif

    if ((unsigned int)count >= sizeof(uint16_t)) {
        uint16_t length;
        int len = recv(sock, (uint8_t *)&length, sizeof(uint16_t), 0);

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

/* return length on success
 * return -1 on failure
 */
static int read_TCP_packet(sock_t sock, uint8_t *data, uint16_t length)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    unsigned long count = 0;
    ioctlsocket(sock, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock, FIONREAD, &count);
#endif

    if (count >= length) {
        int len = recv(sock, data, length, 0);

        if (len != length) {
            fprintf(stderr, "FAIL recv packet\n");
            return -1;
        }

        return len;
    }

    return -1;
}

/* return length of recieved packet on success.
 * return 0 if could not read any packet.
 * return -1 on failure (connection must be killed).
 */
static int read_packet_TCP_secure_connection(TCP_Secure_Connection *con, uint8_t *data, uint16_t max_len)
{
    if (con->next_packet_length == 0) {
        uint16_t len = read_length(con->sock);

        if (len == (uint16_t)~0)
            return -1;

        if (len == 0)
            return 0;

        con->next_packet_length = len;
    }

    if (max_len + crypto_box_MACBYTES < con->next_packet_length)
        return -1;

    uint8_t data_encrypted[con->next_packet_length];
    int len_packet = read_TCP_packet(con->sock, data_encrypted, con->next_packet_length);

    if (len_packet != con->next_packet_length)
        return 0;

    con->next_packet_length = 0;

    int len = decrypt_data_fast(con->shared_key, con->recv_nonce, data_encrypted, len_packet, data);

    if (len + crypto_box_MACBYTES != len_packet)
        return -1;

    increment_nonce(con->recv_nonce);

    return len;
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
static int send_pending_data(TCP_Secure_Connection *con)
{
    if (con->last_packet_length == 0) {
        return 0;
    }

    uint16_t left = con->last_packet_length - con->last_packet_sent;
    int len = send(con->sock, con->last_packet + con->last_packet_sent, left, 0);

    if (len <= 0)
        return -1;

    if (len == left) {
        con->last_packet_length = 0;
        con->last_packet_sent = 0;
        return 0;
    }

    if (len > left)
        return -1;

    con->last_packet_sent += len;
    return -1;

}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int write_packet_TCP_secure_connection(TCP_Secure_Connection *con, uint8_t *data, uint16_t length)
{
    if (length + crypto_box_MACBYTES > MAX_PACKET_SIZE)
        return -1;

    if (send_pending_data(con) == -1)
        return 0;

    uint8_t packet[sizeof(uint16_t) + length + crypto_box_MACBYTES];

    uint16_t c_length = htons(length + crypto_box_MACBYTES);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_fast(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (sizeof(packet) - sizeof(uint16_t)))
        return -1;

    increment_nonce(con->sent_nonce);

    len = send(con->sock, packet, sizeof(packet), 0);

    if ((unsigned int)len == sizeof(packet))
        return 1;

    if (len <= 0)
        return 0;

    memcpy(con->last_packet, packet, length);
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

/* return 1 if everything went well.
 * return -1 if the connection must be killed.
 */
static int handle_TCP_handshake(TCP_Secure_Connection *con, uint8_t *data, uint16_t length, uint8_t *self_secret_key)
{
    if (length != TCP_CLIENT_HANDSHAKE_SIZE)
        return -1;

    if (con->status != TCP_STATUS_CONNECTED)
        return -1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(data, self_secret_key, shared_key);
    uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
    int len = decrypt_data_fast(shared_key, data + crypto_box_PUBLICKEYBYTES,
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

    len = encrypt_data_fast(shared_key, response, resp_plain, TCP_HANDSHAKE_PLAIN_SIZE, response + crypto_box_NONCEBYTES);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE + crypto_box_MACBYTES)
        return -1;

    if (TCP_SERVER_HANDSHAKE_SIZE != send(con->sock, response, TCP_SERVER_HANDSHAKE_SIZE, 0))
        return -1;

    encrypt_precompute(plain, temp_secret_key, con->shared_key);
    con->status = TCP_STATUS_UNCONFIRMED;
    return 1;
}

/* return 1 if connection handshake was handled correctly.
 * return 0 if we didn't get it yet.
 * return -1 if the connection must be killed.
 */
static int read_connection_handshake(TCP_Secure_Connection *con, uint8_t *self_secret_key)
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
static int send_routing_response(TCP_Secure_Connection *con, uint8_t rpid, uint8_t *public_key)
{
    uint8_t data[1 + 1 + crypto_box_PUBLICKEYBYTES];
    data[0] = TCP_PACKET_ROUTING_RESPONSE;
    data[1] = rpid;
    memcpy(data + 2, public_key, crypto_box_PUBLICKEYBYTES);

    return write_packet_TCP_secure_connection(con, data, sizeof(data));
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_connect_notification(TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_CONNECTION_NOTIFICATION, id + NUM_RESERVED_PORTS};
    return write_packet_TCP_secure_connection(con, data, sizeof(data));
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
static int send_disconnect_notification(TCP_Secure_Connection *con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_DISCONNECT_NOTIFICATION, id + NUM_RESERVED_PORTS};
    return write_packet_TCP_secure_connection(con, data, sizeof(data));
}

/* return 0 on success.
 * return -1 on failure (connection must be killed).
 */
static int handle_TCP_routing_req(TCP_Server *TCP_server, uint32_t con_id, uint8_t *public_key)
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
        if (con->connections[i].status == 0) {
            index = i;
            break;
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

static int disconnect_conection_index(TCP_Server *TCP_server, TCP_Secure_Connection *con, uint8_t con_number)
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
        //TODO: return values?
        send_disconnect_notification(con, con_number);
        return 0;
    } else {
        return -1;
    }
}

/* return 0 on success
 * return -1 on failure
 */
static int handle_TCP_packet(TCP_Server *TCP_server, uint32_t con_id, uint8_t *data, uint16_t length)
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

            return disconnect_conection_index(TCP_server, con, data[1] - NUM_RESERVED_PORTS);
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            break;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            break;
        }

        case TCP_PACKET_ONION_REQUEST: {
            //if (length <= 1 + crypto_box_NONCEBYTES + ONION_SEND_BASE*2)
            //    return -1;

            //TODO onion_send_1(Onion *onion, data + 1 + crypto_box_NONCEBYTES, length - (1 + crypto_box_NONCEBYTES), IP_Port source, data + 1);
            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {

            break;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS)
                return -1;

            uint8_t con_id = data[0] - NUM_RESERVED_PORTS;

            if (con_id >= NUM_CLIENT_CONNECTIONS)
                return -1;

            if (con->connections[con_id].status == 0)
                return -1;

            if (con->connections[con_id].status != 2)
                return 0;

            uint32_t index = con->connections[con_id].index;
            uint8_t other_con_id = con->connections[con_id].other_id + NUM_RESERVED_PORTS;
            uint8_t new_data[length];
            memcpy(new_data, data, length);
            new_data[0] = other_con_id;
            int ret = write_packet_TCP_secure_connection(&TCP_server->accepted_connection_array[index], new_data, length);

            if (ret == -1)
                return -1;

            return 0;
        }
    }

    return 0;
}


static int confirm_TCP_connection(TCP_Server *TCP_server, TCP_Secure_Connection *con, uint8_t *data, uint16_t length)
{
    int index = add_accepted(TCP_server, con);

    if (index == -1)
        return -1;

    TCP_Secure_Connection *conn = &TCP_server->accepted_connection_array[index];

    if (handle_TCP_packet(TCP_server, index, data, length) == -1) {
        kill_TCP_connection(conn);
        del_accepted(TCP_server, index);
    }

    return 0;
}

/* return 1 on success
 * return 0 on failure
 */
static int accept_connection(TCP_Server *TCP_server, sock_t sock)
{
    if (!sock_valid(sock))
        return 0;

    if (!set_nonblock(sock)) {
        kill_sock(sock);
        return 0;
    }

    TCP_Secure_Connection *conn =
        &TCP_server->incomming_connection_queue[TCP_server->incomming_connection_queue_index % MAX_INCOMMING_CONNECTIONS];

    if (conn->status != TCP_STATUS_NO_STATUS)
        kill_TCP_connection(conn);

    conn->status = TCP_STATUS_CONNECTED;
    conn->sock = sock;
    conn->next_packet_length = 0;

    ++TCP_server->incomming_connection_queue_index;
    return 1;
}

static sock_t new_listening_TCP_socket(int family, uint16_t port)
{
    sock_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if (!sock_valid(sock)) {
        return ~0;
    }

    int ok = set_nonblock(sock);

    if (ok && family == AF_INET6) {
        ok = set_dualstack(sock);
    }

    ok = ok && bind_to_port(sock, family, port) && (listen(sock, TCP_MAX_BACKLOG) == 0);

    if (!ok) {
        kill_sock(sock);
        return ~0;
    }

    return sock;
}

TCP_Server *new_TCP_server(uint8_t ipv6_enabled, uint16_t num_sockets, uint16_t *ports, uint8_t *public_key,
                           uint8_t *secret_key)
{
    if (num_sockets == 0 || ports == NULL)
        return NULL;

    TCP_Server *temp = calloc(1, sizeof(TCP_Server));

    if (temp == NULL)
        return NULL;

    temp->socks_listening = calloc(num_sockets, sizeof(sock_t));

    if (temp->socks_listening == NULL) {
        free(temp);
        return NULL;
    }

    uint8_t family;

    if (ipv6_enabled) {
        family = AF_INET6;
    } else {
        family = AF_INET;
    }

    uint32_t i;

    for (i = 0; i < num_sockets; ++i) {
        sock_t sock = new_listening_TCP_socket(family, ports[i]);

        if (sock_valid(sock)) {
            temp->socks_listening[temp->num_listening_socks] = sock;
            ++temp->num_listening_socks;
        }
    }

    memcpy(temp->public_key, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp->secret_key, secret_key, crypto_box_SECRETKEYBYTES);
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
        } while (accept_connection(TCP_server, sock));
    }
}

static void do_TCP_incomming(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMMING_CONNECTIONS; ++i) {
        if (TCP_server->incomming_connection_queue[i].status != TCP_STATUS_CONNECTED)
            continue;

        int ret = read_connection_handshake(&TCP_server->incomming_connection_queue[i], TCP_server->secret_key);

        if (ret == -1) {
            kill_TCP_connection(&TCP_server->incomming_connection_queue[i]);
        } else if (ret == 1) {
            TCP_Secure_Connection *conn_old = &TCP_server->incomming_connection_queue[i];
            TCP_Secure_Connection *conn_new =
                &TCP_server->unconfirmed_connection_queue[TCP_server->unconfirmed_connection_queue_index % MAX_INCOMMING_CONNECTIONS];

            if (conn_new->status != TCP_STATUS_NO_STATUS)
                kill_TCP_connection(conn_new);

            memcpy(conn_new, conn_old, sizeof(TCP_Secure_Connection));
            memset(conn_old, 0, sizeof(TCP_Secure_Connection));
            ++TCP_server->unconfirmed_connection_queue_index;
        }
    }
}

static void do_TCP_unconfirmed(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMMING_CONNECTIONS; ++i) {
        TCP_Secure_Connection *conn = &TCP_server->unconfirmed_connection_queue[i];

        if (conn->status != TCP_STATUS_UNCONFIRMED)
            continue;

        uint8_t packet[MAX_PACKET_SIZE];
        int len = read_packet_TCP_secure_connection(conn, packet, sizeof(packet));

        if (len == 0) {
            continue;
        } else if (len == -1) {
            kill_TCP_connection(conn);
            continue;
        } else {
            if (confirm_TCP_connection(TCP_server, conn, packet, len) == -1) {
                kill_TCP_connection(conn);
            } else {
                memset(conn, 0, sizeof(TCP_Secure_Connection));
            }
        }
    }
}

static void do_TCP_confirmed(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < TCP_server->size_accepted_connections; ++i) {
        TCP_Secure_Connection *conn = &TCP_server->accepted_connection_array[i];

        if (conn->status != TCP_STATUS_CONFIRMED)
            continue;

        send_pending_data(conn);
        uint8_t packet[MAX_PACKET_SIZE];
        int len;

        while ((len = read_packet_TCP_secure_connection(conn, packet, sizeof(packet)))) {
            if (len == -1) {
                kill_TCP_connection(conn);
                del_accepted(TCP_server, i);
                break;
            }

            if (handle_TCP_packet(TCP_server, i, packet, len) == -1) {
                kill_TCP_connection(conn);
                del_accepted(TCP_server, i);
                break;
            }
        }
    }
}

void do_TCP_server(TCP_Server *TCP_server)
{
    do_TCP_accept_new(TCP_server);
    do_TCP_incomming(TCP_server);
    do_TCP_unconfirmed(TCP_server);
    do_TCP_confirmed(TCP_server);
}

void kill_TCP_server(TCP_Server *TCP_server)
{
    uint32_t i;

    for (i = 0; i < TCP_server->num_listening_socks; ++i) {
        kill_sock(TCP_server->socks_listening[i]);
    }

    free(TCP_server->socks_listening);
    free(TCP_server);
}
