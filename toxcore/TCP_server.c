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

/* return length on success
 * return 0 if nothing has been read from socket.
 * return ~0 on failure.
 */
static uint16_t read_length(sock_t sock)
{
    int count;
    ioctl(sock, FIONREAD, &count);

    if ((unsigned int)count >= sizeof(uint16_t)) {
        uint16_t length;
        int len = recv(sock, &length, sizeof(uint16_t), 0);

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
    int count;
    ioctl(sock, FIONREAD, &count);

    if (count >= length) {
        int len = recv(sock, data, length, 0);

        if (len != length) {
            fprintf(stderr, "FAIL recv packet\n");
            return -1;
        }

        return length;
    }

    return -1;
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
        if (TCP_server->incomming_connection_queue[i].status != TCP_STATUS_CONNECTED)
            continue;
    }
}
void do_TCP_server(TCP_Server *TCP_server)
{
    do_TCP_accept_new(TCP_server);
    do_TCP_incomming(TCP_server);
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
