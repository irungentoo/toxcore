/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay client part of Tox.
 */
#include "TCP_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "TCP_common.h"
#include "ccompat.h"
#include "mono_time.h"
#include "util.h"

typedef struct TCP_Client_Conn {
    // TODO(iphydf): Add an enum for this.
    uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint32_t number;
} TCP_Client_Conn;

struct TCP_Client_Connection {
    TCP_Connection con;
    TCP_Client_Status status;
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* our public key */
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* public key of the server */
    IP_Port ip_port; /* The ip and port of the server */
    TCP_Proxy_Info proxy_info;
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint16_t next_packet_length;

    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];

    uint64_t kill_at;

    uint64_t last_pinged;
    uint64_t ping_id;

    uint64_t ping_response_id;
    uint64_t ping_request_id;

    TCP_Client_Conn connections[NUM_CLIENT_CONNECTIONS];
    tcp_routing_response_cb *response_callback;
    void *response_callback_object;
    tcp_routing_status_cb *status_callback;
    void *status_callback_object;
    tcp_routing_data_cb *data_callback;
    void *data_callback_object;
    tcp_oob_data_cb *oob_data_callback;
    void *oob_data_callback_object;

    tcp_onion_response_cb *onion_callback;
    void *onion_callback_object;

    forwarded_response_cb *forwarded_response_callback;
    void *forwarded_response_callback_object;

    /* Can be used by user. */
    void *custom_object;
    uint32_t custom_uint;
};

const uint8_t *tcp_con_public_key(const TCP_Client_Connection *con)
{
    return con->public_key;
}

IP_Port tcp_con_ip_port(const TCP_Client_Connection *con)
{
    return con->ip_port;
}

TCP_Client_Status tcp_con_status(const TCP_Client_Connection *con)
{
    return con->status;
}
void *tcp_con_custom_object(const TCP_Client_Connection *con)
{
    return con->custom_object;
}
uint32_t tcp_con_custom_uint(const TCP_Client_Connection *con)
{
    return con->custom_uint;
}
void tcp_con_set_custom_object(TCP_Client_Connection *con, void *object)
{
    con->custom_object = object;
}
void tcp_con_set_custom_uint(TCP_Client_Connection *con, uint32_t value)
{
    con->custom_uint = value;
}

/**
 * @retval true on success
 * @retval false on failure
 */
non_null()
static bool connect_sock_to(const Logger *logger, Socket sock, const IP_Port *ip_port, const TCP_Proxy_Info *proxy_info)
{
    if (proxy_info->proxy_type != TCP_PROXY_NONE) {
        return net_connect(logger, sock, &proxy_info->ip_port);
    } else {
        return net_connect(logger, sock, ip_port);
    }
}

/**
 * @retval 1 on success.
 * @retval 0 on failure.
 */
non_null()
static int proxy_http_generate_connection_request(TCP_Client_Connection *tcp_conn)
{
    char one[] = "CONNECT ";
    char two[] = " HTTP/1.1\nHost: ";
    char three[] = "\r\n\r\n";

    char ip[TOX_INET6_ADDRSTRLEN];

    if (!ip_parse_addr(&tcp_conn->ip_port.ip, ip, sizeof(ip))) {
        return 0;
    }

    const uint16_t port = net_ntohs(tcp_conn->ip_port.port);
    const int written = snprintf((char *)tcp_conn->con.last_packet, MAX_PACKET_SIZE, "%s%s:%hu%s%s:%hu%s", one, ip, port,
                                 two, ip, port, three);

    if (written < 0 || MAX_PACKET_SIZE < written) {
        return 0;
    }

    tcp_conn->con.last_packet_length = written;
    tcp_conn->con.last_packet_sent = 0;
    return 1;
}

/**
 * @retval 1 on success.
 * @retval 0 if no data received.
 * @retval -1 on failure (connection refused).
 */
non_null()
static int proxy_http_read_connection_response(const Logger *logger, const TCP_Client_Connection *tcp_conn)
{
    char success[] = "200";
    uint8_t data[16]; // draining works the best if the length is a power of 2

    const int ret = read_TCP_packet(logger, tcp_conn->con.ns, tcp_conn->con.sock, data, sizeof(data) - 1,
                                    &tcp_conn->con.ip_port);

    if (ret == -1) {
        return 0;
    }

    data[sizeof(data) - 1] = 0;

    if (strstr((const char *)data, success) != nullptr) {
        // drain all data
        uint16_t data_left = net_socket_data_recv_buffer(tcp_conn->con.ns, tcp_conn->con.sock);

        while (data_left > 0) {
            uint8_t temp_data[16];
            const uint16_t temp_data_size = min_u16(data_left, sizeof(temp_data));

            if (read_TCP_packet(logger, tcp_conn->con.ns, tcp_conn->con.sock, temp_data, temp_data_size,
                                &tcp_conn->con.ip_port) == -1) {
                LOGGER_ERROR(logger, "failed to drain TCP data (but ignoring failure)");
                return 1;
            }

            data_left -= temp_data_size;
        }

        return 1;
    }

    return -1;
}

#define TCP_SOCKS5_PROXY_HS_VERSION_SOCKS5 0x05
#define TCP_SOCKS5_PROXY_HS_COMM_ESTABLISH_REQUEST 0x01
#define TCP_SOCKS5_PROXY_HS_COMM_REQUEST_GRANTED 0x00
#define TCP_SOCKS5_PROXY_HS_AUTH_METHODS_SUPPORTED 0x01
#define TCP_SOCKS5_PROXY_HS_NO_AUTH 0x00
#define TCP_SOCKS5_PROXY_HS_RESERVED 0x00
#define TCP_SOCKS5_PROXY_HS_ADDR_TYPE_IPV4 0x01
#define TCP_SOCKS5_PROXY_HS_ADDR_TYPE_IPV6 0x04

non_null()
static void proxy_socks5_generate_greetings(TCP_Client_Connection *tcp_conn)
{
    tcp_conn->con.last_packet[0] = TCP_SOCKS5_PROXY_HS_VERSION_SOCKS5;
    tcp_conn->con.last_packet[1] = TCP_SOCKS5_PROXY_HS_AUTH_METHODS_SUPPORTED;
    tcp_conn->con.last_packet[2] = TCP_SOCKS5_PROXY_HS_NO_AUTH;

    tcp_conn->con.last_packet_length = 3;
    tcp_conn->con.last_packet_sent = 0;
}

/**
 * @retval 1 on success.
 * @retval 0 if no data received.
 * @retval -1 on failure (connection refused).
 */
non_null()
static int socks5_read_handshake_response(const Logger *logger, const TCP_Client_Connection *tcp_conn)
{
    uint8_t data[2];
    const int ret = read_TCP_packet(logger, tcp_conn->con.ns, tcp_conn->con.sock, data, sizeof(data), &tcp_conn->con.ip_port);

    if (ret == -1) {
        return 0;
    }

    if (data[0] == TCP_SOCKS5_PROXY_HS_VERSION_SOCKS5 && data[1] == TCP_SOCKS5_PROXY_HS_COMM_REQUEST_GRANTED) {
        return 1;
    }

    return -1;
}

non_null()
static void proxy_socks5_generate_connection_request(TCP_Client_Connection *tcp_conn)
{
    tcp_conn->con.last_packet[0] = TCP_SOCKS5_PROXY_HS_VERSION_SOCKS5;
    tcp_conn->con.last_packet[1] = TCP_SOCKS5_PROXY_HS_COMM_ESTABLISH_REQUEST;
    tcp_conn->con.last_packet[2] = TCP_SOCKS5_PROXY_HS_RESERVED;
    uint16_t length = 3;

    if (net_family_is_ipv4(tcp_conn->ip_port.ip.family)) {
        tcp_conn->con.last_packet[3] = TCP_SOCKS5_PROXY_HS_ADDR_TYPE_IPV4;
        ++length;
        memcpy(tcp_conn->con.last_packet + length, tcp_conn->ip_port.ip.ip.v4.uint8, sizeof(IP4));
        length += sizeof(IP4);
    } else {
        tcp_conn->con.last_packet[3] = TCP_SOCKS5_PROXY_HS_ADDR_TYPE_IPV6;
        ++length;
        memcpy(tcp_conn->con.last_packet + length, tcp_conn->ip_port.ip.ip.v6.uint8, sizeof(IP6));
        length += sizeof(IP6);
    }

    memcpy(tcp_conn->con.last_packet + length, &tcp_conn->ip_port.port, sizeof(uint16_t));
    length += sizeof(uint16_t);

    tcp_conn->con.last_packet_length = length;
    tcp_conn->con.last_packet_sent = 0;
}

/**
 * @retval 1 on success.
 * @retval 0 if no data received.
 * @retval -1 on failure (connection refused).
 */
non_null()
static int proxy_socks5_read_connection_response(const Logger *logger, const TCP_Client_Connection *tcp_conn)
{
    if (net_family_is_ipv4(tcp_conn->ip_port.ip.family)) {
        uint8_t data[4 + sizeof(IP4) + sizeof(uint16_t)];
        const int ret = read_TCP_packet(logger, tcp_conn->con.ns, tcp_conn->con.sock, data, sizeof(data), &tcp_conn->con.ip_port);

        if (ret == -1) {
            return 0;
        }

        if (data[0] == TCP_SOCKS5_PROXY_HS_VERSION_SOCKS5 && data[1] == TCP_SOCKS5_PROXY_HS_COMM_REQUEST_GRANTED) {
            return 1;
        }
    } else {
        uint8_t data[4 + sizeof(IP6) + sizeof(uint16_t)];
        int ret = read_TCP_packet(logger, tcp_conn->con.ns, tcp_conn->con.sock, data, sizeof(data), &tcp_conn->con.ip_port);

        if (ret == -1) {
            return 0;
        }

        if (data[0] == TCP_SOCKS5_PROXY_HS_VERSION_SOCKS5 && data[1] == TCP_SOCKS5_PROXY_HS_COMM_REQUEST_GRANTED) {
            return 1;
        }
    }

    return -1;
}

/**
 * @retval 0 on success.
 * @retval -1 on failure.
 */
non_null()
static int generate_handshake(TCP_Client_Connection *tcp_conn)
{
    uint8_t plain[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE];
    crypto_new_keypair(tcp_conn->con.rng, plain, tcp_conn->temp_secret_key);
    random_nonce(tcp_conn->con.rng, tcp_conn->con.sent_nonce);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, tcp_conn->con.sent_nonce, CRYPTO_NONCE_SIZE);
    memcpy(tcp_conn->con.last_packet, tcp_conn->self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    random_nonce(tcp_conn->con.rng, tcp_conn->con.last_packet + CRYPTO_PUBLIC_KEY_SIZE);
    const int len = encrypt_data_symmetric(tcp_conn->con.shared_key, tcp_conn->con.last_packet + CRYPTO_PUBLIC_KEY_SIZE, plain,
                                     sizeof(plain), tcp_conn->con.last_packet + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if (len != sizeof(plain) + CRYPTO_MAC_SIZE) {
        return -1;
    }

    tcp_conn->con.last_packet_length = CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + sizeof(plain) + CRYPTO_MAC_SIZE;
    tcp_conn->con.last_packet_sent = 0;
    return 0;
}

/**
 * @param data must be of length TCP_SERVER_HANDSHAKE_SIZE
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
non_null()
static int handle_handshake(TCP_Client_Connection *tcp_conn, const uint8_t *data)
{
    uint8_t plain[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE];
    const int len = decrypt_data_symmetric(tcp_conn->con.shared_key, data, data + CRYPTO_NONCE_SIZE,
                                     TCP_SERVER_HANDSHAKE_SIZE - CRYPTO_NONCE_SIZE, plain);

    if (len != sizeof(plain)) {
        return -1;
    }

    memcpy(tcp_conn->recv_nonce, plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);
    encrypt_precompute(plain, tcp_conn->temp_secret_key, tcp_conn->con.shared_key);
    crypto_memzero(tcp_conn->temp_secret_key, CRYPTO_SECRET_KEY_SIZE);
    return 0;
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_routing_request(const Logger *logger, TCP_Client_Connection *con, const uint8_t *public_key)
{
    uint8_t packet[1 + CRYPTO_PUBLIC_KEY_SIZE];
    packet[0] = TCP_PACKET_ROUTING_REQUEST;
    memcpy(packet + 1, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    return write_packet_TCP_secure_connection(logger, &con->con, packet, sizeof(packet), true);
}

void routing_response_handler(TCP_Client_Connection *con, tcp_routing_response_cb *response_callback, void *object)
{
    con->response_callback = response_callback;
    con->response_callback_object = object;
}

void routing_status_handler(TCP_Client_Connection *con, tcp_routing_status_cb *status_callback, void *object)
{
    con->status_callback = status_callback;
    con->status_callback_object = object;
}

non_null() static int tcp_send_ping_response(const Logger *logger, TCP_Client_Connection *con);
non_null() static int tcp_send_ping_request(const Logger *logger, TCP_Client_Connection *con);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure.
 */
int send_data(const Logger *logger, TCP_Client_Connection *con, uint8_t con_id, const uint8_t *data, uint16_t length)
{
    if (con_id >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    if (con->connections[con_id].status != 2) {
        return -1;
    }

    if (tcp_send_ping_response(logger, con) == 0 || tcp_send_ping_request(logger, con) == 0) {
        return 0;
    }

    VLA(uint8_t, packet, 1 + length);
    packet[0] = con_id + NUM_RESERVED_PORTS;
    memcpy(packet + 1, data, length);
    return write_packet_TCP_secure_connection(logger, &con->con, packet, SIZEOF_VLA(packet), false);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure.
 */
int send_oob_packet(const Logger *logger, TCP_Client_Connection *con, const uint8_t *public_key, const uint8_t *data,
                    uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH) {
        return -1;
    }

    VLA(uint8_t, packet, 1 + CRYPTO_PUBLIC_KEY_SIZE + length);
    packet[0] = TCP_PACKET_OOB_SEND;
    memcpy(packet + 1, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length);
    return write_packet_TCP_secure_connection(logger, &con->con, packet, SIZEOF_VLA(packet), false);
}


/** @brief Set the number that will be used as an argument in the callbacks related to con_id.
 *
 * When not set by this function, the number is -1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_number(TCP_Client_Connection *con, uint8_t con_id, uint32_t number)
{
    if (con_id >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    if (con->connections[con_id].status == 0) {
        return -1;
    }

    con->connections[con_id].number = number;
    return 0;
}

void routing_data_handler(TCP_Client_Connection *con, tcp_routing_data_cb *data_callback, void *object)
{
    con->data_callback = data_callback;
    con->data_callback_object = object;
}

void oob_data_handler(TCP_Client_Connection *con, tcp_oob_data_cb *oob_data_callback, void *object)
{
    con->oob_data_callback = oob_data_callback;
    con->oob_data_callback_object = object;
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
static int client_send_disconnect_notification(const Logger *logger, TCP_Client_Connection *con, uint8_t id)
{
    uint8_t packet[1 + 1];
    packet[0] = TCP_PACKET_DISCONNECT_NOTIFICATION;
    packet[1] = id;
    return write_packet_TCP_secure_connection(logger, &con->con, packet, sizeof(packet), true);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
static int tcp_send_ping_request(const Logger *logger, TCP_Client_Connection *con)
{
    if (con->ping_request_id == 0) {
        return 1;
    }

    uint8_t packet[1 + sizeof(uint64_t)];
    packet[0] = TCP_PACKET_PING;
    memcpy(packet + 1, &con->ping_request_id, sizeof(uint64_t));
    const int ret = write_packet_TCP_secure_connection(logger, &con->con, packet, sizeof(packet), true);

    if (ret == 1) {
        con->ping_request_id = 0;
    }

    return ret;
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
static int tcp_send_ping_response(const Logger *logger, TCP_Client_Connection *con)
{
    if (con->ping_response_id == 0) {
        return 1;
    }

    uint8_t packet[1 + sizeof(uint64_t)];
    packet[0] = TCP_PACKET_PONG;
    memcpy(packet + 1, &con->ping_response_id, sizeof(uint64_t));
    const int ret = write_packet_TCP_secure_connection(logger, &con->con, packet, sizeof(packet), true);

    if (ret == 1) {
        con->ping_response_id = 0;
    }

    return ret;
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_disconnect_request(const Logger *logger, TCP_Client_Connection *con, uint8_t con_id)
{
    if (con_id >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    con->connections[con_id].status = 0;
    con->connections[con_id].number = 0;
    return client_send_disconnect_notification(logger, con, con_id + NUM_RESERVED_PORTS);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_onion_request(const Logger *logger, TCP_Client_Connection *con, const uint8_t *data, uint16_t length)
{
    VLA(uint8_t, packet, 1 + length);
    packet[0] = TCP_PACKET_ONION_REQUEST;
    memcpy(packet + 1, data, length);
    return write_packet_TCP_secure_connection(logger, &con->con, packet, SIZEOF_VLA(packet), false);
}

void onion_response_handler(TCP_Client_Connection *con, tcp_onion_response_cb *onion_callback, void *object)
{
    con->onion_callback = onion_callback;
    con->onion_callback_object = object;
}

/** @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_forward_request_tcp(const Logger *logger, TCP_Client_Connection *con, const IP_Port *dest, const uint8_t *data, uint16_t length)
{
    if (length > MAX_FORWARD_DATA_SIZE) {
        return -1;
    }

    VLA(uint8_t, packet, 1 + MAX_PACKED_IPPORT_SIZE + length);
    packet[0] = TCP_PACKET_FORWARD_REQUEST;
    const int ipport_length = pack_ip_port(logger, packet + 1, MAX_PACKED_IPPORT_SIZE, dest);

    if (ipport_length == -1) {
        return 0;
    }

    memcpy(packet + 1 + ipport_length, data, length);
    return write_packet_TCP_secure_connection(logger, &con->con, packet, 1 + ipport_length + length, false);
}

void forwarding_handler(TCP_Client_Connection *con, forwarded_response_cb *forwarded_response_callback, void *object)
{
    con->forwarded_response_callback = forwarded_response_callback;
    con->forwarded_response_callback_object = object;
}

/** Create new TCP connection to ip_port/public_key */
TCP_Client_Connection *new_TCP_connection(
        const Logger *logger, const Mono_Time *mono_time, const Random *rng, const Network *ns, const IP_Port *ip_port,
        const uint8_t *public_key, const uint8_t *self_public_key, const uint8_t *self_secret_key,
        const TCP_Proxy_Info *proxy_info)
{
    if (!net_family_is_ipv4(ip_port->ip.family) && !net_family_is_ipv6(ip_port->ip.family)) {
        return nullptr;
    }

    const TCP_Proxy_Info default_proxyinfo = {{{{0}}}};

    if (proxy_info == nullptr) {
        proxy_info = &default_proxyinfo;
    }

    Family family = ip_port->ip.family;

    if (proxy_info->proxy_type != TCP_PROXY_NONE) {
        family = proxy_info->ip_port.ip.family;
    }

    const Socket sock = net_socket(ns, family, TOX_SOCK_STREAM, TOX_PROTO_TCP);

    if (!sock_valid(sock)) {
        return nullptr;
    }

    if (!set_socket_nosigpipe(ns, sock)) {
        kill_sock(ns, sock);
        return nullptr;
    }

    if (!(set_socket_nonblock(ns, sock) && connect_sock_to(logger, sock, ip_port, proxy_info))) {
        kill_sock(ns, sock);
        return nullptr;
    }

    TCP_Client_Connection *temp = (TCP_Client_Connection *)calloc(1, sizeof(TCP_Client_Connection));

    if (temp == nullptr) {
        kill_sock(ns, sock);
        return nullptr;
    }

    temp->con.ns = ns;
    temp->con.rng = rng;
    temp->con.sock = sock;
    temp->con.ip_port = *ip_port;
    memcpy(temp->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(temp->self_public_key, self_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    encrypt_precompute(temp->public_key, self_secret_key, temp->con.shared_key);
    temp->ip_port = *ip_port;
    temp->proxy_info = *proxy_info;

    switch (proxy_info->proxy_type) {
        case TCP_PROXY_HTTP: {
            temp->status = TCP_CLIENT_PROXY_HTTP_CONNECTING;
            proxy_http_generate_connection_request(temp);
            break;
        }

        case TCP_PROXY_SOCKS5: {
            temp->status = TCP_CLIENT_PROXY_SOCKS5_CONNECTING;
            proxy_socks5_generate_greetings(temp);
            break;
        }

        case TCP_PROXY_NONE: {
            temp->status = TCP_CLIENT_CONNECTING;

            if (generate_handshake(temp) == -1) {
                kill_sock(ns, sock);
                free(temp);
                return nullptr;
            }

            break;
        }
    }

    temp->kill_at = mono_time_get(mono_time) + TCP_CONNECTION_TIMEOUT;

    return temp;
}

non_null()
static int handle_TCP_client_routing_response(TCP_Client_Connection *conn, const uint8_t *data, uint16_t length)
{
    if (length != 1 + 1 + CRYPTO_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (data[1] < NUM_RESERVED_PORTS) {
        return 0;
    }

    const uint8_t con_id = data[1] - NUM_RESERVED_PORTS;

    if (conn->connections[con_id].status != 0) {
        return 0;
    }

    conn->connections[con_id].status = 1;
    conn->connections[con_id].number = -1;
    memcpy(conn->connections[con_id].public_key, data + 2, CRYPTO_PUBLIC_KEY_SIZE);

    if (conn->response_callback != nullptr) {
        conn->response_callback(conn->response_callback_object, con_id, conn->connections[con_id].public_key);
    }

    return 0;
}

non_null()
static int handle_TCP_client_connection_notification(TCP_Client_Connection *conn, const uint8_t *data, uint16_t length)
{
    if (length != 1 + 1) {
        return -1;
    }

    if (data[1] < NUM_RESERVED_PORTS) {
        return -1;
    }

    const uint8_t con_id = data[1] - NUM_RESERVED_PORTS;

    if (conn->connections[con_id].status != 1) {
        return 0;
    }

    conn->connections[con_id].status = 2;

    if (conn->status_callback != nullptr) {
        conn->status_callback(conn->status_callback_object, conn->connections[con_id].number, con_id,
                              conn->connections[con_id].status);
    }

    return 0;
}

non_null()
static int handle_TCP_client_disconnect_notification(TCP_Client_Connection *conn, const uint8_t *data, uint16_t length)
{
    if (length != 1 + 1) {
        return -1;
    }

    if (data[1] < NUM_RESERVED_PORTS) {
        return -1;
    }

    const uint8_t con_id = data[1] - NUM_RESERVED_PORTS;

    if (conn->connections[con_id].status == 0) {
        return 0;
    }

    if (conn->connections[con_id].status != 2) {
        return 0;
    }

    conn->connections[con_id].status = 1;

    if (conn->status_callback != nullptr) {
        conn->status_callback(conn->status_callback_object, conn->connections[con_id].number, con_id,
                              conn->connections[con_id].status);
    }

    return 0;
}

non_null()
static int handle_TCP_client_ping(const Logger *logger, TCP_Client_Connection *conn, const uint8_t *data, uint16_t length)
{
    if (length != 1 + sizeof(uint64_t)) {
        return -1;
    }

    uint64_t ping_id;
    memcpy(&ping_id, data + 1, sizeof(uint64_t));
    conn->ping_response_id = ping_id;
    tcp_send_ping_response(logger, conn);
    return 0;
}

non_null()
static int handle_TCP_client_pong(TCP_Client_Connection *conn, const uint8_t *data, uint16_t length)
{
    if (length != 1 + sizeof(uint64_t)) {
        return -1;
    }

    uint64_t ping_id;
    memcpy(&ping_id, data + 1, sizeof(uint64_t));

    if (ping_id != 0) {
        if (ping_id == conn->ping_id) {
            conn->ping_id = 0;
        }

        return 0;
    }

    return -1;
}

non_null(1, 2) nullable(4)
static int handle_TCP_client_oob_recv(TCP_Client_Connection *conn, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length <= 1 + CRYPTO_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (conn->oob_data_callback != nullptr) {
        conn->oob_data_callback(conn->oob_data_callback_object, data + 1, data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                length - (1 + CRYPTO_PUBLIC_KEY_SIZE), userdata);
    }

    return 0;
}

/**
 * @retval 0 on success
 * @retval -1 on failure
 */
non_null(1, 2, 3) nullable(5)
static int handle_TCP_client_packet(const Logger *logger, TCP_Client_Connection *conn, const uint8_t *data,
                                    uint16_t length, void *userdata)
{
    if (length <= 1) {
        return -1;
    }

    switch (data[0]) {
        case TCP_PACKET_ROUTING_RESPONSE:
            return handle_TCP_client_routing_response(conn, data, length);

        case TCP_PACKET_CONNECTION_NOTIFICATION:
            return handle_TCP_client_connection_notification(conn, data, length);

        case TCP_PACKET_DISCONNECT_NOTIFICATION:
            return handle_TCP_client_disconnect_notification(conn, data, length);

        case TCP_PACKET_PING:
            return handle_TCP_client_ping(logger, conn, data, length);

        case TCP_PACKET_PONG:
            return handle_TCP_client_pong(conn, data, length);

        case TCP_PACKET_OOB_RECV:
            return handle_TCP_client_oob_recv(conn, data, length, userdata);

        case TCP_PACKET_ONION_RESPONSE: {
            if (conn->onion_callback != nullptr) {
                conn->onion_callback(conn->onion_callback_object, data + 1, length - 1, userdata);
            }
            return 0;
        }

        case TCP_PACKET_FORWARDING: {
            if (conn->forwarded_response_callback != nullptr) {
                conn->forwarded_response_callback(conn->forwarded_response_callback_object, data + 1, length - 1, userdata);
            }
            return 0;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS) {
                return -1;
            }

            const uint8_t con_id = data[0] - NUM_RESERVED_PORTS;

            if (conn->data_callback != nullptr) {
                conn->data_callback(conn->data_callback_object, conn->connections[con_id].number, con_id, data + 1, length - 1,
                                    userdata);
            }
        }
    }

    return 0;
}

non_null(1, 2) nullable(3)
static bool tcp_process_packet(const Logger *logger, TCP_Client_Connection *conn, void *userdata)
{
    uint8_t packet[MAX_PACKET_SIZE];
    const int len = read_packet_TCP_secure_connection(logger, conn->con.ns, conn->con.sock, &conn->next_packet_length, conn->con.shared_key, conn->recv_nonce, packet, sizeof(packet), &conn->ip_port);

    if (len == 0) {
        return false;
    }

    if (len == -1) {
        conn->status = TCP_CLIENT_DISCONNECTED;
        return false;
    }

    if (handle_TCP_client_packet(logger, conn, packet, len, userdata) == -1) {
        conn->status = TCP_CLIENT_DISCONNECTED;
        return false;
    }

    return true;
}

non_null(1, 2, 3) nullable(4)
static int do_confirmed_TCP(const Logger *logger, TCP_Client_Connection *conn, const Mono_Time *mono_time,
                            void *userdata)
{
    send_pending_data(logger, &conn->con);
    tcp_send_ping_response(logger, conn);
    tcp_send_ping_request(logger, conn);

    if (mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_FREQUENCY)) {
        uint64_t ping_id = random_u64(conn->con.rng);

        if (ping_id == 0) {
            ++ping_id;
        }

        conn->ping_request_id = ping_id;
        conn->ping_id = ping_id;
        tcp_send_ping_request(logger, conn);
        conn->last_pinged = mono_time_get(mono_time);
    }

    if (conn->ping_id != 0 && mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_TIMEOUT)) {
        conn->status = TCP_CLIENT_DISCONNECTED;
        return 0;
    }

    while (tcp_process_packet(logger, conn, userdata)) {
        // Keep reading until error or out of data.
        continue;
    }

    return 0;
}

/** Run the TCP connection */
void do_TCP_connection(const Logger *logger, const Mono_Time *mono_time,
                       TCP_Client_Connection *tcp_connection, void *userdata)
{
    if (tcp_connection->status == TCP_CLIENT_DISCONNECTED) {
        return;
    }

    if (tcp_connection->status == TCP_CLIENT_PROXY_HTTP_CONNECTING) {
        if (send_pending_data(logger, &tcp_connection->con) == 0) {
            const int ret = proxy_http_read_connection_response(logger, tcp_connection);

            if (ret == -1) {
                tcp_connection->kill_at = 0;
                tcp_connection->status = TCP_CLIENT_DISCONNECTED;
            }

            if (ret == 1) {
                generate_handshake(tcp_connection);
                tcp_connection->status = TCP_CLIENT_CONNECTING;
            }
        }
    }

    if (tcp_connection->status == TCP_CLIENT_PROXY_SOCKS5_CONNECTING) {
        if (send_pending_data(logger, &tcp_connection->con) == 0) {
            int ret = socks5_read_handshake_response(logger, tcp_connection);

            if (ret == -1) {
                tcp_connection->kill_at = 0;
                tcp_connection->status = TCP_CLIENT_DISCONNECTED;
            }

            if (ret == 1) {
                proxy_socks5_generate_connection_request(tcp_connection);
                tcp_connection->status = TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED;
            }
        }
    }

    if (tcp_connection->status == TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED) {
        if (send_pending_data(logger, &tcp_connection->con) == 0) {
            int ret = proxy_socks5_read_connection_response(logger, tcp_connection);

            if (ret == -1) {
                tcp_connection->kill_at = 0;
                tcp_connection->status = TCP_CLIENT_DISCONNECTED;
            }

            if (ret == 1) {
                generate_handshake(tcp_connection);
                tcp_connection->status = TCP_CLIENT_CONNECTING;
            }
        }
    }

    if (tcp_connection->status == TCP_CLIENT_CONNECTING) {
        if (send_pending_data(logger, &tcp_connection->con) == 0) {
            tcp_connection->status = TCP_CLIENT_UNCONFIRMED;
        }
    }

    if (tcp_connection->status == TCP_CLIENT_UNCONFIRMED) {
        uint8_t data[TCP_SERVER_HANDSHAKE_SIZE];
        const int len = read_TCP_packet(logger, tcp_connection->con.ns, tcp_connection->con.sock, data, sizeof(data), &tcp_connection->con.ip_port);

        if (sizeof(data) == len) {
            if (handle_handshake(tcp_connection, data) == 0) {
                tcp_connection->kill_at = UINT64_MAX;
                tcp_connection->status = TCP_CLIENT_CONFIRMED;
            } else {
                tcp_connection->kill_at = 0;
                tcp_connection->status = TCP_CLIENT_DISCONNECTED;
            }
        }
    }

    if (tcp_connection->status == TCP_CLIENT_CONFIRMED) {
        do_confirmed_TCP(logger, tcp_connection, mono_time, userdata);
    }

    if (tcp_connection->kill_at <= mono_time_get(mono_time)) {
        tcp_connection->status = TCP_CLIENT_DISCONNECTED;
    }
}

/** Kill the TCP connection */
void kill_TCP_connection(TCP_Client_Connection *tcp_connection)
{
    if (tcp_connection == nullptr) {
        return;
    }

    wipe_priority_list(tcp_connection->con.priority_queue_start);
    kill_sock(tcp_connection->con.ns, tcp_connection->con.sock);
    crypto_memzero(tcp_connection, sizeof(TCP_Client_Connection));
    free(tcp_connection);
}
