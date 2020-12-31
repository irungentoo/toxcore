/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TCP_COMMON_H
#define C_TOXCORE_TOXCORE_TCP_COMMON_H

#include "crypto_core.h"
#include "network.h"

typedef struct TCP_Priority_List TCP_Priority_List;
struct TCP_Priority_List {
    TCP_Priority_List *next;
    uint16_t size;
    uint16_t sent;
    uint8_t *data;
};

nullable(1)
void wipe_priority_list(TCP_Priority_List *p);

#define NUM_RESERVED_PORTS 16
#define NUM_CLIENT_CONNECTIONS (256 - NUM_RESERVED_PORTS)

#define TCP_PACKET_ROUTING_REQUEST  0
#define TCP_PACKET_ROUTING_RESPONSE 1
#define TCP_PACKET_CONNECTION_NOTIFICATION 2
#define TCP_PACKET_DISCONNECT_NOTIFICATION 3
#define TCP_PACKET_PING 4
#define TCP_PACKET_PONG 5
#define TCP_PACKET_OOB_SEND 6
#define TCP_PACKET_OOB_RECV 7
#define TCP_PACKET_ONION_REQUEST  8
#define TCP_PACKET_ONION_RESPONSE 9
#define TCP_PACKET_FORWARD_REQUEST 10
#define TCP_PACKET_FORWARDING 11

#define TCP_HANDSHAKE_PLAIN_SIZE (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE)
#define TCP_SERVER_HANDSHAKE_SIZE (CRYPTO_NONCE_SIZE + TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE)
#define TCP_CLIENT_HANDSHAKE_SIZE (CRYPTO_PUBLIC_KEY_SIZE + TCP_SERVER_HANDSHAKE_SIZE)
#define TCP_MAX_OOB_DATA_LENGTH 1024

/** frequency to ping connected nodes and timeout in seconds */
#define TCP_PING_FREQUENCY 30
#define TCP_PING_TIMEOUT 10

#define MAX_PACKET_SIZE 2048

typedef struct TCP_Connection {
    const Random *rng;
    const Network *ns;
    Socket sock;
    IP_Port ip_port;  // for debugging.
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    TCP_Priority_List *priority_queue_start;
    TCP_Priority_List *priority_queue_end;
} TCP_Connection;

/**
 * @retval 0 if pending data was sent completely
 * @retval -1 if it wasn't
 */
non_null()
int send_pending_data_nonpriority(const Logger *logger, TCP_Connection *con);

/**
 * @retval 0 if pending data was sent completely
 * @retval -1 if it wasn't
 */
non_null()
int send_pending_data(const Logger *logger, TCP_Connection *con);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
int write_packet_TCP_secure_connection(
        const Logger *logger, TCP_Connection *con, const uint8_t *data, uint16_t length,
        bool priority);

/** @brief Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
non_null()
int read_TCP_packet(
        const Logger *logger, const Network *ns, Socket sock, uint8_t *data, uint16_t length, const IP_Port *ip_port);

/**
 * @return length of received packet on success.
 * @retval 0 if could not read any packet.
 * @retval -1 on failure (connection must be killed).
 */
non_null()
int read_packet_TCP_secure_connection(
        const Logger *logger, const Network *ns, Socket sock, uint16_t *next_packet_length,
        const uint8_t *shared_key, uint8_t *recv_nonce, uint8_t *data,
        uint16_t max_len, const IP_Port *ip_port);

#endif
