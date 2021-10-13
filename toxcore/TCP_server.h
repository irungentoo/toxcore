/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/*
 * Implementation of the TCP relay server part of Tox.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_SERVER_H
#define C_TOXCORE_TOXCORE_TCP_SERVER_H

#include "crypto_core.h"
#include "list.h"
#include "onion.h"

#define MAX_INCOMING_CONNECTIONS 256

#define TCP_MAX_BACKLOG MAX_INCOMING_CONNECTIONS

#define MAX_PACKET_SIZE 2048

#define TCP_HANDSHAKE_PLAIN_SIZE (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE)
#define TCP_SERVER_HANDSHAKE_SIZE (CRYPTO_NONCE_SIZE + TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE)
#define TCP_CLIENT_HANDSHAKE_SIZE (CRYPTO_PUBLIC_KEY_SIZE + TCP_SERVER_HANDSHAKE_SIZE)
#define TCP_MAX_OOB_DATA_LENGTH 1024

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

#define ARRAY_ENTRY_SIZE 6

/* frequency to ping connected nodes and timeout in seconds */
#define TCP_PING_FREQUENCY 30
#define TCP_PING_TIMEOUT 10

typedef enum TCP_Status {
    TCP_STATUS_NO_STATUS,
    TCP_STATUS_CONNECTED,
    TCP_STATUS_UNCONFIRMED,
    TCP_STATUS_CONFIRMED,
} TCP_Status;

typedef struct TCP_Priority_List TCP_Priority_List;

struct TCP_Priority_List {
    TCP_Priority_List *next;
    uint16_t size;
    uint16_t sent;
    uint8_t data[];
};

void wipe_priority_list(TCP_Priority_List *p);

typedef struct TCP_Server TCP_Server;

const uint8_t *tcp_server_public_key(const TCP_Server *tcp_server);
size_t tcp_server_listen_count(const TCP_Server *tcp_server);

/* Create new TCP server instance.
 */
TCP_Server *new_TCP_server(const Logger *logger, uint8_t ipv6_enabled, uint16_t num_sockets, const uint16_t *ports,
                           const uint8_t *secret_key, Onion *onion);

/* Run the TCP_server
 */
void do_TCP_server(TCP_Server *tcp_server, Mono_Time *mono_time);

/* Kill the TCP server
 */
void kill_TCP_server(TCP_Server *tcp_server);

/* Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return -1 on failure.
 */
uint16_t read_TCP_length(const Logger *logger, Socket sock);

/* Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
int read_TCP_packet(const Logger *logger, Socket sock, uint8_t *data, uint16_t length);

/* return length of received packet on success.
 * return 0 if could not read any packet.
 * return -1 on failure (connection must be killed).
 */
int read_packet_TCP_secure_connection(const Logger *logger, Socket sock, uint16_t *next_packet_length,
                                      const uint8_t *shared_key, uint8_t *recv_nonce, uint8_t *data, uint16_t max_len);


#endif
