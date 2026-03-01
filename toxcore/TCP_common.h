/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TCP_COMMON_H
#define C_TOXCORE_TOXCORE_TCP_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "net.h"
#include "net_profile.h"
#include "network.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TCP_Priority_List TCP_Priority_List;
struct TCP_Priority_List {
    TCP_Priority_List *_Nullable next;
    uint16_t size;
    uint16_t sent;
    uint8_t *_Nonnull data;
};

void wipe_priority_list(const Memory *_Nonnull mem, TCP_Priority_List *_Nullable p);
#define NUM_RESERVED_PORTS 16
#define NUM_CLIENT_CONNECTIONS (256 - NUM_RESERVED_PORTS)

typedef enum Tcp_Packet {
    TCP_PACKET_ROUTING_REQUEST          = 0,
    TCP_PACKET_ROUTING_RESPONSE         = 1,
    TCP_PACKET_CONNECTION_NOTIFICATION  = 2,
    TCP_PACKET_DISCONNECT_NOTIFICATION  = 3,
    TCP_PACKET_PING                     = 4,
    TCP_PACKET_PONG                     = 5,
    TCP_PACKET_OOB_SEND                 = 6,
    TCP_PACKET_OOB_RECV                 = 7,
    TCP_PACKET_ONION_REQUEST            = 8,
    TCP_PACKET_ONION_RESPONSE           = 9,
    TCP_PACKET_FORWARD_REQUEST          = 10,
    TCP_PACKET_FORWARDING               = 11,
} Tcp_Packet;

const char *_Nonnull tcp_packet_type_to_string(Tcp_Packet type);
bool tcp_packet_from_int(uint32_t value, Tcp_Packet *_Nonnull out_enum);

#define TCP_HANDSHAKE_PLAIN_SIZE (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE)
#define TCP_SERVER_HANDSHAKE_SIZE (CRYPTO_NONCE_SIZE + TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE)
#define TCP_CLIENT_HANDSHAKE_SIZE (CRYPTO_PUBLIC_KEY_SIZE + TCP_SERVER_HANDSHAKE_SIZE)
#define TCP_MAX_OOB_DATA_LENGTH 1024

/** frequency to ping connected nodes and timeout in seconds */
#define TCP_PING_FREQUENCY 30
#define TCP_PING_TIMEOUT 10

#define MAX_PACKET_SIZE 2048

typedef struct TCP_Connection {
    const Memory *_Nonnull mem;
    const Random *_Nonnull rng;
    const Network *_Nonnull ns;
    Socket sock;
    IP_Port ip_port;  // for debugging.
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    TCP_Priority_List *_Nullable priority_queue_start;
    TCP_Priority_List *_Nullable priority_queue_end;

    // This is a shared pointer to the parent's respective Net_Profile object
    // (either TCP_Server for TCP server packets or TCP_Connections for TCP client packets).
    Net_Profile *_Nullable net_profile;
} TCP_Connection;

/**
 * @retval 0 if pending data was sent completely
 * @retval -1 if it wasn't
 */
int send_pending_data_nonpriority(const Logger *_Nonnull logger, TCP_Connection *_Nonnull con);

/**
 * @retval 0 if pending data was sent completely
 * @retval -1 if it wasn't
 */
int send_pending_data(const Logger *_Nonnull logger, TCP_Connection *_Nonnull con);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int write_packet_tcp_secure_connection(const Logger *_Nonnull logger, TCP_Connection *_Nonnull con, const uint8_t *_Nonnull data, uint16_t length, bool priority);

/** @brief Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
int read_tcp_packet(const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Network *_Nonnull ns, Socket sock, uint8_t *_Nonnull data, uint16_t length,
                    const IP_Port *_Nonnull ip_port);

/**
 * @return length of received packet on success.
 * @retval 0 if could not read any packet.
 * @retval -1 on failure (connection must be killed).
 */
int read_packet_tcp_secure_connection(const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Network *_Nonnull ns, Socket sock, uint16_t *_Nonnull next_packet_length,
                                      const uint8_t *_Nonnull shared_key, uint8_t *_Nonnull recv_nonce, uint8_t *_Nonnull data, uint16_t max_len, const IP_Port *_Nonnull ip_port);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TCP_COMMON_H */
