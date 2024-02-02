/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay server part of Tox.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_SERVER_H
#define C_TOXCORE_TOXCORE_TCP_SERVER_H

#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"
#include "onion.h"

#define MAX_INCOMING_CONNECTIONS 256

#define TCP_MAX_BACKLOG MAX_INCOMING_CONNECTIONS

#define ARRAY_ENTRY_SIZE 6

typedef enum TCP_Status {
    TCP_STATUS_NO_STATUS,
    TCP_STATUS_CONNECTED,
    TCP_STATUS_UNCONFIRMED,
    TCP_STATUS_CONFIRMED,
} TCP_Status;

typedef struct TCP_Server TCP_Server;

non_null()
const uint8_t *tcp_server_public_key(const TCP_Server *tcp_server);
non_null()
size_t tcp_server_listen_count(const TCP_Server *tcp_server);

/** Create new TCP server instance. */
non_null(1, 2, 3, 4, 7, 8) nullable(9, 10)
TCP_Server *new_tcp_server(const Logger *logger, const Memory *mem, const Random *rng, const Network *ns,
                           bool ipv6_enabled, uint16_t num_sockets, const uint16_t *ports,
                           const uint8_t *secret_key, Onion *onion, Forwarding *forwarding);

/** Run the TCP_server */
non_null()
void do_tcp_server(TCP_Server *tcp_server, const Mono_Time *mono_time);

/** Kill the TCP server */
nullable(1)
void kill_tcp_server(TCP_Server *tcp_server);

#endif /* C_TOXCORE_TOXCORE_TCP_SERVER_H */
