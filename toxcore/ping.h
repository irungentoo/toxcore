/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/**
 * Buffered pinging using cyclic arrays.
 */
#ifndef C_TOXCORE_TOXCORE_PING_H
#define C_TOXCORE_TOXCORE_PING_H

#include <stdint.h>

#include "DHT.h"
#include "network.h"

typedef struct Ping Ping;

non_null()
Ping *ping_new(const struct Mono_Time *mono_time, DHT *dht);

non_null()
void ping_kill(Ping *ping);

/** Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
non_null()
int32_t ping_add(Ping *ping, const uint8_t *public_key, const IP_Port *ip_port);

non_null()
void ping_iterate(Ping *ping);

non_null()
void ping_send_request(Ping *ping, const IP_Port *ipp, const uint8_t *public_key);

#endif // C_TOXCORE_TOXCORE_PING_H
