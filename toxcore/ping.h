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
Ping *ping_new(const Mono_Time *mono_time, const Random *rng, DHT *dht);

nullable(1)
void ping_kill(Ping *ping);

/** @brief Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 * @retval 0 if node was added.
 * @retval -1 if node was not added.
 */
non_null()
int32_t ping_add(Ping *ping, const uint8_t *public_key, const IP_Port *ip_port);

/** @brief Ping all the valid nodes in the to_ping list every TIME_TO_PING seconds.
 * This function must be run at least once every TIME_TO_PING seconds.
 */
non_null()
void ping_iterate(Ping *ping);

non_null()
void ping_send_request(Ping *ping, const IP_Port *ipp, const uint8_t *public_key);

#endif // C_TOXCORE_TOXCORE_PING_H
