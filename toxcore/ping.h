/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
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
#include "attributes.h"
#include "crypto_core.h"
#include "mem.h"
#include "mono_time.h"
#include "net.h"
#include "network.h"

typedef struct Ping Ping;

Ping *_Nullable ping_new(const Memory *_Nonnull mem, const Mono_Time *_Nonnull mono_time, const Random *_Nonnull rng, DHT *_Nonnull dht, Networking_Core *_Nonnull net);

void ping_kill(const Memory *_Nonnull mem, Ping *_Nullable ping);
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
int32_t ping_add(Ping *_Nonnull ping, const uint8_t *_Nonnull public_key, const IP_Port *_Nonnull ip_port);

/** @brief Ping all the valid nodes in the to_ping list every TIME_TO_PING seconds.
 * This function must be run at least once every TIME_TO_PING seconds.
 */
void ping_iterate(Ping *_Nonnull ping);

void ping_send_request(Ping *_Nonnull ping, const IP_Port *_Nonnull ipp, const uint8_t *_Nonnull public_key);

#endif /* C_TOXCORE_TOXCORE_PING_H */
