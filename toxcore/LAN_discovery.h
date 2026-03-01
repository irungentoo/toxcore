/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * LAN discovery implementation.
 */
#ifndef C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
#define C_TOXCORE_TOXCORE_LAN_DISCOVERY_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"
#include "net.h"
#include "network.h"

/**
 * Interval in seconds between LAN discovery packet sending.
 */
#define LAN_DISCOVERY_INTERVAL         10

typedef struct Broadcast_Info Broadcast_Info;

/**
 * Send a LAN discovery pcaket to the broadcast address with port port.
 *
 * @return true on success, false on failure.
 */
bool lan_discovery_send(const Networking_Core *_Nonnull net, const Broadcast_Info *_Nonnull broadcast, const uint8_t *_Nonnull dht_pk, uint16_t port);

/**
 * Discovers broadcast devices and IP addresses.
 */
Broadcast_Info *_Nullable lan_discovery_init(const Memory *_Nonnull mem, const Network *_Nonnull ns);

/**
 * Free all resources associated with the broadcast info.
 */
void lan_discovery_kill(Broadcast_Info *_Nullable broadcast);
/**
 * Is IP a local ip or not.
 */
bool ip_is_local(const IP *_Nonnull ip);

/**
 * Checks if a given IP isn't routable.
 *
 * @return true if ip is a LAN ip, false if it is not.
 */
bool ip_is_lan(const IP *_Nonnull ip);

#endif /* C_TOXCORE_TOXCORE_LAN_DISCOVERY_H */
