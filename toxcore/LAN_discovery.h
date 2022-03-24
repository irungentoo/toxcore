/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * LAN discovery implementation.
 */
#ifndef C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
#define C_TOXCORE_TOXCORE_LAN_DISCOVERY_H

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
non_null()
bool lan_discovery_send(const Networking_Core *net, const Broadcast_Info *broadcast, const uint8_t *dht_pk, uint16_t port);

/**
 * Discovers broadcast devices and IP addresses.
 */
non_null()
Broadcast_Info *lan_discovery_init(const Network *ns);

/**
 * Free all resources associated with the broadcast info.
 */
nullable(1)
void lan_discovery_kill(Broadcast_Info *broadcast);

/**
 * Is IP a local ip or not.
 */
non_null()
bool ip_is_local(const IP *ip);

/**
 * Checks if a given IP isn't routable.
 *
 * @return true if ip is a LAN ip, false if it is not.
 */
non_null()
bool ip_is_lan(const IP *ip);

#endif // C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
