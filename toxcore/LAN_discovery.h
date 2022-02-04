/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * LAN discovery implementation.
 */
#ifndef C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
#define C_TOXCORE_TOXCORE_LAN_DISCOVERY_H

#include "DHT.h"

/**
 * Interval in seconds between LAN discovery packet sending.
 */
#define LAN_DISCOVERY_INTERVAL         10

/**
 * Send a LAN discovery pcaket to the broadcast address with port port.
 *
 * @return true on success, false on failure.
 */
bool lan_discovery_send(Networking_Core *net, const uint8_t *dht_pk, uint16_t port);

/**
 * Sets up packet handlers.
 */
void lan_discovery_init(DHT *dht);

/**
 * Clear packet handlers.
 */
void lan_discovery_kill(DHT *dht);

/**
 * Is IP a local ip or not.
 */
bool ip_is_local(const IP *ip);

/**
 * Checks if a given IP isn't routable.
 *
 * @return true if ip is a LAN ip, false if it is not.
 */
bool ip_is_lan(const IP *ip);

#endif // C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
