/*
 * LAN discovery implementation.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
#define C_TOXCORE_TOXCORE_LAN_DISCOVERY_H

#include "DHT.h"

#ifndef DHT_DEFINED
#define DHT_DEFINED
typedef struct DHT DHT;
#endif /* DHT_DEFINED */

#ifndef IP_DEFINED
#define IP_DEFINED
typedef struct IP IP;
#endif /* IP_DEFINED */

/**
 * Interval in seconds between LAN discovery packet sending.
 */
#define LAN_DISCOVERY_INTERVAL         10

uint32_t lan_discovery_interval(void);

/**
 * Send a LAN discovery pcaket to the broadcast address with port port.
 */
int32_t lan_discovery_send(uint16_t port, DHT *dht);

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
bool ip_is_local(IP ip);

/**
 * Checks if a given IP isn't routable.
 *
 * @return true if ip is a LAN ip, false if it is not.
 */
bool ip_is_lan(IP ip);

#endif // C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
