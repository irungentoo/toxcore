/*  LAN_discovery.h
 *
 *  LAN discovery implementation.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef LAN_DISCOVERY_H
#define LAN_DISCOVERY_H


#include "DHT.h"

/* Interval in seconds between LAN discovery packet sending. */
#define LAN_DISCOVERY_INTERVAL 10

/* Send a LAN discovery pcaket to the broadcast address with port port. */
int send_LANdiscovery(uint16_t port, DHT *dht);

/* Sets up packet handlers. */
void LANdiscovery_init(DHT *dht);

/* checks if a given IP isn't routable
 *
 *  return 0 if ip is a LAN ip.
 *  return -1 if it is not.
 */
int LAN_ip(IP ip);


#endif
