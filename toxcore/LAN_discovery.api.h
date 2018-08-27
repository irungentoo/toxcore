%{
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
#ifndef LAN_DISCOVERY_H
#define LAN_DISCOVERY_H

#include "DHT.h"
%}

class dHT { struct this; }
class iP { struct this; }

namespace lan_discovery {

/**
 * Interval in seconds between LAN discovery packet sending.
 */
const INTERVAL = 10;

/**
 * Send a LAN discovery pcaket to the broadcast address with port port.
 */
static int32_t send(uint16_t port, dHT::this *dht);

/**
 * Sets up packet handlers.
 */
static void init(dHT::this *dht);

/**
 * Clear packet handlers.
 */
static void kill(dHT::this *dht);

}

/**
 * Is IP a local ip or not.
 */
static bool ip_is_local(iP::this ip);

/**
 * Checks if a given IP isn't routable.
 *
 * @return true if ip is a LAN ip, false if it is not.
 */
static bool ip_is_lan(iP::this ip);

%{
#endif
%}
