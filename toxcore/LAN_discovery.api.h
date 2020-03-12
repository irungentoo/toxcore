%{
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * LAN discovery implementation.
 */
#ifndef C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
#define C_TOXCORE_TOXCORE_LAN_DISCOVERY_H

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
#endif // C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
%}
