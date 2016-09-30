/*
 * ping.h -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
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
 */
#ifndef PING_H
#define PING_H

#include "DHT.h"
#include "network.h"

#include <stdint.h>

typedef struct PING PING;

/* Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TOPING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int add_to_ping(PING *ping, const uint8_t *public_key, IP_Port ip_port);
void do_to_ping(PING *ping);

PING *new_ping(DHT *dht);
void kill_ping(PING *ping);

int send_ping_request(PING *ping, IP_Port ipp, const uint8_t *public_key);

#endif /* PING_H */
