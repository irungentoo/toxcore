%{
/*
 * Buffered pinging using cyclic arrays.
 */

/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 * This file is donated to the Tox Project.
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
#ifndef C_TOXCORE_TOXCORE_PING_H
#define C_TOXCORE_TOXCORE_PING_H

#include "DHT.h"
#include "network.h"

#include <stdint.h>
%}

class iP_Port { struct this; }
class dHT { struct this; }
class mono_Time { struct this; }

class ping {

struct this;

static this new(const mono_Time::this *mono_time, dHT::this *dht);
void kill();

/** Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TOPING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int32_t add(const uint8_t *public_key, iP_Port::this ip_port);
void iterate();

int32_t send_request(iP_Port::this ipp, const uint8_t *public_key);

}

%{
#endif // C_TOXCORE_TOXCORE_PING_H
%}
