%{
/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/*
 * Buffered pinging using cyclic arrays.
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
