/*
 * group_announce.h -- Similar to ping.h, but designed for group chat purposes
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
#ifndef __GROUP_ANNOUNCE_H__
#define __GROUP_ANNOUNCE_H__

#include "DHT.h"
 
typedef struct ANNOUNCE ANNOUNCE;

/* Initiate the process of the announcement, claiming a node is part of a group chat.
 *
 * dht = DHT object we're operating on
 * self_long_pk = extended (encryption+signature) public key of the node announcing its presence
 * self_long_sk = signing private key of the same node
 * chat_id = id of chat we're announcing to
 * 
 * return -1 in case of error
 * return number of send packets otherwise
 */
int send_gc_announce_request(DHT *dht, const uint8_t self_long_pk[],
                            const uint8_t self_long_sk[], const uint8_t chat_id[]);

/* Sends an actual announcement packet to the node specified as client_id on ipp */
int send_gc_get_announced_nodes_request(DHT *dht, const uint8_t self_long_pk[],
                            const uint8_t self_long_sk[], const uint8_t chat_id[]);

/* Retrieve nodes by request id, returns 0 if no nodes found or request in progress, number of nodes otherwise */
int get_requested_gc_nodes(ANNOUNCE *announce, const uint8_t chat_id[],
                            Announced_Node_format *nodes);

/* Do some periodic work, currently removes expired announcements */
int do_announce(ANNOUNCE *announce);

ANNOUNCE *new_announce(DHT *dht);
void kill_announce(ANNOUNCE *announce);


#endif /* __GROUP_ANNOUNCE_H__ */
