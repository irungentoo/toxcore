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

/* Maximum newly announced online (in terms of group chats) nodes */
#define MAX_ANNOUNCED_NODES 30

int add_announced_nodes(ANNOUNCE *announce, const uint8_t *client_id, uint8_t *chat_id, IP_Port ip_port, int inner);
int get_announced_nodes(ANNOUNCE *announce, const uint8_t *chat_id, Node_format *nodes_list, int inner);

ANNOUNCE *new_announce(DHT *dht);
void kill_announce(ANNOUNCE *announce);

int send_gc_announce_request(ANNOUNCE *announce, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id);
int get_gc_announced_nodes_request(DHT * dht, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id);

#endif /* __GROUP_ANNOUNCE_H__ */
