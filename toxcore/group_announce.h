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

typedef struct GROUP_ANNOUNCE GROUP_ANNOUNCE;


int add_group_announced_nodes(GROUP_ANNOUNCE *announce, uint8_t *client_id, uint8_t *chat_id, IP_Port ip_port);

GROUP_ANNOUNCE *new_group_announce(DHT *dht);
void kill_group_announce(GROUP_ANNOUNCE *announce);

int send_group_announce_request(GROUP_ANNOUNCE *announce, IP_Port ipp, uint8_t *client_id, uint8_t *chat_id);
int get_group_announced_nodes_request(DHT * dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, Node_format *sendback_node);

#endif /* __GROUP_ANNOUNCE_H__ */
