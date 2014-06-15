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

typedef struct ANNOUNCE ANNOUNCE;

typedef struct __attribute__ ((__packed__))
{
    uint8_t client_id[CLIENT_ID_SIZE];
    uint8_t chat_id[CLIENT_ID_SIZE]
    IP_Port ip_port;
}
Announced_node_format;

int add_announced_nodes(ANNOUNCE *announce, uint8_t *client_id, IP_Port ip_port);
void do_announced_nodes(ANNOUNCE *announce);

ANNOUNCE *new_announce(DHT *dht);
void kill_announce(ANNOUNCE *announce);

int send_announce_request(PING *ping, IP_Port ipp, uint8_t *client_id);


#endif /* __GROUP_ANNOUNCE_H__ */
