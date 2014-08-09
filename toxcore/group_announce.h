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
#include <types.h>
 
typedef struct ANNOUNCE ANNOUNCE;

/* Maximum newly announced online (in terms of group chats) nodes */
#define MAX_ANNOUNCED_NODES 30

int add_announced_nodes(ANNOUNCE *announce, const Groupchat_announcement_format *announcement, int inner);
int get_announced_nodes(ANNOUNCE *announce, const uint8_t *chat_id, Node_format *nodes_list, int inner);

ANNOUNCE *new_announce(DHT *dht);
void kill_announce(ANNOUNCE *announce);

/* Verify that the signed message corresponts to the data in the structure */
int verify_gc_announce_request(const Groupchat_announcement_format* announcement);

/* Signs the fields of the announcement */
int prepare_gc_announce_request(Groupchat_announcement_format* announcement, const uint8_t *node_private_key);

/* Initiate the process of the announcement, claiming a node is part of a group chat.
 *
 * dht = DHT object we're operating on
 * node_public_key = extended (encryption+signature) public key of the node announcing its presence
 * node_private_key = signing private key of the same node
 * chat_id = id of chat we're announcing to
 * 
 * return -1 in case of error
 * return 0 otherwise
 */
int initiate_gc_announce_request(DHT *dht, const uint8_t *node_public_key, const uint8_t *node_private_key, const uint8_t *chat_id);

/* Dispatches an announce request either saving it or passing further depending whether 
 * the current node is the closest node it knows to the chat_id or not */
int dispatch_gc_announce_request(DHT *dht, const Groupchat_announcement_format* announcement);

/* Sends an actual announcement packet to the node specified as client_id on ipp */
int send_gc_announce_request(DHT * dht, const uint8_t *client_id, IP_Port ipp, const Groupchat_announcement_format* announcement);
int get_gc_announced_nodes_request(DHT * dht, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id);

/* Consider moving to network */
int send_common_tox_packet(DHT *dht, const uint8_t *destination_id, IP_Port ipp, uint8_t type, uint8_t *payload, size_t length);
int recv_common_tox_packet(DHT *dht, const uint8_t *packet, uint8_t *cleartext, size_t clearlength);

#endif /* __GROUP_ANNOUNCE_H__ */
