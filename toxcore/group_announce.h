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
#ifndef GROUP_ANNOUNCE_H
#define GROUP_ANNOUNCE_H

#include "DHT.h"

#define MAX_GCA_SELF_REQUESTS 30

typedef struct {
    uint8_t     client_id[EXT_PUBLIC_KEY];
    IP_Port     ip_port;
} GC_Announce_Node;

struct GC_Announce;
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
int gca_send_announce_request(struct GC_Announce *announce, const uint8_t *self_long_pk,
                              const uint8_t *self_long_sk, const uint8_t *chat_id);

/* Sends an actual announcement packet to the node specified as client_id on ipp */
int gca_send_get_nodes_request(struct GC_Announce *announce, const uint8_t *self_long_pk,
                               const uint8_t *self_long_sk, const uint8_t *chat_id);

/* Retrieve nodes by chat id, returns 0 if no nodes found or request in progress, number of nodes otherwise */
int gca_get_requested_nodes(struct GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes);

/* Do some periodic work, currently removes expired announcements */
void do_gca(struct GC_Announce *announce);

/* Cleans up announce data (call on group exit) */
void gca_cleanup(struct GC_Announce *announce, const uint8_t *chat_id);

struct GC_Announce *new_gca(DHT *dht);
void kill_gca(struct GC_Announce *announce);

/* Copies your own ip_port structure to target. (TODO: This should probably go somewhere else)
 *
 * Return 0 on succcess.
 * Return -1 on failure.
 */
int ipport_self_copy(const DHT *dht, IP_Port *target);

/* Creates a GC_Announce_Node using client_id and your own IP_Port struct
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int make_self_gca_node(const DHT *dht, GC_Announce_Node *node, const uint8_t *client_id);

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_gca_nodes(uint8_t *data, uint16_t length, const GC_Announce_Node *nodes, uint16_t number);

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_gca_nodes(GC_Announce_Node *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len,
                     const uint8_t *data, uint16_t length, uint8_t tcp_enabled);

#endif /* GROUP_ANNOUNCE_H */
