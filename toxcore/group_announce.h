/*
 * group_announce.h -- Similar to ping.h, but designed for group chat purposes
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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
#include "stdbool.h"

typedef struct Messenger Messenger;
typedef struct GC_Announce GC_Announce;

#define MAX_GCA_SELF_REQUESTS 30
#define MAX_GCA_ANNOUNCED_NODES 30
#define MAX_GCA_SELF_ANNOUNCEMENTS 30
#define MAX_GCA_SENT_NODES 4

typedef struct {
    uint8_t public_key[EXT_PUBLIC_KEY];
    IP_Port ip_port;
} GC_Announce_Node;

/* Holds nodes that we receive when we send a request. Used to join groups */
struct GC_AnnounceRequest {
    GC_Announce_Node nodes[MAX_GCA_SENT_NODES];
    uint64_t req_id;
    uint64_t time_added;
    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t self_public_key[EXT_PUBLIC_KEY];
    uint8_t self_secret_key[EXT_SECRET_KEY];
    bool ready;
};

/* Holds announced nodes we get via announcements */
struct GC_AnnouncedNode {
    uint8_t chat_id[CHAT_ID_SIZE];
    GC_Announce_Node node;
    uint64_t last_rcvd_ping;
    uint64_t last_sent_ping;
    uint64_t time_added;
    uint64_t ping_id;
    bool self;   /* true if this is our own announcement; will never be pinged or timeout */
};

/* Holds our own announcements when we join a group.
 * Currently will only keep track of up to MAX_GCA_SELF_ANNOUNCEMENTS groups at once.
 */
struct GC_AnnouncedSelf {
    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t self_public_key[EXT_PUBLIC_KEY];
    uint8_t self_secret_key[EXT_SECRET_KEY];
    uint64_t last_rcvd_ping;
    bool is_set;
};

struct GC_Announce {
    Messenger *messenger;
    DHT *dht;
    struct GC_AnnouncedNode announcements[MAX_GCA_ANNOUNCED_NODES];
    struct GC_AnnounceRequest requests[MAX_GCA_SELF_REQUESTS];
    struct GC_AnnouncedSelf self_announce[MAX_GCA_SELF_ANNOUNCEMENTS];
};

/* Initiate the process of announcing a group to the DHT.
 *
 * announce: announce object we're operating on.
 * self_public_key: extended (encryption+signature) public key of the node announcing its presence
 * self_secret_key: signing private key of the same node
 * chat_id: chat_id of the group (public signature key)
 *
 * return -1 in case of error
 * return number of send packets otherwise
 */
int gca_send_announce_request(GC_Announce *announce, const uint8_t *self_public_key,
                              const uint8_t *self_secret_key, const uint8_t *chat_id);

/* Sends an announcement packet to the node specified as public_key with ipp */
int gca_send_get_nodes_request(GC_Announce *announce, const uint8_t *self_public_key,
                               const uint8_t *self_secret_key, const uint8_t *chat_id);

/* Retrieve nodes with chat_id.
 *
 * returns 0 if no nodes found or request in progress.
 * returns the number of nodes otherwise.
 */
size_t gca_get_requested_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes);

/* Do some periodic work, currently removes expired announcements */
void do_gca(GC_Announce *announce);

/* Cleans up announcements related to chat_id (call on group exit) */
void gca_cleanup(GC_Announce *announce, const uint8_t *chat_id);

GC_Announce *new_gca(Messenger *m);

void kill_gca(GC_Announce *announce);

/* Copies your own ip_port structure to dest. (TODO: This should probably go somewhere else)
 *
 * Return 0 on succcess.
 * Return -1 on failure.
 */
int ipport_self_copy(const DHT *dht, IP_Port *dest);

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
int pack_gca_nodes(uint8_t *data, uint16_t length, const GC_Announce_Node *nodes, uint32_t number);

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_gca_nodes(GC_Announce_Node *nodes, uint32_t max_num_nodes, uint16_t *processed_data_len,
                     const uint8_t *data, uint16_t length, uint8_t tcp_enabled);

#endif /* GROUP_ANNOUNCE_H */
