/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * Similar to ping.h, but designed for group chat purposes
 */
#ifndef GROUP_ANNOUNCE_H
#define GROUP_ANNOUNCE_H

#include "DHT.h"
#include "stdbool.h"

typedef struct GC_Announce GC_Announce;

#define MAX_GCA_SELF_REQUESTS 30
#define MAX_GCA_ANNOUNCED_NODES 30
#define MAX_GCA_SELF_ANNOUNCEMENTS 30
#define MAX_GCA_SENT_NODES 4

typedef struct GC_Announce_Node {
    uint8_t public_key[ENC_PUBLIC_KEY];
    IP_Port ip_port;
} GC_Announce_Node;

/* Holds nodes that we receive when we send a request. Used to join groups */
struct GC_AnnounceRequest {
    GC_Announce_Node nodes[MAX_GCA_SENT_NODES];
    uint64_t req_id;
    uint64_t time_added;
    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t self_public_key[ENC_PUBLIC_KEY];
    uint8_t self_secret_key[ENC_SECRET_KEY];
    bool ready;
};

/* Holds announced nodes we get via DHT announcements */
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
    uint8_t self_public_key[ENC_PUBLIC_KEY];
    uint8_t self_secret_key[ENC_SECRET_KEY];
    uint64_t last_rcvd_ping;
    bool is_set;
};

typedef void update_addresses_cb(GC_Announce *announce, const uint8_t *chat_id, void *user_data);

struct GC_Announce {
    Mono_Time *mono_time;
    DHT *dht;
    update_addresses_cb *update_addresses;
    void *update_addresses_obj;

    struct GC_AnnouncedNode announcements[MAX_GCA_ANNOUNCED_NODES];
    struct GC_AnnounceRequest requests[MAX_GCA_SELF_REQUESTS];
    struct GC_AnnouncedSelf self_announce[MAX_GCA_SELF_ANNOUNCEMENTS];

    uint32_t packet_relay_rate;
    uint64_t relay_rate_timer;
};

/* Initiate the process of announcing a group to the DHT.
 *
 * announce: announce object we're operating on.
 * self_public_key: encryption public key of the peer announcing its presence
 * self_secret_key: encryption secret key of the peer
 * chat_id: chat_id of the group (chat public signature key)
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
int gca_send_announce_request(GC_Announce *announce, const uint8_t *self_public_key,
                              const uint8_t *self_secret_key, const uint8_t *chat_id);

/* Creates a DHT request for nodes that hold announcements for chat_id.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
int gca_send_get_nodes_request(GC_Announce *announce, const uint8_t *self_public_key,
                               const uint8_t *self_secret_key, const uint8_t *chat_id);

/* Retrieves nodes for chat_id (nodes must already be obtained via gca_send_announce_request).
 *
 * returns the number of nodes found.
 */
size_t gca_get_requested_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes);

/* Main group announce loop: Pings nodes and checks timeouts. */
void do_gca(GC_Announce *announce);

/* Removes peer with public_key in chat_id's group from requests list */
void gca_peer_cleanup(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *peer_pk);

/* Cleans up announcements related to chat_id (call on group exit or when privacy state is set to private) */
void gca_cleanup(GC_Announce *announce, const uint8_t *chat_id);

GC_Announce *new_gca(Mono_Time *mono_time, DHT *dht);

/* Called when associated Messenger object is killed. */
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
