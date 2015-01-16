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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "group_announce.h"

#include "logger.h"
#include "util.h"
#include "network.h"
#include "DHT.h"

#define TIME_STAMP_SIZE (sizeof(uint64_t))
#define RAND_ID_SIZE (sizeof(uint64_t))

/* type + sender_dht_pk + nonce + */
#define GCA_HEADER_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES)

/* type + ping_id + chat_id_hash + client_id_hash */
#define GCA_PING_PLAIN_SIZE (1 + RAND_ID_SIZE + sizeof(uint32_t) + sizeof(uint32_t))
#define GCA_PING_DHT_SIZE (GCA_HEADER_SIZE + GCA_PING_PLAIN_SIZE + crypto_box_MACBYTES)

/* Type + Chat_ID + IP_Port + Client_ID + Timestamp + Signature */
#define GCA_REQUEST_PLAIN_SIZE (1 + (EXT_PUBLIC_KEY * 2) + ENC_PUBLIC_KEY + sizeof(IP_Port) + TIME_STAMP_SIZE + SIGNATURE_SIZE)
#define GCA_REQUEST_DHT_SIZE (GCA_HEADER_SIZE + GCA_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

/* Type + Chat_ID + IP_Port + RequestID + Client_ID + Timestamp + Signature */
#define GCA_GETNODES_REQUEST_PLAIN_SIZE (1 + (EXT_PUBLIC_KEY * 2) + sizeof(IP_Port) + RAND_ID_SIZE + TIME_STAMP_SIZE + SIGNATURE_SIZE)
#define GCA_GETNODES_REQUEST_DHT_SIZE (GCA_HEADER_SIZE + GCA_GETNODES_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

/* Type + Num_Nodes + Nodes + RequestID */
#define GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE (1 + sizeof(uint32_t) + sizeof(GC_Announce_Node) * MAX_GCA_SENT_NODES + RAND_ID_SIZE)
#define GCA_GETNODES_RESPONSE_DHT_MAX_SIZE (GCA_HEADER_SIZE + RAND_ID_SIZE + GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE + crypto_box_MACBYTES)
#define GCA_GETNODES_RESPONSE_PLAIN_MIN_SIZE (GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE - (sizeof(GC_Announce_Node) * (MAX_SENT_NODES - 1)))
#define GCA_GETNODES_RESPONSE_DHT_MIN_SIZE (GCA_HEADER_SIZE + RAND_ID_SIZE + GCA_GETNODES_RESPONSE_PLAIN_MIN_SIZE + crypto_box_MACBYTES)

#define GCA_PING_INTERVAL 40
#define GCA_NODES_EXPIRATION (GCA_PING_INTERVAL * 2)

#define MAX_GCA_SENT_NODES 4
#define MAX_GCA_ANNOUNCED_NODES 30
#define MAX_GCA_SELF_ANNOUNCEMENTS  30

/* Holds nodes that we receive when we send a request, used to join groups */
struct GC_AnnounceRequest {
    uint8_t chat_id[EXT_PUBLIC_KEY];
    GC_Announce_Node nodes[MAX_GCA_SENT_NODES];
    uint64_t req_id;
    uint64_t time_added;
    bool ready;

    /* This is redundant but it's the easiest way */
    uint8_t long_pk[EXT_PUBLIC_KEY];
    uint8_t long_sk[EXT_SECRET_KEY];
};

/* Holds our own announcements when we create or join a group */
struct GC_SelfAnnouncedNode {
    uint32_t chat_id_hash;
    uint32_t client_id_hash;
    uint64_t time_added;
};

/* Holds announced nodes we get via announcements */
struct GC_AnnouncedNode {
    uint8_t chat_id[EXT_PUBLIC_KEY];
    uint8_t dht_public_key[ENC_PUBLIC_KEY];
    GC_Announce_Node node;
    uint64_t last_rcvd_ping;
    uint64_t last_sent_ping;
    uint64_t time_added;
    uint64_t ping_id;
    uint32_t chat_id_hash;
    uint32_t client_id_hash;
};

typedef struct GC_Announce {
    DHT *dht;

    struct GC_AnnouncedNode announcements[MAX_GCA_ANNOUNCED_NODES];
    struct GC_SelfAnnouncedNode self_announcements[MAX_GCA_SELF_ANNOUNCEMENTS];
    struct GC_AnnounceRequest self_requests[MAX_GCA_SELF_REQUESTS];
} GC_Announce;

/* Handle all decrypt procedures */
static int unwrap_gca_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key,
                             uint8_t *data, uint8_t packet_type, const uint8_t *packet, uint16_t length)
{
    uint16_t plain_length = 0;

    switch (packet_type) {
        case NET_PACKET_GCA_ANNOUNCE:
            plain_length = GCA_REQUEST_PLAIN_SIZE;
            break;

        case NET_PACKET_GCA_GET_NODES:
            plain_length = GCA_GETNODES_REQUEST_PLAIN_SIZE;
            break;

        case NET_PACKET_GCA_SEND_NODES:
            plain_length = length - (GCA_GETNODES_RESPONSE_DHT_MAX_SIZE - GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE);
            break;

        case NET_PACKET_GCA_PING_RESPONSE:
        /* fallthrough */
        case NET_PACKET_GCA_PING_REQUEST:
            plain_length = GCA_PING_PLAIN_SIZE;
            break;

        default:
            return -1;
    }

    if (id_equal(packet + 1, self_public_key)) {
        fprintf(stderr, "announce unwrap failed: id_equal failed\n");
        return -1;
    }

    memcpy(public_key, packet + 1, ENC_PUBLIC_KEY);

    int header_len = 0;
    uint8_t nonce[crypto_box_NONCEBYTES];

    if (packet_type == NET_PACKET_GCA_SEND_NODES) {
        header_len = 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE + crypto_box_NONCEBYTES;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE, crypto_box_NONCEBYTES);
    } else {
        header_len = 1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);
    }

    uint8_t plain[plain_length];
    int len = decrypt_data(public_key, self_secret_key, nonce, packet + header_len, length - header_len, plain);

    if (len != plain_length) {
        fprintf(stderr, "announce decrypt failed! len %d\n", len);
        return -1;
    }

    if (plain[0] != packet_type)
        return -1;

    memcpy(data, plain, plain_length);
    return plain_length;
}

/* Handle all encrypt procedures */
static int wrap_gca_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key,
                           const uint8_t *recv_public_key, uint8_t *packet, const uint8_t *data,
                           uint32_t length, uint8_t packet_type)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[length + crypto_box_MACBYTES];
    int len = encrypt_data(recv_public_key, send_secret_key, nonce, data, length, encrypt);

    if (len != sizeof(encrypt)) {
        fprintf(stderr, "Announce encrypt failed\n");
        return -1;
    }

    packet[0] = packet_type;
    memcpy(packet + 1, send_public_key, ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);

    memcpy(packet + GCA_HEADER_SIZE, encrypt, len);
    return GCA_HEADER_SIZE + len;
}

static int add_gc_announced_node(GC_Announce *announce, const uint8_t *dht_pk, const uint8_t *chat_id,
                                 const GC_Announce_Node node);

static int dispatch_packet_announce_request(GC_Announce* announce, Node_format *nodes, int nclosest,
                                            const uint8_t *chat_id, const uint8_t *sender_pk, const uint8_t *data,
                                            uint32_t length, bool self)
{
    uint8_t packet[GCA_REQUEST_DHT_SIZE];
    int i, sent = 0;

    /* Relay announce request to all nclosest nodes if self announce */
    for (i = 0; i < nclosest; i++) {
        if (!self && id_closest(chat_id, nodes[i].client_id, sender_pk) != 1)
            continue;

        int packet_length = wrap_gca_packet(announce->dht->self_public_key, announce->dht->self_secret_key,
                                            nodes[i].client_id, packet, data, length, NET_PACKET_GCA_ANNOUNCE);

        if (packet_length == -1)
            continue;

        if (sendpacket(announce->dht->net, nodes[i].ip_port, packet, packet_length) != -1)
            ++sent;
    }

    /* Add to announcements if we're the closest node to chat_id and we aren't the announcer */
    if (! sent | self) {
        GC_Announce_Node node;
        uint8_t chat_id[EXT_PUBLIC_KEY];
        memcpy(chat_id, data + 1, EXT_PUBLIC_KEY);

        uint8_t dht_public_key[ENC_PUBLIC_KEY];
        memcpy(dht_public_key, data + 1 + EXT_PUBLIC_KEY, ENC_PUBLIC_KEY);

        memcpy(&node.ip_port, data + 1 + EXT_PUBLIC_KEY + ENC_PUBLIC_KEY, sizeof(IP_Port));
        memcpy(node.client_id, data + 1 + EXT_PUBLIC_KEY + ENC_PUBLIC_KEY + sizeof(IP_Port), EXT_PUBLIC_KEY);

        add_gc_announced_node(announce, dht_public_key, chat_id, node);
    }

    return sent;
}

static int dispatch_packet_get_nodes_request(GC_Announce* announce, Node_format *nodes, int nclosest,
                                             const uint8_t *chat_id, const uint8_t *sender_pk, const uint8_t *data,
                                             uint32_t length, bool self)
{
    uint8_t packet[GCA_GETNODES_REQUEST_DHT_SIZE];
    int i, sent = 0;

    for (i = 0; i < nclosest; i++) {
        if (!self && id_closest(chat_id, nodes[i].client_id, sender_pk) != 1)
            continue;

        int packet_length = wrap_gca_packet(announce->dht->self_public_key, announce->dht->self_secret_key,
                                            nodes[i].client_id, packet, data, length, NET_PACKET_GCA_GET_NODES);
        if (packet_length == -1)
            continue;

        if (sendpacket(announce->dht->net, nodes[i].ip_port, packet, packet_length) != -1)
            ++sent;
    }

    return sent;
}

/* Returns the number of sent packets */
static int dispatch_packet(GC_Announce* announce, const uint8_t *chat_id, const uint8_t *sender_pk,
                           const uint8_t *data, uint32_t length, uint8_t packet_type, bool self)
{
    Node_format nodes[MAX_SENT_NODES];
    int nclosest = get_close_nodes(announce->dht, chat_id, nodes, 0, 1, 1);

    if (nclosest > MAX_GCA_SENT_NODES)
        nclosest = MAX_GCA_SENT_NODES;
    else if (nclosest == -1)
        return -1;

    if (packet_type == NET_PACKET_GCA_ANNOUNCE)
        return dispatch_packet_announce_request(announce, nodes, nclosest, chat_id, sender_pk, data, length, self);

    if (packet_type == NET_PACKET_GCA_GET_NODES)
        return dispatch_packet_get_nodes_request(announce, nodes, nclosest, chat_id, sender_pk, data, length, self);

    return -1;
}

/* Add requested online chat members to announce->self_requests
 *
 * Returns index of matching index on success.
 * Returns -1 on failure.
 */
static int add_requested_gc_nodes(GC_Announce *announce, const GC_Announce_Node *node, uint64_t req_id,
                                  uint32_t nodes_num)
{
    int i;
    uint32_t j;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; i++) {
        if (announce->self_requests[i].req_id != req_id)
            continue;

        for (j = 0; j < nodes_num; j++) {
            if (ipport_isset(&node[j].ip_port)
                && memcmp(announce->self_requests[i].long_pk, node[j].client_id, EXT_PUBLIC_KEY) != 0) {
                memcpy(announce->self_requests[i].nodes[j].client_id, node[j].client_id, EXT_PUBLIC_KEY);
                ipport_copy(&announce->self_requests[i].nodes[j].ip_port, &node[j].ip_port);
                announce->self_requests[i].ready = true;
            }
        }

        return i;
    }

    return -1;
}

static int add_announced_nodes_helper(GC_Announce *announce, const uint8_t *dht_pk, const uint8_t *chat_id,
                                      const GC_Announce_Node node, int idx, bool update)
{
    /* never timeout self */
    uint64_t timestamp = memcmp(announce->dht->self_public_key, dht_pk, ENC_PUBLIC_KEY) == 0
                         ? (uint64_t) -GCA_NODES_EXPIRATION - 1 : unix_time();

    announce->announcements[idx].last_rcvd_ping = timestamp;
    announce->announcements[idx].last_sent_ping = timestamp;
    announce->announcements[idx].time_added = timestamp;
    ipport_copy(&announce->announcements[idx].node.ip_port, &node.ip_port);

    if (update)
        return;

    memcpy(announce->announcements[idx].node.client_id, node.client_id, EXT_PUBLIC_KEY);
    memcpy(announce->announcements[idx].chat_id, chat_id, EXT_PUBLIC_KEY);
    memcpy(announce->announcements[idx].dht_public_key, dht_pk, ENC_PUBLIC_KEY);
    announce->announcements[idx].chat_id_hash = jenkins_hash(chat_id, EXT_PUBLIC_KEY);
    announce->announcements[idx].client_id_hash = jenkins_hash(node.client_id, EXT_PUBLIC_KEY);

    return idx;
}

/* Add announced node to announcements.
   If no slots are free replace the oldest node. */
static int add_gc_announced_node(GC_Announce *announce, const uint8_t *dht_pk, const uint8_t *chat_id,
                                 const GC_Announce_Node node)
{
    int i, oldest_idx = 0;
    uint64_t oldest_announce = 0;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; i++) {
        if (oldest_announce < announce->announcements[i].time_added) {
            oldest_announce = announce->announcements[i].time_added;
            oldest_idx = i;
        }

        if (id_long_equal(announce->announcements[i].node.client_id, node.client_id)
            && id_long_equal(announce->announcements[i].chat_id, chat_id))
            return add_announced_nodes_helper(announce, dht_pk, chat_id, node, i, true);

        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            return add_announced_nodes_helper(announce, dht_pk, chat_id, node, i, false);
    }

    return add_announced_nodes_helper(announce, dht_pk, chat_id, node, oldest_idx, false);
}

/* add our own announcement to self_announcements
   If no slots are free replace the oldest node. */
static int add_gc_self_announced_node(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *client_id)
{
    int i, oldest_idx = 0;
    uint64_t oldest_announce = 0;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (oldest_announce < announce->self_announcements[i].time_added) {
            oldest_announce = announce->self_announcements[i].time_added;
            oldest_idx = i;
        }

        if (announce->self_announcements[i].chat_id_hash == 0) {
            announce->self_announcements[i].time_added = unix_time();
            announce->self_announcements[i].chat_id_hash = jenkins_hash(chat_id, EXT_PUBLIC_KEY);
            announce->self_announcements[i].client_id_hash = jenkins_hash(client_id, EXT_PUBLIC_KEY);
            return i;
        }
    }

    announce->self_announcements[oldest_idx].time_added = unix_time();
    announce->self_announcements[oldest_idx].chat_id_hash = jenkins_hash(chat_id, EXT_PUBLIC_KEY);
    announce->self_announcements[oldest_idx].client_id_hash = jenkins_hash(client_id, EXT_PUBLIC_KEY);
    return oldest_idx;
}

/* Gets up to MAX_GCA_SENT_NODES nodes that hold chat_id from announcements and add them to nodes array.
 * Returns the number of added nodes.
 */
static int get_gc_announced_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes)
{
    int i, j = 0;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; i++) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            continue;

        if (id_long_equal(announce->announcements[i].chat_id, chat_id)) {
            memcpy(nodes[j].client_id, announce->announcements[i].node.client_id, EXT_PUBLIC_KEY);
            ipport_copy(&nodes[j].ip_port, &announce->announcements[i].node.ip_port);

            if (++j == MAX_GCA_SENT_NODES)
                break;
        }
    }

    return j;
}

/* Adds requested nodes that hold chat_id to self_requests.
 *
 * Returns array index on success.
 * Returns -1 on failure.
 */
static int add_announce_self_request(GC_Announce *announce, const uint8_t *chat_id, uint64_t req_id,
                                     const uint8_t *self_long_pk, const uint8_t *self_long_sk)
{
    int i;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; i++) {
        if (announce->self_requests[i].req_id == 0) {
            announce->self_requests[i].ready = 0;
            announce->self_requests[i].req_id = req_id;
            announce->self_requests[i].time_added = unix_time();
            memcpy(announce->self_requests[i].chat_id, chat_id, EXT_PUBLIC_KEY);
            memcpy(announce->self_requests[i].long_pk, self_long_pk, EXT_PUBLIC_KEY);
            memcpy(announce->self_requests[i].long_sk, self_long_sk, EXT_PUBLIC_KEY);
            return i;
        }
    }

    return -1;
}

/* Announce a new group chat */
int gca_send_announce_request(GC_Announce *announce, const uint8_t *self_long_pk, const uint8_t *self_long_sk,
                              const uint8_t *chat_id)
{
    DHT *dht = announce->dht;

    uint8_t data[GCA_REQUEST_PLAIN_SIZE];
    data[0] = NET_PACKET_GCA_ANNOUNCE;
    memcpy(data + 1, chat_id, EXT_PUBLIC_KEY);
    memcpy(data + 1 + EXT_PUBLIC_KEY, announce->dht->self_public_key, ENC_PUBLIC_KEY);

    IP_Port ipp;
    int i;

    for (i = 0; i < LCLIENT_LIST; i++) {
        if (ipport_isset(&dht->close_clientlist[i].assoc4.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc4.ret_ip_port);
            break;
        }

        if (ipport_isset(&dht->close_clientlist[i].assoc6.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc6.ret_ip_port);
            break;
        }
    }

    if (!ipport_isset(&ipp))
        return -1;

    memcpy(data + 1 + EXT_PUBLIC_KEY + ENC_PUBLIC_KEY, &ipp, sizeof(IP_Port));

    if (sign_data(data, 1 + EXT_PUBLIC_KEY + ENC_PUBLIC_KEY + sizeof(IP_Port), self_long_sk, self_long_pk, data) == -1)
        return -1;

    add_gc_self_announced_node(announce, chat_id, self_long_pk);

    return dispatch_packet(announce, chat_id, dht->self_public_key, data, GCA_REQUEST_PLAIN_SIZE,
                           NET_PACKET_GCA_ANNOUNCE, true);
}

/* Attempts to relay an announce request to close nodes.
 * If we are the closest node store the node in announcements
 */
int handle_gca_request(void *ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length != GCA_REQUEST_DHT_SIZE)
        return -1;

    GC_Announce* announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GCA_REQUEST_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, public_key, data,
                                         packet[0], packet, length);

    if (plain_length != GCA_REQUEST_PLAIN_SIZE)
        return -1;

    if (crypto_sign_verify_detached(data + GCA_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    data, GCA_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(data + GCA_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE
                                            - TIME_STAMP_SIZE - EXT_PUBLIC_KEY)) != 0)
        return -1;

    return dispatch_packet(announce, data+1, dht->self_public_key, data,
                           GCA_REQUEST_PLAIN_SIZE, NET_PACKET_GCA_ANNOUNCE, false);
}

/* Sends a request for nodes that hold chat_id */
int gca_send_get_nodes_request(GC_Announce* announce, const uint8_t *self_long_pk, const uint8_t *self_long_sk,
                               const uint8_t *chat_id)
{
    DHT *dht = announce->dht;

    uint8_t data[GCA_GETNODES_REQUEST_PLAIN_SIZE];
    data[0] = NET_PACKET_GCA_GET_NODES;
    memcpy(data + 1, chat_id, EXT_PUBLIC_KEY);

    IP_Port ipp;
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST; i++) {
        if (ipport_isset(&dht->close_clientlist[i].assoc4.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc4.ret_ip_port);
            break;
        }

        if (ipport_isset(&dht->close_clientlist[i].assoc6.ret_ip_port)) {
            ipport_copy(&ipp, &dht->close_clientlist[i].assoc6.ret_ip_port);
            break;
        }
    }

    if (!ipport_isset(&ipp))
        return -1;

    memcpy(data + 1 + EXT_PUBLIC_KEY, &ipp, sizeof(IP_Port));
    uint64_t request_id = random_64b();
    U64_to_bytes(data + 1 + EXT_PUBLIC_KEY + sizeof(IP_Port), request_id);

    uint8_t sigdata[GCA_GETNODES_REQUEST_PLAIN_SIZE];
    if (sign_data(data, 1 + EXT_PUBLIC_KEY + sizeof(IP_Port) + RAND_ID_SIZE, self_long_sk, self_long_pk, sigdata) == -1)
        return -1;

    add_announce_self_request(announce, chat_id, request_id, self_long_pk, self_long_sk);

    return dispatch_packet(announce, chat_id, dht->self_public_key, sigdata, GCA_GETNODES_REQUEST_PLAIN_SIZE,
                           NET_PACKET_GCA_GET_NODES, true);
}

/* Sends nodes that hold chat_id to node that requested them */
static int send_gca_get_nodes_response(DHT *dht, const uint8_t *chat_id, uint64_t request_id, IP_Port ipp,
                                       const uint8_t *receiver_pk, GC_Announce_Node *nodes, uint32_t num_nodes)
{
    uint8_t data[GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE];
    data[0] = NET_PACKET_GCA_SEND_NODES;
    U32_to_bytes(data + 1, num_nodes);
    memcpy(data + 1 + sizeof(uint32_t), nodes, sizeof(GC_Announce_Node) * num_nodes);
    uint32_t data_length = 1 + sizeof(uint32_t) + sizeof(GC_Announce_Node) * num_nodes + RAND_ID_SIZE;
    U64_to_bytes(data + data_length - RAND_ID_SIZE, request_id);

    uint8_t packet[GCA_GETNODES_RESPONSE_DHT_MAX_SIZE];
    int packet_length = wrap_gca_packet(dht->self_public_key, dht->self_secret_key, receiver_pk, packet, data,
                                        data_length, NET_PACKET_GCA_SEND_NODES);
    if (packet_length == -1)
        return -1;

    /* insert request_id into packet header after the packet type and chat_id */
    memmove(packet + 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE, packet + 1 + ENC_PUBLIC_KEY,
            packet_length - 1 - ENC_PUBLIC_KEY);
    U64_to_bytes(packet + 1 + ENC_PUBLIC_KEY, request_id);
    packet_length += RAND_ID_SIZE;

    return sendpacket(dht->net, ipp, packet, packet_length);
}

int handle_gc_get_announced_nodes_request(void *ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length != GCA_GETNODES_REQUEST_DHT_SIZE)
        return -1;

    GC_Announce* announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GCA_GETNODES_REQUEST_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, public_key, data,
                                         packet[0], packet, length);

    if (plain_length != GCA_GETNODES_REQUEST_PLAIN_SIZE)
        return -1;

    if (crypto_sign_verify_detached(data + GCA_GETNODES_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    data, GCA_GETNODES_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(data + GCA_GETNODES_REQUEST_PLAIN_SIZE - SIGNATURE_SIZE
                                    - TIME_STAMP_SIZE - EXT_PUBLIC_KEY)) != 0)
        return -1;

    GC_Announce_Node nodes[MAX_GCA_SENT_NODES];
    int num_nodes = get_gc_announced_nodes(announce, data + 1, nodes);

    if (num_nodes > 0) {
        uint64_t request_id;
        bytes_to_U64(&request_id, data + 1 + EXT_PUBLIC_KEY + sizeof(IP_Port));
        IP_Port ipp;
        memcpy(&ipp, data + 1 + EXT_PUBLIC_KEY, sizeof(IP_Port));

        return send_gca_get_nodes_response(dht, data+1, request_id, ipp,
                                                    data + GCA_GETNODES_REQUEST_PLAIN_SIZE
                                                    - EXT_PUBLIC_KEY - TIME_STAMP_SIZE - SIGNATURE_SIZE,
                                                    nodes, num_nodes);
    }

    return dispatch_packet(announce, data+1, dht->self_public_key, data,
                           GCA_GETNODES_REQUEST_PLAIN_SIZE, NET_PACKET_GCA_GET_NODES, false);
}

int handle_gca_get_nodes_response(void *ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    // NB: most probably we'll get nodes from different peers, so this would be called several times
    // TODO: different request_ids for the same chat_id... Probably

    if (length < GCA_GETNODES_RESPONSE_DHT_MIN_SIZE || length > GCA_GETNODES_RESPONSE_DHT_MAX_SIZE)
        return -1;

    GC_Announce *announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    uint64_t request_id = 0;
    bytes_to_U64(&request_id, packet + 1 + ENC_PUBLIC_KEY);

    if (request_id == 0)
        return -1;

    int plain_length = 0;
    uint32_t i;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; i++) {
        if (announce->self_requests[i].req_id == request_id) {
            plain_length = unwrap_gca_packet(announce->self_requests[i].long_pk,
                                             announce->self_requests[i].long_sk,
                                             public_key, data, packet[0],packet, length);
            break;
        }
    }

    if (plain_length < GCA_GETNODES_RESPONSE_PLAIN_MIN_SIZE || plain_length > GCA_GETNODES_RESPONSE_PLAIN_MAX_SIZE)
        return -1;

    uint64_t request_id_enc;
    bytes_to_U64(&request_id_enc, data + plain_length - RAND_ID_SIZE);

    if (request_id != request_id_enc)
        return -1;

    GC_Announce_Node nodes[MAX_GCA_SENT_NODES];
    uint32_t num_nodes;
    bytes_to_U32(&num_nodes, data + 1);

    /* this should never happen so assume it's malicious and ignore */
    if (num_nodes > MAX_GCA_SENT_NODES || num_nodes == 0)
        return -1;

    memcpy(nodes, data + 1 + sizeof(uint32_t), sizeof(GC_Announce_Node) * num_nodes);

    if (add_requested_gc_nodes(announce, nodes, request_id, num_nodes) == -1)
        return -1;

    return 0;
}

/* Get group chat online members, which you searched for with get_announced_nodes_request */
int gca_get_requested_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes)
{
    int i, j, k = 0;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; i++) {
        if (!id_long_equal(announce->self_requests[i].chat_id, chat_id))
            continue;

        if (! (announce->self_requests[i].ready == 1 && announce->self_requests[i].req_id != 0) )
            continue;

        for (j = 0; j < MAX_GCA_SENT_NODES; j++) {
            if (ipport_isset(&announce->self_requests[i].nodes[j].ip_port)) {
                memcpy(nodes[k].client_id, announce->self_requests[i].nodes[j].client_id, EXT_PUBLIC_KEY);
                ipport_copy(&nodes[k].ip_port, &announce->self_requests[i].nodes[j].ip_port);

                if (++k == MAX_GCA_SENT_NODES)
                    return k;
            }
        }
    }

    return k;
}

int handle_gca_ping_response(void *ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length != GCA_PING_DHT_SIZE)
        return -1;

    GC_Announce *announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GCA_PING_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];

    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, public_key, data,
                                         packet[0], packet, length);
    if (plain_length != GCA_PING_PLAIN_SIZE)
        return -1;

    uint64_t ping_id;
    memcpy(&ping_id, data + 1, RAND_ID_SIZE);

    uint32_t chat_id_hash;
    bytes_to_U32(&chat_id_hash, data + 1 + RAND_ID_SIZE + sizeof(uint32_t));

    int i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (announce->announcements[i].ping_id == ping_id && announce->announcements[i].chat_id_hash == chat_id_hash) {
            announce->announcements[i].ping_id = 0;

            if (!ipport_isset(&announce->announcements[i].node.ip_port))
                return -1;

             announce->announcements[i].last_rcvd_ping = unix_time();
             return 0;
        }
    }

    return -1;
}

static int send_gca_ping_response(DHT *dht, IP_Port ipp, const uint8_t *data, const uint8_t *dht_recv_pk)
{
    uint8_t response[GCA_PING_PLAIN_SIZE];
    response[0] = NET_PACKET_GCA_PING_RESPONSE;
    memcpy(response + 1, data + 1, GCA_PING_PLAIN_SIZE - 1);

    uint8_t packet[GCA_PING_DHT_SIZE];
    int len = wrap_gca_packet(dht->self_public_key, dht->self_secret_key, dht_recv_pk, packet,
                              response, GCA_PING_PLAIN_SIZE, NET_PACKET_GCA_PING_RESPONSE);
    if (len == -1)
        return -1;

    return sendpacket(dht->net, ipp, packet, len);
}

int handle_gca_ping_request(void *ancp, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length != GCA_PING_DHT_SIZE)
        return -1;

    GC_Announce *announce = ancp;
    DHT *dht = announce->dht;

    uint8_t data[GCA_PING_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];

    int plain_length = unwrap_gca_packet(dht->self_public_key, dht->self_secret_key, public_key,
                                         data, packet[0], packet, length);

    if (plain_length != GCA_PING_PLAIN_SIZE)
        return -1;

    uint32_t chat_id_hash;
    bytes_to_U32(&chat_id_hash, data + 1 + RAND_ID_SIZE);

    uint32_t client_id_hash;
    bytes_to_U32(&client_id_hash, data + 1 + RAND_ID_SIZE + sizeof(uint32_t));

    int i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (announce->self_announcements[i].chat_id_hash == chat_id_hash
            && announce->self_announcements[i].client_id_hash == client_id_hash)
            return send_gca_ping_response(dht, ipp, data, public_key);
    }

    return -1;
}

static int gca_send_ping_request(DHT *dht, GC_Announce_Node *node, uint64_t ping_id, const uint8_t *dht_recv_pk,
                                 uint32_t chat_id_hash, uint32_t client_id_hash)
{
    uint8_t data[GCA_PING_PLAIN_SIZE];
    data[0] = NET_PACKET_GCA_PING_REQUEST;

    memcpy(data + 1, &ping_id, RAND_ID_SIZE);
    U32_to_bytes(data + 1 + RAND_ID_SIZE, chat_id_hash);
    U32_to_bytes(data + 1 + RAND_ID_SIZE + sizeof(uint32_t), client_id_hash);

    uint8_t packet[GCA_PING_DHT_SIZE];
    int len = wrap_gca_packet(dht->self_public_key, dht->self_secret_key, dht_recv_pk, packet, data,
                              GCA_PING_PLAIN_SIZE, NET_PACKET_GCA_PING_REQUEST);
    if (len == -1)
        return -1;

    return sendpacket(dht->net, node->ip_port, packet, len);
}

static void ping_gca_nodes(GC_Announce *announce)
{
    int i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            continue;

        if (!is_timeout(announce->announcements[i].last_sent_ping, GCA_PING_INTERVAL))
            continue;

        uint64_t ping_id = random_64b();
        announce->announcements[i].ping_id = ping_id;

        if (gca_send_ping_request(announce->dht, &announce->announcements[i].node, ping_id,
                                  announce->announcements[i].dht_public_key,
                                  announce->announcements[i].chat_id_hash,
                                  announce->announcements[i].client_id_hash) != -1) {
            announce->announcements[i].last_sent_ping = unix_time();
        }
    }
}

void do_gca(GC_Announce *announce)
{
    int i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; i++) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port))
            continue;

        if (is_timeout(announce->announcements[i].last_rcvd_ping, GCA_NODES_EXPIRATION))
            memset(&announce->announcements[i], 0, sizeof(struct GC_AnnouncedNode));
    }

    ping_gca_nodes(announce);
}

void gca_cleanup(GC_Announce *announce, const uint8_t *chat_id)
{
    int i;

    /* Remove ourself from announcements for chat_id since we never timeout */
    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (! (ipport_isset(&announce->announcements[i].node.ip_port)
            && id_long_equal(announce->announcements[i].chat_id, chat_id)) )
            continue;

        if (memcmp(announce->announcements[i].dht_public_key, announce->dht->self_public_key, ENC_PUBLIC_KEY) == 0)
            memset(&announce->announcements[i], 0, sizeof(struct GC_AnnouncedNode));
    }

    /* Remove all self_announcements for chat_id */
    uint32_t chat_id_hash = jenkins_hash(chat_id, EXT_PUBLIC_KEY);

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (announce->self_announcements[i].chat_id_hash == chat_id_hash)
            memset(&announce->self_announcements[i], 0, sizeof(struct GC_SelfAnnouncedNode));
    }

    /* Remove all self_requests for chat_id */
    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (! (announce->self_requests[i].ready && announce->self_requests[i].req_id > 0) )
            continue;

        if (id_long_equal(announce->self_requests[i].chat_id, chat_id))
            memset(&announce->self_requests[i], 0, sizeof(struct GC_AnnounceRequest));
    }
}

GC_Announce *new_gca(DHT *dht)
{
    GC_Announce *announce = calloc(1, sizeof(GC_Announce));

    if (announce == NULL)
        return NULL;

    announce->dht = dht;
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_ANNOUNCE, &handle_gca_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_GET_NODES, &handle_gc_get_announced_nodes_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_SEND_NODES, &handle_gca_get_nodes_response, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_REQUEST, &handle_gca_ping_request, announce);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_RESPONSE, &handle_gca_ping_response, announce);
    return announce;
}

void kill_gca(GC_Announce *announce)
{
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_ANNOUNCE, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_GET_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_SEND_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_REQUEST, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GCA_PING_RESPONSE, NULL, NULL);

    free(announce);
}
