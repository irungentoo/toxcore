/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * Similar to ping.h, but designed for group chat purposes
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Messenger.h"
#include "logger.h"
#include "util.h"
#include "mono_time.h"
#include "network.h"
#include "DHT.h"

#include "group_announce.h"
#include "group_chats.h"

#ifndef VANILLA_NACL

enum {
    RAND_ID_SIZE = sizeof(uint64_t),

    /* type + sender_dht_pk + nonce + */
    GCA_HEADER_SIZE = 1 + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE,

    /* type + ping_id */
    GCA_PING_REQUEST_PLAIN_SIZE = 1 + RAND_ID_SIZE,
    GCA_PING_REQUEST_DHT_SIZE = GCA_HEADER_SIZE + ENC_PUBLIC_KEY + GCA_PING_REQUEST_PLAIN_SIZE + CRYPTO_MAC_SIZE,

    /* type + ping_id */
    GCA_PING_RESPONSE_PLAIN_SIZE = 1 + RAND_ID_SIZE,
    GCA_PING_RESPONSE_DHT_SIZE = GCA_HEADER_SIZE + GCA_PING_RESPONSE_PLAIN_SIZE + CRYPTO_MAC_SIZE,

    GCA_PING_INTERVAL = 60,
    GCA_NODES_EXPIRATION = GCA_PING_INTERVAL * 3 + 10,
    GCA_RELAY_RATE_LIMIT = 30,

    MAX_GCA_PACKET_SIZE = 1024,
};

/* Copies your own ip_port structure to dest. (TODO: This should probably go somewhere else)
 *
 * Return 0 on succcess.
 * Return -1 on failure.
 */
int ipport_self_copy(const DHT *dht, IP_Port *dest)
{
    for (size_t i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *const client = dht_get_close_client(dht, i);
        const IP_Port *const ip_port4 = &client->assoc4.ret_ip_port;

        if (ipport_isset(ip_port4)) {
            ipport_copy(dest, ip_port4);
            break;
        }

        const IP_Port *const ip_port6 = &client->assoc6.ret_ip_port;

        if (ipport_isset(ip_port6)) {
            ipport_copy(dest, ip_port6);
            break;
        }
    }

    if (!ipport_isset(dest)) {
        return -1;
    }

    return 0;
}

/* Creates a GC_Announce_Node using public_key and your own IP_Port struct
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int make_self_gca_node(const DHT *dht, GC_Announce_Node *node, const uint8_t *public_key)
{
    if (ipport_self_copy(dht, &node->ip_port) == -1) {
        return -1;
    }

    memcpy(node->public_key, public_key, ENC_PUBLIC_KEY);
    return 0;
}

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_gca_nodes(uint8_t *data, uint16_t length, const GC_Announce_Node *nodes, uint32_t number)
{
    uint32_t i;
    int packed_length = 0;

    for (i = 0; i < number; ++i) {
        int ipp_size = pack_ip_port(data + packed_length, length - packed_length, &nodes[i].ip_port);

        if (ipp_size == -1) {
            return -1;
        }

        packed_length += ipp_size;

        if (packed_length + ENC_PUBLIC_KEY > length) {
            return -1;
        }

        memcpy(data + packed_length, nodes[i].public_key, ENC_PUBLIC_KEY);
        packed_length += ENC_PUBLIC_KEY;
    }

    return packed_length;
}

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_gca_nodes(GC_Announce_Node *nodes, uint32_t max_num_nodes, uint16_t *processed_data_len,
                     const uint8_t *data, uint16_t length, uint8_t tcp_enabled)
{
    uint32_t num = 0, len_processed = 0;

    while (num < max_num_nodes && len_processed < length) {
        int ipp_size = unpack_ip_port(&nodes[num].ip_port, data + len_processed, length - len_processed, tcp_enabled);

        if (ipp_size == -1) {
            return -1;
        }

        len_processed += ipp_size;

        if (len_processed + ENC_PUBLIC_KEY > length) {
            return -1;
        }

        memcpy(nodes[num].public_key, data + len_processed, ENC_PUBLIC_KEY);
        len_processed += ENC_PUBLIC_KEY;
        ++num;
    }

    if (processed_data_len) {
        *processed_data_len = len_processed;
    }

    return num;
}

/* Removes plaintext header and decrypts packets.
 *
 * Returns length of plaintext data on success.
 * Returns -1 on failure.
 */
static int unwrap_gca_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key,
                             uint8_t *data, size_t data_size, uint8_t packet_type, const uint8_t *packet, uint16_t length)
{
    if (id_equal(packet + 1, self_public_key)) {
        fprintf(stderr, "Announce unwrap failed: id_equal failed\n");
        return -1;
    }

    if (public_key) {
        memcpy(public_key, packet + 1, ENC_PUBLIC_KEY);
    }

    size_t header_len = GCA_HEADER_SIZE;
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    if (packet_type == NET_PACKET_GCA_SEND_NODES) {
        header_len += RAND_ID_SIZE;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE, CRYPTO_NONCE_SIZE);
    } else if (packet_type == NET_PACKET_GCA_PING_REQUEST) {
        header_len += ENC_PUBLIC_KEY;
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY + ENC_PUBLIC_KEY, CRYPTO_NONCE_SIZE);
    } else {
        memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY, CRYPTO_NONCE_SIZE);
    }

    if (length <= header_len + CRYPTO_MAC_SIZE) {
        fprintf(stderr, "Announce unwrap failed: Encrypted length is too small %d\n", length);
        return -1;
    }

    size_t plain_len = length - header_len - CRYPTO_MAC_SIZE;

    if (plain_len > data_size) {
        fprintf(stderr, "Announce unwrap failed: plain len (%u) is larger than data_len (%u)\n", (unsigned)plain_len,
                (unsigned)data_size);
        return -1;
    }

    VLA(uint8_t, plain, plain_len);
    int len = decrypt_data(public_key, self_secret_key, nonce, packet + header_len, length - header_len, plain);

    if (len != plain_len) {
        fprintf(stderr, "Announce unwrap failed: length is %d, type is %u\n", len, plain[0]);
        return -1;
    }

    if (plain[0] != packet_type) {
        fprintf(stderr, "Announce unwrap failed with wrong packet type %d - expected %d\n", plain[0], packet_type);
        return -1;
    }

    memcpy(data, plain, len);
    return len;
}

/* Encrypts data of length and adds a plaintext header containing the packet type,
 * public encryption key of the sender, and the nonce used to encrypt data.
 */
static int wrap_gca_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key,
                           const uint8_t *recv_public_key, uint8_t *packet, uint32_t packet_size,
                           const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (packet_size < length + GCA_HEADER_SIZE + CRYPTO_MAC_SIZE) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    VLA(uint8_t, encrypt, length + CRYPTO_MAC_SIZE);
    int len = encrypt_data(recv_public_key, send_secret_key, nonce, data, length, encrypt);

    if (len != SIZEOF_VLA(encrypt)) {
        fprintf(stderr, "Announce encrypt failed\n");
        return -1;
    }

    packet[0] = packet_type;
    memcpy(packet + 1, send_public_key, ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + GCA_HEADER_SIZE, encrypt, len);

    return GCA_HEADER_SIZE + len;
}

static bool gca_rate_limit(GC_Announce *announce);
static void remove_gca_self_announce(GC_Announce *announce, const uint8_t *chat_id);
static size_t add_gc_announced_node(GC_Announce *announce, const uint8_t *chat_id, const GC_Announce_Node node,
                                    bool self);

static int dispatch_packet_announce_request(GC_Announce *announce, const uint8_t *chat_id,
        const uint8_t *origin_pk, const uint8_t *self_pk,
        const uint8_t *data, uint32_t length, bool self)
{
    Node_format dht_nodes[MAX_SENT_NODES];
    uint32_t nclosest = get_close_nodes(announce->dht, chat_id, dht_nodes, net_family_unspec, 1, 1);
    nclosest = min_u32(MAX_GCA_SENT_NODES, nclosest);

    VLA(uint8_t, packet, length + GCA_HEADER_SIZE + CRYPTO_MAC_SIZE);
    uint32_t i;
    uint16_t sent = 0;

    /* Relay announce request to all nclosest nodes */
    for (i = 0; i < nclosest; ++i) {
        if (origin_pk && id_equal(origin_pk, dht_nodes[i].public_key)) {
            continue;
        }

        if (id_closest(chat_id, dht_nodes[i].public_key, self_pk) != 1) {
            continue;
        }

        int packet_length = wrap_gca_packet(dht_get_self_public_key(announce->dht),
                                            dht_get_self_secret_key(announce->dht),
                                            dht_nodes[i].public_key, packet, SIZEOF_VLA(packet), data, length,
                                            NET_PACKET_GCA_ANNOUNCE);

        if (packet_length == -1) {
            continue;
        }

        if (sendpacket(dht_get_net(announce->dht), dht_nodes[i].ip_port, packet, packet_length) != -1) {
            ++sent;
        }
    }

    /* Add to announcements if we're the closest node to chat_id */
    if (sent == 0) {
        GC_Announce_Node node;

        if (unpack_gca_nodes(&node, 1, nullptr, data + 1 + CHAT_ID_SIZE, length - 1 - CHAT_ID_SIZE, 0) != 1) {
            return -1;
        }

        add_gc_announced_node(announce, chat_id, node, self);

        /* We will never need to ping or renew our own announcement */
        if (self) {
            remove_gca_self_announce(announce, chat_id);
        }
    }

    return sent;
}

static int dispatch_packet_get_nodes_request(GC_Announce *announce, const uint8_t *chat_id,
        const uint8_t *origin_pk, const uint8_t *self_pk,
        const uint8_t *data, uint32_t length, bool self)
{
    Node_format dht_nodes[MAX_SENT_NODES];
    uint32_t nclosest = get_close_nodes(announce->dht, chat_id, dht_nodes, net_family_unspec, 1, 1);
    nclosest = min_u32(MAX_GCA_SENT_NODES, nclosest);

    VLA(uint8_t, packet, length + GCA_HEADER_SIZE + CRYPTO_MAC_SIZE);
    uint32_t i;
    uint16_t sent = 0;

    for (i = 0; i < nclosest; ++i) {
        if (!self) {
            if (origin_pk && id_equal(origin_pk, dht_nodes[i].public_key)) {
                continue;
            }

            if (id_closest(chat_id, dht_nodes[i].public_key, self_pk) != 1) {
                continue;
            }
        }

        int packet_length = wrap_gca_packet(dht_get_self_public_key(announce->dht),
                                            dht_get_self_secret_key(announce->dht),
                                            dht_nodes[i].public_key, packet, SIZEOF_VLA(packet), data, length,
                                            NET_PACKET_GCA_GET_NODES);

        if (packet_length == -1) {
            continue;
        }

        if (sendpacket(dht_get_net(announce->dht), dht_nodes[i].ip_port, packet, packet_length) != -1) {
            ++sent;
        }
    }

    return sent;
}

/* Returns the number of sent packets */
static int dispatch_packet(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *origin_pk,
                           const uint8_t *self_pk, const uint8_t *data, uint32_t length, uint8_t packet_type,
                           bool self)
{
    if (gca_rate_limit(announce)) {
        return 0;
    }

    if (packet_type == NET_PACKET_GCA_ANNOUNCE) {
        return dispatch_packet_announce_request(announce, chat_id, origin_pk, self_pk, data, length, self);
    }

    if (packet_type == NET_PACKET_GCA_GET_NODES) {
        return dispatch_packet_get_nodes_request(announce, chat_id, origin_pk, self_pk, data, length, self);
    }

    return -1;
}

/* Add requested online chat members to announce->requests
 *
 * Returns index of match on success.
 * Returns -1 on failure.
 */
static int add_requested_gc_nodes(GC_Announce *announce, const GC_Announce_Node *node, uint64_t req_id,
                                  uint32_t nodes_num)
{
    size_t i;
    uint32_t j;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (announce->requests[i].req_id != req_id) {
            continue;
        }

        for (j = 0; j < nodes_num && j < MAX_GCA_SENT_NODES; ++j) {
            if (ipport_isset(&node[j].ip_port)
                    && !id_equal(announce->requests[i].self_public_key, node[j].public_key)) {
                memcpy(announce->requests[i].nodes[j].public_key, node[j].public_key, ENC_PUBLIC_KEY);
                ipport_copy(&announce->requests[i].nodes[j].ip_port, &node[j].ip_port);
                announce->requests[i].ready = true;
            }
        }

        if (announce->requests[i].ready && announce->update_addresses) {
            (*announce->update_addresses)(announce, announce->requests[i].chat_id, announce->update_addresses_obj);
        }

        return i;
    }

    return -1;
}

static size_t add_announced_nodes_helper(GC_Announce *announce, const uint8_t *chat_id, const GC_Announce_Node node,
        size_t idx, bool self)
{
    ipport_copy(&announce->announcements[idx].node.ip_port, &node.ip_port);
    memcpy(announce->announcements[idx].node.public_key, node.public_key, ENC_PUBLIC_KEY);
    memcpy(announce->announcements[idx].chat_id, chat_id, CHAT_ID_SIZE);
    announce->announcements[idx].last_rcvd_ping = mono_time_get(announce->mono_time);
    announce->announcements[idx].last_sent_ping = mono_time_get(announce->mono_time);
    announce->announcements[idx].time_added = mono_time_get(announce->mono_time);
    announce->announcements[idx].self = self;

    return idx;
}

/* Add announced node to announcements. If no slots are free replace the oldest node.
 *
 * Returns index of added node.
 */
static size_t add_gc_announced_node(GC_Announce *announce, const uint8_t *chat_id, const GC_Announce_Node node,
                                    bool self)
{
    size_t i, oldest_idx = 0;
    uint64_t oldest_announce = 0;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (oldest_announce < announce->announcements[i].time_added) {
            oldest_announce = announce->announcements[i].time_added;
            oldest_idx = i;
        }

        if (id_equal(announce->announcements[i].node.public_key, node.public_key)
                && chat_id_equal(announce->announcements[i].chat_id, chat_id)) {
            return add_announced_nodes_helper(announce, chat_id, node, i, self);
        }

        if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
            return add_announced_nodes_helper(announce, chat_id, node, i, self);
        }
    }

    return add_announced_nodes_helper(announce, chat_id, node, oldest_idx, self);
}

/* Gets up to MAX_GCA_SENT_NODES nodes that hold chat_id from announcements and add them to nodes array.
 * Returns the number of added nodes.
 */
static uint32_t get_gc_announced_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes)
{
    size_t i;
    uint32_t num = 0;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
            continue;
        }

        if (chat_id_equal(announce->announcements[i].chat_id, chat_id)) {
            memcpy(nodes[num].public_key, announce->announcements[i].node.public_key, ENC_PUBLIC_KEY);
            ipport_copy(&nodes[num].ip_port, &announce->announcements[i].node.ip_port);

            if (++num == MAX_GCA_SENT_NODES) {
                break;
            }
        }
    }

    return num;
}

/* Initiates requests holder for our nodes request responses for chat_id.
 * If all slots are full the oldest entry is replaced
 */
static void init_gca_self_request(GC_Announce *announce, const uint8_t *chat_id, uint64_t req_id,
                                  const uint8_t *self_public_key, const uint8_t *self_secret_key)
{
    size_t i, idx = 0;
    uint64_t oldest_req = 0;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (announce->requests[i].req_id == 0) {
            idx = i;
            break;
        }

        if (oldest_req < announce->requests[i].time_added) {
            oldest_req = announce->requests[i].time_added;
            idx = i;
        }
    }

    memset(&announce->requests[idx], 0, sizeof(struct GC_AnnounceRequest));
    announce->requests[idx].req_id = req_id;
    announce->requests[idx].time_added = mono_time_get(announce->mono_time);
    memcpy(announce->requests[idx].chat_id, chat_id, CHAT_ID_SIZE);
    memcpy(announce->requests[idx].self_public_key, self_public_key, ENC_PUBLIC_KEY);
    memcpy(announce->requests[idx].self_secret_key, self_secret_key, ENC_SECRET_KEY);
}

/* Adds our own announcement to self_announce.
 *
 * Returns array index on success.
 * Returns -1 if self_announce is full.
 */
static int add_gca_self_announce(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *self_public_key,
                                 const uint8_t *self_secret_key)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set) {
            announce->self_announce[i].last_rcvd_ping = mono_time_get(announce->mono_time);
            announce->self_announce[i].is_set = true;
            memcpy(announce->self_announce[i].chat_id, chat_id, CHAT_ID_SIZE);
            memcpy(announce->self_announce[i].self_public_key, self_public_key, ENC_PUBLIC_KEY);
            memcpy(announce->self_announce[i].self_secret_key, self_secret_key, ENC_SECRET_KEY);
            return i;
        }
    }

    return -1;
}

/* Removes all instances of chat_id from self_announce. */
static void remove_gca_self_announce(GC_Announce *announce, const uint8_t *chat_id)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set) {
            continue;
        }

        if (chat_id_equal(announce->self_announce[i].chat_id, chat_id)) {
            memset(&announce->self_announce[i], 0, sizeof(struct GC_AnnouncedSelf));
        }
    }
}

/* Returns true if a self announce entry exists containing chat_id/self_public_key.
 * Returns false otherwise.
 */
static bool gca_self_announce_set(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *public_key)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set) {
            continue;
        }

        if (chat_id_equal(announce->self_announce[i].chat_id, chat_id)
                && id_equal(announce->self_announce[i].self_public_key, public_key)) {
            return true;
        }
    }

    return false;
}

/* Announce a new group chat.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
int gca_send_announce_request(GC_Announce *announce, const uint8_t *self_public_key, const uint8_t *self_secret_key,
                              const uint8_t *chat_id)
{
    DHT *dht = announce->dht;

    if (gca_self_announce_set(announce, chat_id, self_public_key)) {
        return 0;
    }

    add_gca_self_announce(announce, chat_id, self_public_key, self_secret_key);

    /* packet contains: type, chat_id, node */
    uint8_t data[1 + CHAT_ID_SIZE + sizeof(GC_Announce_Node)];
    data[0] = NET_PACKET_GCA_ANNOUNCE;
    memcpy(data + 1, chat_id, CHAT_ID_SIZE);

    GC_Announce_Node self_node;

    if (make_self_gca_node(dht, &self_node, self_public_key) == -1) {
        return -1;
    }

    int node_len = pack_gca_nodes(data + 1 + CHAT_ID_SIZE, sizeof(GC_Announce_Node), &self_node, 1);

    if (node_len <= 0) {
        return -1;
    }

    uint32_t length = 1 + CHAT_ID_SIZE + node_len;

    if (length > MAX_GCA_PACKET_SIZE) {
        return -1;
    }

    return dispatch_packet(announce, chat_id, nullptr, dht_get_self_public_key(dht), data, length, NET_PACKET_GCA_ANNOUNCE,
                           true);
}

/* Attempts to relay an announce request to close nodes.
 * If we are the closest node store the node in announcements (this happens in dispatch_packet_announce_request)
 */
static int handle_gca_request(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length, void *userdata)
{
    GC_Announce *announce = (GC_Announce *)object;
    DHT *dht = announce->dht;

    if (length <=  GCA_HEADER_SIZE + CRYPTO_MAC_SIZE || length > MAX_GCA_PACKET_SIZE) {
        return -1;
    }

    uint16_t data_length = length - (GCA_HEADER_SIZE + CRYPTO_MAC_SIZE);
    uint16_t d_header_len = 1 + CHAT_ID_SIZE;

    if (data_length <= d_header_len) {
        return -1;
    }

    VLA(uint8_t, data, data_length);
    uint8_t origin_pk[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht_get_self_public_key(dht), dht_get_self_secret_key(dht), origin_pk, data,
                                         SIZEOF_VLA(data), packet[0], packet, length);

    if (plain_length != SIZEOF_VLA(data)) {
        fprintf(stderr, "unwrap failed in handle_gca_request (plain_length: %u, data size: %u)\n",
                (unsigned)plain_length, (unsigned)SIZEOF_VLA(data));
        return -1;
    }

    GC_Announce_Node node;

    if (unpack_gca_nodes(&node, 1, nullptr, data + d_header_len, plain_length - d_header_len, 0) != 1) {
        return -1;
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    memcpy(chat_id, data + 1, CHAT_ID_SIZE);

    return dispatch_packet(announce, chat_id, origin_pk, dht_get_self_public_key(dht), data, plain_length,
                           NET_PACKET_GCA_ANNOUNCE, false);
}

/* Creates a DHT request for nodes that hold announcements for chat_id.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
int gca_send_get_nodes_request(GC_Announce *announce, const uint8_t *self_public_key, const uint8_t *self_secret_key,
                               const uint8_t *chat_id)
{
    DHT *dht = announce->dht;

    /* packet contains: type, chat_id, request_id, node */
    uint8_t data[1 + CHAT_ID_SIZE + RAND_ID_SIZE + sizeof(GC_Announce_Node)];
    data[0] = NET_PACKET_GCA_GET_NODES;
    memcpy(data + 1, chat_id, CHAT_ID_SIZE);

    uint64_t request_id = random_u64();
    net_pack_u64(data + 1 + CHAT_ID_SIZE, request_id);

    GC_Announce_Node self_node;

    if (make_self_gca_node(dht, &self_node, self_public_key) == -1) {
        return -1;
    }

    int node_len = pack_gca_nodes(data + 1 + CHAT_ID_SIZE + RAND_ID_SIZE, sizeof(GC_Announce_Node), &self_node, 1);

    if (node_len <= 0) {
        fprintf(stderr, "pack_nodes failed in send_get_nodes_request\n");
        return -1;
    }

    uint32_t length = 1 + CHAT_ID_SIZE + RAND_ID_SIZE + node_len;
    init_gca_self_request(announce, chat_id, request_id, self_public_key, self_secret_key);

    return dispatch_packet(announce, chat_id, nullptr, dht_get_self_public_key(dht), data, length, NET_PACKET_GCA_GET_NODES,
                           true);
}

/* Sends nodes that hold chat_id to node that requested them */
static int send_gca_get_nodes_response(GC_Announce *announce, uint64_t request_id, IP_Port ipp,
                                       const uint8_t *receiver_pk,
                                       GC_Announce_Node *nodes, uint32_t num_nodes)
{
    DHT *dht = announce->dht;

    if (gca_rate_limit(announce)) {
        return 0;
    }

    /* packet contains: type, num_nodes, nodes, request_id */
    VLA(uint8_t, data, 1 + sizeof(uint32_t) + sizeof(GC_Announce_Node) * num_nodes + RAND_ID_SIZE);
    data[0] = NET_PACKET_GCA_SEND_NODES;
    net_pack_u32(data + 1, num_nodes);

    int nodes_len = pack_gca_nodes(data + 1 + sizeof(uint32_t), sizeof(GC_Announce_Node) * num_nodes,
                                   nodes, num_nodes);

    if (nodes_len <= 0) {
        fprintf(stderr, "pack_gca_nodes failed in send_gca_get_nodes_response (%d)\n", nodes_len);
        return -1;
    }

    uint32_t plain_length = 1 + sizeof(uint32_t) + nodes_len + RAND_ID_SIZE;
    net_pack_u64(data + plain_length - RAND_ID_SIZE, request_id);

    VLA(uint8_t, packet, plain_length + RAND_ID_SIZE + GCA_HEADER_SIZE + CRYPTO_MAC_SIZE);
    int packet_length = wrap_gca_packet(dht_get_self_public_key(dht), dht_get_self_secret_key(dht), receiver_pk, packet,
                                        SIZEOF_VLA(packet), data, plain_length, NET_PACKET_GCA_SEND_NODES);

    if (packet_length == -1) {
        fprintf(stderr, "wrap failed in send_gca_get_nodes_response\n");
        return -1;
    }

    /* insert request_id into packet header after the packet type and dht_pk */
    memmove(packet + 1 + ENC_PUBLIC_KEY + RAND_ID_SIZE, packet + 1 + ENC_PUBLIC_KEY, packet_length - 1 - ENC_PUBLIC_KEY);
    net_pack_u64(packet + 1 + ENC_PUBLIC_KEY, request_id);
    packet_length += RAND_ID_SIZE;

    return sendpacket(dht_get_net(dht), ipp, packet, packet_length);
}

static int handle_gc_get_announced_nodes_request(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length,
        void *userdata)
{
    GC_Announce *announce = (GC_Announce *)object;
    DHT *dht = announce->dht;

    if (length <= GCA_HEADER_SIZE + CRYPTO_MAC_SIZE || length > MAX_GCA_PACKET_SIZE) {
        return -1;
    }

    uint16_t data_length = length - (GCA_HEADER_SIZE + CRYPTO_MAC_SIZE);
    uint16_t d_header_len = 1 + CHAT_ID_SIZE + RAND_ID_SIZE;

    if (data_length <= d_header_len) {
        return -1;
    }

    VLA(uint8_t, data, data_length);
    uint8_t origin_pk[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht_get_self_public_key(dht), dht_get_self_secret_key(dht), origin_pk, data,
                                         SIZEOF_VLA(data), packet[0], packet, length);

    if (plain_length != SIZEOF_VLA(data)) {
        fprintf(stderr, "unwrap failed in handle_gc_get_announced_nodes_request %d\n", plain_length);
        return -1;
    }

    GC_Announce_Node node;

    if (unpack_gca_nodes(&node, 1, nullptr, data + d_header_len, plain_length - d_header_len, 0) != 1) {
        fprintf(stderr, "unpack failed in handle_gc_get_announced_nodes_request\n");
        return -1;
    }

    GC_Announce_Node nodes[MAX_GCA_SENT_NODES];
    uint32_t num_nodes = get_gc_announced_nodes(announce, data + 1, nodes);

    if (num_nodes) {
        uint64_t request_id;
        net_unpack_u64(data + 1 + CHAT_ID_SIZE, &request_id);
        return send_gca_get_nodes_response(announce, request_id, node.ip_port, node.public_key, nodes, num_nodes);
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    memcpy(chat_id, data + 1, CHAT_ID_SIZE);

    return dispatch_packet(announce, chat_id, origin_pk, dht_get_self_public_key(dht), data, plain_length,
                           NET_PACKET_GCA_GET_NODES, false);
}

static int handle_gca_get_nodes_response(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length,
        void *userdata)
{
    GC_Announce *announce = (GC_Announce *)object;

    if (length <= GCA_HEADER_SIZE + CRYPTO_MAC_SIZE + RAND_ID_SIZE || length > MAX_GCA_PACKET_SIZE) {
        return -1;
    }

    uint16_t data_length = length - (GCA_HEADER_SIZE + CRYPTO_MAC_SIZE + RAND_ID_SIZE);

    if (data_length <= 1 + sizeof(uint32_t) + RAND_ID_SIZE) {
        return -1;
    }

    VLA(uint8_t, data, data_length);
    uint8_t public_key[ENC_PUBLIC_KEY];

    uint64_t request_id;
    net_unpack_u64(packet + 1 + ENC_PUBLIC_KEY, &request_id);

    int plain_length = 0;
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (announce->requests[i].req_id == request_id) {
            plain_length = unwrap_gca_packet(announce->requests[i].self_public_key,
                                             announce->requests[i].self_secret_key,
                                             public_key, data, SIZEOF_VLA(data),
                                             packet[0], packet, length);
            break;
        }
    }

    if (plain_length != SIZEOF_VLA(data)) {
        return -1;
    }

    uint64_t request_id_enc;
    net_unpack_u64(data + plain_length - RAND_ID_SIZE, &request_id_enc);

    if (request_id != request_id_enc) {
        return -1;
    }

    uint32_t num_nodes;
    net_unpack_u32(data + 1, &num_nodes);

    /* this should never happen so assume it's malicious and ignore */
    if (num_nodes > MAX_GCA_SENT_NODES || num_nodes == 0) {
        return -1;
    }

    VLA(GC_Announce_Node, nodes, num_nodes);
    int num_packed = unpack_gca_nodes(nodes, num_nodes, nullptr, data + 1 + sizeof(uint32_t),
                                      plain_length - 1 - sizeof(uint32_t), 0);

    if (num_packed != num_nodes) {
        fprintf(stderr, "unpack failed in handle_gca_get_nodes_response (got %d, expected %u)\n", num_packed, num_nodes);
        return -1;
    }

    if (add_requested_gc_nodes(announce, nodes, request_id, num_nodes) == -1) {
        return -1;
    }

    return 0;
}

/* Retrieves nodes for chat_id (nodes must already be obtained via gca_send_announce_request).
 *
 * returns the number of nodes found.
 */
size_t gca_get_requested_nodes(GC_Announce *announce, const uint8_t *chat_id, GC_Announce_Node *nodes)
{
    size_t i, j, k = 0;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (!(announce->requests[i].ready == 1 && announce->requests[i].req_id != 0)) {
            continue;
        }

        if (!chat_id_equal(announce->requests[i].chat_id, chat_id)) {
            continue;
        }

        for (j = 0; j < MAX_GCA_SENT_NODES; ++j) {
            if (ipport_isset(&announce->requests[i].nodes[j].ip_port)) {
                memcpy(nodes[k].public_key, announce->requests[i].nodes[j].public_key, ENC_PUBLIC_KEY);
                ipport_copy(&nodes[k].ip_port, &announce->requests[i].nodes[j].ip_port);

                if (++k == MAX_GCA_SENT_NODES) {
                    return k;
                }
            }
        }
    }

    return k;
}

static int handle_gca_ping_response(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length, void *userdata)
{
    GC_Announce *announce = (GC_Announce *)object;
    DHT *dht = announce->dht;

    if (length != GCA_PING_RESPONSE_DHT_SIZE) {
        return -1;
    }

    uint8_t data[GCA_PING_RESPONSE_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];

    int plain_length = unwrap_gca_packet(dht_get_self_public_key(dht), dht_get_self_secret_key(dht), public_key, data,
                                         sizeof(data), packet[0], packet, length);

    if (plain_length != GCA_PING_RESPONSE_PLAIN_SIZE) {
        return -1;
    }

    uint64_t ping_id;
    memcpy(&ping_id, data + 1, RAND_ID_SIZE);

    size_t i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (announce->announcements[i].ping_id == ping_id) {
            announce->announcements[i].ping_id = 0;

            if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
                return -1;
            }

            announce->announcements[i].last_rcvd_ping = mono_time_get(announce->mono_time);
            return 0;
        }
    }

    return -1;
}

static int send_gca_ping_response(DHT *dht, IP_Port ipp, const uint8_t *data, const uint8_t *rcv_pk)
{
    uint8_t response[GCA_PING_RESPONSE_PLAIN_SIZE];
    response[0] = NET_PACKET_GCA_PING_RESPONSE;
    memcpy(response + 1, data + 1, GCA_PING_RESPONSE_PLAIN_SIZE - 1);

    uint8_t packet[GCA_PING_RESPONSE_DHT_SIZE];
    int len = wrap_gca_packet(dht_get_self_public_key(dht), dht_get_self_secret_key(dht), rcv_pk, packet, sizeof(packet),
                              response, GCA_PING_RESPONSE_PLAIN_SIZE, NET_PACKET_GCA_PING_RESPONSE);

    if (len == -1) {
        return -1;
    }

    return sendpacket(dht_get_net(dht), ipp, packet, len);
}

static int handle_gca_ping_request(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length, void *userdata)
{
    GC_Announce *announce = (GC_Announce *)object;
    DHT *dht = announce->dht;

    if (length != GCA_PING_REQUEST_DHT_SIZE) {
        return -1;
    }

    uint8_t self_public_key[ENC_PUBLIC_KEY];
    memcpy(self_public_key, packet + 1 + ENC_PUBLIC_KEY, ENC_PUBLIC_KEY);

    size_t i;
    bool node_found = false;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set) {
            continue;
        }

        if (memcmp(self_public_key, announce->self_announce[i].self_public_key, ENC_PUBLIC_KEY) == 0) {
            node_found = true;
            break;
        }
    }

    if (!node_found) {
        fprintf(stderr, "handle announce ping request failed\n");
        return -1;
    }

    uint8_t data[GCA_PING_REQUEST_PLAIN_SIZE];
    uint8_t public_key[ENC_PUBLIC_KEY];
    int plain_length = unwrap_gca_packet(dht_get_self_public_key(dht), announce->self_announce[i].self_secret_key,
                                         public_key, data, sizeof(data), packet[0], packet, length);

    if (plain_length != GCA_PING_REQUEST_PLAIN_SIZE) {
        fprintf(stderr, "handle ping request unwrap failed\n");
        return -1;
    }

    announce->self_announce[i].last_rcvd_ping = mono_time_get(announce->mono_time);

    return send_gca_ping_response(dht, ipp, data, public_key);
}

static int send_gca_ping_request(DHT *dht, GC_Announce_Node *node, uint64_t ping_id)
{
    uint8_t data[GCA_PING_REQUEST_PLAIN_SIZE];
    data[0] = NET_PACKET_GCA_PING_REQUEST;
    memcpy(data + 1, &ping_id, RAND_ID_SIZE);

    uint8_t packet[GCA_PING_REQUEST_DHT_SIZE];
    int len = wrap_gca_packet(dht_get_self_public_key(dht), dht_get_self_secret_key(dht), node->public_key, packet,
                              sizeof(packet), data, GCA_PING_REQUEST_PLAIN_SIZE, NET_PACKET_GCA_PING_REQUEST);

    if (len == -1) {
        return -1;
    }

    /* insert recipient's public key into packet header after the packet type and dht_pk */
    memmove(packet + 1 + ENC_PUBLIC_KEY + ENC_PUBLIC_KEY, packet + 1 + ENC_PUBLIC_KEY, len - 1 - ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, node->public_key, ENC_PUBLIC_KEY);
    len += ENC_PUBLIC_KEY;

    return sendpacket(dht_get_net(dht), node->ip_port, packet, len);
}

/* Increases rate limit.
 *
 * Returns true if we've hit the rate limit.
 */
static bool gca_rate_limit(GC_Announce *announce)
{
    ++announce->packet_relay_rate;

    return announce->packet_relay_rate >= GCA_RELAY_RATE_LIMIT;
}

/* Keeps track of the rate at which we're sending announce packets.
 *
 * This is very basic and is only used to hinder spam and infinite DHT loops which may be
 * caused by malicious clients or mismatched versions of toxcore.
 */
static void gca_do_rate_limit(GC_Announce *announce)
{
    if (announce->packet_relay_rate == 0) {
        return;
    }

    uint64_t tm = mono_time_get(announce->mono_time);

    if (announce->relay_rate_timer < tm) {
        announce->relay_rate_timer = tm;
        announce->packet_relay_rate /= 2;
    }
}

static void ping_gca_nodes(GC_Announce *announce)
{
    size_t i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
            continue;
        }

        if (announce->announcements[i].self
                || !mono_time_is_timeout(announce->mono_time, announce->announcements[i].last_sent_ping, GCA_PING_INTERVAL)) {
            continue;
        }

        uint64_t ping_id = random_u64();
        announce->announcements[i].ping_id = ping_id;
        announce->announcements[i].last_sent_ping = mono_time_get(announce->mono_time);
        send_gca_ping_request(announce->dht, &announce->announcements[i].node, ping_id);
    }
}

#define SELF_ANNOUNCE_TIMEOUT GCA_NODES_EXPIRATION

/* Checks time of last received ping request for self announces and renews the announcement if necessary */
static void renew_gca_self_announces(GC_Announce *announce)
{
    size_t i;

    for (i = 0; i < MAX_GCA_SELF_ANNOUNCEMENTS; ++i) {
        if (!announce->self_announce[i].is_set) {
            continue;
        }

        if (mono_time_is_timeout(announce->mono_time, announce->self_announce[i].last_rcvd_ping, SELF_ANNOUNCE_TIMEOUT)) {
            announce->self_announce[i].last_rcvd_ping = mono_time_get(announce->mono_time);
            announce->self_announce[i].is_set = false;
            gca_send_announce_request(announce, announce->self_announce[i].self_public_key,
                                      announce->self_announce[i].self_secret_key,
                                      announce->self_announce[i].chat_id);
        }
    }
}

static void check_gca_node_timeouts(GC_Announce *announce)
{
    size_t i;

    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
            continue;
        }

        if (!announce->announcements[i].self
                && mono_time_is_timeout(announce->mono_time, announce->announcements[i].last_rcvd_ping, GCA_NODES_EXPIRATION)) {
            memset(&announce->announcements[i], 0, sizeof(struct GC_AnnouncedNode));
        }
    }
}

void do_gca(GC_Announce *announce)
{
    gca_do_rate_limit(announce);
    ping_gca_nodes(announce);
    check_gca_node_timeouts(announce);
    renew_gca_self_announces(announce);
}

/* Removes peer with public_key in chat_id's group from requests list */
void gca_peer_cleanup(GC_Announce *announce, const uint8_t *chat_id, const uint8_t *peer_pk)
{
    size_t i, j;

    for (i = 0; i < MAX_GCA_SELF_REQUESTS; ++i) {
        if (!(announce->requests[i].ready && announce->requests[i].req_id != 0)) {
            continue;
        }

        if (!chat_id_equal(announce->requests[i].chat_id, chat_id)) {
            continue;
        }

        for (j = 0; j < MAX_GCA_SENT_NODES; ++j) {
            if (id_equal(announce->requests[i].nodes[j].public_key, peer_pk)) {
                memset(&announce->requests[i].nodes[j], 0, sizeof(GC_Announce_Node));
                return;
            }
        }
    }
}

void gca_cleanup(GC_Announce *announce, const uint8_t *chat_id)
{
    size_t i;

    /* Remove self announcements for chat_id */
    for (i = 0; i < MAX_GCA_ANNOUNCED_NODES; ++i) {
        if (announce->announcements[i].self && chat_id_equal(announce->announcements[i].chat_id, chat_id)) {
            memset(&announce->announcements[i], 0, sizeof(struct GC_AnnouncedNode));
        }
    }

    remove_gca_self_announce(announce, chat_id);
}

GC_Announce *new_gca(Mono_Time *mono_time, DHT *dht)
{
    GC_Announce *announce = (GC_Announce *)calloc(1, sizeof(GC_Announce));

    if (announce == nullptr) {
        return nullptr;
    }

    announce->mono_time = mono_time;
    announce->dht = dht;
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_ANNOUNCE, &handle_gca_request, announce);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_GET_NODES, &handle_gc_get_announced_nodes_request,
                               announce);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_SEND_NODES, &handle_gca_get_nodes_response,
                               announce);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_PING_REQUEST, &handle_gca_ping_request, announce);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_PING_RESPONSE, &handle_gca_ping_response,
                               announce);
    return announce;
}

void kill_gca(GC_Announce *announce)
{
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_ANNOUNCE, nullptr, nullptr);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_GET_NODES, nullptr, nullptr);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_SEND_NODES, nullptr, nullptr);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_PING_REQUEST, nullptr, nullptr);
    networking_registerhandler(dht_get_net(announce->dht), NET_PACKET_GCA_PING_RESPONSE, nullptr, nullptr);

    free(announce);
}

#endif /* VANILLA_NACL */
