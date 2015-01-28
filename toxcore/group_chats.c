/* group_chats.c
 *
 * An implementation of massive text only group chats.
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"
#include "network.h"
#include "group_chats.h"
#include "group_announce.h"
#include "LAN_discovery.h"
#include "util.h"
#include "Messenger.h"

#define GC_INVITE_REQUEST_PLAIN_SIZE SEMI_INVITE_CERT_SIGNED_SIZE
#define GC_INVITE_REQUEST_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

#define GC_INVITE_RESPONSE_PLAIN_SIZE INVITE_CERT_SIGNED_SIZE
#define GC_INVITE_RESPONSE_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

#define HASH_ID_BYTES (sizeof(uint32_t))
#define MIN_GC_PACKET_SIZE (1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES)
#define MAX_GC_PACKET_SIZE 65507

#define GROUP_JOIN_TIMEOUT 10  // TODO: find ideal value
#define GROUP_PING_INTERVAL 40
#define GROUP_PEER_TIMEOUT (GROUP_PING_INTERVAL * 3 + 10)
#define GROUP_SELF_TIMEOUT (GROUP_PEER_TIMEOUT + GROUP_PING_INTERVAL)

/* Group packet ID's */
#define GP_BROADCAST 0
#define GP_INVITE_REQUEST 1
#define GP_INVITE_RESPONSE 2
#define GP_INVITE_RESPONSE_REJECT 3
#define GP_SYNC_REQUEST 4
#define GP_SYNC_RESPONSE 5
#define GP_FRIEND_INVITE 6

static int peernumber_valid(const GC_Chat *chat, uint32_t peernumber);
static int groupnumber_valid(const GC_Session *c, int groupnumber);
static int peer_in_chat(const GC_Chat *chat, const uint8_t *client_id);
static int peer_add(Messenger *m, int groupnumber, const GC_GroupPeer *peer);
static void peer_update(GC_Chat *chat, const GC_GroupPeer *peer, uint32_t peernumber);
static int peer_delete(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint16_t length);
static int group_delete(GC_Session *c, GC_Chat *chat);
static int peer_nick_is_taken(const GC_Chat *chat, const uint8_t *nick, uint16_t length);

/* packs number of peers into data of maxlength length.
 *
 * Return length of packed peers on success.
 * Return -1 on failure.
 */
static int pack_gc_peers(uint8_t *data, uint16_t length, const GC_GroupPeer *peers, uint16_t number)
{
    // TODO: Split the ip_port part into its own function and reuse it with all pack/unpack functions
    uint32_t i, packed_length = 0;

    for (i = 0; i < number; ++i) {
        int ipv6 = -1;
        uint8_t net_family;

        if (peers[i].ip_port.ip.family == AF_INET) {
            ipv6 = 0;
            net_family = TOX_AF_INET;
        } else if (peers[i].ip_port.ip.family == TCP_INET) {
            ipv6 = 0;
            net_family = TOX_TCP_INET;
        } else if (peers[i].ip_port.ip.family == AF_INET6) {
            ipv6 = 1;
            net_family = TOX_AF_INET6;
        } else if (peers[i].ip_port.ip.family == TCP_INET6) {
            ipv6 = 1;
            net_family = TOX_TCP_INET6;
        } else {
            return -1;
        }

        uint32_t size = 0;

        if (ipv6 == 0) {
            size = 1 + sizeof(IP4) + sizeof(uint16_t);

            if (packed_length + size > length)
                return -1;

            data[packed_length] = net_family;
            memcpy(data + packed_length + 1, &peers[i].ip_port.ip.ip4, sizeof(IP4));
            memcpy(data + packed_length + 1 + sizeof(IP4), &peers[i].ip_port.port, sizeof(uint16_t));
            packed_length += size;
        } else if (ipv6 == 1) {
            size = 1 + sizeof(IP6) + sizeof(uint16_t);

            if (packed_length + size > length)
                return -1;

            data[packed_length] = net_family;
            memcpy(data + packed_length + 1, &peers[i].ip_port.ip.ip6, sizeof(IP6));
            memcpy(data + packed_length + 1 + sizeof(IP6), &peers[i].ip_port.port, sizeof(uint16_t));
            packed_length += size;
        } else {
            return -1;
        }

        if (packed_length + sizeof(GC_GroupPeer) - size > length)
            return -1;

        memcpy(data + packed_length, peers[i].client_id, EXT_PUBLIC_KEY);
        packed_length += EXT_PUBLIC_KEY;
        memcpy(data + packed_length, peers[i].invite_certificate, INVITE_CERT_SIGNED_SIZE);
        packed_length += INVITE_CERT_SIGNED_SIZE;
        memcpy(data + packed_length, peers[i].role_certificate, ROLE_CERT_SIGNED_SIZE);
        packed_length += ROLE_CERT_SIGNED_SIZE;
        memcpy(data + packed_length, peers[i].nick, peers[i].nick_len);
        packed_length += MAX_GC_NICK_SIZE;
        U16_to_bytes(data + packed_length, peers[i].nick_len);
        packed_length += sizeof(uint16_t);
        memcpy(data + packed_length, &peers[i].status, sizeof(uint8_t));
        packed_length += sizeof(uint8_t);
        memcpy(data + packed_length, &peers[i].verified, sizeof(uint8_t));
        packed_length += sizeof(uint8_t);
        memcpy(data + packed_length, &peers[i].role, sizeof(uint8_t));
        packed_length += sizeof(uint8_t);
        U64_to_bytes(data + packed_length, peers[i].last_update_time);
        packed_length += sizeof(uint64_t);
        U64_to_bytes(data + packed_length, peers[i].last_rcvd_ping);
        packed_length += sizeof(uint64_t);

        /* don't inherit ignore */
        uint8_t ignore = 0;
        memcpy(data + packed_length, &ignore, sizeof(uint8_t));
        packed_length += sizeof(uint8_t);
    }

    return packed_length;
}

/* Unpack data of length into peers of size max_num_peers.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked peers on success.
 * return -1 on failure.
 */
int unpack_gc_peers(GC_GroupPeer *peers, uint16_t max_num_peers, uint16_t *processed_data_len,
                    const uint8_t *data, uint16_t length, uint8_t tcp_enabled)
{
    uint32_t num = 0, len_processed = 0;

    while (num < max_num_peers && len_processed < length) {
        int ipv6 = -1;
        uint8_t host_family;

        if (data[len_processed] == TOX_AF_INET) {
            ipv6 = 0;
            host_family = AF_INET;
        } else if (data[len_processed] == TOX_TCP_INET) {
            if (!tcp_enabled)
                return -1;

            ipv6 = 0;
            host_family = TCP_INET;
        } else if (data[len_processed] == TOX_AF_INET6) {
            ipv6 = 1;
            host_family = AF_INET6;
        } else if (data[len_processed] == TOX_TCP_INET6) {
            if (!tcp_enabled)
                return -1;

            ipv6 = 1;
            host_family = TCP_INET6;
        } else {
            return -1;
        }

        uint32_t size = 0;

        if (ipv6 == 0) {
            size = 1 + sizeof(IP4) + sizeof(uint16_t);

            if (len_processed + size > length)
                return -1;

            peers[num].ip_port.ip.family = host_family;
            memcpy(&peers[num].ip_port.ip.ip4, data + len_processed + 1, sizeof(IP4));
            memcpy(&peers[num].ip_port.port, data + len_processed + 1 + sizeof(IP4), sizeof(uint16_t));
            len_processed += size;
        } else if (ipv6 == 1) {
            size = 1 + sizeof(IP6) + sizeof(uint16_t);

            if (len_processed + size > length)
                return -1;

            peers[num].ip_port.ip.family = host_family;
            memcpy(&peers[num].ip_port.ip.ip6, data + len_processed + 1, sizeof(IP6));
            memcpy(&peers[num].ip_port.port, data + len_processed + 1 + sizeof(IP6), sizeof(uint16_t));
            len_processed += size;
        } else {
            return -1;
        }

        if (len_processed + sizeof(GC_GroupPeer) - size > length)
            return -1;

        memcpy(peers[num].client_id, data + len_processed, EXT_PUBLIC_KEY);
        len_processed += EXT_PUBLIC_KEY;
        memcpy(peers[num].invite_certificate, data + len_processed, INVITE_CERT_SIGNED_SIZE);
        len_processed += INVITE_CERT_SIGNED_SIZE;
        memcpy(peers[num].role_certificate, data + len_processed, ROLE_CERT_SIGNED_SIZE);
        len_processed += ROLE_CERT_SIGNED_SIZE;
        memcpy(peers[num].nick, data + len_processed, MAX_GC_NICK_SIZE);
        len_processed += MAX_GC_NICK_SIZE;
        bytes_to_U16(&peers[num].nick_len, data + len_processed);
        len_processed += sizeof(uint16_t);
        memcpy(&peers[num].status, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        memcpy(&peers[num].ignore, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        memcpy(&peers[num].verified, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        memcpy(&peers[num].role, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        bytes_to_U64(&peers[num].last_update_time, data + len_processed);
        len_processed += sizeof(uint64_t);
        bytes_to_U64(&peers[num].last_rcvd_ping, data + len_processed);
        len_processed += sizeof(uint64_t);

        ++num;
    }

    if (processed_data_len)
        *processed_data_len = len_processed;

    return num;
}

/* Decrypts data using sender's public key, self secret key and a nonce. */
static int unwrap_group_packet(const uint8_t *self_pk, const uint8_t *self_sk, uint8_t *sender_pk,
                               uint8_t *data, uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_GC_PACKET_SIZE || length > MAX_GC_PACKET_SIZE) {
        fprintf(stderr, "unwrap failed: invalid packet size\n");
        return -1;
    }

    if (id_long_equal(packet + 1 + HASH_ID_BYTES, self_pk)) {
        fprintf(stderr, "unwrap failed: id_long_equal failed\n");
        return -1;
    }

    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, EXT_PUBLIC_KEY);

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY, crypto_box_NONCEBYTES);

    uint8_t plain[MAX_GC_PACKET_SIZE];
    int len = decrypt_data(ENC_KEY(sender_pk), ENC_KEY(self_sk), nonce,
                           packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES,
                           length - (1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES), plain);
    if (len <= 0) {
        fprintf(stderr, "decrypt failed: len %d\n", len);
        return -1;
    }

    *packet_type = plain[0];
    --len;
    memcpy(data, plain + 1, len);
    return len;
}

/* Encrypts data using self secret key, recipient's public key and a new nonce.
 * Adds header consisting of: packet identifier, hash_id, self public key, nonce.
 */
static int wrap_group_packet(const uint8_t *self_pk, const uint8_t *self_sk, const uint8_t *recv_pk, uint8_t *packet,
                             const uint8_t *data, uint32_t length, uint8_t packet_type, uint32_t hash_id)
{
    if (length + MIN_GC_PACKET_SIZE > MAX_GC_PACKET_SIZE)
        return -1;

    uint8_t plain[MAX_GC_PACKET_SIZE];
    plain[0] = packet_type;

    memcpy(plain + 1, data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[1 + length + crypto_box_MACBYTES];
    int len = encrypt_data(ENC_KEY(recv_pk), ENC_KEY(self_sk), nonce, plain, length + 1, encrypt);

    if (len != sizeof(encrypt)) {
        fprintf(stderr, "encrypt failed. packet type: %d, len: %d\n", packet_type, len);
        return -1;
    }

    packet[0] = NET_PACKET_GC_MESSAGE;
    U32_to_bytes(packet + 1, hash_id);
    memcpy(packet + 1 + HASH_ID_BYTES, self_pk, EXT_PUBLIC_KEY);
    memcpy(packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES, encrypt, len);

    return 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + len;
}

/* General function for packet sending */
static int send_groupchatpacket(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                                const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (length == 0)
        return -1;

    if (id_long_equal(chat->self_public_key, public_key))
        return -1;

    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->self_secret_key, public_key, packet, data, length,
                                packet_type, chat->hash_id);
    if (len == -1)
        return -1;

    return sendpacket(chat->net, ip_port, packet, len);
}

static GC_Chat* get_chat_by_hash_id(GC_Session* c, uint32_t hash_id)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; i ++) {
        if (c->chats[i].hash_id == hash_id)
            return &c->chats[i];
    }

    return NULL;
}

static int gc_send_sync_request(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    U64_to_bytes(data + EXT_PUBLIC_KEY, chat->last_synced_time);
    return send_groupchatpacket(chat, ip_port, public_key, data, EXT_PUBLIC_KEY+TIME_STAMP_SIZE, GP_SYNC_REQUEST);
}

static int gc_send_sync_response(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                                 const uint8_t *data, uint32_t length)
{
    return send_groupchatpacket(chat, ip_port, public_key, data, length, GP_SYNC_RESPONSE);
}

static int send_gc_self_join(const GC_Session *c, const GC_Chat *chat);

static int handle_gc_sync_response(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *public_key,
                                   const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!id_long_equal(public_key, data))
        return -1;

    uint32_t len = EXT_PUBLIC_KEY;

    bytes_to_U64(&chat->last_synced_time, data + len);
    len += TIME_STAMP_SIZE;
    bytes_to_U16(&(chat->topic_len), data + len);
    len += sizeof(uint16_t);

    if (chat->topic_len > MAX_GC_TOPIC_SIZE)
        chat->topic_len = MAX_GC_TOPIC_SIZE;

    memcpy(chat->topic, data + len, chat->topic_len);
    len += chat->topic_len;
    bytes_to_U16(&(chat->group_name_len), data + len);
    len += sizeof(uint16_t);

    if (chat->group_name_len > MAX_GC_GROUP_NAME_SIZE)
        chat->group_name_len = MAX_GC_GROUP_NAME_SIZE;

    memcpy(chat->group_name, data + len, chat->group_name_len);
    len += chat->group_name_len;

    uint32_t num_peers;
    bytes_to_U32(&num_peers, data + len);
    len += sizeof(uint32_t);

    if (num_peers == 0 || num_peers > MAX_GROUP_NUM_PEERS)
        return -1;

    uint32_t group_size = sizeof(GC_GroupPeer) * num_peers;
    GC_GroupPeer *peers = calloc(1, group_size);

    if (peers == NULL)
        return -1;

    uint16_t peers_len = 0;
    int unpacked_peers = unpack_gc_peers(peers, num_peers, &peers_len, data + len, group_size, 1);

    if (unpacked_peers != num_peers || peers_len == 0) {
        fprintf(stderr, "unpack peers failed: got %d expected %d\n", unpacked_peers, num_peers);
        return -1;
    }

    len += peers_len;

    uint32_t i;

    for (i = 0; i < num_peers; i++) {
        int peernum = peer_in_chat(chat, peers[i].client_id);

        if (peernum != -1)
            peer_update(chat, &peers[i], peernum);
        else
            peer_add(m, groupnumber, &peers[i]);
    }

    free(peers);

    chat->connection_state = CS_CONNECTED;

    if (send_gc_self_join(m->group_handler, chat) == -1) {
        gc_group_exit(c, chat, NULL, 0);
        return -1;
    }

    gca_send_announce_request(c->announce, chat->self_public_key, chat->self_secret_key, chat->chat_public_key);

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    if (c->self_join)
        (*c->self_join)(m, groupnumber, c->self_join_userdata);

    return 0;
}

/* Returns number of peers */
int gc_get_peernames(const GC_Chat *chat, uint8_t nicks[][MAX_GC_NICK_SIZE], uint16_t lengths[], uint32_t num_peers)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers && i < num_peers; i++) {
        memcpy(nicks[i], chat->group[i].nick, chat->group[i].nick_len);
        lengths[i] = chat->group[i].nick_len;
    }

    return i;
}

int gc_get_numpeers(const GC_Chat *chat)
{
    return chat->numpeers;
}

static int self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer);

static int handle_gc_sync_request(const Messenger *m, GC_Chat *chat, IP_Port ipp, const uint8_t *public_key,
                                  const uint8_t *data, uint32_t length)
{
    if (!id_long_equal(public_key, data))
        return -1;

    // TODO: Check if we know the peer and if peer is verified

    uint8_t response[MAX_GC_PACKET_SIZE];
    memcpy(response, chat->self_public_key, EXT_PUBLIC_KEY);
    uint32_t len = EXT_PUBLIC_KEY;

    uint64_t last_synced_time;
    bytes_to_U64(&last_synced_time, data + len);

    if (last_synced_time > chat->last_synced_time) {
        // TODO: probably we should initiate sync request ourself, cause requester has more fresh info
        uint32_t num_peers = 0;
        U32_to_bytes(response + len, num_peers);
        len += sizeof(uint32_t);
        fprintf(stderr, "handle_gc_sync_request: sync time???\n");
        return gc_send_sync_response(chat, ipp, public_key, response, len);
    }

    /* Add: last synced time, topic len, topic, groupname len, groupname */
    U64_to_bytes(response + len, chat->last_synced_time);
    len += TIME_STAMP_SIZE;
    U16_to_bytes(response + len, chat->topic_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->topic, chat->topic_len);
    len += chat->topic_len;
    U16_to_bytes(response + len, chat->group_name_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->group_name, chat->group_name_len);
    len += chat->group_name_len;

    int group_size = sizeof(GC_GroupPeer) * (chat->numpeers - 1);

    int max_len = EXT_PUBLIC_KEY + TIME_STAMP_SIZE + group_size + sizeof(uint16_t)
                + chat->topic_len + sizeof(uint16_t) + chat->group_name_len;

    /* This is the technical limit to the number of peers you can have in a group.
       Perhaps it could be handled better (TODO: split packet?) */
    if (max_len > MAX_GC_PACKET_SIZE)
        return -1;

    GC_GroupPeer *peers = calloc(1, group_size);

    if (peers == NULL)
        return -1;

    uint32_t i, num_peers = 0;

    if (self_to_peer(m->group_handler, chat, &peers[num_peers++]) == -1) {
        free(peers);
        return -1;
    }

    for (i = 1; i < chat->numpeers; ++i) {
        if ((chat->group[i].last_update_time > last_synced_time)
            && (!id_long_equal(chat->group[i].client_id, public_key))) {
            memcpy(&peers[num_peers++], &chat->group[i], sizeof(GC_GroupPeer));
        }
    }

    U32_to_bytes(response + len, num_peers);
    len += sizeof(uint32_t);

    int peers_len = pack_gc_peers(response + len, sizeof(GC_GroupPeer) * num_peers, peers, num_peers);

    if (peers_len <= 0) {
        fprintf(stderr, "pack_gc_peers failed %d\n", peers_len);
        return -1;
    }

    len += peers_len;
    free(peers);

    return gc_send_sync_response(chat, ipp, public_key, response, len);
}

static int make_invite_cert(const uint8_t *private_key, const uint8_t *public_key, uint8_t *half_certificate);

/* Send invite request with half-signed invite certificate, as well as
 * self state, including your nick length, nick, and status.
 *
 * Return -1 if fail
 * Return 0 if success
 */
static int gc_send_invite_request(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    if (make_invite_cert(chat->self_secret_key, chat->self_public_key, data) == -1)
        return -1;

    U16_to_bytes(data + SEMI_INVITE_CERT_SIGNED_SIZE, chat->group[0].nick_len);
    memcpy(data + SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t), chat->group[0].nick, chat->group[0].nick_len);
    uint32_t length = SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t) + chat->group[0].nick_len + 1;
    memcpy(data + length - 1, &(chat->group[0].status), sizeof(uint8_t));

    return send_groupchatpacket(chat, ip_port, public_key, data, length, GP_INVITE_REQUEST);
}

/* Return -1 if fail
 * Return 0 if succes
 */
static int gc_send_invite_response(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                                   const uint8_t *data, uint32_t length)
{
    return send_groupchatpacket(chat, ip_port, public_key, data, length, GP_INVITE_RESPONSE);
}

/* Return -1 if fail
 * Return 0 if success
 */
static int handle_gc_invite_response(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data,
                                     uint32_t length)
{
    if (!id_long_equal(public_key, data + SEMI_INVITE_CERT_SIGNED_SIZE)) {
        fprintf(stderr, "id_long_equal failed\n");
        return -1;
    }

    if (data[0] != GC_INVITE) {
        fprintf(stderr, "wrong packet type\n");
        return -1;
    }

    /* Verify our own signature */
    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(chat->self_public_key)) != 0) {
        fprintf(stderr, "handle_gc_invite_response sign verify failed (self)\n");
        return -1;
    }

    /* Verify inviter signature */
    if (crypto_sign_verify_detached(data + INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(public_key)) != 0) {
        fprintf(stderr, "handle_gc_invite_response sign verify failed (inviter)\n");
        return -1;
    }

    memcpy(chat->group[0].invite_certificate, data, INVITE_CERT_SIGNED_SIZE);

    return gc_send_sync_request(chat, ipp, public_key);
}

static int handle_gc_invite_response_reject(Messenger *m, int groupnumber, const uint8_t *public_key,
                                            const uint8_t *data, uint32_t length)
{
    if (!id_long_equal(public_key, data))
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (length != EXT_PUBLIC_KEY + 1)
        return -1;

    uint8_t type = data[EXT_PUBLIC_KEY];

    if (type >= GJ_INVALID)
        return -1;

    if (c->rejected)
        (*c->rejected)(m, groupnumber, type, c->rejected_userdata);

    group_delete(c, chat);
    return 0;
}

static int gc_invite_response_reject(const GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, uint8_t type)
{
    uint8_t data[EXT_PUBLIC_KEY + 1];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    data[EXT_PUBLIC_KEY] = type;
    uint32_t length = EXT_PUBLIC_KEY + 1;

    return send_groupchatpacket(chat, ipp, public_key, data, length, GP_INVITE_RESPONSE_REJECT);
}

static int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key,
                            const uint8_t *public_key, uint8_t *certificate);

/* Return -1 if fail
 * Return 0 if success
 */
int handle_gc_invite_request(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *public_key,
                             const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->numpeers >= chat->maxpeers)
        return gc_invite_response_reject(chat, ipp, public_key, GJ_GROUP_FULL);

    uint8_t  invite_certificate[INVITE_CERT_SIGNED_SIZE];

    if (!id_long_equal(public_key, data + 1)) {
        fprintf(stderr, "handle_gc_invite_request id_long_equal failed!\n");
        return -1;
    }

    if (data[0] != GC_INVITE)
        return -1;

    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(public_key)) != 0) {
        fprintf(stderr, "handle_gc_invite_request sign_verify failed!\n");
        return -1;
    }

    if (sign_certificate(data, SEMI_INVITE_CERT_SIGNED_SIZE, chat->self_secret_key, chat->self_public_key,
                         invite_certificate) == -1) {
        fprintf(stderr, "handle_gc_invite_request sign failed!\n");
        return -1;
    }

    /* Adding peer we just invited to the peer group list */
    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL) {
        gc_invite_response_reject(chat, ipp, public_key, GJ_INVITE_FAILED);
        return -1;
    }

    memcpy(peer->client_id, public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, invite_certificate, sizeof(invite_certificate));
    bytes_to_U16(&(peer->nick_len), data + SEMI_INVITE_CERT_SIGNED_SIZE);

    if (peer->nick_len > MAX_GC_NICK_SIZE)
        peer->nick_len = MAX_GC_NICK_SIZE;

    memcpy(peer->nick, data + SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t), peer->nick_len);
    memcpy(&(peer->status), data + SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t) + peer->nick_len, 1);
    peer->role = GR_USER;
    peer->verified = true;
    peer->ip_port = ipp;

    if (peer_nick_is_taken(chat, peer->nick, peer->nick_len)) {
        free(peer);
        return gc_invite_response_reject(chat, ipp, public_key, GJ_NICK_TAKEN);
    }

    if (peer_in_chat(chat, peer->client_id) != -1) {
        free(peer);
        return gc_invite_response_reject(chat, ipp, public_key, GJ_INVITE_FAILED);
    }

    int peernumber = peer_add(m, groupnumber, peer);

    free(peer);

    if (peernumber < 0) {
        fprintf(stderr, "handle_gc_invite_request failed: peernum < 0\n");
        gc_invite_response_reject(chat, ipp, public_key, GJ_INVITE_FAILED);
        return -1;
    }

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    if (c->peer_join)
        (*c->peer_join)(m, groupnumber, peernumber, c->peer_join_userdata);

    return gc_send_invite_response(chat, ipp, public_key, invite_certificate, INVITE_CERT_SIGNED_SIZE);
}

static int send_gc_broadcast_packet(const GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    if (!length || !data)
        return -1;

    if (length + EXT_PUBLIC_KEY > MAX_GC_PACKET_SIZE)
        return -1;

    uint8_t packet[length + EXT_PUBLIC_KEY];
    memcpy(packet, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(packet + EXT_PUBLIC_KEY, data, length);
    length += EXT_PUBLIC_KEY;

    // TODO: send to all peers... Or rather we should make efficient sophisticated routing :)
    // Currently ping_group() and others think that we send only one packet. Change ping_group() in case
    // of this function changing
    return send_groupchatpacket(chat, chat->group[peernumber].ip_port, chat->group[peernumber].client_id,
                                packet, length, GP_BROADCAST);
}

static int send_gc_ping(const GC_Chat *chat)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_PING;
    uint32_t length = 1;

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i)
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;

    return 0;
}

static int handle_gc_ping(Messenger *m, int groupnumber, uint32_t peernumber, IP_Port ipp)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);
    chat->group[peernumber].ip_port = ipp;
    chat->group[peernumber].last_rcvd_ping = unix_time();
    return 0;
}

int send_gc_status(const GC_Chat *chat, uint8_t status_type)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_STATUS;
    data[1] = chat->group[0].status;

    uint32_t i, length = 2;

    for (i = 1; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_self_status(GC_Chat *chat, uint8_t status_type)
{
    if (status_type >= GS_INVALID)
        return -1;

    chat->group[0].status = status_type;
    return send_gc_status(chat, status_type);
}

static int handle_gc_status(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);
    chat->group[peernumber].status = data[0];
    chat->group[peernumber].last_update_time = unix_time();
    return 0;
}

/* Returns peernumber's status.
 * Returns GS_INVALID on failure.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint8_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return GS_INVALID;

    return chat->group[peernumber].status;
}

/* Returns peernumber's group role.
 * Returns GR_INVALID on failure.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint8_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return GR_INVALID;

    return chat->group[peernumber].role;
}

static int send_gc_self_join(const GC_Session *c, const GC_Chat *chat)
{
    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    if (self_to_peer(c, chat, peer) == -1) {
        free(peer);
        return -1;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_NEW_PEER;

    int peers_len = pack_gc_peers(data + 1, sizeof(GC_GroupPeer), peer, 1);

    if (peers_len <= 0) {
        fprintf(stderr, "pack_gc_peers failed in send_gc_self_join %d\n", peers_len);
        return -1;
    }

    free(peer);

    uint32_t length = 1 + peers_len;
    uint32_t i;

    for (i = 1; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

static int verify_cert_integrity(const uint8_t *certificate);

static int handle_gc_new_peer(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    int unpacked_peers = unpack_gc_peers(peer, 1, 0, data, sizeof(GC_GroupPeer), 1);

    if (unpacked_peers != 1) {
        fprintf(stderr, "unpack peers failed in handle_gc_new_peer: got %d expected 1\n", unpacked_peers);
        return -1;
    }

    // TODO: Probably we should make it also optional, but I'm personally against it (c) henotba
    if (verify_cert_integrity(peer->invite_certificate) == -1) {
        free(peer);
        fprintf(stderr, "handle_gc_new_peer fail! verify cert failed\n");
        return -1;
    }

    peer->ip_port = ipp;

    int peernumber = peer_add(m, groupnumber, peer);
    free(peer);

    if (peernumber == -1) {
        fprintf(stderr, "handle_gc_new_peer fail (peernumber == -1)!\n");
        return -1;
    }

    if (peernumber != -2) {
        if (c->peerlist_update)
            (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

        if (c->peer_join)
            (*c->peer_join)(m, groupnumber, peernumber, c->peer_join_userdata);
    }

    return 0;
}

static int send_gc_self_exit(const GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE)
        length = MAX_GC_PART_MESSAGE_SIZE;

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_PEER_EXIT;
    U64_to_bytes(data + 1, unix_time());
    memcpy(data + 1 + TIME_STAMP_SIZE, partmessage, length);
    length = 1 + TIME_STAMP_SIZE + length;

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

static int handle_gc_peer_exit(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                               uint32_t length)
{
    length -= TIME_STAMP_SIZE;

    if (length > MAX_GC_PART_MESSAGE_SIZE)
        length = MAX_GC_PART_MESSAGE_SIZE;

    return peer_delete(m, groupnumber, peernumber, data + TIME_STAMP_SIZE, length);
}

int send_gc_change_nick(const GC_Chat *chat)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    data[0] = GM_CHANGE_NICK;
    memcpy(data + 1, chat->group[0].nick, chat->group[0].nick_len);
    uint32_t length = 1 + chat->group[0].nick_len;

    uint32_t i;

    for (i = 1; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_self_nick(Messenger *m, int groupnumber, const uint8_t *nick, uint16_t length)
{
    if (length == 0)
        return -1;

    if (length > MAX_GC_NICK_SIZE)
        length = MAX_GC_NICK_SIZE;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (peer_nick_is_taken(chat, nick, length))
        return -2;

    memcpy(chat->group[0].nick, nick, length);
    chat->group[0].nick_len = length;

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return send_gc_change_nick(chat);
}

/* Return -1 on error
 * Return nick length if success
 */
int gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    memcpy(nick, chat->group[0].nick, chat->group[0].nick_len);
    return chat->group[0].nick_len;
}

/* Return -1 on error
 * Return nick length if success
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peernumber, uint8_t *namebuffer)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    memcpy(namebuffer, chat->group[peernumber].nick, chat->group[peernumber].nick_len);
    return chat->group[peernumber].nick_len;
}

static int handle_gc_change_nick(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *nick,
                                 uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (length > MAX_GC_NICK_SIZE)
        return -1;

    if (peer_nick_is_taken(chat, nick, length))
        return -1;

    if (c->nick_change)
        (*c->nick_change)(m, groupnumber, peernumber, nick, length, c->nick_change_userdata);

    memcpy(chat->group[peernumber].nick, nick, length);
    chat->group[peernumber].nick_len = length;
    chat->group[peernumber].last_update_time = unix_time();

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return 0;
}

int send_gc_change_topic(const GC_Chat *chat)
{
    uint8_t data[MAX_GC_PACKET_SIZE];

    data[0] = GM_CHANGE_TOPIC;
    memcpy(data + 1, chat->topic, chat->topic_len);
    uint32_t length = 1 + chat->topic_len;

    uint32_t i;

    for (i = 1; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length)
{
    if (length > MAX_GC_TOPIC_SIZE)
        length = MAX_GC_TOPIC_SIZE;

    if (chat->group[0].role >= GR_OBSERVER)
        return -1;

    memcpy(chat->topic, topic, length);
    chat->topic_len = length;
    return send_gc_change_topic(chat);
}

 /* Return topic length. */
int gc_get_topic(const GC_Chat *chat, uint8_t *topicbuffer)
{
    memcpy(topicbuffer, chat->topic, chat->topic_len);
    return chat->topic_len;
}

static int handle_gc_change_topic(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                  uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (length > MAX_GC_TOPIC_SIZE)
        return -1;

    if (chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    // NB: peernumber could be used to verify who is changing the topic in some cases
    memcpy(chat->topic, data, length);
    chat->topic_len = length;

    if (c->topic_change)
        (*c->topic_change)(m, groupnumber, peernumber, data, length, c->topic_change_userdata);

    return 0;
}

/* Returns group_name length */
int gc_get_group_name(const GC_Chat *chat, uint8_t *groupname)
{
    memcpy(groupname, chat->group_name, chat->group_name_len);
    return chat->group_name_len;
}

/* Sends a plain message or an action, depending on type */
int gc_send_message(const GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    if (chat->group[0].role >= GR_OBSERVER)
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = type;
    U64_to_bytes(data + 1, unix_time());
    memcpy(data + 1 + TIME_STAMP_SIZE, message, length);
    length = 1 + TIME_STAMP_SIZE + length;

    uint32_t i;

    for (i = 1; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

static int handle_gc_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                             uint32_t length, uint8_t type)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    length -= TIME_STAMP_SIZE;

    if (type == GM_PLAIN_MESSAGE && c->message) {
        (*c->message)(m, groupnumber, peernumber, data + TIME_STAMP_SIZE, length, c->message_userdata);
    } else if (type == GM_ACTION_MESSAGE && c->action) {
        (*c->action)(m, groupnumber, peernumber, data + TIME_STAMP_SIZE, length, c->action_userdata);
    }

    return 0;
}

int gc_send_private_message(const GC_Chat *chat, uint32_t peernumber, const uint8_t *message, uint16_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (chat->group[0].role >= GR_OBSERVER)
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_PRVT_MESSAGE;
    U64_to_bytes(data + 1, unix_time());
    memcpy(data + 1 + TIME_STAMP_SIZE, message, length);
    length = 1 + TIME_STAMP_SIZE + length;

    if (send_gc_broadcast_packet(chat, peernumber, data, length) == -1)
        return -1;

    return 0;
}

static int handle_gc_private_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                     uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    length -= TIME_STAMP_SIZE;

    if (c->private_message)
        (*c->private_message)(m, groupnumber, peernumber, data + TIME_STAMP_SIZE, length, c->private_message_userdata);

    return 0;
}

static int make_role_cert(const uint8_t *private_key, const uint8_t *public_key, const uint8_t *target_pub_key,
                            uint8_t *certificate, uint8_t cert_type);
/* Return -1 if fail
 * Return 0 if success
 */
int gc_send_op_certificate(const GC_Chat *chat, uint32_t peernumber, uint8_t cert_type)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (chat->group[0].role > GR_OP)
        return -1;

    uint8_t certificate[ROLE_CERT_SIGNED_SIZE];
    if (make_role_cert(chat->self_secret_key, chat->self_public_key, chat->group[peernumber].client_id,
                       certificate, cert_type) == -1)
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_OP_CERTIFICATE;
    memcpy(data + 1, certificate, sizeof(certificate));
    uint32_t length = 1 + ROLE_CERT_SIGNED_SIZE;

    uint32_t i;

    for (i = 1; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

static int process_role_cert(Messenger *m, int groupnumber, const uint8_t *certificate);

static int handle_gc_op_certificate(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (process_role_cert(m, groupnumber, data) == -1)
        return -1;

    uint8_t target_pk[EXT_PUBLIC_KEY];
    memcpy(target_pk, CERT_TARGET_KEY(data), EXT_PUBLIC_KEY);

    int target_peernum = peer_in_chat(chat, target_pk);

    if (target_peernum == -1)
        return -1;

    uint8_t cert_type = data[0];

    if (c->op_certificate)
        (*c->op_certificate)(m, groupnumber, peernumber, target_peernum, cert_type, c->op_certificate_userdata);

    return 0;
}

int gc_toggle_ignore(GC_Chat *chat, uint32_t peernumber, uint8_t ignore)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (ignore != 0 && ignore != 1)
        return -1;

    chat->group[peernumber].ignore = ignore;
    return 0;
}

static int handle_gc_broadcast(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *sender_pk,
                               const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;

    if (!c)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!id_long_equal(sender_pk, data)) {
        fprintf(stderr, "handle broadcast packet failed: id_long_equal\n");
        return -1;
    }

    uint8_t packet_type = data[EXT_PUBLIC_KEY];
    uint32_t len = length - 1 - EXT_PUBLIC_KEY;
    uint8_t dt[len];
    memcpy(dt, data + 1 + EXT_PUBLIC_KEY, len);

    // TODO: Check if peer is verified. Actually we should make it optional
    int peernumber = peer_in_chat(chat, sender_pk);

    if (peernumber == -1 && data[EXT_PUBLIC_KEY] != GM_NEW_PEER)
        return -1;

    switch (packet_type) {
        case GM_PING:
            return handle_gc_ping(m, groupnumber, peernumber, ipp);
        case GM_STATUS:
            return handle_gc_status(m, groupnumber, peernumber, dt, len);
        case GM_NEW_PEER:
            return handle_gc_new_peer(m, groupnumber, ipp, dt, len);
        case GM_CHANGE_NICK:
            return handle_gc_change_nick(m, groupnumber, peernumber, dt, len);
        case GM_CHANGE_TOPIC:
            return handle_gc_change_topic(m, groupnumber, peernumber, dt, len);
        case GM_PLAIN_MESSAGE:
        /* fallthrough */
        case GM_ACTION_MESSAGE:
            return handle_gc_message(m, groupnumber, peernumber, dt, len, packet_type);
        case GM_PRVT_MESSAGE:
            return handle_gc_private_message(m, groupnumber, peernumber, dt, len);
        case GM_OP_CERTIFICATE:
            return handle_gc_op_certificate(m, groupnumber, peernumber, dt, len);
        case GM_PEER_EXIT:
            return handle_gc_peer_exit(m, groupnumber, peernumber, dt, len);
        default:
            return -1;
    }

    return -1;
}

/* If we receive a group chat packet we call this function so it can be handled.
 * return 0 if packet is handled correctly.
 * return -1 if it didn't handle the packet or if the packet was shit.
 */
static int handle_groupchatpacket(void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_GC_PACKET_SIZE || length > MAX_GC_PACKET_SIZE) {
        fprintf(stderr, "invalid packe size\n");
        return -1;
    }

    uint32_t hash_id;
    bytes_to_U32(&hash_id, packet + 1);

    Messenger *m = object;
    GC_Chat* chat = get_chat_by_hash_id(m->group_handler, hash_id);

    if (!chat) {
        fprintf(stderr, "get_chat_by_hash_id failed (type %u)\n", packet[0]);
        return -1;
    }

    chat->self_last_rcvd_ping = unix_time();   /* consider any received packet a keepalive */

    uint8_t sender_pk[EXT_PUBLIC_KEY];
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;

    int len = unwrap_group_packet(chat->self_public_key, chat->self_secret_key, sender_pk, data, &packet_type,
                                  packet, length);
    if (len <= 0)
        return -1;

    switch (packet_type) {
        case GP_BROADCAST:
            return handle_gc_broadcast(m, chat->groupnumber, source, sender_pk, data, len);
        case GP_INVITE_REQUEST:
            return handle_gc_invite_request(m, chat->groupnumber, source, sender_pk, data, len);
        case GP_INVITE_RESPONSE:
            return handle_gc_invite_response(chat, source, sender_pk, data, len);
        case GP_INVITE_RESPONSE_REJECT:
            return handle_gc_invite_response_reject(m, chat->groupnumber, sender_pk, data, len);
        case GP_SYNC_REQUEST:
            return handle_gc_sync_request(m, chat, source, sender_pk, data, len);
        case GP_SYNC_RESPONSE:
            return handle_gc_sync_response(m, chat->groupnumber, source, sender_pk, data, len);
        default:
            return -1;
    }

    return -1;
}

void gc_callback_message(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t,
                         const uint8_t *, uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->message = function;
    c->message_userdata = userdata;
}

void gc_callback_private_message(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t,
                                const uint8_t *, uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->private_message = function;
    c->private_message_userdata = userdata;
}

void gc_callback_action(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t,
                        const uint8_t *, uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->action = function;
    c->action_userdata = userdata;
}

void gc_callback_op_certificate(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t, uint32_t,
                                uint8_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->op_certificate = function;
    c->op_certificate_userdata = userdata;
}

void gc_callback_nick_change(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t,
                             const uint8_t *, uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->nick_change = function;
    c->nick_change_userdata = userdata;
}

void gc_callback_topic_change(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t,
                              const uint8_t *, uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->topic_change = function;
    c->topic_change_userdata = userdata;
}

void gc_callback_peer_join(Messenger *m, void (*function)(Messenger *m, int, uint32_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_join = function;
    c->peer_join_userdata = userdata;
}

void gc_callback_peer_exit(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint32_t,
                           const uint8_t *, uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_exit = function;
    c->peer_exit_userdata = userdata;
}

void gc_callback_self_join(Messenger* m, void (*function)(Messenger *m, int groupnumber, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->self_join = function;
    c->self_join_userdata = userdata;
}

void gc_callback_peerlist_update(Messenger *m, void (*function)(Messenger *m, int groupnumber, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peerlist_update = function;
    c->peerlist_update_userdata = userdata;
}

void gc_callback_self_timeout(Messenger *m, void (*function)(Messenger *m, int groupnumber, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->self_timeout = function;
    c->self_timeout_userdata = userdata;
}

void gc_callback_rejected(Messenger *m, void (*function)(Messenger *m, int groupnumber, uint8_t type, void *),
                          void *userdata)
{
    GC_Session *c = m->group_handler;
    c->rejected = function;
    c->rejected_userdata = userdata;
}

/* Make invite certificate
 * This cert is only half-done, cause it needs to be signed by inviter also
 * Return -1 if fail, 0 if success
 */
static int make_invite_cert(const uint8_t *private_key, const uint8_t *public_key, uint8_t *half_certificate)
{
    uint8_t buf[ROLE_CERT_SIGNED_SIZE];
    buf[0] = GC_INVITE;
    return sign_certificate(buf, 1, private_key, public_key, half_certificate);
}

/* Make role certificate
 * Return -1 if fail, 0 if success
 */
static int make_role_cert(const uint8_t *private_key, const uint8_t *public_key, const uint8_t *target_pub_key,
                          uint8_t *certificate, uint8_t cert_type)
{
    if (cert_type >= GC_INVITE)
        return -1;

    uint8_t buf[ROLE_CERT_SIGNED_SIZE];
    buf[0] = cert_type;
    memcpy(buf + 1, target_pub_key, EXT_PUBLIC_KEY);

    return sign_certificate(buf, 1 + EXT_PUBLIC_KEY, private_key, public_key, certificate);
}

/* Sign a certificate.
 * Add signer public key, time stamp and signature in the end of the data
 * Return -1 if fail, 0 if success
 */
static int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *private_key,
                            const uint8_t *public_key, uint8_t *certificate)
{
    memcpy(certificate, data, length);
    memcpy(certificate + length, public_key, EXT_PUBLIC_KEY);

    U64_to_bytes(certificate + length + EXT_PUBLIC_KEY, unix_time());
    uint32_t mlen = length + EXT_PUBLIC_KEY + TIME_STAMP_SIZE;

    if (crypto_sign_detached(certificate + mlen, NULL, certificate, mlen, SIG_KEY(private_key)) != 0)
        return -1;

    return 0;
}

/* Return -1 if certificate is corrupted
 * Return 0 if certificate is consistent
 */
static int verify_cert_integrity(const uint8_t *certificate)
{
    uint8_t cert_type = certificate[0];

    if (cert_type >= GC_INVALID)
        return -1;

    if (cert_type == GC_INVITE) {
        uint8_t invitee_pk[SIG_PUBLIC_KEY];
        uint8_t inviter_pk[SIG_PUBLIC_KEY];
        memcpy(invitee_pk, SIG_KEY(CERT_INVITEE_KEY(certificate)), SIG_PUBLIC_KEY);
        memcpy(inviter_pk, SIG_KEY(CERT_INVITER_KEY(certificate)), SIG_PUBLIC_KEY);

        if (crypto_sign_verify_detached(certificate + INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                        certificate, INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                        inviter_pk) != 0)
            return -1;

         if (crypto_sign_verify_detached(certificate + SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                         certificate, SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                         invitee_pk) != 0)
            return -1;

    } else {
        uint8_t source_pk[SIG_PUBLIC_KEY];
        memcpy(source_pk, SIG_KEY(CERT_SOURCE_KEY(certificate)), SIG_PUBLIC_KEY);

        if (crypto_sign_verify_detached(certificate + ROLE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                        certificate, ROLE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                        source_pk) != 0)
            return -1;

    }

    return 0;
}

/* Return -1 if we don't know who signed the certificate
 * Return -2 if cert is signed by chat pk, e.g. in case it is the cert founder created for himself
 * Return peer number in other cases
 */
static int process_invite_cert(const GC_Chat *chat, const uint8_t *certificate)
{
    if (certificate[0] != GC_INVITE)
        return -1;

    uint8_t inviter_pk[EXT_PUBLIC_KEY];
    uint8_t invitee_pk[EXT_PUBLIC_KEY];
    memcpy(inviter_pk, CERT_INVITER_KEY(certificate), EXT_PUBLIC_KEY);
    memcpy(invitee_pk, CERT_INVITEE_KEY(certificate), EXT_PUBLIC_KEY);

    int peer1 = peer_in_chat(chat, invitee_pk); // TODO: processing after adding?

    if (peer1 == -1)
        return -1;

    if (id_long_equal(chat->chat_public_key, inviter_pk)) {
        chat->group[peer1].verified = 1;
        return -2;
    }

    chat->group[peer1].verified = 0;

    int peer2 = peer_in_chat(chat, inviter_pk);

    if (peer2 == -1)
        return -1;

    if (chat->group[peer2].verified) {
        chat->group[peer1].verified = 1;
        return peer2;
    }

    return -1;
}

/* Return -1 if cert isn't issued by ops or if target is a founder or we don't know the source
 * Return issuer peer number in other cases
 * Add roles or ban depending on the cert and save the cert in role_cert arrays (works for ourself and peers)
 */
static int process_role_cert(Messenger *m, int groupnumber, const uint8_t *certificate)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    uint8_t cert_type = certificate[0];

    uint8_t source_pk[EXT_PUBLIC_KEY];
    uint8_t target_pk[EXT_PUBLIC_KEY];
    memcpy(source_pk, CERT_SOURCE_KEY(certificate), EXT_PUBLIC_KEY);
    memcpy(target_pk, CERT_TARGET_KEY(certificate), EXT_PUBLIC_KEY);

    int src = peer_in_chat(chat, source_pk);

    if (src == -1)
        return -1;

    /* Issuer is not an OP or founder */
    if (chat->group[src].role > GR_OP)
        return -1;

    /* Check if certificate is for us.
     * Note: Attempts to circumvent certficiates by modifying this code
     * will not have any effect on other peers in the group.
     */
    if (id_long_equal(target_pk, chat->self_public_key)) {
        if (chat->group[0].role == GR_FOUNDER)
            return -1;

        switch (cert_type) {
            case GC_PROMOTE_OP:
                if (chat->group[0].role == GR_OP)
                    return -1;

                chat->group[0].role = GR_OP;
                break;

            case GC_REVOKE_OP:
                if (chat->group[0].role != GR_OP)
                    return -1;

                chat->group[0].role = GR_USER;
                break;

            case GC_SILENCE:
                chat->group[0].role = GR_OBSERVER;
                break;

            case GC_BAN: {
                group_delete(c, chat);
                break;
            }

            default:
                return -1;
        }

        memcpy(chat->group[0].role_certificate, certificate, ROLE_CERT_SIGNED_SIZE);

        return src;
    }

    int trg = peer_in_chat(chat, target_pk);

    if (trg == -1)
        return -1;

    if (chat->group[trg].role == GR_FOUNDER)
        return -1;

    switch (cert_type) {
        case GC_PROMOTE_OP:
            if (chat->group[trg].role == GR_OP)
                return -1;

            chat->group[trg].role = GR_OP;
            break;

        case GC_REVOKE_OP:
            if (chat->group[trg].role != GR_OP)
                return -1;

            chat->group[trg].role = GR_USER;
            break;

        case GC_SILENCE:
            chat->group[trg].role = GR_OBSERVER;
            break;

        case GC_BAN:
            /* TODO: how do we prevent the peer from simply rejoining? */
            peer_delete(m, groupnumber, trg, NULL, 0);
            return src;

        default:
            return -1;
    }

    memcpy(chat->group[trg].role_certificate, certificate, ROLE_CERT_SIGNED_SIZE);
    chat->group[trg].last_update_time = unix_time();

    return src;
}

static int process_chain_trust(GC_Chat *chat)
{
    // TODO !!!??!
    return -1;
}

/* Check if peer with client_id is in peer array.
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 * TODO: make this more efficient.
 */
static int peer_in_chat(const GC_Chat *chat, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (id_long_equal(chat->group[i].client_id, client_id))
            return i;
    }

    return -1;
}

static int peernumber_valid(const GC_Chat *chat, uint32_t peernumber)
{
    return peernumber < chat->numpeers;
}

static int peer_delete(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint16_t length)
{
    GC_Session *c = m->group_handler;

    /* Needs to occur before peer is removed*/
    if (c->peer_exit)
        (*c->peer_exit)(m, groupnumber, peernumber, data, length, c->peer_exit_userdata);

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    --chat->numpeers;

    if (chat->numpeers == 0) {
        free(chat->group);
        chat->group = NULL;

        if (c->peerlist_update)
            (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

        return 0;
    }

    if (chat->numpeers != peernumber)
        memcpy(&chat->group[peernumber], &chat->group[chat->numpeers], sizeof(GC_GroupPeer));

    GC_GroupPeer *temp = realloc(chat->group, sizeof(GC_GroupPeer) * chat->numpeers);

    if (temp == NULL)
        return -1;

    chat->group = temp;

    /* Needs to occur after peer is removed */
    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return 0;
}

/* Add peer to groupnumber's group list.
 *
 * Return peernumber if success.
 * Return -1 if fail.
 * Return -2 if peer is already added
 */
static int peer_add(Messenger *m, int groupnumber, const GC_GroupPeer *peer)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    int peernumber = peer_in_chat(chat, peer->client_id);

    if (peernumber != -1)
        return -2;

    if (peer_nick_is_taken(chat, peer->nick, peer->nick_len))
        return -1;

    GC_GroupPeer *temp = realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (temp == NULL)
        return -1;

    peernumber = chat->numpeers++;
    memcpy(&(temp[peernumber]), peer, sizeof(GC_GroupPeer));

    chat->group = temp;
    chat->group[peernumber].last_rcvd_ping = unix_time();
    chat->group[peernumber].last_update_time = unix_time();

    if (chat->group[peernumber].nick_len > MAX_GC_NICK_SIZE)
        chat->group[peernumber].nick_len = MAX_GC_NICK_SIZE;

    return peernumber;
}

static void peer_update(GC_Chat *chat, const GC_GroupPeer *peer, uint32_t peernumber)
{
    memcpy(&(chat->group[peernumber]), peer, sizeof(GC_GroupPeer));
}

/* Copies own peer data to peer */
static int self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer)
{
    IP_Port self_ipp;
    if (ipport_self_copy(c->messenger->dht, &self_ipp) == -1)
        return -1;

    memcpy(&(peer->ip_port), &self_ipp, sizeof(IP_Port));

    memcpy(peer->client_id, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, chat->group[0].invite_certificate, INVITE_CERT_SIGNED_SIZE);
    memcpy(peer->role_certificate, chat->group[0].role_certificate, ROLE_CERT_SIGNED_SIZE);
    memcpy(peer->nick, chat->group[0].nick, chat->group[0].nick_len);
    peer->nick_len = chat->group[0].nick_len;
    peer->status = chat->group[0].status;
    peer->role = chat->group[0].role;
    peer->last_update_time = unix_time();
}

static void check_peer_timeouts(Messenger *m, int groupnumber)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return;

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (is_timeout(chat->group[i].last_rcvd_ping, GROUP_PEER_TIMEOUT))
            peer_delete(m, groupnumber, i, (uint8_t *) "Timed out", 9);
    }
}

static void ping_group(GC_Chat *chat)
{
    if (is_timeout(chat->last_sent_ping_time, GROUP_PING_INTERVAL)) {
        // TODO: add validation to send_ping
        send_gc_ping(chat);
        chat->last_sent_ping_time = unix_time();
    }
}

static int rejoin_group(GC_Session *c, GC_Chat *chat);

void do_gc(GC_Session *c)
{
    if (!c)
        return;

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];

        if (chat->connection_state == CS_CONNECTED) {
            ping_group(chat);
            check_peer_timeouts(c->messenger, i);

            /* Try to auto-rejoin group if we get disconnected (This won't be necessary with persistent chats) */
            if (is_timeout(chat->self_last_rcvd_ping, GROUP_SELF_TIMEOUT) && chat->numpeers > 1) {
                if (c->self_timeout)
                    (*c->self_timeout)(c->messenger, i, c->self_timeout_userdata);

                rejoin_group(c, chat);
            }
        }

        else if (chat->connection_state == CS_CONNECTING) {
            if (is_timeout(chat->self_last_rcvd_ping, GROUP_JOIN_TIMEOUT)) {
                chat->connection_state = CS_DISCONNECTED;
                chat->self_last_rcvd_ping = unix_time();

                if (gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                               chat->chat_public_key) == -1)
                    group_delete(c, chat);
            }
        }

        else if (chat->connection_state == CS_DISCONNECTED) {
            GC_Announce_Node nodes[MAX_GCA_SELF_REQUESTS];
            int num_nodes = gca_get_requested_nodes(c->announce, chat->chat_public_key, nodes);

            /* Try to join random node */
            if (num_nodes) {
                chat->connection_state = CS_CONNECTING;
                int n = random_int() % num_nodes;

                if (gc_send_invite_request(chat, nodes[n].ip_port, nodes[n].client_id) == -1)
                    group_delete(c, chat);
            }
        }
    }

    do_gca(c->announce);
}

static GC_ChatCredentials *new_groupcredentials(GC_Chat *chat)
{
    GC_ChatCredentials *credentials = malloc(sizeof(GC_ChatCredentials));

    if (credentials == NULL) {
        return NULL;
    }

    create_long_keypair(credentials->chat_public_key, credentials->chat_secret_key);

    credentials->ops = malloc(sizeof(GC_ChatOps));

    if (credentials->ops == NULL) {
        free(credentials);
        return NULL;
    }

    credentials->creation_time = unix_time();
    memcpy(credentials->ops->client_id, chat->self_public_key, EXT_PUBLIC_KEY);

    return credentials;
}

/* Set the size of the groupchat list to n.
 *
 *  return -1 on failure.
 *  return 0 success.
 */
static int realloc_groupchats(GC_Session *c, uint32_t n)
{
    if (n == 0) {
        free(c->chats);
        c->chats = NULL;
        return 0;
    }

    GC_Chat *temp = realloc(c->chats, n * sizeof(GC_Chat));

    if (temp == NULL)
        return -1;

    c->chats = temp;
    return 0;
}

static int get_new_group_index(GC_Session *c)
{
    if (c == NULL)
        return -1;

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state == CS_NONE)
            return i;
    }

    if (realloc_groupchats(c, c->num_chats + 1) != 0)
        return -1;

    int new_index = c->num_chats;
    memset(&(c->chats[new_index]), 0, sizeof(GC_Chat));
    ++c->num_chats;
    return new_index;
}

static int create_new_group(GC_Session *c, bool founder)
{
    // TODO: Need to handle the situation when we load info from locally stored data
    int groupnumber = get_new_group_index(c);

    if (groupnumber == -1)
        return -1;

    Messenger *m = c->messenger;

    GC_Chat *chat = &c->chats[groupnumber];

    chat->groupnumber = groupnumber;
    chat->numpeers = 0;
    chat->last_synced_time = 0; // TODO: delete this later, it's for testing now
    chat->connection_state = CS_DISCONNECTED;
    chat->net = m->net;
    memcpy(chat->topic, " ", 1);
    chat->topic_len = 1;
    chat->maxpeers = MAX_GROUP_NUM_PEERS;
    chat->self_last_rcvd_ping = unix_time();
    chat->last_sent_ping_time = unix_time();

    if (founder) {
        chat->credentials = new_groupcredentials(chat);

        if (chat->credentials == NULL) {
            group_delete(c, chat);
            return -1;
        }
    } else {
        chat->credentials = NULL;
    }

    create_long_keypair(chat->self_public_key, chat->self_secret_key);

    GC_GroupPeer *self = calloc(1, sizeof(GC_GroupPeer));

    if (self == NULL) {
        group_delete(c, chat);
        return -1;
    }

    memcpy(self->nick, m->name, m->name_length);
    self->nick_len = m->name_length;
    self->status = m->userstatus;
    self->role = GR_FOUNDER ? founder : GR_USER;

    if (peer_add(m, groupnumber, self) != 0) {    /* you are always peernumber/index 0 */
        free(self);
        group_delete(c, chat);
        return -1;
    }

    free(self);
    return groupnumber;
}

/* Creates a new group and announces it
 *
 * Return groupnumber on success
 * Return -1 on failure
 */
int gc_group_add(GC_Session *c, const uint8_t *group_name, uint16_t length)
{
    if (length > MAX_GC_GROUP_NAME_SIZE || length == 0)
        return -1;

    int groupnumber = create_new_group(c, true);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    memcpy(chat->chat_public_key, chat->credentials->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->group_name, group_name, length);
    chat->group_name_len = length;
    chat->connection_state = CS_CONNECTED;
    chat->hash_id = jenkins_hash(chat->chat_public_key, EXT_PUBLIC_KEY);

    /* We send announce to the DHT so that everyone can join our chat */
    if (gca_send_announce_request(c->announce, chat->self_public_key, chat->self_secret_key, chat->chat_public_key) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return groupnumber;
}

/* Sends an invite request to an existing group using the invite key
 *
 * Return groupnumber on success.
 * Reutrn -1 on failure.
 */
int gc_group_join(GC_Session *c, const uint8_t *invite_key)
{
    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    memcpy(chat->chat_public_key, invite_key, EXT_PUBLIC_KEY);
    chat->hash_id = jenkins_hash(invite_key, EXT_PUBLIC_KEY);

    if (gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key, invite_key) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return groupnumber;
}

/* Resets and rejoins chat.
 * Saved state includes the chat_public_key, hash_id, groupnumber, self name and self status.
 *
 * Returns groupnumber on success.
 * Returns -1 on falure.
 */
static int rejoin_group(GC_Session *c, GC_Chat *chat)
{
    GC_Chat new_chat;
    memset(&new_chat, 0, sizeof(GC_Chat));

    GC_GroupPeer *oldself = calloc(1, sizeof(GC_GroupPeer));

    if (oldself == NULL) {
        group_delete(c, chat);
        return -1;
    }

    oldself->role = GR_USER;

    if (self_to_peer(c, chat, oldself) == -1) {
        free(oldself);
        group_delete(c, chat);
        return -1;
    }

    memcpy(new_chat.chat_public_key, chat->chat_public_key, EXT_PUBLIC_KEY);
    new_chat.hash_id = chat->hash_id;
    new_chat.groupnumber = chat->groupnumber;
    new_chat.connection_state = CS_DISCONNECTED;
    create_long_keypair(new_chat.self_public_key, new_chat.self_secret_key);

    memcpy(&c->chats[new_chat.groupnumber], &new_chat, sizeof(GC_Chat));

    if (peer_add(c->messenger, new_chat.groupnumber, oldself) != 0) {
        free(oldself);
        group_delete(c, chat);
        return -1;
    }

    free(oldself);

    gca_cleanup(c->announce, chat->chat_public_key);

    if (gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key, chat->chat_public_key) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return chat->groupnumber;
}

/* Invites friendnumber to chat. Packet includes: Type, chat_id, node
 *
 * Return 0 on success.
 * Return -1 on fail.
 */
int gc_invite_friend(GC_Session *c, GC_Chat *chat, int32_t friendnumber)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;

    memcpy(packet + 1, chat->chat_public_key, EXT_PUBLIC_KEY);

    GC_Announce_Node self_node;
    if (make_self_gca_node(c->messenger->dht, &self_node, chat->self_public_key) == -1)
        return -1;

    int node_len = pack_gca_nodes(packet + 1 + EXT_PUBLIC_KEY, sizeof(GC_Announce_Node), &self_node, 1);

    if (node_len <= 0) {
        fprintf(stderr, "pack_gca_nodes failed in gc_invite_friend (%d)\n", node_len);
        return -1;
    }

    uint16_t length = 1 + EXT_PUBLIC_KEY + node_len;
    return send_group_invite_packet(c->messenger, friendnumber, packet, length);
}

/* Joins a group using the invite data received in a friend's group invite.
 *
 * Return groupnumber on success.
 * Return -1 on failure.
 */
int gc_accept_invite(GC_Session *c, const uint8_t *data, uint16_t length)
{
    uint8_t chat_id[EXT_PUBLIC_KEY];
    memcpy(chat_id, data, EXT_PUBLIC_KEY);

    GC_Announce_Node node;
    if (unpack_gca_nodes(&node, 1, 0, data + EXT_PUBLIC_KEY, length - EXT_PUBLIC_KEY, 0) != 1)
        return -1;

    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    memcpy(chat->chat_public_key, chat_id, EXT_PUBLIC_KEY);
    chat->hash_id = jenkins_hash(chat_id, EXT_PUBLIC_KEY);

    if (gc_send_invite_request(chat, node.ip_port, node.client_id) == -1)
        return -1;

    return groupnumber;
}

void kill_groupcredentials(GC_ChatCredentials *credentials)
{
    if (credentials == NULL)
        return;

    free(credentials->ops);
    free(credentials);
}

GC_Session *new_groupchats(Messenger* m)
{
    GC_Session *c = calloc(sizeof(GC_Session), 1);

    if (c == NULL)
        return NULL;

    c->messenger = m;
    c->announce = new_gca(m->dht);

    if (c->announce == NULL) {
        free(c);
        return NULL;
    }

    networking_registerhandler(m->net, NET_PACKET_GC_MESSAGE, &handle_groupchatpacket, m);
    return c;
}

/* Deletes chat from group chat array and cleans up.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int group_delete(GC_Session* c, GC_Chat *chat)
{
    if (c == NULL)
        return -1;

    gca_cleanup(c->announce, chat->chat_public_key);
    kill_groupcredentials(chat->credentials);
    free(chat->group);

    int index = chat->groupnumber;
    memset(&(c->chats[index]), 0, sizeof(GC_Chat));

    uint32_t i;

    for (i = c->num_chats; i > 0; --i) {
        if (c->chats[i-1].connection_state != CS_NONE)
            break;
    }

    if (c->num_chats != i) {
        c->num_chats = i;

        if (realloc_groupchats(c, c->num_chats) != 0)
            return -1;
    }

    return 0;
}

/* Sends parting message to group and deletes group.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length)
{
    send_gc_self_exit(chat, message, length);
    return group_delete(c, chat);
}

void gc_kill_groupchats(GC_Session* c)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state != CS_NONE)
            gc_group_exit(c, &c->chats[i], NULL, 0);
    }

    kill_gca(c->announce);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_MESSAGE, NULL, NULL);
    free(c);
}

/* Return 1 if groupnumber is a valid group chat index
 * Return 0 otherwise
 */
static int groupnumber_valid(const GC_Session* c, int groupnumber)
{
    if (groupnumber < 0 || groupnumber >= c->num_chats)
        return 0;

    if (c->chats == NULL)
        return 0;

    return c->chats[groupnumber].connection_state != CS_NONE;
}

/* Return groupnumber's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session* c, int groupnumber)
{
    if (!groupnumber_valid(c, groupnumber))
        return NULL;

    return &c->chats[groupnumber];
}

/* Return 1 if nick is in use by a group member (including self)
 * Return 0 otherwise
 */
static int peer_nick_is_taken(const GC_Chat *chat, const uint8_t *nick, uint16_t length)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].nick_len == length && memcmp(chat->group[i].nick, nick, length) == 0)
            return 1;
    }

    return 0;
}
