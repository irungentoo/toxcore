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

#define NET_PACKET_GROUP_CHATS 9 /* WARNING. Temporary measure. */

static int peernumber_valid(const GC_Chat *chat, uint32_t peernumber);
static int groupnumber_valid(const GC_Session* c, int groupnumber);
static int peer_in_chat(const GC_Chat *chat, const uint8_t *client_id);
static int peer_add(Messenger *m, int groupnumber, const GC_GroupPeer *peer);
static void peer_update(GC_Chat *chat, const GC_GroupPeer *peer, uint32_t peernumber);
static int peer_delete(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint16_t length);
static int group_delete(GC_Session* c, GC_Chat *chat);

enum {
    GP_GET_NODES,
    GP_SEND_NODES,
    GP_BROADCAST,
    GP_INVITE_REQUEST,
    GP_INVITE_RESPONSE,
    GP_SYNC_REQUEST,
    GP_SYNC_RESPONSE
} GROUP_PACKET;


/* Shamelessly taken from wikipedia's Jenkins hash function page
 */
static uint32_t calculate_hash(const uint8_t *key, size_t len)
{
    uint32_t hash, i;

    for (hash = i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
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
    int len = decrypt_data(sender_pk, self_sk, nonce,
                           packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES,
                           length - (1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES), plain);
    if (len <= 0) {
        fprintf(stderr, "decrypt failed: packet type: %d, len %d\n", plain[0], len);
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
    int len = encrypt_data(recv_pk, self_sk, nonce, plain, length + 1, encrypt);

    if (len != sizeof(encrypt)) {
        fprintf(stderr, "encrypt failed. packet type: %d, len: %d\n", packet_type, len);
        return -1;
    }

    packet[0] = NET_PACKET_GROUP_CHATS;
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

static int send_gc_self_join(const GC_Chat *chat);

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
    uint32_t num_peers;
    bytes_to_U32(&num_peers, data + len);
    len += sizeof(uint32_t);

    if (num_peers == 0)
        return -1;

    bytes_to_U64(&chat->last_synced_time, data + len);
    len += TIME_STAMP_SIZE;

    uint32_t group_size = sizeof(GC_GroupPeer) * num_peers;
    GC_GroupPeer *peers = calloc(1, group_size);

    if (peers == NULL)
        return -1;

    memcpy(peers, data + len, group_size);
    len += group_size;

    uint32_t i;

    for (i = 0; i < num_peers; i++) {
        int peernum = peer_in_chat(chat, peers[i].client_id);

        if (peernum != -1)
            peer_update(chat, &peers[i], peernum);
        else
            peer_add(m, groupnumber, &peers[i]);
    }

    free(peers);

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

    chat->group[chat->numpeers - 1].ip_port = ipp;     /* The last one is always the sender */
    chat->connection_state = CS_CONNECTED;

    if (send_gc_self_join(chat) == -1) {
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

static void self_to_peer(const GC_Chat *chat, GC_GroupPeer *peer);

static int handle_gc_sync_request(GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, const uint8_t *data,
                                  uint32_t length)
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

    int group_size = sizeof(GC_GroupPeer) * chat->numpeers;
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

    for (i = 0; i < chat->numpeers; i++) {
        if ((chat->group[i].last_update_time > last_synced_time)
            && (!id_long_equal(chat->group[i].client_id, public_key))) {
            memcpy(&peers[num_peers], &chat->group[i], sizeof(GC_GroupPeer));
            ++num_peers;
        }
    }

    /* Add yourself */
    self_to_peer(chat, &peers[num_peers]);
    ++num_peers;

    /* Add: num peers, last synced time, peerlist, topic len, topic, groupname len, groupname */
    U32_to_bytes(response + len, num_peers);
    len += sizeof(uint32_t);
    U64_to_bytes(response + len, chat->last_synced_time);
    len += TIME_STAMP_SIZE;
    memcpy(response + len, peers, sizeof(GC_GroupPeer) * num_peers);
    len += sizeof(GC_GroupPeer) * num_peers;
    U16_to_bytes(response + len, chat->topic_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->topic, chat->topic_len);
    len += chat->topic_len;
    U16_to_bytes(response + len, chat->group_name_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->group_name, chat->group_name_len);
    len += chat->group_name_len;

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

    U16_to_bytes(data + SEMI_INVITE_CERT_SIGNED_SIZE, chat->self_nick_len);
    memcpy(data + SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t), chat->self_nick, chat->self_nick_len);
    uint32_t length = SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t) + chat->self_nick_len + 1;
    memcpy(data + length - 1, &(chat->self_status), sizeof(uint8_t));

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
    if (!id_long_equal(public_key, data + SEMI_INVITE_CERT_SIGNED_SIZE))
        return -1;

    if (data[0] != GC_INVITE)
        return -1;

    /* Verify our own signature */
    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERT_SIGNED_SIZE-SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(chat->self_public_key)) != 0)
        return -1;

    /* Verify inviter signature */
    if (crypto_sign_verify_detached(data + INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(public_key)) != 0)
        return -1;

    memcpy(chat->self_invite_certificate, data, INVITE_CERT_SIGNED_SIZE);

    return gc_send_sync_request(chat, ipp, public_key);
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

    uint8_t  invite_certificate[INVITE_CERT_SIGNED_SIZE];

    if (!id_long_equal(public_key, data + 1))
        return -1;

    if (data[0] != GC_INVITE)
        return -1;

    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_KEY(public_key)) != 0)
        return -1;

    if (sign_certificate(data, SEMI_INVITE_CERT_SIGNED_SIZE, chat->self_secret_key, chat->self_public_key,
                         invite_certificate) == -1)
        return -1;

    /* Adding peer we just invited to the peer group list */
    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

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

    int peernumber = peer_add(m, groupnumber, peer);

    free(peer);

    if (peernumber < 0) {
        fprintf(stderr, "handle_gc_invite_request failed: peernum < 0\n");
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

static int send_gc_ping(const GC_Chat *chat, uint32_t numpeers)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint32_t length;

    data[0] = GM_PING;
    length = 1;

    uint32_t i;

    for (i = 0; i < numpeers; ++i)
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
    data[1] = chat->self_status;

    uint32_t i, length = 2;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_self_status(GC_Chat *chat, uint8_t status_type)
{
    if (status_type >= GS_INVALID)
        return -1;

    chat->self_status = status_type;
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

static int send_gc_self_join(const GC_Chat *chat){

    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    self_to_peer(chat, peer);

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = GM_NEW_PEER;
    memcpy(data + 1, peer, sizeof(GC_GroupPeer));
    uint32_t length = 1 + sizeof(GC_GroupPeer);

    free(peer);

    uint32_t i;

    for (i = 0; i < chat->numpeers; i++) {
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

    if (length != sizeof(GC_GroupPeer)) {
        fprintf(stderr, "handle_gc_new_peer fail! wrong length\n");
        return -1;
    }

    GC_GroupPeer *peer = calloc(1, sizeof(GC_GroupPeer));

    if (peer == NULL)
        return -1;

    memcpy(peer, data, length);

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

    for (i = 0; i < chat->numpeers; ++i) {
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
    memcpy(data + 1, chat->self_nick, chat->self_nick_len);
    uint32_t length = 1 + chat->self_nick_len;

    uint32_t i;

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_self_nick(GC_Chat *chat, const uint8_t *nick, uint16_t length)
{
    if (length == 0)
        return -1;

    if (length > MAX_GC_NICK_SIZE)
        length = MAX_GC_NICK_SIZE;

    memcpy(chat->self_nick, nick, length);
    chat->self_nick_len = length;
    return send_gc_change_nick(chat);
}

/* Return -1 on error
 * Return nick length if success
 */
int gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    memcpy(nick, chat->self_nick, chat->self_nick_len);
    return chat->self_nick_len;
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

int handle_gc_change_nick(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (length > MAX_GC_NICK_SIZE)
        return -1;

    if (c->nick_change)
        (*c->nick_change)(m, groupnumber, peernumber, data, length, c->nick_change_userdata);

    memcpy(chat->group[peernumber].nick, data, length);
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

    for (i = 0; i < chat->numpeers; i++) {
        if (send_gc_broadcast_packet(chat, i, data, length) == -1)
            return -1;
    }

    return 0;
}

int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length)
{
    if (length > MAX_GC_TOPIC_SIZE)
        length = MAX_GC_TOPIC_SIZE;

    if (chat->self_role >= GR_OBSERVER)
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

    if (chat->self_role >= GR_OBSERVER)
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    data[0] = type;
    U64_to_bytes(data + 1, unix_time());
    memcpy(data + 1 + TIME_STAMP_SIZE, message, length);
    length = 1 + TIME_STAMP_SIZE + length;

    uint32_t i;

    for (i = 0; i < chat->numpeers; i++) {
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

    if (chat->self_role >= GR_OBSERVER)
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

    if (chat->self_role > GR_OP)
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

    for (i = 0; i < chat->numpeers; i++) {
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

    chat->group[peernumber].ignore = (bool) ignore;
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
            return handle_gc_message(m, groupnumber, peernumber, dt, len, GM_PLAIN_MESSAGE);
        case GM_ACTION_MESSAGE:
            return handle_gc_message(m, groupnumber, peernumber, dt, len, GM_ACTION_MESSAGE);
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
        fprintf(stderr, "get_chat_by_hash_id failed\n");
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
        case GP_INVITE_REQUEST:
            return handle_gc_invite_request(m, chat->groupnumber, source, sender_pk, data, len);
        case GP_INVITE_RESPONSE:
            return handle_gc_invite_response(chat, source, sender_pk, data, len);
        case GP_SYNC_REQUEST:
            return handle_gc_sync_request(chat, source, sender_pk, data, len);
        case GP_SYNC_RESPONSE:
            return handle_gc_sync_response(m, chat->groupnumber, source, sender_pk, data, len);
        case GP_BROADCAST:
            return handle_gc_broadcast(m, chat->groupnumber, source, sender_pk, data, len);
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
        chat->group[peer1].verified = true;
        return -2;
    }

    chat->group[peer1].verified = false;

    int peer2 = peer_in_chat(chat, inviter_pk);

    if (peer2 == -1)
        return -1;

    if (chat->group[peer2].verified) {
        chat->group[peer1].verified = true;
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
        if (chat->self_role == GR_FOUNDER)
            return -1;

        switch (cert_type) {
            case GC_PROMOTE_OP:
                if (chat->self_role == GR_OP)
                    return -1;

                chat->self_role = GR_OP;
                break;

            case GC_REVOKE_OP:
                if (chat->self_role != GR_OP)
                    return -1;

                chat->self_role = GR_USER;
                break;

            case GC_SILENCE:
                chat->self_role = GR_OBSERVER;
                break;

            case GC_BAN: {
                chat->self_role = GR_BANNED;

                int i;

                for (i = 0; i < chat->numpeers; ++i)
                    peer_delete(m, groupnumber, i, NULL, 0);

                break;
            }

            default:
                return -1;
        }

        memcpy(chat->self_role_certificate, certificate, ROLE_CERT_SIGNED_SIZE);

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
static void self_to_peer(const GC_Chat *chat, GC_GroupPeer *peer)
{
    // NB: we cannot add out ip_port
    memcpy(peer->client_id, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, chat->self_invite_certificate, INVITE_CERT_SIGNED_SIZE);
    memcpy(peer->role_certificate, chat->self_role_certificate, ROLE_CERT_SIGNED_SIZE);
    memcpy(peer->nick, chat->self_nick, chat->self_nick_len);
    peer->nick_len = chat->self_nick_len;
    peer->status = chat->self_status;
    peer->role = chat->self_role;
    peer->last_update_time = unix_time();
}

static void check_peer_timeouts(Messenger *m, int groupnumber)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return;

    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (is_timeout(chat->group[i].last_rcvd_ping, GROUP_PEER_TIMEOUT))
            peer_delete(m, groupnumber, i, (uint8_t *) "Timed out", 9);
    }
}

static void ping_group(GC_Chat *chat)
{
    if (is_timeout(chat->last_sent_ping_time, GROUP_PING_INTERVAL)) {
        // TODO: add validation to send_ping
        send_gc_ping(chat, chat->numpeers);
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
        if (c->chats[i].connection_state == CS_CONNECTED) {
            ping_group(&c->chats[i]);
            check_peer_timeouts(c->messenger, i);

            /* Try to auto-rejoin group if we get disconnected */
            if (is_timeout(c->chats[i].self_last_rcvd_ping, GROUP_SELF_TIMEOUT) && c->chats[i].self_role < GR_BANNED
                && c->chats[i].numpeers > 0) {
                if (c->self_timeout)
                    (*c->self_timeout)(c->messenger, i, c->self_timeout_userdata);

                rejoin_group(c, &c->chats[i]);
            }

            continue;
        }

        if (c->chats[i].connection_state == CS_DISCONNECTED) {
            /* FIXME Max nodes is always 20? */
            GC_Announce_Node nodes[20];
            int rc = gca_get_requested_nodes(c->announce, c->chats[i].chat_public_key, nodes);
            /* Try to join random node */
            if (rc) {
                int n = random_int() % rc;

                if (gc_send_invite_request(&c->chats[i], nodes[n].ip_port, nodes[n].client_id) == -1) {
                    group_delete(c, &c->chats[i]);
                    continue;
                }

                c->chats[i].connection_state = CS_CONNECTING;
            }
        } /* if connection_state is CS_CONNECTING it's waiting for a join response and should do nothing */
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
    credentials->ops->role = GR_FOUNDER;

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

static int create_new_group(GC_Session *c)
{
    // TODO: Need to handle the situation when we load info from locally stored data
    int new_index = get_new_group_index(c);

    if (new_index == -1)
        return -1;

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[new_index];

    memcpy(chat->self_nick, m->name, m->name_length);
    chat->self_nick_len = m->name_length;
    chat->self_status = GS_NONE;
    chat->groupnumber = new_index;
    chat->numpeers = 0;
    chat->last_synced_time = 0; // TODO: delete this later, it's for testing now
    chat->connection_state = CS_DISCONNECTED;
    chat->net = m->net;

    create_long_keypair(chat->self_public_key, chat->self_secret_key);

    return new_index;
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

    int groupnumber = create_new_group(c);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    chat->credentials = new_groupcredentials(chat);

    if (chat->credentials == NULL) {
        group_delete(c, chat);
        return -1;
    }

    memcpy(chat->founder_public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->chat_public_key, chat->credentials->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->group_name, group_name, length);
    memcpy(chat->topic, " ", 1);
    chat->topic_len = 1;
    chat->group_name_len = length;
    chat->connection_state = CS_CONNECTED;
    chat->self_role = GR_FOUNDER;
    chat->hash_id = calculate_hash(chat->chat_public_key, EXT_PUBLIC_KEY);

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
    int groupnumber = create_new_group(c);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    memcpy(chat->chat_public_key, invite_key, EXT_PUBLIC_KEY);

    chat->hash_id = calculate_hash(invite_key, EXT_PUBLIC_KEY);
    chat->self_role = GR_USER;

    if (gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key, invite_key) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return groupnumber;
}

/* Resets and rejoins chat.
 * Saved state includes the chat_public_key, groupnumber, self name and self status.
 *
 * Returns groupnumber on success.
 * Returns -1 on falure.
 */
static int rejoin_group(GC_Session *c, GC_Chat *chat)
{
    GC_Chat new_chat;
    memset(&new_chat, 0, sizeof(GC_Chat));

    memcpy(new_chat.chat_public_key, chat->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(new_chat.self_nick, chat->self_nick, chat->self_nick_len);
    new_chat.self_nick_len = chat->self_nick_len;
    new_chat.self_status = chat->self_status;
    new_chat.hash_id = chat->hash_id;
    new_chat.groupnumber = chat->groupnumber;
    new_chat.self_role = GR_USER;
    new_chat.connection_state = CS_DISCONNECTED;
    create_long_keypair(new_chat.self_public_key, new_chat.self_secret_key);

    memcpy(&c->chats[new_chat.groupnumber], &new_chat, sizeof(GC_Chat));

    if (gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key, chat->chat_public_key) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return chat->groupnumber;
}

void kill_groupcredentials(GC_ChatCredentials *credentials)
{
    if (credentials == NULL)
        return;

    free(credentials->ops);
    free(credentials);
}

GC_Session* new_groupchats(Messenger* m)
{
    GC_Session* c = calloc(sizeof(GC_Session), 1);

    if (c == NULL)
        return NULL;

    c->messenger = m;
    c->announce = new_gca(m->dht);

    if (c->announce == NULL) {
        free(c);
        return NULL;
    }

    networking_registerhandler(m->net, NET_PACKET_GROUP_CHATS, &handle_groupchatpacket, m);
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

    kill_groupcredentials(chat->credentials);

    if (chat->group)
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
    networking_registerhandler(c->messenger->net, NET_PACKET_GROUP_CHATS, NULL, NULL);
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
