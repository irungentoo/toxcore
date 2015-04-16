/* group_chats.c
 *
 * An implementation of massive text only group chats.
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"
#include "network.h"
#include "group_chats.h"
#include "group_announce.h"
#include "group_connection.h"
#include "LAN_discovery.h"
#include "util.h"
#include "Messenger.h"

#define GC_INVITE_REQUEST_PLAIN_SIZE SEMI_INVITE_CERT_SIGNED_SIZE
#define GC_INVITE_REQUEST_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

#define GC_INVITE_RESPONSE_PLAIN_SIZE INVITE_CERT_SIGNED_SIZE
#define GC_INVITE_RESPONSE_DHT_SIZE (1 + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_INVITE_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

/* Header information attached to all broadcast messages.
 * broadcast_type, public key, timestamp, message_id
 */
#define GC_BROADCAST_ENC_HEADER_SIZE (1 + EXT_PUBLIC_KEY + TIME_STAMP_SIZE)

#define HASH_ID_BYTES (sizeof(uint32_t))
#define MESSAGE_ID_BYTES (sizeof(uint64_t))
#define MIN_GC_PACKET_SIZE (1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + 1 + MESSAGE_ID_BYTES + crypto_box_MACBYTES)
#define MAX_GC_PACKET_SIZE 65507

static int groupnumber_valid(const GC_Session *c, int groupnumber);
static int peer_add(Messenger *m, int groupnumber, GC_GroupPeer *peer, const GC_PeerAddress *addr);
static int group_delete(GC_Session *c, GC_Chat *chat);
static int get_nick_peernumber(const GC_Chat *chat, const uint8_t *nick, uint16_t length);
static int sync_gc_announced_nodes(const GC_Session *c, GC_Chat *chat);

// for debugging
static void print_peer(const GC_GroupPeer *peer)
{
    fprintf(stderr, "ENC PK: %s\n", id_toa(peer->addr.public_key));
    fprintf(stderr, "SIG PK: %s\n", id_toa(SIG_PK(peer->addr.public_key)));
    fprintf(stderr, "IP: %s\n", ip_ntoa(&peer->addr.ip_port.ip));
    fprintf(stderr, "Invite cert: %s\n", id_toa(peer->invite_certificate));
    fprintf(stderr, "Role cert: %s\n", id_toa(peer->role_certificate));
    fprintf(stderr, "Nick: %s\n", peer->nick);
    fprintf(stderr, "Nick len: %u\n", peer->nick_len);
    fprintf(stderr, "Status: %u\n", peer->status);
    fprintf(stderr, "Ignore: %d\n", peer->ignore);
    fprintf(stderr, "Role: %u\n", peer->role);
}

static GC_Chat *get_chat_by_hash(GC_Session *c, uint32_t hash)
{
    if (!c)
        return NULL;

    uint32_t i;

    for (i = 0; i < c->num_chats; i ++) {
        if (c->chats[i].chat_id_hash == hash)
            return &c->chats[i];
    }

    return NULL;
}

/* Check if peer with public_key is in peer array.
 *
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 *
 * TODO: make this more efficient.
 */
static int peer_in_chat(const GC_Chat *chat, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (memcmp(ENC_KEY(chat->group[i].addr.public_key), ENC_KEY(public_key), ENC_PUBLIC_KEY) == 0)
            return i;
    }

    return -1;
}

static bool peernumber_valid(const GC_Chat *chat, int peernumber)
{
    return peernumber >= 0 && peernumber < chat->numpeers;
}

static void self_gc_connected(GC_Chat *chat)
{
    chat->connection_state = CS_CONNECTED;
    chat->group[0].time_connected = unix_time();
}

/* Expands the chat_id into the extended chat public key (encryption key + signature key)
 * dest must have room for EXT_PUBLIC_KEY bytes.
 */
static void expand_chat_id(uint8_t *dest, const uint8_t *chat_id)
{
    crypto_sign_ed25519_pk_to_curve25519(dest, chat_id);
    memcpy(dest + ENC_PUBLIC_KEY, chat_id, SIG_PUBLIC_KEY);
}

/* copies GC_PeerAddress info from src to dest */
static void copy_gc_peer_addr(GC_PeerAddress *dest, const GC_PeerAddress *src)
{
    memcpy(dest, src, sizeof(GC_PeerAddress));
}

/* Copies up to max_addrs peer addresses from chat to addrs.
 *
 * Returns number of addresses copied.
 */
uint16_t gc_copy_peer_addrs(const GC_Chat *chat, GC_PeerAddress *addrs, size_t max_addrs)
{
    uint32_t i;
    uint16_t num = 0;

    for (i = 1; i < chat->numpeers && i < max_addrs; ++i) {
        if (ipport_isset(&chat->group[i].addr.ip_port))
            addrs[num++] = chat->group[i].addr;
    }

    return num;
}

static void clear_gc_addrs_list(GC_Chat *chat)
{
     memset(chat->addr_list, 0, sizeof(GC_PeerAddress) * MAX_GC_PEER_ADDRS);
     chat->addrs_idx = 0;
     chat->num_addrs = 0;
}

/* Updates chat_id's addr_list when we get a nodes request reply from DHT.
 * This will clear previous entries. */
void gc_update_addrs(GC_Announce *announce, const uint8_t *chat_id)
{
    uint32_t chat_id_hash = jenkins_hash(chat_id, CHAT_ID_SIZE);
    GC_Chat *chat = get_chat_by_hash(announce->group_handler, chat_id_hash);

    if (chat == NULL)
        return;

    clear_gc_addrs_list(chat);

    GC_Announce_Node nodes[MAX_GCA_SELF_REQUESTS];
    uint32_t num_nodes = gca_get_requested_nodes(announce, CHAT_ID(chat->chat_public_key), nodes);
    chat->num_addrs = MIN(num_nodes, MAX_GC_PEER_ADDRS);

    if (chat->num_addrs == 0)
        return;

    size_t i;

    for (i = 0; i < chat->num_addrs; ++i) {
        ipport_copy(&chat->addr_list[i].ip_port, &nodes[i].ip_port);
        memcpy(chat->addr_list[i].public_key, nodes[i].public_key, EXT_PUBLIC_KEY);
    }

    /* If we're already connected this is part of the DHT sync procedure */
    if (chat->connection_state == CS_CONNECTED)
        sync_gc_announced_nodes(announce->group_handler, chat);
}

/* Returns number of peers */
uint32_t gc_get_peernames(const GC_Chat *chat, uint8_t nicks[][MAX_GC_NICK_SIZE], uint16_t lengths[],
                          uint32_t num_peers)
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

/* Packs number of peer addresses into data of maxlength length.
 * Note: Only the encryption part of the public key is packed.
 *
 * Return length of packed peer addresses on success.
 * Return -1 on failure.
 */
static int pack_gc_addresses(uint8_t *data, uint16_t length, const GC_PeerAddress *addrs, uint16_t number)
{
    uint32_t i, packed_length = 0;

    for (i = 0; i < number; ++i) {
        int ipp_size = pack_ip_port(data, length, packed_length, &addrs[i].ip_port);

        if (ipp_size == -1)
            return -1;

        packed_length += ipp_size;

        if (packed_length + ENC_PUBLIC_KEY > length)
            return -1;

        memcpy(data + packed_length, ENC_KEY(addrs[i].public_key), ENC_PUBLIC_KEY);
        packed_length += ENC_PUBLIC_KEY;
    }

    return packed_length;
}

/* Unpack data of length into addrs of size max_num_addrs.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked addresses on success.
 * return -1 on failure.
 */
int unpack_gc_addresses(GC_PeerAddress *addrs, uint16_t max_num_addrs, uint16_t *processed_data_len,
                        const uint8_t *data, uint16_t length, uint8_t tcp_enabled)
{
    uint32_t num = 0, len_processed = 0;

    while (num < max_num_addrs && len_processed < length) {
        int ipp_size = unpack_ip_port(&addrs[num].ip_port, len_processed, data, length, tcp_enabled);

        if (ipp_size == -1)
            return -1;

        len_processed += ipp_size;

        if (len_processed + ENC_PUBLIC_KEY > length)
            return -1;

        memcpy(ENC_KEY(addrs[num].public_key), data + len_processed, ENC_PUBLIC_KEY);
        len_processed += ENC_PUBLIC_KEY;
        ++num;
    }

    if (processed_data_len)
        *processed_data_len = len_processed;

    return num;
}

/* Size of peer data that we pack for transfer (does not include variable sizes for IP_Port or nick).
 * packed data includes: signed invite cert, signed role cert, nick length, status, role
 */
#define PACKED_GC_PEER_SIZE (INVITE_CERT_SIGNED_SIZE + ROLE_CERT_SIGNED_SIZE + sizeof(uint16_t)\
                            + sizeof(uint8_t) + sizeof(uint8_t))

/* Packs peer info into data of maxlength length.
 *
 * Return length of packed peer on success.
 * Return -1 on failure.
 */
static int pack_gc_peer(uint8_t *data, uint16_t length, const GC_GroupPeer *peer)
{
    if (PACKED_GC_PEER_SIZE + peer->nick_len > length)
        return -1;

    uint32_t packed_length = 0;

    memcpy(data + packed_length, peer->invite_certificate, INVITE_CERT_SIGNED_SIZE);
    packed_length += INVITE_CERT_SIGNED_SIZE;
    memcpy(data + packed_length, peer->role_certificate, ROLE_CERT_SIGNED_SIZE);
    packed_length += ROLE_CERT_SIGNED_SIZE;
    U16_to_bytes(data + packed_length, peer->nick_len);
    packed_length += sizeof(uint16_t);
    memcpy(data + packed_length, peer->nick, peer->nick_len);
    packed_length += peer->nick_len;
    memcpy(data + packed_length, &peer->status, sizeof(uint8_t));
    packed_length += sizeof(uint8_t);
    memcpy(data + packed_length, &peer->role, sizeof(uint8_t));
    packed_length += sizeof(uint8_t);

    return packed_length;
}

/* Unpacks peer of length info into peer.
 *
 * Returns the length of processed data on success.
 * Returns -1 on failure.
 */
static int unpack_gc_peer(GC_GroupPeer *peer, const uint8_t *data, uint16_t length)
{
    if (PACKED_GC_PEER_SIZE + MAX_GC_NICK_SIZE > length)
        return -1;

    uint32_t len_processed = 0;

    memcpy(peer->invite_certificate, data + len_processed, INVITE_CERT_SIGNED_SIZE);
    len_processed += INVITE_CERT_SIGNED_SIZE;
    memcpy(peer->role_certificate, data + len_processed, ROLE_CERT_SIGNED_SIZE);
    len_processed += ROLE_CERT_SIGNED_SIZE;
    bytes_to_U16(&peer->nick_len, data + len_processed);
    len_processed += sizeof(uint16_t);
    peer->nick_len = MIN(MAX_GC_NICK_SIZE, peer->nick_len);
    memcpy(peer->nick, data + len_processed, peer->nick_len);
    len_processed += peer->nick_len;
    memcpy(&peer->status, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    memcpy(&peer->role, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    return len_processed;
}

/* Decrypts data using sender's public key, self secret key and a nonce. */
static int unwrap_group_packet(const uint8_t *self_pk, const uint8_t *self_sk, uint8_t *sender_pk,
                               uint8_t *data, uint64_t *message_id, uint8_t *packet_type, const uint8_t *packet,
                               uint16_t length)
{
    if (length < MIN_GC_PACKET_SIZE || length > MAX_GC_PACKET_SIZE)
        return -1;

    if (ext_pk_equal(packet + 1 + HASH_ID_BYTES, self_pk)) {
        fprintf(stderr, "unwrap failed: ext_pk_equal failed\n");
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
        fprintf(stderr, "decrypt failed: len %d\n", len);
        return -1;
    }

    *packet_type = plain[0];
    bytes_to_U64(message_id, plain + 1);
    len = len - 1 - MESSAGE_ID_BYTES;
    memcpy(data, plain + 1 + MESSAGE_ID_BYTES, len);

    return len;
}

/* Encrypts data of length using self secret key, recipient's public key and a new nonce.
 *
 * Adds encrypted header consisting of: packet type, message_id
 * Adds plaintext header consisting of: packet identifier, chat_id_hash, self public key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int wrap_group_packet(const uint8_t *self_pk, const uint8_t *self_sk, const uint8_t *recv_pk,
                             uint8_t *packet, const uint8_t *data, uint32_t length, uint64_t message_id,
                             uint8_t packet_type, uint32_t chat_id_hash)
{
    if (length + MIN_GC_PACKET_SIZE > MAX_GC_PACKET_SIZE)
        return -1;

    uint8_t plain[MAX_GC_PACKET_SIZE];
    plain[0] = packet_type;
    U64_to_bytes(plain + 1, message_id);
    memcpy(plain + 1 + MESSAGE_ID_BYTES, data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[1 + MESSAGE_ID_BYTES + length + crypto_box_MACBYTES];
    int len = encrypt_data(recv_pk, self_sk, nonce, plain, length + 1 + MESSAGE_ID_BYTES, encrypt);

    if (len != sizeof(encrypt)) {
        fprintf(stderr, "encrypt failed. packet type: %d, len: %d\n", packet_type, len);
        return -1;
    }

    packet[0] = NET_PACKET_GC_MESSAGE;
    U32_to_bytes(packet + 1, chat_id_hash);
    memcpy(packet + 1 + HASH_ID_BYTES, self_pk, EXT_PUBLIC_KEY);
    memcpy(packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES, encrypt, len);

    return 1 + HASH_ID_BYTES + EXT_PUBLIC_KEY + crypto_box_NONCEBYTES + len;
}

static int send_lossy_group_packet(const GC_Chat *chat, IP_Port ip_port, const uint8_t *public_key,
                                   const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    if (length == 0)
        return -1;

    if (ext_pk_equal(chat->self_public_key, public_key))
        return -1;

    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->self_secret_key, public_key, packet, data, length,
                                0, packet_type, chat->chat_id_hash);
    if (len == -1)
        return -1;

    return sendpacket(chat->net, ip_port, packet, len);
}

static int send_lossless_group_packet(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length,
                                      uint8_t packet_type)
{
    if (!data || length == 0)
        return -1;

    if (ext_pk_equal(chat->self_public_key, chat->group[peernumber].addr.public_key))
        return -1;

    uint64_t message_id = chat->gcc[peernumber].send_message_id;
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->self_secret_key, chat->group[peernumber].addr.public_key,
                                packet, data, length, message_id, packet_type, chat->chat_id_hash);
    if (len == -1) {
        fprintf(stderr, "wrap packet failed %d\n", len);
        return -1;
    }

    if (gcc_add_send_ary(chat, packet, len, peernumber, packet_type) == -1) {
        fprintf(stderr, "add_send_ary failed (type %u)\n", packet_type);
        return -1;
    }

    return sendpacket(chat->net, chat->group[peernumber].addr.ip_port, packet, len);
}

/* Sends a group sync request to peernumber.
 * num_peers should be set to 0 if this is our initial sync request on join.
 */
static int send_gc_sync_request(GC_Chat *chat, uint32_t peernumber, uint32_t num_peers)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    U32_to_bytes(data + EXT_PUBLIC_KEY, num_peers);
    uint32_t length = EXT_PUBLIC_KEY + sizeof(uint32_t);

    return send_lossless_group_packet(chat, peernumber, data, length, GP_SYNC_REQUEST);
}

static int send_gc_sync_response(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, peernumber, data, length, GP_SYNC_RESPONSE);
}

static int send_gc_self_join(const GC_Session *c, GC_Chat *chat);

int handle_gc_sync_response(Messenger *m, int groupnumber, const uint8_t *public_key, const uint8_t *data,
                            uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!ext_pk_equal(public_key, data))
        return -1;

    uint32_t len = EXT_PUBLIC_KEY;

    bytes_to_U16(&(chat->topic_len), data + len);
    len += sizeof(uint16_t);
    chat->topic_len = MIN(MAX_GC_TOPIC_SIZE, chat->topic_len);
    memcpy(chat->topic, data + len, chat->topic_len);
    len += chat->topic_len;
    bytes_to_U16(&(chat->group_name_len), data + len);
    len += sizeof(uint16_t);
    chat->group_name_len = MIN(MAX_GC_GROUP_NAME_SIZE, chat->group_name_len);
    memcpy(chat->group_name, data + len, chat->group_name_len);
    len += chat->group_name_len;

    uint32_t num_peers;
    bytes_to_U32(&num_peers, data + len);
    len += sizeof(uint32_t);

    if (num_peers == 0 || num_peers > MAX_GROUP_NUM_PEERS)
        return -1;

    uint32_t addrs_size = sizeof(GC_PeerAddress) * num_peers;
    GC_PeerAddress *addrs = calloc(1, addrs_size);

    if (addrs == NULL)
        return -1;

    uint16_t addrs_len = 0;
    int unpacked_addrs = unpack_gc_addresses(addrs, num_peers, &addrs_len, data + len, addrs_size, 1);

    if (unpacked_addrs != num_peers || addrs_len == 0) {
        free(addrs);
        fprintf(stderr, "unpack_gc_addresses failed: got %d expected %d\n", unpacked_addrs, num_peers);
        return -1;
    }

    len += addrs_len;

    GC_GroupPeer *peers = calloc(1, sizeof(GC_GroupPeer) * num_peers);

    if (peers == NULL) {
        free(addrs);
        return -1;
    }

    uint32_t i;

    for (i = 0; i < num_peers; i++) {
        if (peer_in_chat(chat, addrs[i].public_key) == -1)
            peer_add(m, groupnumber, &peers[i], &addrs[i]);
    }

    free(addrs);
    free(peers);

    if (send_gc_self_join(m->group_handler, chat) == -1)
        return -1;

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    if (chat->connection_state == CS_CONNECTED)
        return 0;

    if (chat->num_addrs > 0)
        sync_gc_announced_nodes(c, chat);

    self_gc_connected(chat);
    gca_send_announce_request(c->announce, chat->self_public_key, chat->self_secret_key, CHAT_ID(chat->chat_public_key));

    if (c->self_join)
        (*c->self_join)(m, groupnumber, c->self_join_userdata);

    return 0;
}

static void self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer);

int handle_gc_sync_request(const Messenger *m, int groupnumber, const uint8_t *public_key,
                           int peernumber, const uint8_t *data, uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (!ext_pk_equal(public_key, data))
        return -1;

    uint32_t req_num_peers;
    bytes_to_U32(&req_num_peers, data + EXT_PUBLIC_KEY);

    /* Sync request is not necessary */
    if (req_num_peers > 0 && req_num_peers >= chat->numpeers) {
        fprintf(stderr, "sync request from %s rejected\n", chat->group[peernumber].nick);
        return 0;
    }

    uint8_t response[MAX_GC_PACKET_SIZE];
    memcpy(response, chat->self_public_key, EXT_PUBLIC_KEY);
    uint32_t len = EXT_PUBLIC_KEY;

    /* Response packet contains: topic len, topic, groupname len, groupname */
    U16_to_bytes(response + len, chat->topic_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->topic, chat->topic_len);
    len += chat->topic_len;
    U16_to_bytes(response + len, chat->group_name_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->group_name, chat->group_name_len);
    len += chat->group_name_len;

    int peer_addr_size = sizeof(GC_PeerAddress) * (chat->numpeers - 1);

    int max_len = EXT_PUBLIC_KEY + peer_addr_size + sizeof(uint16_t) + chat->topic_len + sizeof(uint16_t)
                  + chat->group_name_len;

    /* This is the technical limit to the number of peers you can have in a group.
       Perhaps it could be handled better (TODO: split packet?) */
    if (max_len > MAX_GC_PACKET_SIZE)
        return -1;

    GC_PeerAddress *peer_addrs = calloc(1, peer_addr_size);

    if (peer_addrs == NULL)
        return -1;

    uint32_t i, num = 0;

    /* must add self separately because reasons */
    GC_PeerAddress self_addr;
    memcpy(&self_addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    ipport_self_copy(m->dht, &self_addr.ip_port);
    copy_gc_peer_addr(&peer_addrs[num++], &self_addr);

    for (i = 1; i < chat->numpeers; ++i) {
        if (!ext_pk_equal(chat->group[i].addr.public_key, public_key) && chat->group[i].confirmed)
            copy_gc_peer_addr(&peer_addrs[num++], &chat->group[i].addr);
    }

    U32_to_bytes(response + len, num);
    len += sizeof(uint32_t);

    int addrs_len = pack_gc_addresses(response + len, sizeof(GC_PeerAddress) * num, peer_addrs, num);
    len += addrs_len;
    free(peer_addrs);

    if (addrs_len <= 0) {
        fprintf(stderr, "pack_gc_addresses failed %d\n", addrs_len);
        return -1;
    }

    return send_gc_sync_response(chat, peernumber, response, len);
}

/* Checks if our peerlist is out of sync with peernumber.
 * Returns true if we set a sync request.
 */
static bool check_gc_sync_status(const GC_Chat *chat, uint32_t peernumber, uint32_t real_num_peers)
{
    if (chat->numpeers >= real_num_peers) {
        chat->group[peernumber].peer_sync_timer = 0;
        return false;
    }

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->group[i].peer_sync_timer != 0)
            return false;
    }

    chat->group[peernumber].peer_sync_timer = unix_time();

    return true;
}

/* Checks if we have a pending sync request with peernumber and sends a sync request
 * if the timer is up.
 */
#define GROUP_PEER_SYNC_TIMER (GROUP_PING_INTERVAL * 2)
static int try_gc_peer_sync(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->group[peernumber].peer_sync_timer == 0)
        return -1;

    if (!is_timeout(chat->group[peernumber].peer_sync_timer, GROUP_PEER_SYNC_TIMER))
        return -1;

    chat->group[peernumber].peer_sync_timer = 0;

    return send_gc_sync_request(chat, peernumber, chat->numpeers);
}

static int send_gc_peer_request(GC_Chat *chat, uint32_t peernumber);

/* Compares our peerlist with our announced nodes and attempts to do a handshake
 * with any nodes that are not in our peerlist.
 *
 * Returns 0 on success.
 * Returns -1 on faillure.
 */
static int sync_gc_announced_nodes(const GC_Session *c, GC_Chat *chat)
{
    GC_GroupPeer self;
    self_to_peer(c, chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    uint32_t len = EXT_PUBLIC_KEY;

    int peers_len = pack_gc_peer(data + len, sizeof(data) - len, &self);
    len += peers_len;

    if (peers_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in sync_gc_announced_nodes %d\n", peers_len);
        return -1;
    }

    uint16_t i;

    for (i = 0; i < chat->num_addrs; ++i) {
        if (peer_in_chat(chat, chat->addr_list[i].public_key) != -1)
            continue;

        GC_GroupPeer tmp_peer;
        memset(&tmp_peer, 0, sizeof(GC_GroupPeer));
        int peernumber = peer_add(c->messenger, chat->groupnumber, &tmp_peer, &chat->addr_list[i]);

        if (peernumber == -1)
            continue;

        send_lossless_group_packet(chat, peernumber, data, len, GP_NEW_PEER);
        send_gc_peer_request(chat, peernumber);
    }

    return 0;
}

/* Returns true if peernumber has reset their connection with us */
static bool peer_connection_was_reset(const GC_Chat *chat, uint32_t peernumber, uint64_t message_id)
{
    return message_id == 1 && chat->group[peernumber].confirmed == true;
}

static int make_invite_cert(const uint8_t *secret_key, const uint8_t *public_key, uint8_t *half_certificate);

/* Send invite request with half-signed invite certificate, as well as
 * self state, including your nick and nick length.
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
    uint32_t length = SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t) + chat->group[0].nick_len;
    return send_lossy_group_packet(chat, ip_port, public_key, data, length, GP_INVITE_REQUEST);
}

/* Return -1 if fail
 * Return 0 if succes
 */
static int gc_send_invite_response(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, peernumber, data, length, GP_INVITE_RESPONSE);
}

/* Return -1 if fail
 * Return 0 if success
 */
static int handle_gc_invite_response(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *public_key,
                                     const uint8_t *data, uint32_t length, uint64_t message_id)
{
    if (message_id != 1)
        return -1;

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state == CS_CONNECTED)
        return -1;

    if (!ext_pk_equal(public_key, data + SEMI_INVITE_CERT_SIGNED_SIZE)) {
        fprintf(stderr, "ext_pk_equal failed\n");
        return -1;
    }

    if (data[0] != GC_INVITE)
        return -1;

    /* Verify our own signature */
    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_PK(chat->self_public_key)) != 0) {
        fprintf(stderr, "handle_gc_invite_response sign verify failed (self)\n");
        return -1;
    }

    /* Verify inviter signature */
    if (crypto_sign_verify_detached(data + INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, SIG_PK(public_key)) != 0) {
        fprintf(stderr, "handle_gc_invite_response sign verify failed (inviter)\n");
        return -1;
    }

    memcpy(chat->group[0].invite_certificate, data, INVITE_CERT_SIGNED_SIZE);
    chat->group[0].verified = true;

    /* Add inviter to peerlist with incomplete info so that we can use a lossless connection */
    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    memcpy(peer.addr.public_key, public_key, EXT_PUBLIC_KEY);
    ipport_copy(&peer.addr.ip_port, &ipp);

    int peernumber = peer_add(m, groupnumber, &peer, NULL);

    if (peernumber == -1) {
        fprintf(stderr, "peer_add failed in handle_invite_response\n");
        return -1;
    }

    chat->group[peernumber].verified = true;

    ++chat->gcc[peernumber].recv_message_id;
    gc_send_message_ack(chat, peernumber, message_id, 0);

    return send_gc_sync_request(chat, peernumber, 0);
}

static int handle_gc_invite_response_reject(Messenger *m, int groupnumber, const uint8_t *public_key,
                                            const uint8_t *data, uint32_t length)
{
    if (!ext_pk_equal(public_key, data))
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state == CS_CONNECTED)
        return -1;

    if (length != EXT_PUBLIC_KEY + 1)
        return -1;

    uint8_t type = data[EXT_PUBLIC_KEY];

    if (type >= GJ_INVALID)
        return -1;

    chat->connection_state = CS_FAILED;

    if (c->rejected)
        (*c->rejected)(m, groupnumber, type, c->rejected_userdata);

    return 0;
}

static int gc_invite_response_reject(const GC_Chat *chat, IP_Port ipp, const uint8_t *public_key, uint8_t type)
{
    uint8_t data[EXT_PUBLIC_KEY + 1];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    data[EXT_PUBLIC_KEY] = type;
    uint32_t length = EXT_PUBLIC_KEY + 1;

    return send_lossy_group_packet(chat, ipp, public_key, data, length, GP_INVITE_RESPONSE_REJECT);
}

static int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *secret_key,
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

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    uint64_t tm = unix_time();

    if (chat->last_peer_join_time == tm)
        return -1;

    chat->last_peer_join_time = tm;

    if (chat->numpeers >= chat->maxpeers)
        return gc_invite_response_reject(chat, ipp, public_key, GJ_GROUP_FULL);

    uint8_t  invite_certificate[INVITE_CERT_SIGNED_SIZE];

    if (!ext_pk_equal(public_key, data + 1)) {
        fprintf(stderr, "handle_gc_invite_request ext_pk_equal failed!\n");
        return -1;
    }

    if (data[0] != GC_INVITE)
        return -1;

    if (crypto_sign_verify_detached(data + SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE, data,
                                    SEMI_INVITE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    SIG_PK(public_key)) != 0) {
        fprintf(stderr, "handle_gc_invite_request sign_verify failed!\n");
        return -1;
    }

    if (sign_certificate(data, SEMI_INVITE_CERT_SIGNED_SIZE, chat->self_secret_key, chat->self_public_key,
                         invite_certificate) == -1) {
        fprintf(stderr, "handle_gc_invite_request sign failed!\n");
        return -1;
    }

    /* Adding peer we just invited to the peer group list. Necessary to create lossless connection */
    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    uint8_t nick[MAX_GC_NICK_SIZE];
    uint16_t nick_len;
    bytes_to_U16(&nick_len, data + SEMI_INVITE_CERT_SIGNED_SIZE);
    nick_len = MIN(nick_len, MAX_GC_NICK_SIZE);

    memcpy(nick, data + SEMI_INVITE_CERT_SIGNED_SIZE + sizeof(uint16_t), nick_len);
    memcpy(peer.addr.public_key, public_key, EXT_PUBLIC_KEY);
    ipport_copy(&peer.addr.ip_port, &ipp);

    if (get_nick_peernumber(chat, nick, nick_len) != -1)
        return gc_invite_response_reject(chat, ipp, public_key, GJ_NICK_TAKEN);

    if (peer_in_chat(chat, peer.addr.public_key) != -1)
        return gc_invite_response_reject(chat, ipp, public_key, GJ_INVITE_FAILED);

    int peernumber = peer_add(m, groupnumber, &peer, NULL);

    if (peernumber == -1) {
        fprintf(stderr, "handle_gc_invite_request failed: peernum < 0\n");
        gc_invite_response_reject(chat, ipp, public_key, GJ_INVITE_FAILED);
        return -1;
    }

    chat->group[peernumber].verified = true;

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return gc_send_invite_response(chat, peernumber, invite_certificate, INVITE_CERT_SIGNED_SIZE);
}

/* Creates packet with broadcast header info followed by data of length.
 * Returns length of packet including header.
 */
static uint32_t make_gc_broadcast_header(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t *packet,
                                         uint8_t bc_type)
{
    uint32_t header_len = EXT_PUBLIC_KEY;
    memcpy(packet, chat->self_public_key, EXT_PUBLIC_KEY);
    packet[header_len] = bc_type;
    header_len += sizeof(uint8_t);
    U64_to_bytes(packet + header_len, unix_time());
    header_len += TIME_STAMP_SIZE;

    if (length > 0)
        memcpy(packet + header_len, data, length);

    return length + header_len;
}

/* sends a group broadcast packet to all peers except self.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_broadcast_packet(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t bc_type)
{
    if (length + GC_BROADCAST_ENC_HEADER_SIZE > MAX_GC_PACKET_SIZE)
        return -1;

    uint8_t packet[length + GC_BROADCAST_ENC_HEADER_SIZE];
    uint32_t packet_len = make_gc_broadcast_header(chat, data, length, packet, bc_type);
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->group[i].confirmed)
            send_lossless_group_packet(chat, i, packet, packet_len, GP_BROADCAST);
    }

    return 0;
}

static int handle_gc_ping(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *sender_pk,
                          int peernumber, const uint8_t *data, uint32_t length)
{
    if (!ext_pk_equal(sender_pk, data))
        return -1;

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (!chat)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (!chat->group[peernumber].verified)
        return -1;

    ipport_copy(&chat->group[peernumber].addr.ip_port, &ipp);
    chat->group[peernumber].last_rcvd_ping = unix_time();

    uint32_t real_num_peers;
    bytes_to_U32(&real_num_peers, data + EXT_PUBLIC_KEY);

    check_gc_sync_status(chat, peernumber, real_num_peers);
    return 0;
}

int gc_set_self_status(GC_Chat *chat, uint8_t status_type)
{
    if (status_type >= GS_INVALID)
        return -1;

    chat->group[0].status = status_type;
    uint8_t data[1];
    data[0] = chat->group[0].status;
    return send_gc_broadcast_packet(chat, data, 1, GM_STATUS);
}

static int handle_bc_change_status(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                   uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (!chat)
        return -1;

    uint8_t status = data[0];

    if (status >= GS_INVALID)
        return -1;

    chat->group[peernumber].status = status;
    chat->group[peernumber].last_update_time = unix_time();

    if (c->status_change)
        (*c->status_change)(m, groupnumber, peernumber, status, c->status_change_userdata);

    return 0;
}

/* Returns peernumber's status.
 * Returns GS_INVALID on failure.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return GS_INVALID;

    return chat->group[peernumber].status;
}

/* Returns peernumber's group role.
 * Returns GR_INVALID on failure.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return GR_INVALID;

    return chat->group[peernumber].role;
}

/* Copies the chat_id to dest */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest)
{
    memcpy(dest, CHAT_ID(chat->chat_public_key), CHAT_ID_SIZE);
}

int handle_gc_peer_request(Messenger *m, int groupnumber, const uint8_t *public_key, int peernumber,
                           const uint8_t *data, uint32_t length)
{
    if (!ext_pk_equal(public_key, data))
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    GC_GroupPeer self;
    self_to_peer(c, chat, &self);

    uint8_t packet[MAX_GC_PACKET_SIZE];
    memcpy(packet, chat->self_public_key, EXT_PUBLIC_KEY);
    uint32_t len = EXT_PUBLIC_KEY;

    int packed_len = pack_gc_peer(packet + len, sizeof(packet) - len, &self);
    len += packed_len;

    if (packed_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in handle_gc_peer_request %d\n", packed_len);
        return -1;
    }

    return send_lossless_group_packet(chat, peernumber, packet, len, GP_NEW_PEER);
}

static int send_gc_peer_request(GC_Chat *chat, uint32_t peernumber)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    uint32_t len = EXT_PUBLIC_KEY;
    return send_lossless_group_packet(chat, peernumber, data, len, GP_PEER_REQUEST);
}

/* Sends self info to all group peers and requests info from all group peers.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_self_join(const GC_Session *c, GC_Chat *chat)
{
    GC_GroupPeer self;
    self_to_peer(c, chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    uint32_t len = EXT_PUBLIC_KEY;

    int peers_len = pack_gc_peer(data + len, sizeof(data) - len, &self);
    len += peers_len;

    if (peers_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in send_gc_self_join %d\n", peers_len);
        return -1;
    }

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (!chat->group[i].confirmed) {
            send_lossless_group_packet(chat, i, data, len, GP_NEW_PEER);
            send_gc_peer_request(chat, i);
        }
    }

    return 0;
}

static int verify_cert_integrity(const uint8_t *certificate);

int handle_gc_new_peer(Messenger *m, int groupnumber, const uint8_t *sender_pk, IP_Port ipp, const uint8_t *data,
                       uint32_t length, uint64_t message_id)
{
    if (!ext_pk_equal(data, sender_pk))
        return -1;

    if (length <= EXT_PUBLIC_KEY)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    if (chat->numpeers >= chat->maxpeers)
        return -1;

    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    if (unpack_gc_peer(&peer, data + EXT_PUBLIC_KEY, sizeof(GC_GroupPeer)) == -1) {
        fprintf(stderr, "unpack_gc_peer failed in handle_bc_new_peer\n");
        return -1;
    }

    // TODO: Probably we should make it also optional, but I'm personally against it (c) henotba
    if (verify_cert_integrity(peer.invite_certificate) == -1) {
        fprintf(stderr, "handle_bc_new_peer fail! verify cert failed\n");
        return -1;
    }

    if (peer.nick_len == 0)
        return -1;

    ipport_copy(&peer.addr.ip_port, &ipp);
    memcpy(peer.addr.public_key, sender_pk, EXT_PUBLIC_KEY);

    int peer_exists = peer_in_chat(chat, sender_pk);
    int peernumber = peer_add(m, groupnumber, &peer, NULL);

    if (peernumber == -1) {
        if (peer_exists != -1)
            chat->group[peer_exists].confirmed = false;

        fprintf(stderr, "handle_bc_new_peer failed (peernumber == -1)!\n");
        return -1;
    }

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    if (c->peer_join && !chat->group[peernumber].confirmed
        && chat->group[0].time_connected != chat->group[peernumber].time_connected)
        (*c->peer_join)(m, groupnumber, peernumber, c->peer_join_userdata);

    /* this is a handshake packet */
    if (peer_exists == -1) {
        gc_send_message_ack(chat, peernumber, message_id, 0);
        ++chat->gcc[peernumber].recv_message_id;
    }
    /* If peer has reset their connection with us we must do the same in order to re-sync */
    else if (peer_connection_was_reset(chat, peernumber, message_id)) {
        gcc_peer_cleanup(&chat->gcc[peernumber]);
        gc_send_message_ack(chat, peernumber, message_id, 0);
        ++chat->gcc[peernumber].recv_message_id;
    }

    chat->group[peernumber].verified = true;
    chat->group[peernumber].confirmed = true;

    return 0;
}

static int send_gc_self_exit(GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE)
        length = MAX_GC_PART_MESSAGE_SIZE;

    return send_gc_broadcast_packet(chat, partmessage, length, GM_PEER_EXIT);
}

static int handle_bc_peer_exit(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                               uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE)
        length = MAX_GC_PART_MESSAGE_SIZE;

    return gc_peer_delete(m, groupnumber, peernumber, data, length);
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

    if (get_nick_peernumber(chat, nick, length) != -1)
        return -2;

    memcpy(chat->group[0].nick, nick, length);
    chat->group[0].nick_len = length;

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return send_gc_broadcast_packet(chat, nick, length, GM_CHANGE_NICK);
}

/* Return nick length */
uint16_t gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    memcpy(nick, chat->group[0].nick, chat->group[0].nick_len);
    return chat->group[0].nick_len;
}

/* Return your own nick length */
uint16_t gc_get_self_nick_size(const GC_Chat *chat)
{
    return chat->group[0].nick_len;
}

/* Return your own group role */
uint8_t gc_get_self_role(const GC_Chat *chat)
{
    return chat->group[0].role;
}

/* Return your own status */
uint8_t gc_get_self_status(const GC_Chat *chat)
{
    return chat->group[0].status;
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

/* Return -1 on error
 * Return nick length if success
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    return chat->group[peernumber].nick_len;
}

static int handle_bc_change_nick(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *nick,
                                 uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    /* This shouldn't happen; if it does we need to refresh this peer's info */
    if (length > MAX_GC_NICK_SIZE || get_nick_peernumber(chat, nick, length) != -1) {
        chat->group[peernumber].confirmed = false;
        return send_gc_peer_request(chat, peernumber);
    }

    if (c->nick_change)
        (*c->nick_change)(m, groupnumber, peernumber, nick, length, c->nick_change_userdata);

    memcpy(chat->group[peernumber].nick, nick, length);
    chat->group[peernumber].nick_len = length;
    chat->group[peernumber].last_update_time = unix_time();

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

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

    return send_gc_broadcast_packet(chat, topic, length, GM_CHANGE_TOPIC);
}

 /* Return topic length. */
int gc_get_topic(const GC_Chat *chat, uint8_t *topicbuffer)
{
    memcpy(topicbuffer, chat->topic, chat->topic_len);
    return chat->topic_len;
}

 /* Return topic length. */
uint16_t gc_get_topic_size(const GC_Chat *chat)
{
    return chat->topic_len;
}

static int handle_bc_change_topic(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
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

/* Returns group_name length */
uint16_t gc_get_group_name_size(const GC_Chat *chat)
{
    return chat->group_name_len;
}

/* Sends a plain message or an action, depending on type */
int gc_send_message(GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    if (chat->group[0].role >= GR_OBSERVER)
        return -1;

    return send_gc_broadcast_packet(chat, message, length, type);
}

static int handle_bc_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
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

    if (type == GM_PLAIN_MESSAGE && c->message) {
        (*c->message)(m, groupnumber, peernumber, data, length, c->message_userdata);
    } else if (type == GM_ACTION_MESSAGE && c->action) {
        (*c->action)(m, groupnumber, peernumber, data, length, c->action_userdata);
    }

    return 0;
}

int gc_send_private_message(GC_Chat *chat, uint32_t peernumber, const uint8_t *message, uint16_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (chat->group[0].role >= GR_OBSERVER)
        return -1;

    uint8_t packet[length + GC_BROADCAST_ENC_HEADER_SIZE];
    uint32_t packet_len = make_gc_broadcast_header(chat, message, length, packet, GM_PRVT_MESSAGE);

    return send_lossless_group_packet(chat, peernumber, packet, packet_len, GP_BROADCAST);
}

static int handle_bc_private_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                     uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    if (c->private_message)
        (*c->private_message)(m, groupnumber, peernumber, data, length, c->private_message_userdata);

    return 0;
}

static int make_role_cert(const uint8_t *secret_key, const uint8_t *public_key, const uint8_t *target_pub_key,
                          uint8_t *certificate, uint8_t cert_type);
/* Return -1 if fail
 * Return 0 if success
 */
int gc_send_op_certificate(GC_Chat *chat, uint32_t peernumber, uint8_t cert_type)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (chat->group[0].role > GR_OP)
        return -1;

    uint8_t certificate[ROLE_CERT_SIGNED_SIZE];
    if (make_role_cert(chat->self_secret_key, chat->self_public_key, chat->group[peernumber].addr.public_key,
                       certificate, cert_type) == -1)
        return -1;

    return send_gc_broadcast_packet(chat, certificate, ROLE_CERT_SIGNED_SIZE, GM_OP_CERTIFICATE);

}

static int process_role_cert(Messenger *m, int groupnumber, const uint8_t *certificate);

static int handle_bc_op_certificate(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
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

#define VALID_GC_MESSAGE_ACK(a, b) (((a) == 0) || ((b) == 0))

/* If read_id is non-zero sends a read-receipt for read_id's packet.
 * If request_id is non-zero sends a request for the respective id's packet.
 */
int gc_send_message_ack(const GC_Chat *chat, uint32_t peernum, uint64_t read_id, uint64_t request_id)
{
    if (!VALID_GC_MESSAGE_ACK(read_id, request_id))
        return -1;

    uint8_t data[EXT_PUBLIC_KEY + MESSAGE_ID_BYTES + MESSAGE_ID_BYTES];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    U64_to_bytes(data + EXT_PUBLIC_KEY, read_id);
    U64_to_bytes(data + EXT_PUBLIC_KEY + MESSAGE_ID_BYTES, request_id);
    uint32_t length = EXT_PUBLIC_KEY + MESSAGE_ID_BYTES + MESSAGE_ID_BYTES;

    return send_lossy_group_packet(chat, chat->group[peernum].addr.ip_port, chat->group[peernum].addr.public_key,
                                   data, length, GP_MESSAGE_ACK);
}

/* If packet contains a non-zero request_id we try to resend its respective packet.
 * If packet contains a non-zero read_id we remove the packet from our send array.
 *
 * Return -1 if error or we fail to send a packet in case of a request response.
 */
static int handle_gc_message_ack(GC_Chat *chat, const uint8_t *sender_pk, int peernumber,
                                 const uint8_t *data, uint32_t length)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (!ext_pk_equal(sender_pk, data))
        return -1;

    uint64_t read_id, request_id;
    bytes_to_U64(&read_id, data + EXT_PUBLIC_KEY);
    bytes_to_U64(&request_id, data + EXT_PUBLIC_KEY + MESSAGE_ID_BYTES);

    if (!VALID_GC_MESSAGE_ACK(read_id, request_id))
        return -1;

    if (read_id > 0)
        return gcc_handle_ack(&chat->gcc[peernumber], read_id);

    /* re-send requested packet */
    GC_Connection *gconn = &chat->gcc[peernumber];
    uint64_t tm = unix_time();
    uint16_t idx = get_ary_index(request_id);

    if (gconn->send_ary[idx].message_id == request_id
        && (gconn->send_ary[idx].last_send_try != tm || gconn->send_ary[idx].time_added == tm)) {
        gconn->send_ary[idx].last_send_try = tm;
        return sendpacket(chat->net, chat->group[peernumber].addr.ip_port, gconn->send_ary[idx].data, gconn->send_ary[idx].data_length);
    }

    return -1;
}

int gc_toggle_ignore(GC_Chat *chat, uint32_t peernumber, uint8_t ignore)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (ignore > 1)
        return -1;

    chat->group[peernumber].ignore = ignore;
    return 0;
}

int handle_gc_broadcast(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *sender_pk, int peernumber,
                        const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;

    if (!c)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (!ext_pk_equal(sender_pk, data))
        return -1;

    uint8_t broadcast_type = data[EXT_PUBLIC_KEY];

    if (!chat->group[peernumber].confirmed)
        return -1;

    uint64_t timestamp;
    bytes_to_U64(&timestamp, data + 1);

    uint32_t m_len = length - GC_BROADCAST_ENC_HEADER_SIZE;
    uint8_t message[m_len];
    memcpy(message, data + GC_BROADCAST_ENC_HEADER_SIZE, m_len);

    switch (broadcast_type) {
        case GM_STATUS:
            return handle_bc_change_status(m, groupnumber, peernumber, message, m_len);
        case GM_CHANGE_NICK:
            return handle_bc_change_nick(m, groupnumber, peernumber, message, m_len);
        case GM_CHANGE_TOPIC:
            return handle_bc_change_topic(m, groupnumber, peernumber, message, m_len);
        case GM_PLAIN_MESSAGE:
        /* fallthrough */
        case GM_ACTION_MESSAGE:
            return handle_bc_message(m, groupnumber, peernumber, message, m_len, broadcast_type);
        case GM_PRVT_MESSAGE:
            return handle_bc_private_message(m, groupnumber, peernumber, message, m_len);
        case GM_OP_CERTIFICATE:
            return handle_bc_op_certificate(m, groupnumber, peernumber, message, m_len);
        case GM_PEER_EXIT:
            return handle_bc_peer_exit(m, groupnumber, peernumber, message, m_len);
        default:
            fprintf(stderr, "Warning: handle_gc_broadcast received an invalid broadcast type %u\n", broadcast_type);
            return -1;
    }

    return -1;
}

/* If we receive a group chat packet we call this function so it can be handled.
 * return non-negative value if packet is handled correctly.
 * return -1 if it didn't handle the packet or if the packet was shit.
 */
static int handle_groupchatpacket(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_GC_PACKET_SIZE || length > MAX_GC_PACKET_SIZE)
        return -1;

    uint32_t chat_id_hash;
    bytes_to_U32(&chat_id_hash, packet + 1);

    Messenger *m = object;
    GC_Chat* chat = get_chat_by_hash(m->group_handler, chat_id_hash);

    if (!chat) {
        fprintf(stderr, "get_chat_by_hash failed (type %u)\n", packet[0]);
        return -1;
    }

    uint8_t sender_pk[EXT_PUBLIC_KEY];
    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;
    uint64_t message_id;

    int len = unwrap_group_packet(chat->self_public_key, chat->self_secret_key, sender_pk, data,
                                  &message_id, &packet_type, packet, length);
    if (len <= 0)
        return -1;

    chat->self_last_rcvd_ping = unix_time();   /* consider any received packet a keepalive */

    int lossless = -1;
    int peernumber = peer_in_chat(chat, sender_pk);

    /* Handle a lossless packet.
     *
     * peernumber may be -1 for lossless GP_NEW_PEER and GP_INVITE_RESPONSE packets
     * which act like a handshake. These are acked immediately in their respective handlers.
     * If peernumber has reset our connection we reset theirs and ack immediately.
     */
    if (peernumber >= 0 && LOSSLESS_PACKET(packet_type) && !peer_connection_was_reset(chat, peernumber, message_id)) {
        lossless = gcc_handle_recv_message(chat, peernumber, data, len, packet_type, message_id);

        if (lossless == -1)
            return -1;

        /* Duplicate packet */
        if (lossless == 0)
            return gc_send_message_ack(chat, peernumber, message_id, 0);

        /* request missing packet */
        if (lossless == 1)
            return gc_send_message_ack(chat, peernumber, 0, chat->gcc[peernumber].recv_message_id + 1);
    }

    int ret = -1;

    switch (packet_type) {
        case GP_BROADCAST:
            ret = handle_gc_broadcast(m, chat->groupnumber, ipp, sender_pk, peernumber, data, len);
            break;
        case GP_MESSAGE_ACK:
            ret = handle_gc_message_ack(chat, sender_pk, peernumber, data, len);
            break;
        case GP_PING:
            ret = handle_gc_ping(m, chat->groupnumber, ipp, sender_pk, peernumber, data, len);
            break;
        case GP_INVITE_REQUEST:
            ret = handle_gc_invite_request(m, chat->groupnumber, ipp, sender_pk, data, len);
            break;
        case GP_INVITE_RESPONSE:
            ret = handle_gc_invite_response(m, chat->groupnumber, ipp, sender_pk, data, len, message_id);
            break;
        case GP_INVITE_RESPONSE_REJECT:
            ret = handle_gc_invite_response_reject(m, chat->groupnumber, sender_pk, data, len);
            break;
        case GP_SYNC_REQUEST:
            ret = handle_gc_sync_request(m, chat->groupnumber, sender_pk, peernumber, data, len);
            break;
        case GP_SYNC_RESPONSE:
            ret = handle_gc_sync_response(m, chat->groupnumber, sender_pk, data, len);
            break;
        case GP_NEW_PEER:
            ret = handle_gc_new_peer(m, chat->groupnumber, sender_pk, ipp, data, len, message_id);
            break;
        case GP_PEER_REQUEST:
            ret = handle_gc_peer_request(m, chat->groupnumber, sender_pk, peernumber, data, length);
            break;
    }

    if (lossless == 2 && ret != -1 && peernumber_valid(chat, peernumber)) {
        gc_send_message_ack(chat, peernumber, message_id, 0);
        gcc_check_recv_ary(m, chat->groupnumber, peernumber);
    }

    return ret;
}

void gc_callback_message(Messenger *m, void (*function)(Messenger *m, int, uint32_t, const uint8_t *, uint16_t,
                         void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->message = function;
    c->message_userdata = userdata;
}

void gc_callback_private_message(Messenger *m, void (*function)(Messenger *m, int, uint32_t, const uint8_t *,
                                 uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->private_message = function;
    c->private_message_userdata = userdata;
}

void gc_callback_action(Messenger *m, void (*function)(Messenger *m, int, uint32_t, const uint8_t *, uint16_t,
                        void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->action = function;
    c->action_userdata = userdata;
}

void gc_callback_op_certificate(Messenger *m, void (*function)(Messenger *m, int, uint32_t, uint32_t, uint8_t,
                               void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->op_certificate = function;
    c->op_certificate_userdata = userdata;
}

void gc_callback_nick_change(Messenger *m, void (*function)(Messenger *m, int, uint32_t, const uint8_t *,
                             uint16_t, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->nick_change = function;
    c->nick_change_userdata = userdata;
}

void gc_callback_status_change(Messenger *m, void (*function)(Messenger *m, int, uint32_t, uint8_t, void *),
                               void *userdata)
{
    GC_Session *c = m->group_handler;
    c->status_change = function;
    c->status_change_userdata = userdata;
}

void gc_callback_topic_change(Messenger *m, void (*function)(Messenger *m, int, uint32_t, const uint8_t *,
                              uint16_t, void *), void *userdata)
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

void gc_callback_peer_exit(Messenger *m, void (*function)(Messenger *m, int, uint32_t, const uint8_t *, uint16_t,
                           void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_exit = function;
    c->peer_exit_userdata = userdata;
}

void gc_callback_self_join(Messenger* m, void (*function)(Messenger *m, int, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->self_join = function;
    c->self_join_userdata = userdata;
}

void gc_callback_peerlist_update(Messenger *m, void (*function)(Messenger *m, int, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peerlist_update = function;
    c->peerlist_update_userdata = userdata;
}

void gc_callback_rejected(Messenger *m, void (*function)(Messenger *m, int, uint8_t type, void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->rejected = function;
    c->rejected_userdata = userdata;
}

/* Make invite certificate
 * This cert is only half-done, cause it needs to be signed by inviter also
 * Return -1 if fail, 0 if success
 */
static int make_invite_cert(const uint8_t *secret_key, const uint8_t *public_key, uint8_t *half_certificate)
{
    uint8_t buf[ROLE_CERT_SIGNED_SIZE];
    buf[0] = GC_INVITE;
    return sign_certificate(buf, 1, secret_key, public_key, half_certificate);
}

/* Make role certificate
 * Return -1 if fail, 0 if success
 */
static int make_role_cert(const uint8_t *secret_key, const uint8_t *public_key, const uint8_t *target_pub_key,
                          uint8_t *certificate, uint8_t cert_type)
{
    if (cert_type >= GC_INVITE)
        return -1;

    uint8_t buf[ROLE_CERT_SIGNED_SIZE];
    buf[0] = cert_type;
    memcpy(buf + 1, target_pub_key, EXT_PUBLIC_KEY);

    return sign_certificate(buf, 1 + EXT_PUBLIC_KEY, secret_key, public_key, certificate);
}

/* Sign a certificate.
 * Add signer public key, time stamp and signature in the end of the data
 * Return -1 if fail, 0 if success
 */
static int sign_certificate(const uint8_t *data, uint32_t length, const uint8_t *secret_key,
                            const uint8_t *public_key, uint8_t *certificate)
{
    memcpy(certificate, data, length);
    memcpy(certificate + length, public_key, EXT_PUBLIC_KEY);
    U64_to_bytes(certificate + length + EXT_PUBLIC_KEY, unix_time());
    uint32_t mlen = length + EXT_PUBLIC_KEY + TIME_STAMP_SIZE;

    if (crypto_sign_detached(certificate + mlen, NULL, certificate, mlen, SIG_SK(secret_key)) != 0)
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
        memcpy(invitee_pk, SIG_PK(CERT_INVITEE_KEY(certificate)), SIG_PUBLIC_KEY);
        memcpy(inviter_pk, SIG_PK(CERT_INVITER_KEY(certificate)), SIG_PUBLIC_KEY);

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
        memcpy(source_pk, SIG_PK(CERT_SOURCE_KEY(certificate)), SIG_PUBLIC_KEY);

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
 * TODO: update this function with new chat_id size and make it actually work
 */
static int process_invite_cert(const GC_Chat *chat, const uint8_t *certificate)
{
    return -1;

    if (certificate[0] != GC_INVITE)
        return -1;

    uint8_t inviter_pk[EXT_PUBLIC_KEY];
    uint8_t invitee_pk[EXT_PUBLIC_KEY];
    memcpy(inviter_pk, CERT_INVITER_KEY(certificate), EXT_PUBLIC_KEY);
    memcpy(invitee_pk, CERT_INVITEE_KEY(certificate), EXT_PUBLIC_KEY);

    int peer1 = peer_in_chat(chat, invitee_pk); // TODO: processing after adding?

    if (peer1 == -1)
        return -1;

    if (ext_pk_equal(chat->chat_public_key, inviter_pk)) {
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
    if (ext_pk_equal(target_pk, chat->self_public_key)) {
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
           // gc_peer_delete(m, groupnumber, trg, NULL, 0);
            return -1;

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

/* Deletets peernumber from group.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_peer_delete(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint16_t length)
{
    GC_Session *c = m->group_handler;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    /* Needs to occur before peer is removed*/
    if (c->peer_exit && chat->group[peernumber].confirmed)
        (*c->peer_exit)(m, groupnumber, peernumber, data, length, c->peer_exit_userdata);

    gca_peer_cleanup(m->group_handler->announce, CHAT_ID(chat->chat_public_key), chat->group[peernumber].addr.public_key);
    gcc_peer_cleanup(&chat->gcc[peernumber]);

    --chat->numpeers;

    if (chat->numpeers != peernumber) {
        memcpy(&chat->group[peernumber], &chat->group[chat->numpeers], sizeof(GC_GroupPeer));
        memcpy(&chat->gcc[peernumber], &chat->gcc[chat->numpeers], sizeof(GC_Connection));
    }

    memset(&chat->group[chat->numpeers], 0, sizeof(GC_GroupPeer));
    memset(&chat->gcc[chat->numpeers], 0, sizeof(GC_Connection));

    GC_GroupPeer *tmp_group = realloc(chat->group, sizeof(GC_GroupPeer) * chat->numpeers);

    if (tmp_group == NULL)
        return -1;

    chat->group = tmp_group;

    GC_Connection *tmp_gcc = realloc(chat->gcc, sizeof(GC_Connection) * chat->numpeers);

    if (tmp_gcc == NULL)
        return -1;

    chat->gcc = tmp_gcc;

    /* Needs to occur after peer is removed */
    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return 0;
}

static int peer_update(GC_Chat *chat, GC_GroupPeer *peer, uint32_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    peer->time_connected = chat->group[peernumber].time_connected;
    peer->peer_pk_hash = chat->group[peernumber].peer_pk_hash;
    peer->verified = chat->group[peernumber].verified;
    peer->confirmed = chat->group[peernumber].confirmed;
    memcpy(&(chat->group[peernumber]), peer, sizeof(GC_GroupPeer));

    return peernumber;
}

/* Add peer to groupnumber's group list.
 *
 * Return peernumber if success.
 * Return -1 if fail.
 */
static int peer_add(Messenger *m, int groupnumber, GC_GroupPeer *peer, const GC_PeerAddress *addr)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    peer->last_rcvd_ping = unix_time();
    peer->last_update_time = unix_time();

    if (addr)
        copy_gc_peer_addr(&peer->addr, addr);

    int nick_num = get_nick_peernumber(chat, peer->nick, peer->nick_len);
    int peernumber = peer_in_chat(chat, peer->addr.public_key);

    if (nick_num != -1 && peernumber != nick_num)   // duplicate nick
        return -1;

    if (peernumber >= 0)
        return peer_update(chat, peer, peernumber);

    GC_Connection *tmp_gcc = realloc(chat->gcc, sizeof(GC_Connection) * (chat->numpeers + 1));

    if (tmp_gcc == NULL)
        return -1;

    GC_GroupPeer *tmp_group = realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (tmp_group == NULL)
        return -1;

    peernumber = chat->numpeers++;

    memcpy(&(tmp_group[peernumber]), peer, sizeof(GC_GroupPeer));
    memset(&(tmp_gcc[peernumber]), 0, sizeof(GC_Connection));

    chat->gcc = tmp_gcc;
    chat->group = tmp_group;

    chat->group[peernumber].time_connected = unix_time();
    chat->group[peernumber].peer_pk_hash = jenkins_hash(peer->addr.public_key, EXT_PUBLIC_KEY);

    chat->gcc[peernumber].send_message_id = 1;
    chat->gcc[peernumber].send_ary_start = 1;
    chat->gcc[peernumber].recv_message_id = 0;

    return peernumber;
}

/* Copies own peer data to peer */
static void self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer)
{
    memset(peer, 0, sizeof(GC_GroupPeer));
    memcpy(peer->addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(peer->invite_certificate, chat->group[0].invite_certificate, INVITE_CERT_SIGNED_SIZE);
    memcpy(peer->role_certificate, chat->group[0].role_certificate, ROLE_CERT_SIGNED_SIZE);
    memcpy(peer->nick, chat->group[0].nick, chat->group[0].nick_len);
    peer->nick_len = chat->group[0].nick_len;
    peer->status = chat->group[0].status;
    peer->role = chat->group[0].role;
    peer->confirmed = true;
}

static void do_peer_connections(Messenger *m, int groupnumber)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return;

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (is_timeout(chat->group[i].last_rcvd_ping, GROUP_PEER_TIMEOUT)) {
            gc_peer_delete(m, groupnumber, i, (uint8_t *) "Timed out", 9);
        } else {
            try_gc_peer_sync(chat, i);
            gcc_resend_packets(m, chat, i);   // This function may delete the peer
        }
        if (i >= chat->numpeers)
            break;
    }
}


static void ping_group(GC_Chat *chat)
{
    if (!is_timeout(chat->last_sent_ping_time, GROUP_PING_INTERVAL))
        return;

    uint8_t data[MAX_GC_PACKET_SIZE];
    memcpy(data, chat->self_public_key, EXT_PUBLIC_KEY);
    U32_to_bytes(data + EXT_PUBLIC_KEY, chat->numpeers);

    uint32_t length = EXT_PUBLIC_KEY + sizeof(uint32_t);
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->group[i].verified)
            send_lossy_group_packet(chat, chat->group[i].addr.ip_port, chat->group[i].addr.public_key,
                                    data, length, GP_PING);
    }

    chat->last_sent_ping_time = unix_time();
}

#define GROUP_SEARCH_ANNOUNCE_INTERVAL 300

/* Searches the DHT for nodes belonging to the group periodically in case of a split group.
 * The search frequency is relative to the number of peers in the group.
 */
static void search_gc_announce(GC_Session *c, GC_Chat *chat)
{
    if (!is_timeout(chat->announce_search_timer, GROUP_SEARCH_ANNOUNCE_INTERVAL))
        return;

    chat->announce_search_timer = unix_time();

    if (random_int_range(chat->numpeers) == 0) {
        /* DHT response/sync procedure is handled in gc_update_addrs() */
        gca_send_get_nodes_request(c->announce, chat->self_public_key,
                                   chat->self_secret_key, CHAT_ID(chat->chat_public_key));
    }
}

#define GROUP_JOIN_ATTEMPT_INTERVAL 2
#define GROUP_GET_NEW_NODES_INTERVAL 15
#define GROUP_MAX_GET_NODES_ATTEMPTS 3

/* CS_CONNECTED: Peers are pinged, unsent packets are resent, and timeouts are checked.
 * CS_CONNECTING: Look for new DHT nodes after an interval.
 * CS_DISCONNECTED: Send an invite request using a random node if our timeout GROUP_JOIN_ATTEMPT_INTERVAL has expired.
 * CS_FAILED: Do nothing. This occurrs if we cannot connect to a group or our invite request is rejected.
 */
void do_gc(GC_Session *c)
{
    if (!c)
        return;

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];

        if (!chat)
            continue;

        switch (chat->connection_state) {
            case CS_CONNECTED: {
                ping_group(chat);
                do_peer_connections(c->messenger, i);
                search_gc_announce(c, chat);

                break;
            }

            case CS_CONNECTING: {
                if (chat->get_nodes_attempts > GROUP_MAX_GET_NODES_ATTEMPTS) {
                    self_gc_connected(chat);

                    /* If we can't get an invite we assume the group is empty */
                    if (!chat->group[0].verified
                        || gca_send_announce_request(c->announce, chat->self_public_key,
                                                     chat->self_secret_key, CHAT_ID(chat->chat_public_key)) == -1) {
                        if (c->rejected)
                            (*c->rejected)(c->messenger, i, GJ_INVITE_FAILED, c->rejected_userdata);

                        chat->connection_state = CS_FAILED;
                    }

                    break;
                }

                if (is_timeout(chat->self_last_rcvd_ping, GROUP_GET_NEW_NODES_INTERVAL)) {
                    ++chat->get_nodes_attempts;
                    chat->self_last_rcvd_ping = unix_time();
                    gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                               CHAT_ID(chat->chat_public_key));
                }

                chat->connection_state = CS_DISCONNECTED;
                break;
            }

            case CS_DISCONNECTED: {
                if (chat->num_addrs && is_timeout(chat->last_join_attempt, GROUP_JOIN_ATTEMPT_INTERVAL)) {
                    chat->last_join_attempt = unix_time();

                    if (gc_send_invite_request(chat, chat->addr_list[chat->addrs_idx].ip_port,
                                               chat->addr_list[chat->addrs_idx].public_key) == -1) {
                        if (c->rejected)
                            (*c->rejected)(c->messenger, i, GJ_INVITE_FAILED, c->rejected_userdata);

                        chat->connection_state = CS_FAILED;
                        break;
                    }

                    chat->addrs_idx = (chat->addrs_idx + 1) % chat->num_addrs;
                }

                if (onion_connection_status(c->messenger->onion_c))
                    chat->connection_state = CS_CONNECTING;

                break;
            }

            case CS_FAILED: {
                break;
            }
        }
    }
}

static GC_ChatCredentials *new_groupcredentials(GC_Chat *chat)
{
    GC_ChatCredentials *credentials = malloc(sizeof(GC_ChatCredentials));

    if (credentials == NULL)
        return NULL;

    create_extended_keypair(credentials->chat_public_key, credentials->chat_secret_key);

    credentials->ops = malloc(sizeof(GC_ChatOps));

    if (credentials->ops == NULL) {
        free(credentials);
        return NULL;
    }

    credentials->creation_time = unix_time();
    memcpy(credentials->ops->public_key, chat->self_public_key, EXT_PUBLIC_KEY);

    return credentials;
}

static int make_founder_certificates(const GC_Chat *chat)
{
    uint8_t semi_cert[SEMI_INVITE_CERT_SIGNED_SIZE];
    if (make_invite_cert(chat->self_secret_key, chat->self_public_key, semi_cert) == -1)
        return -1;

    if (sign_certificate(semi_cert, SEMI_INVITE_CERT_SIGNED_SIZE, chat->self_secret_key,
                         chat->self_public_key, chat->group[0].invite_certificate) == -1)
        return -1;

    return 0;
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
    int groupnumber = get_new_group_index(c);

    if (groupnumber == -1)
        return -1;

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[groupnumber];

    chat->groupnumber = groupnumber;
    chat->numpeers = 0;
    chat->connection_state = CS_DISCONNECTED;
    chat->net = m->net;
    memcpy(chat->topic, " ", 1);
    chat->topic_len = 1;
    chat->maxpeers = MAX_GROUP_NUM_PEERS;
    chat->self_last_rcvd_ping = unix_time();
    chat->last_sent_ping_time = unix_time();
    chat->announce_search_timer = unix_time();

    GC_GroupPeer self;
    memset(&self, 0, sizeof(GC_GroupPeer));

    if (founder) {
        self.verified = true;
        chat->credentials = new_groupcredentials(chat);

        if (chat->credentials == NULL) {
            group_delete(c, chat);
            return -1;
        }
    }

    create_extended_keypair(chat->self_public_key, chat->self_secret_key);

    memcpy(self.nick, m->name, m->name_length);
    self.nick_len = m->name_length;
    self.status = m->userstatus;
    self.role = GR_FOUNDER ? founder : GR_USER;

    if (peer_add(m, groupnumber, &self, NULL) != 0) {    /* you are always peernumber/index 0 */
        group_delete(c, chat);
        return -1;
    }

    return groupnumber;
}

/* Loads a previously saved group and attempts to connect to it.
 *
 * Returns groupnumber on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, struct SAVED_GROUP *save)
{
    int groupnumber = get_new_group_index(c);

    if (groupnumber == -1)
        return -1;

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[groupnumber];

    chat->groupnumber = groupnumber;
    chat->numpeers = 0;
    chat->connection_state = CS_DISCONNECTED;
    chat->net = m->net;
    chat->maxpeers = MAX_GROUP_NUM_PEERS;
    chat->self_last_rcvd_ping = unix_time();
    chat->last_sent_ping_time = unix_time();
    chat->announce_search_timer = unix_time();

    memcpy(chat->group_name, save->group_name, MAX_GC_GROUP_NAME_SIZE);
    memcpy(chat->topic, save->topic, MAX_GC_TOPIC_SIZE);
    memcpy(chat->chat_public_key, save->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->self_public_key, save->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->self_secret_key, save->self_secret_key, EXT_SECRET_KEY);
    chat->topic_len = ntohs(save->topic_len);
    chat->group_name_len = ntohs(save->group_name_len);
    chat->chat_id_hash = jenkins_hash(CHAT_ID(chat->chat_public_key), CHAT_ID_SIZE);

    GC_GroupPeer self;
    memset(&self, 0, sizeof(GC_GroupPeer));

    memcpy(self.invite_certificate, save->self_invite_cert, INVITE_CERT_SIGNED_SIZE);
    memcpy(self.role_certificate, save->self_role_cert, ROLE_CERT_SIGNED_SIZE);
    memcpy(self.nick, save->self_nick, MAX_GC_NICK_SIZE);
    self.nick_len = ntohs(save->self_nick_len);
    self.role = save->self_role;
    self.status = save->self_status;
    self.verified = (bool) save->self_verified;

    if (peer_add(m, groupnumber, &self, NULL) != 0)
        return -1;

    uint16_t i, num = 0, num_addrs = ntohs(save->num_addrs);

    for (i = 0; i < num_addrs && i < MAX_GC_PEER_ADDRS; ++i) {
        if (ipport_isset(&save->addrs[i].ip_port))
            chat->addr_list[num++] = save->addrs[i];
    }

    chat->num_addrs = num;

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

    self_gc_connected(chat);
    memcpy(chat->chat_public_key, chat->credentials->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->group_name, group_name, length);
    chat->group_name_len = length;
    chat->chat_id_hash = jenkins_hash(CHAT_ID(chat->chat_public_key), CHAT_ID_SIZE);

    if (make_founder_certificates(chat) == -1) {
        group_delete(c, chat);
        return -1;
    }

    if (gca_send_announce_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                  CHAT_ID(chat->chat_public_key)) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return groupnumber;
}

/* Sends an invite request to an existing group using the chat_id
 * The two keys must be either both null or both nonnull, and if the latter they'll be
 * used instead of generating new ones
 *
 * Return groupnumber on success.
 * Reutrn -1 on failure.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id)
{
    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = jenkins_hash(CHAT_ID(chat->chat_public_key), CHAT_ID_SIZE);

    if (chat->num_addrs == 0)
        gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key, CHAT_ID(chat->chat_public_key));

    return groupnumber;
}

/* Resets chat saving all self state and attempts to reconnect to group */
void gc_rejoin_group(GC_Session *c, GC_Chat *chat)
{
    send_gc_self_exit(chat, NULL, 0);

    uint32_t i;

    /* Remove all peers except self. Numpeers decrements with each call to gc_peer_delete */
    for (i = 1; chat->numpeers > 1; )
        if (gc_peer_delete(c->messenger, chat->groupnumber, i, NULL, 0) == -1)
            break;

    chat->connection_state = CS_DISCONNECTED;
    chat->self_last_rcvd_ping = chat->num_addrs > 0 ? unix_time() : 0;  /* Reconnect using saved peers or DHT */
    chat->last_sent_ping_time = unix_time();
    chat->last_join_attempt = unix_time() + 3;  /* Delay reconnection in case of heavy lag for part signal */
    chat->announce_search_timer = unix_time();
    chat->get_nodes_attempts = 0;
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

    memcpy(packet + 1, CHAT_ID(chat->chat_public_key), CHAT_ID_SIZE);

    GC_Announce_Node self_node;
    if (make_self_gca_node(c->messenger->dht, &self_node, chat->self_public_key) == -1)
        return -1;

    int node_len = pack_gca_nodes(packet + 1 + CHAT_ID_SIZE, sizeof(GC_Announce_Node), &self_node, 1);

    if (node_len <= 0) {
        fprintf(stderr, "pack_gca_nodes failed in gc_invite_friend (%d)\n", node_len);
        return -1;
    }

    uint16_t length = 1 + CHAT_ID_SIZE + node_len;
    return send_group_invite_packet(c->messenger, friendnumber, packet, length);
}

/* Joins a group using the invite data received in a friend's group invite.
 *
 * Return groupnumber on success.
 * Return -1 on failure.
 */
int gc_accept_invite(GC_Session *c, const uint8_t *data, uint16_t length)
{
    uint8_t chat_id[CHAT_ID_SIZE];
    memcpy(chat_id, data, CHAT_ID_SIZE);

    GC_Announce_Node node;
    if (unpack_gca_nodes(&node, 1, 0, data + CHAT_ID_SIZE, length - CHAT_ID_SIZE, 0) != 1)
        return -1;

    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = jenkins_hash(CHAT_ID(chat->chat_public_key), CHAT_ID_SIZE);

    if (gc_send_invite_request(chat, node.ip_port, node.public_key) == -1)
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
    c->announce = m->group_announce;
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

    gca_cleanup(c->announce, CHAT_ID(chat->chat_public_key));
    gcc_cleanup(chat);
    kill_groupcredentials(chat->credentials);

    if (chat->group)
        free(chat->group);

    memset(&(c->chats[chat->groupnumber]), 0, sizeof(GC_Chat));

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

void kill_groupchats(GC_Session *c)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state != CS_NONE)
            send_gc_self_exit(&c->chats[i], NULL, 0);
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

/* Count number of active groups.
 *
 * Returns the count.
 */
uint32_t gc_count_groups(const GC_Session *c)
{
    uint32_t i, count = 0;

    for (i = 0; i < c->num_chats; i++)
        if (c->chats[i].connection_state > CS_NONE && c->chats[i].connection_state < CS_INVALID)
            count++;

    return count;
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

/* Return peernumber of peer with nick if nick is taken.
 * Return -1 if nick is not taken.
 */
static int get_nick_peernumber(const GC_Chat *chat, const uint8_t *nick, uint16_t length)
{
    if (length == 0)
        return -1;

    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].nick_len == length && memcmp(chat->group[i].nick, nick, length) == 0)
            return i;
    }

    return -1;
}
