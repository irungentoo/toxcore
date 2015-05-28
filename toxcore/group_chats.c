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

#define GC_MAX_PACKET_PADDING 8
#define GC_PACKET_PADDING_LENGTH(length) (((MAX_GC_PACKET_SIZE - (length)) % GC_MAX_PACKET_PADDING))

#define GC_PLAIN_HS_PACKET_SIZE (sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + SIG_PUBLIC_KEY\
                                 + sizeof(uint8_t) + sizeof(uint8_t))

#define GC_ENCRYPTED_HS_PACKET_SIZE (sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES\
                                     + GC_PLAIN_HS_PACKET_SIZE + crypto_box_MACBYTES)

#define GC_PACKED_SHARED_STATE_SIZE (ENC_PUBLIC_KEY + sizeof(uint32_t) + MAX_GC_GROUP_NAME_SIZE + sizeof(uint16_t)\
                                     + sizeof(uint8_t) + sizeof(uint16_t) + MAX_GC_PASSWD_SIZE\
                                     + GC_MOD_LIST_HASH_SIZE + sizeof(uint32_t))

#define GC_SHARED_STATE_ENC_PACKET_SIZE (HASH_ID_BYTES + SIGNATURE_SIZE + GC_PACKED_SHARED_STATE_SIZE)

/* Header information attached to all broadcast messages. broadcast_type, public key hash, timestamp */
#define GC_BROADCAST_ENC_HEADER_SIZE (1 + HASH_ID_BYTES + TIME_STAMP_SIZE)

#define MESSAGE_ID_BYTES (sizeof(uint64_t))

#define MIN_GC_LOSSLESS_PACKET_SIZE (sizeof(uint8_t) + MESSAGE_ID_BYTES + HASH_ID_BYTES + ENC_PUBLIC_KEY\
                                     + crypto_box_NONCEBYTES + sizeof(uint8_t) + crypto_box_MACBYTES)

#define MIN_GC_LOSSY_PACKET_SIZE (MIN_GC_LOSSLESS_PACKET_SIZE - MESSAGE_ID_BYTES)

#define MAX_GC_PACKET_SIZE 65507

/* approximation of the sync response packet size limit */
#define MAX_GC_NUM_PEERS ((MAX_GC_PACKET_SIZE - MAX_GC_TOPIC_SIZE - sizeof(uint16_t)) / (ENC_PUBLIC_KEY + sizeof(IP_Port)))

static int groupnumber_valid(const GC_Session *c, int groupnumber);
static int peer_add(Messenger *m, int groupnumber, IP_Port *ipp, const uint8_t *public_key);
static int peer_update(Messenger *m, int groupnumber, GC_GroupPeer *peer, uint32_t peernumber);
static int group_delete(GC_Session *c, GC_Chat *chat);
static int get_nick_peernumber(const GC_Chat *chat, const uint8_t *nick, uint16_t length);
static int sync_gc_announced_nodes(const GC_Session *c, GC_Chat *chat);

enum {
    /* lossy packets (ID 0 is reserved) */
    GP_PING = 1,
    GP_MESSAGE_ACK = 2,
    GP_INVITE_RESPONSE_REJECT = 3,

    /* lossless packets */
    GP_BROADCAST = 20,
    GP_PEER_INFO_REQUEST = 21,
    GP_PEER_INFO_RESPONSE = 22,
    GP_INVITE_REQUEST = 23,
    GP_INVITE_RESPONSE = 24,
    GP_SYNC_REQUEST = 25,
    GP_SYNC_RESPONSE = 26,
    GP_SHARED_STATE = 27,
    GP_FRIEND_INVITE = 28,
    GP_HS_RESPONSE_ACK = 29,
} GROUP_PACKET_TYPE;

enum {
    GH_REQUEST,
    GH_RESPONSE
} GROUP_HANDSHAKE_PACKET_TYPE;

enum {
    HS_INVITE_REQUEST,
    HS_PEER_INFO_EXCHANGE
} GROUP_HANDSHAKE_REQUEST_TYPE;


// for debugging
static void print_peer(const GC_GroupPeer *peer, const GC_Connection *gconn)
{
    fprintf(stderr, "ENC PK: %s\n", id_toa(gconn->addr.public_key));
    fprintf(stderr, "SIG PK: %s\n", id_toa(SIG_PK(gconn->addr.public_key)));
    fprintf(stderr, "IP: %s\n", ip_ntoa(&gconn->addr.ip_port.ip));
    fprintf(stderr, "Role cert: %s\n", id_toa(peer->role_certificate));   // Only print first 32 bytes
    fprintf(stderr, "Nick: %s\n", peer->nick);
    fprintf(stderr, "Nick len: %u\n", peer->nick_len);
    fprintf(stderr, "Status: %u\n", peer->status);
    fprintf(stderr, "Role: %u\n", peer->role);
    fprintf(stderr, "Ignore: %d\n", gconn->ignore);
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

/* Returns the jenkins hash of a 32 byte public encryption key */
static uint32_t get_peer_key_hash(const uint8_t *public_key)
{
    return jenkins_one_at_a_time_hash(public_key, ENC_PUBLIC_KEY);
}

/* Returns the jenkins hash of a 32 byte chat_id. */
static uint32_t get_chat_id_hash(const uint8_t *chat_id)
{
    return jenkins_one_at_a_time_hash(chat_id, CHAT_ID_SIZE);
}

/* Check if peer with the encryption public key is in peer list.
 *
 * return peer number if peer is in chat.
 * return -1 if peer is not in chat.
 *
 */
static int peer_in_chat(const GC_Chat *chat, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (memcmp(chat->gcc[i].addr.public_key, public_key, ENC_PUBLIC_KEY) == 0)
            return i;
    }

    return -1;
}

/* Returns mod_list index for peernumber.
 * Returns -1 if peernumber is not a moderator.
 */
static int get_mod_list_index(const GC_Chat *chat, uint32_t peernumber)
{
    uint16_t i;

    for (i = 0; i < chat->num_mods; ++i) {
        if (memcmp(chat->mod_list[i], SIG_PK(chat->gcc[peernumber].addr.public_key), SIG_PUBLIC_KEY) == 0)
            return i;
    }

    return -1;
}

/* Validates the group role that the peer with public_key gave to you.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int validate_gc_peer_role(const GC_Chat *chat, uint8_t role, const uint8_t *public_key)
{
    if (role >= GR_INVALID)
        return -1;

    if (role == GR_FOUNDER) {
        if (memcmp(chat->shared_state.founder_public_key, public_key, ENC_PUBLIC_KEY) == 0)
            return 0;

        return -1;
    }

    return 0;
    // TODO: moderators
}

/* Adds peernumber to the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int add_gc_moderator(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->num_mods >= MAX_GC_MODERATORS)
        return -1;

    uint8_t **tmp_list = realloc(chat->mod_list, sizeof(uint8_t *) * (chat->num_mods + 1));

    if (tmp_list == NULL)
        return -1;

    tmp_list[chat->num_mods] = malloc(sizeof(uint8_t) * SIG_PUBLIC_KEY);

    if (tmp_list[chat->num_mods] == NULL)
        return -1;

    memcpy(tmp_list[chat->num_mods], SIG_PK(chat->gcc[peernumber].addr.public_key), SIG_PUBLIC_KEY);
    chat->mod_list = tmp_list;
    ++chat->num_mods;

    chat->group[peernumber].role = GR_MODERATOR;

    return 0;
}

/* Removes peernumber from the moderator list and sets their new role.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int remove_gc_moderator(GC_Chat *chat, uint32_t peernumber, uint8_t role)
{
    if (chat->num_mods == 0)
        return -1;

    int idx = get_mod_list_index(chat, peernumber);

    if (idx == -1)
        return -1;

    chat->group[peernumber].role = role;

    free(chat->mod_list[idx]);
    --chat->num_mods;

    if (chat->num_mods == 0) {
        free(chat->mod_list);
        chat->mod_list = NULL;
        return 0;
    }

    if (idx != chat->num_mods)
        memcpy(chat->mod_list[idx], chat->mod_list[chat->num_mods], SIG_PUBLIC_KEY);

    uint8_t **tmp_list = realloc(chat->mod_list, sizeof(uint8_t *) * (chat->num_mods));
    chat->mod_list = tmp_list;

    if (chat->mod_list == NULL) {
        chat->num_mods = 0;
        return -1;
    }

    return 0;
}

/* Returns true if peernumber exists */
static bool peernumber_valid(const GC_Chat *chat, int peernumber)
{
    return peernumber >= 0 && peernumber < chat->numpeers;
}

/* Returns true if sender_pk_hash is equal to peernumber's public key hash */
static bool peer_pk_hash_match(GC_Chat *chat, uint32_t peernumber, uint32_t sender_pk_hash)
{
    return sender_pk_hash == chat->gcc[peernumber].public_key_hash;
}

static void self_gc_connected(GC_Chat *chat)
{
    chat->connection_state = CS_CONNECTED;
    chat->gcc[0].time_added = unix_time();
}

/* Sets the password for the group (locally only).
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int set_gc_password_local(GC_Chat *chat, const uint8_t *passwd, uint16_t length)
{
    if (length > MAX_GC_PASSWD_SIZE)
        return -1;

    if (!passwd || length == 0) {
        chat->shared_state.passwd_len = 0;
        memset(chat->shared_state.passwd, 0, MAX_GC_PASSWD_SIZE);
    } else {
        chat->shared_state.passwd_len = length;
        memcpy(chat->shared_state.passwd, passwd, length);
    }

    return 0;
}


/* Sends an announce request to the DHT if group is public.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int group_announce_request(GC_Session *c, const GC_Chat *chat)
{
    if (chat->shared_state.version == 0)
        return -1;

    if (chat->shared_state.privacy_state != GI_PUBLIC)
        return 0;

    return gca_send_announce_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                     CHAT_ID(chat->chat_public_key));
}

/* Sends a get nodes request to the DHT if group is public.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int group_get_nodes_request(GC_Session *c, const GC_Chat *chat)
{
    if (chat->shared_state.privacy_state != GI_PUBLIC)
        return 0;

    return gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                      CHAT_ID(chat->chat_public_key));
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
        if (chat->gcc[i].confirmed)
            addrs[num++] = chat->gcc[i].addr;
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
 * This will clear previous entries.
 */
void gc_update_addrs(GC_Announce *announce, const uint8_t *chat_id)
{
    uint32_t chat_id_hash = get_chat_id_hash(chat_id);
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
        memcpy(chat->addr_list[i].public_key, nodes[i].public_key, ENC_PUBLIC_KEY);
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

/* Returns the number of confirmed peers in peerlist */
static uint32_t get_gc_confirmed_numpeers(const GC_Chat *chat)
{
    uint32_t i, count = 0;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed)
            ++count;
    }

    return count;
}

/* Packs number of peer addresses into data of maxlength length.
 * Note: Only the encryption public key is packed.
 *
 * Return length of packed peer addresses on success.
 * Return -1 on failure.
 */
static int pack_gc_addresses(uint8_t *data, uint16_t length, const GC_PeerAddress *addrs, uint16_t number)
{
    uint32_t i, packed_len = 0;

    for (i = 0; i < number; ++i) {
        int ipp_size = pack_ip_port(data, length, packed_len, &addrs[i].ip_port);

        if (ipp_size == -1)
            return -1;

        packed_len += ipp_size;

        if (packed_len + ENC_PUBLIC_KEY > length)
            return -1;

        memcpy(data + packed_len, ENC_KEY(addrs[i].public_key), ENC_PUBLIC_KEY);
        packed_len += ENC_PUBLIC_KEY;
    }

    return packed_len;
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

/* Size of peer data that we pack for transfer (nick length must be accounted for separately).
 * packed data includes: signed role cert, nick, nick length, status, role
 */
#define PACKED_GC_PEER_SIZE (ROLE_CERT_SIGNED_SIZE + MAX_GC_NICK_SIZE + sizeof(uint16_t) + sizeof(uint8_t)\
                             + sizeof(uint8_t))

/* Packs peer info into data of maxlength length.
 *
 * Return length of packed peer on success.
 * Return -1 on failure.
 */
static int pack_gc_peer(uint8_t *data, uint16_t length, const GC_GroupPeer *peer)
{
    if (PACKED_GC_PEER_SIZE > length)
        return -1;

    uint32_t packed_len = 0;

    memcpy(data + packed_len, peer->role_certificate, ROLE_CERT_SIGNED_SIZE);
    packed_len += ROLE_CERT_SIGNED_SIZE;
    U16_to_bytes(data + packed_len, peer->nick_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, peer->nick, MAX_GC_NICK_SIZE);
    packed_len += MAX_GC_NICK_SIZE;
    memcpy(data + packed_len, &peer->status, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    memcpy(data + packed_len, &peer->role, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);

    return packed_len;
}

/* Unpacks peer info of size length into peer.
 *
 * Returns the length of processed data on success.
 * Returns -1 on failure.
 */
static int unpack_gc_peer(GC_GroupPeer *peer, const uint8_t *data, uint16_t length)
{
    if (PACKED_GC_PEER_SIZE > length)
        return -1;

    uint32_t len_processed = 0;

    memcpy(peer->role_certificate, data + len_processed, ROLE_CERT_SIGNED_SIZE);
    len_processed += ROLE_CERT_SIGNED_SIZE;
    bytes_to_U16(&peer->nick_len, data + len_processed);
    len_processed += sizeof(uint16_t);
    peer->nick_len = MIN(MAX_GC_NICK_SIZE, peer->nick_len);
    memcpy(peer->nick, data + len_processed, MAX_GC_NICK_SIZE);
    len_processed += MAX_GC_NICK_SIZE;
    memcpy(&peer->status, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    memcpy(&peer->role, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    return len_processed;
}

/* Packs shared_state into data. data must have room for at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns packed data length.
 */
static uint32_t pack_gc_shared_state(uint8_t *data, const GC_SharedState *shared_state)
{
    uint32_t packed_len = 0;

    memcpy(data + packed_len, shared_state->founder_public_key, ENC_PUBLIC_KEY);
    packed_len += ENC_PUBLIC_KEY;
    U32_to_bytes(data + packed_len, shared_state->maxpeers);
    packed_len += sizeof(uint32_t);
    U16_to_bytes(data + packed_len, shared_state->group_name_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->group_name, MAX_GC_GROUP_NAME_SIZE);
    packed_len += MAX_GC_GROUP_NAME_SIZE;
    memcpy(data + packed_len, &shared_state->privacy_state, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    U16_to_bytes(data + packed_len, shared_state->passwd_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->passwd, MAX_GC_PASSWD_SIZE);
    packed_len += MAX_GC_PASSWD_SIZE;
    memcpy(data + packed_len, shared_state->mod_list_hash, GC_MOD_LIST_HASH_SIZE);
    packed_len += GC_MOD_LIST_HASH_SIZE;
    U32_to_bytes(data + packed_len, shared_state->version);
    packed_len += sizeof(uint32_t);

    return packed_len;
}

/* Unpacks shared state data into shared_state.
 *
 * Returns the length of processed data on success.
 * Returns -1 on failure.
 */
static uint32_t unpack_gc_shared_state(GC_SharedState *shared_state, const uint8_t *data)
{
    uint32_t len_processed = 0;

    memcpy(shared_state->founder_public_key, data + len_processed, ENC_PUBLIC_KEY);
    len_processed += ENC_PUBLIC_KEY;
    bytes_to_U32(&shared_state->maxpeers, data + len_processed);
    len_processed += sizeof(uint32_t);
    bytes_to_U16(&shared_state->group_name_len, data + len_processed);
    shared_state->group_name_len = MIN(shared_state->group_name_len, MAX_GC_GROUP_NAME_SIZE);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->group_name, data + len_processed, MAX_GC_GROUP_NAME_SIZE);
    len_processed += MAX_GC_GROUP_NAME_SIZE;
    memcpy(&shared_state->privacy_state, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    bytes_to_U16(&shared_state->passwd_len, data + len_processed);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->passwd, data + len_processed, MAX_GC_PASSWD_SIZE);
    len_processed += MAX_GC_PASSWD_SIZE;
    memcpy(shared_state->mod_list_hash, data + len_processed, GC_MOD_LIST_HASH_SIZE);
    len_processed += GC_MOD_LIST_HASH_SIZE;
    bytes_to_U32(&shared_state->version, data + len_processed);
    len_processed += sizeof(uint32_t);

    return len_processed;
}

/* Creates a shared state packet and puts it in data.
 * Packet includes self pk hash, shared state signature, and packed shared state info.
 * data must have room for at least GC_SHARED_STATE_ENC_PACKET_SIZE bytes.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_shared_state_packet(const GC_Chat *chat, uint8_t *data)
{
    U32_to_bytes(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, chat->shared_state_sig, SIGNATURE_SIZE);
    uint32_t packed_len = pack_gc_shared_state(data + HASH_ID_BYTES + SIGNATURE_SIZE, &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE)
        return -1;

    return HASH_ID_BYTES + SIGNATURE_SIZE + packed_len;
}

/* Creates a signature for the group's packed shared state and increments version.
 * This should only be called by the founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sign_gc_shared_state(GC_Chat *chat)
{
    if (chat->group[0].role != GR_FOUNDER)
        return -1;

    if (chat->shared_state.version != UINT32_MAX)   /* improbable, but an overflow would break everything */
        ++chat->shared_state.version;

    uint8_t shared_state[GC_PACKED_SHARED_STATE_SIZE];
    uint32_t packed_len = pack_gc_shared_state(shared_state, &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        --chat->shared_state.version;
        return -1;
    }

    int ret = crypto_sign_detached(chat->shared_state_sig, NULL, shared_state, packed_len, SIG_SK(chat->chat_secret_key));

    if (ret != 0)
        --chat->shared_state.version;

    return ret;
}

/* Decrypts data using the peer's shared key and a nonce.
 * message_id should be set to NULL for lossy packets.
 *
 * Returns length of the plaintext data on success.
 * Returns -1 on failure.
 */
static int unwrap_group_packet(const uint8_t *shared_key, uint8_t *data, uint64_t *message_id,
                               uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    uint8_t plain[MAX_GC_PACKET_SIZE];
    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);

    int plain_len = decrypt_data_symmetric(shared_key, nonce,
                                           packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES,
                                           length - (sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES),
                                           plain);
    if (plain_len <= 0) {
        fprintf(stderr, "decrypt failed: len %d\n", plain_len);
        return -1;
    }

    int min_plain_len = message_id != NULL ? 1 + MESSAGE_ID_BYTES : 1;

    /* remove padding */
    uint8_t *real_plain = plain;
    while (real_plain[0] == 0) {
        ++real_plain;
        --plain_len;

        if (plain_len < min_plain_len)
            return -1;
    }

    uint32_t header_len = sizeof(uint8_t);
    *packet_type = real_plain[0];
    plain_len -= sizeof(uint8_t);

    if (message_id != NULL) {
        bytes_to_U64(message_id, real_plain + sizeof(uint8_t));
        plain_len -= MESSAGE_ID_BYTES;
        header_len += MESSAGE_ID_BYTES;
    }

    memcpy(data, real_plain + header_len, plain_len);

    return plain_len;
}

/* Encrypts data of length using the peer's shared key and a new nonce.
 *
 * Adds encrypted header consisting of: packet type, message_id (only for lossless packets)
 * Adds plaintext header consisting of: packet identifier, chat_id_hash, self public encryption key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int wrap_group_packet(const uint8_t *self_pk, const uint8_t *shared_key, uint8_t *packet,
                             const uint8_t *data, uint32_t length, uint64_t message_id, uint8_t packet_type,
                             uint32_t chat_id_hash, uint8_t packet_id)
{
    uint16_t padding_len = GC_PACKET_PADDING_LENGTH(length);

    if (length + padding_len + MIN_GC_LOSSLESS_PACKET_SIZE > MAX_GC_PACKET_SIZE)
        return -1;

    uint8_t plain[MAX_GC_PACKET_SIZE];
    memset(plain, 0, padding_len);

    uint32_t enc_header_len = sizeof(uint8_t);
    plain[padding_len] = packet_type;

    if (packet_id == NET_PACKET_GC_LOSSLESS) {
        U64_to_bytes(plain + padding_len + sizeof(uint8_t), message_id);
        enc_header_len += MESSAGE_ID_BYTES;
    }

    memcpy(plain + padding_len + enc_header_len, data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint16_t plain_len = padding_len + enc_header_len + length;
    uint8_t encrypt[plain_len + crypto_box_MACBYTES];

    int enc_len = encrypt_data_symmetric(shared_key, nonce, plain, plain_len, encrypt);

    if (enc_len != sizeof(encrypt)) {
        fprintf(stderr, "encrypt failed. packet type: %d, enc_len: %d\n", packet_type, enc_len);
        return -1;
    }

    packet[0] = packet_id;
    U32_to_bytes(packet + sizeof(uint8_t), chat_id_hash);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES, self_pk, ENC_PUBLIC_KEY);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES, encrypt, enc_len);

    return 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + enc_len;
}

static int send_lossy_group_packet(const GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length,
                                   uint8_t packet_type)
{
    if (peernumber == 0)
        return -1;

    if (!chat->gcc[peernumber].handshaked)
        return -1;

    if (!data || length == 0)
        return -1;

    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->gcc[peernumber].shared_key, packet, data,
                                length, 0, packet_type, chat->chat_id_hash, NET_PACKET_GC_LOSSY);
    if (len == -1) {
        fprintf(stderr, "wrap_group_packet failed (type: %u, len: %d)\n", packet_type, len);
        return -1;
    }

    return sendpacket(chat->net, chat->gcc[peernumber].addr.ip_port, packet, len);
}

static int send_lossless_group_packet(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length,
                                      uint8_t packet_type)
{
    if (peernumber == 0)
        return -1;

    if (!chat->gcc[peernumber].handshaked)
        return -1;

    if (!data || length == 0)
        return -1;

    uint64_t message_id = chat->gcc[peernumber].send_message_id;
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, chat->gcc[peernumber].shared_key, packet, data,
                                length, message_id, packet_type, chat->chat_id_hash, NET_PACKET_GC_LOSSLESS);
    if (len == -1) {
        fprintf(stderr, "wrap_group_packet (type: %u, len: %d)\n", packet_type, len);
        return -1;
    }

    if (gcc_add_send_ary(chat, packet, len, peernumber, packet_type) == -1)
        return -1;

    return sendpacket(chat->net, chat->gcc[peernumber].addr.ip_port, packet, len);
}

/* Sends a group sync request to peernumber.
 * num_peers should be set to 0 if this is our initial sync request on join.
 */
static int send_gc_sync_request(GC_Chat *chat, uint32_t peernumber, uint32_t num_peers)
{
    if (chat->gcc[peernumber].pending_sync_request)
        return -1;

    chat->gcc[peernumber].pending_sync_request = true;

    uint32_t length = HASH_ID_BYTES + sizeof(uint32_t) + MAX_GC_PASSWD_SIZE;
    uint8_t data[length];
    U32_to_bytes(data, chat->self_public_key_hash);
    U32_to_bytes(data + HASH_ID_BYTES, num_peers);
    memcpy(data + HASH_ID_BYTES + sizeof(uint32_t), chat->shared_state.passwd, MAX_GC_PASSWD_SIZE);

    return send_lossless_group_packet(chat, peernumber, data, length, GP_SYNC_REQUEST);
}

static int send_gc_sync_response(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, peernumber, data, length, GP_SYNC_RESPONSE);
}

static int send_gc_peer_exchange(const GC_Session *c, GC_Chat *chat, uint32_t peernumber);
static int send_gc_handshake_request(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *public_key,
                                     uint8_t request_type, uint8_t join_type);

static int handle_gc_sync_response(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                   uint32_t length)
{
    if (length <= sizeof(uint16_t))
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!chat->gcc[peernumber].pending_sync_request)
        return -1;

    chat->gcc[peernumber].pending_sync_request = false;

    uint32_t unpacked_len = 0;

    bytes_to_U16(&(chat->topic_len), data);
    unpacked_len += sizeof(uint16_t);
    chat->topic_len = MIN(MAX_GC_TOPIC_SIZE, chat->topic_len);

    if (length - unpacked_len <= chat->topic_len)
        return -1;

    memcpy(chat->topic, data + unpacked_len, chat->topic_len);
    unpacked_len += chat->topic_len;

    if (length - unpacked_len <= sizeof(uint32_t))
        return -1;

    uint32_t num_peers;
    bytes_to_U32(&num_peers, data + unpacked_len);
    unpacked_len += sizeof(uint32_t);

    if (num_peers == 0 || num_peers > MAX_GC_NUM_PEERS)
        return -1;

    GC_PeerAddress *addrs = calloc(1, sizeof(GC_PeerAddress) * num_peers);

    if (addrs == NULL)
        return -1;

    uint16_t addrs_len = 0;
    int unpacked_addrs = unpack_gc_addresses(addrs, num_peers, &addrs_len, data + unpacked_len,
                                             length - unpacked_len, 1);

    if (unpacked_addrs != num_peers || addrs_len == 0) {
        free(addrs);
        fprintf(stderr, "unpack_gc_addresses failed: got %d expected %d\n", unpacked_addrs, num_peers);
        return -1;
    }

    unpacked_len += addrs_len;

    uint32_t i;

    for (i = 0; i < num_peers; i++) {
        if (peer_in_chat(chat, addrs[i].public_key) == -1)
            send_gc_handshake_request(m, groupnumber, addrs[i].ip_port, addrs[i].public_key,
                                      HS_PEER_INFO_EXCHANGE, chat->join_type);
    }

    for (i = 0; i < chat->numpeers; ++i)
        chat->gcc[i].peer_sync_timer = 0;

    free(addrs);

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    if (chat->connection_state == CS_CONNECTED)
        return 0;

    self_gc_connected(chat);
    send_gc_peer_exchange(c, chat, peernumber);
    group_announce_request(c, chat);

    if (chat->num_addrs > 0)
        sync_gc_announced_nodes(c, chat);

    if (c->self_join)
        (*c->self_join)(m, groupnumber, c->self_join_userdata);

    return 0;
}

static int send_peer_shared_state(GC_Chat *chat, uint32_t peernumber);

/* Handles a sync request packet and sends a response containing the topic, topic len, and peer list.
 * Additionally sends the group shared state in a separate packet.
 *
 * If the group is password protected the password in the request data must first be verified.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_sync_request(const Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                  uint32_t length)
{
    if (length != sizeof(uint32_t) + MAX_GC_PASSWD_SIZE)
        return -1;

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    uint32_t req_num_peers;
    bytes_to_U32(&req_num_peers, data);

    /* Sync request is not necessary */
    if (req_num_peers > 0 && req_num_peers >= get_gc_confirmed_numpeers(chat)) {
        fprintf(stderr, "sync request from %s rejected\n", chat->group[peernumber].nick);
        return 0;
    }

    if (chat->shared_state.passwd_len > 0) {
        uint8_t passwd[MAX_GC_PASSWD_SIZE];
        memcpy(passwd, data + sizeof(uint32_t), MAX_GC_PASSWD_SIZE);

        if (memcmp(chat->shared_state.passwd, passwd, chat->shared_state.passwd_len) != 0)
            return -1;
    }

    uint8_t response[MAX_GC_PACKET_SIZE];
    U32_to_bytes(response, chat->self_public_key_hash);
    uint32_t len = HASH_ID_BYTES;

    if (send_peer_shared_state(chat, peernumber) == -1)
        return -1;

    /* Response packet contains: topic len, topic, peer list */
    U16_to_bytes(response + len, chat->topic_len);
    len += sizeof(uint16_t);
    memcpy(response + len, chat->topic, chat->topic_len);
    len += chat->topic_len;

    size_t packed_addrs_size = (ENC_PUBLIC_KEY + sizeof(IP_Port)) * (chat->numpeers - 1);   /* approx. */

    /* This is the technical limit to the number of peers you can have in a group (TODO: split packet?) */
    if ((HASH_ID_BYTES + packed_addrs_size + sizeof(uint16_t) + chat->topic_len) > MAX_GC_PACKET_SIZE)
        return -1;

    GC_PeerAddress *peer_addrs = calloc(1, sizeof(GC_PeerAddress) * (chat->numpeers - 1));

    if (peer_addrs == NULL)
        return -1;

    uint32_t i, num = 0;

    /* must add self separately because reasons */
    GC_PeerAddress self_addr;
    memcpy(&self_addr.public_key, chat->self_public_key, ENC_PUBLIC_KEY);
    ipport_self_copy(m->dht, &self_addr.ip_port);
    copy_gc_peer_addr(&peer_addrs[num++], &self_addr);

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].public_key_hash != chat->gcc[peernumber].public_key_hash && chat->gcc[i].confirmed)
            copy_gc_peer_addr(&peer_addrs[num++], &chat->gcc[i].addr);
    }

    U32_to_bytes(response + len, num);
    len += sizeof(uint32_t);

    int addrs_len = pack_gc_addresses(response + len, sizeof(response) - len, peer_addrs, num);
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
static void check_gc_sync_status(const GC_Chat *chat, uint32_t peernumber, uint32_t other_num_peers)
{
    if (get_gc_confirmed_numpeers(chat) >= other_num_peers) {
        chat->gcc[peernumber].peer_sync_timer = 0;
        return;
    }

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].peer_sync_timer != 0)
            return;
    }

    chat->gcc[peernumber].peer_sync_timer = unix_time();
}

/* Checks if we have a pending sync request with peernumber and sends a sync request
 * if the timer is up.
 */
#define GROUP_PEER_SYNC_TIMER (GC_PING_INTERVAL * 2)
static void try_gc_peer_sync(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->gcc[peernumber].peer_sync_timer == 0)
        return;

    if (!is_timeout(chat->gcc[peernumber].peer_sync_timer, GROUP_PEER_SYNC_TIMER))
        return;

    if (send_gc_sync_request(chat, peernumber, chat->numpeers) != -1)
        chat->gcc[peernumber].peer_sync_timer = 0;
}

static void self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer);
static int send_gc_peer_info_request(GC_Chat *chat, uint32_t peernumber);

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
    U32_to_bytes(data, chat->self_public_key_hash);
    uint32_t len = HASH_ID_BYTES;

    int peers_len = pack_gc_peer(data + len, sizeof(data) - len, &self);
    len += peers_len;

    if (peers_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in sync_gc_announced_nodes %d\n", peers_len);
        return -1;
    }

    uint16_t i;

    for (i = 0; i < chat->num_addrs; ++i) {
        if (peer_in_chat(chat, chat->addr_list[i].public_key) == -1)
            send_gc_handshake_request(c->messenger, chat->groupnumber, chat->addr_list[i].ip_port,
                                      chat->addr_list[i].public_key, HS_PEER_INFO_EXCHANGE, HJ_PUBLIC);
    }

    return 0;
}

/* Send invite request to peernumber. Invite packet contains your nick and the group password.
 * If no group password is necessary the password field will be ignored by the invitee.
 *
 * Return -1 if fail
 * Return 0 if success
 */
static int send_gc_invite_request(GC_Chat *chat, uint32_t peernumber)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    U32_to_bytes(data, chat->self_public_key_hash);
    uint32_t length = HASH_ID_BYTES;
    U16_to_bytes(data + length, chat->group[0].nick_len);
    length += sizeof(uint16_t);
    memcpy(data + length, chat->group[0].nick, chat->group[0].nick_len);
    length += chat->group[0].nick_len;
    memcpy(data + length, chat->shared_state.passwd, MAX_GC_PASSWD_SIZE);
    length += MAX_GC_PASSWD_SIZE;

    return send_lossless_group_packet(chat, peernumber, data, length, GP_INVITE_REQUEST);
}

/* Return -1 if fail
 * Return 0 if succes
 */
static int send_gc_invite_response(GC_Chat *chat, uint32_t peernumber)
{
    uint32_t length = HASH_ID_BYTES;
    uint8_t  data[length];
    U32_to_bytes(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, peernumber, data, length, GP_INVITE_RESPONSE);
}

/* Return -1 if fail
 * Return 0 if success
 */
static int handle_gc_invite_response(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                     uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state == CS_CONNECTED)
        return 0;

    return send_gc_sync_request(chat, peernumber, 0);
}

static int handle_gc_invite_response_reject(Messenger *m, int groupnumber, const uint8_t *data, uint32_t length)
{
    if (length != sizeof(uint8_t))
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state == CS_CONNECTED)
        return 0;

    uint8_t type = data[0];

    if (type >= GJ_INVALID)
        type = GJ_INVITE_FAILED;

    chat->connection_state = CS_FAILED;

    if (c->rejected)
        (*c->rejected)(m, groupnumber, type, c->rejected_userdata);

    return 0;
}

static int send_gc_invite_response_reject(GC_Chat *chat, uint32_t peernumber, uint8_t type)
{
    uint32_t length = HASH_ID_BYTES + 1;
    uint8_t data[length];
    U32_to_bytes(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, &type, sizeof(uint8_t));

    return send_lossy_group_packet(chat, peernumber, data, length, GP_INVITE_RESPONSE_REJECT);
}

/* Handles an invite request.
 *
 * Verifies that the invitee's nick is not already taken, and that the correct password has
 * been supplied if the group is password protected.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
int handle_gc_invite_request(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                             uint32_t length)
{
    if (length <= sizeof(uint16_t) + MAX_GC_PASSWD_SIZE)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    uint8_t invite_error = GJ_INVITE_FAILED;

    if (get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        invite_error = GJ_GROUP_FULL;
        goto failed_invite;
    }

    GC_Connection *gconn = &chat->gcc[peernumber];

    uint16_t nick_len;
    bytes_to_U16(&nick_len, data);

    if (nick_len > MAX_GC_NICK_SIZE)
        goto failed_invite;

    if (length - sizeof(uint16_t) < nick_len)
        goto failed_invite;

    uint8_t nick[MAX_GC_NICK_SIZE];
    memcpy(nick, data + sizeof(uint16_t), nick_len);

    if (get_nick_peernumber(chat, nick, nick_len) != -1) {
        invite_error = GJ_NICK_TAKEN;
        goto failed_invite;
    }

    if (length - sizeof(uint16_t) - nick_len < MAX_GC_PASSWD_SIZE)
        goto failed_invite;

    if (chat->shared_state.passwd_len > 0) {
        uint8_t passwd[MAX_GC_PASSWD_SIZE];
        memcpy(passwd, data + sizeof(uint16_t) + nick_len, MAX_GC_PASSWD_SIZE);

        if (memcmp(chat->shared_state.passwd, passwd, chat->shared_state.passwd_len) != 0) {
            invite_error = GJ_INVALID_PASSWORD;
            goto failed_invite;
        }
    }

    return send_gc_invite_response(chat, peernumber);

failed_invite:
    send_gc_invite_response_reject(chat, peernumber, invite_error);
    gc_peer_delete(m, groupnumber, peernumber, NULL, 0);

    return -1;
}

/* Creates packet with broadcast header info followed by data of length.
 * Returns length of packet including header.
 */
static uint32_t make_gc_broadcast_header(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t *packet,
                                         uint8_t bc_type)
{
    uint32_t header_len = 0;
    U32_to_bytes(packet, chat->self_public_key_hash);
    header_len += HASH_ID_BYTES;
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
        if (chat->gcc[i].confirmed)
            send_lossless_group_packet(chat, i, packet, packet_len, GP_BROADCAST);
    }

    return 0;
}

static int handle_gc_ping(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    if (length != sizeof(uint32_t) * 2)
        return -1;

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (!chat)
        return -1;

    if (!chat->gcc[peernumber].confirmed)
        return -1;

    chat->gcc[peernumber].last_rcvd_ping = unix_time();

    uint32_t other_num_peers, sstate_version;
    bytes_to_U32(&other_num_peers, data);
    bytes_to_U32(&sstate_version, data + sizeof(uint32_t));

    check_gc_sync_status(chat, peernumber, other_num_peers);

    if (sstate_version < chat->shared_state.version)
        send_peer_shared_state(chat, peernumber);
    else if (sstate_version > chat->shared_state.version)
        send_gc_sync_request(chat, peernumber, 0);

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
    if (length != sizeof(uint8_t))
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (!chat)
        return -1;

    uint8_t status = data[0];

    if (status >= GS_INVALID)
        return -1;

    chat->group[peernumber].status = status;

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

/* Sends self peer info to peernumber. If the group is password protected the request
 * will contain the group password, which the recipient will validate in the respective
 * group message handler.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_self_to_peer(const GC_Session *c, GC_Chat *chat, uint32_t peernumber)
{
    GC_GroupPeer self;
    self_to_peer(c, chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];
    U32_to_bytes(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, SIG_PK(chat->self_public_key), SIG_PUBLIC_KEY);
    memcpy(data + HASH_ID_BYTES + SIG_PUBLIC_KEY, chat->shared_state.passwd, MAX_GC_PASSWD_SIZE);
    uint32_t length = HASH_ID_BYTES + SIG_PUBLIC_KEY + MAX_GC_PASSWD_SIZE;

    int packed_len = pack_gc_peer(data + length, sizeof(data) - length, &self);
    length += packed_len;

    if (packed_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in handle_gc_peer_info_request_request %d\n", packed_len);
        return -1;
    }

    return send_lossless_group_packet(chat, peernumber, data, length, GP_PEER_INFO_RESPONSE);
}

static int handle_gc_peer_info_request(Messenger *m, int groupnumber, uint32_t peernumber)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (!chat->gcc[peernumber].confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers)
        return -1;

    return send_self_to_peer(c, chat, peernumber);
}

static int send_gc_peer_info_request(GC_Chat *chat, uint32_t peernumber)
{
    uint32_t length = HASH_ID_BYTES;
    uint8_t data[length];
    U32_to_bytes(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, peernumber, data, length, GP_PEER_INFO_REQUEST);
}

/* Do peer info exchange with peernumber
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_peer_exchange(const GC_Session *c, GC_Chat *chat, uint32_t peernumber)
{
    int ret1 = send_self_to_peer(c, chat, peernumber);
    int ret2 = send_gc_peer_info_request(chat, peernumber);
    return (ret1 == -1 || ret2 == -1) ? -1 : 0;
}

/* Updates peernumber's info, validates their group role, and sets them as a confirmed peer.
 * If the group is password protected the password must first be validated.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_peer_info_response(Messenger *m, int groupnumber, uint32_t peernumber,
                                        const uint8_t *data, uint32_t length)
{
    if (length <= SIG_PUBLIC_KEY + MAX_GC_PASSWD_SIZE)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    if (!chat->gcc[peernumber].confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers)
        return -1;

    if (chat->shared_state.passwd_len > 0) {
        uint8_t passwd[MAX_GC_PASSWD_SIZE];
        memcpy(passwd, data + SIG_PUBLIC_KEY, sizeof(passwd));

        if (memcmp(chat->shared_state.passwd, passwd, chat->shared_state.passwd_len) != 0)
            return -1;
    }

    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    if (unpack_gc_peer(&peer, data + SIG_PUBLIC_KEY + MAX_GC_PASSWD_SIZE,
                       length - SIG_PUBLIC_KEY - MAX_GC_PASSWD_SIZE) == -1) {
        fprintf(stderr, "unpack_gc_peer failed in handle_gc_peer_info_request\n");
        return -1;
    }

    if (validate_gc_peer_role(chat, peer.role, chat->gcc[peernumber].addr.public_key) == -1) {
        fprintf(stderr, "failed to validate peer role\n");
        return -1;
    }

    if (peer_update(m, groupnumber, &peer, peernumber) == -1) {
        fprintf(stderr, "peer_update() failed in handle_gc_peer_info_request\n");
        return -1;
    }

    bool do_callback = chat->gcc[peernumber].time_added - chat->gcc[0].time_added > 1
                      || chat->gcc[0].time_added - chat->gcc[peernumber].time_added > 1;

    if (do_callback && c->peer_join && !chat->gcc[peernumber].confirmed)
        (*c->peer_join)(m, groupnumber, peernumber, c->peer_join_userdata);

    memcpy(SIG_PK(chat->gcc[peernumber].addr.public_key), data, SIG_PUBLIC_KEY);
    chat->gcc[peernumber].confirmed = true;

    return 0;
}

/* Sends the group shared state and its signature to peernumber.
 *
 * Returns a non-negative integer on success.
 * Returns -1 on failure.
 */
static int send_peer_shared_state(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->shared_state.version == 0)
        return -1;

    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    int length = make_gc_shared_state_packet(chat, packet);

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE)
        return -1;

    return send_lossless_group_packet(chat, peernumber, packet, length, GP_SHARED_STATE);
}

/* Sends the group shared state and signature to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure
 */
static int broadcast_gc_shared_state(GC_Chat *chat)
{
    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    int packet_len = make_gc_shared_state_packet(chat, packet);

    if (packet_len != GC_SHARED_STATE_ENC_PACKET_SIZE)
        return -1;

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed)
            send_lossless_group_packet(chat, i, packet, packet_len, GP_SHARED_STATE);
    }

    return 0;
}

/* If privacy state has been set to public we announce ourselves to the DHT.
 * If privacy state has been set to private we remove our self announcement.
 */
static void handle_privacy_state_change(GC_Session *c, const GC_Chat *chat, uint8_t new_privacy_state)
{
    if (new_privacy_state == GI_PUBLIC)
        group_announce_request(c, chat);
    else if (new_privacy_state == GI_PRIVATE)
        gca_cleanup(c->announce, CHAT_ID(chat->chat_public_key));
}

/* Handles a shared state packet.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_shared_state(Messenger *m, int groupnumber, uint32_t peernumber,
                                  const uint8_t *data, uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE - HASH_ID_BYTES)
        goto on_error;

    uint8_t signature[SIGNATURE_SIZE];
    memcpy(signature, data, SIGNATURE_SIZE);

    const uint8_t *ss_data = data + SIGNATURE_SIZE;

    if (crypto_sign_verify_detached(signature, ss_data, GC_PACKED_SHARED_STATE_SIZE,
                                    SIG_PK(chat->chat_public_key)) == -1)
        goto on_error;

    uint32_t version;
    bytes_to_U32(&version, data + length - sizeof(uint32_t));

    if (version < chat->shared_state.version)
        goto on_error;

    uint8_t old_privacy_state = chat->shared_state.privacy_state;

    unpack_gc_shared_state(&chat->shared_state, ss_data);
    memcpy(chat->shared_state_sig, signature, SIGNATURE_SIZE);

    if (old_privacy_state != chat->shared_state.privacy_state)
        handle_privacy_state_change(c, chat, chat->shared_state.privacy_state);

    return 0;

/* If we don't already have a valid shared state we will automatically try to get another invite.
   Otherwise we attempt to ask a different peer for a sync. */
on_error:
    gc_peer_delete(m, groupnumber, peernumber, NULL, 0);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1)
        return -1;

    return send_gc_sync_request(chat, 1, 0);
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

/* Copies your own nick to nick and returns nick length */
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

/* Copies peernumber's nick to namebuffer.
 *
 * Returns nick length on success.
 * Returns -1 on failure.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peernumber, uint8_t *namebuffer)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    memcpy(namebuffer, chat->group[peernumber].nick, chat->group[peernumber].nick_len);
    return chat->group[peernumber].nick_len;
}

/* Returns peernumber's nick length.
 * Returns -1 on failure.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peernumber)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    return chat->group[peernumber].nick_len;
}

static int handle_bc_nick_change(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *nick,
                                 uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    /* If this happens malicious behaviour is highly suspect */
    if (length == 0 || length > MAX_GC_NICK_SIZE || get_nick_peernumber(chat, nick, length) != -1)
        return gc_peer_delete(m, groupnumber, peernumber, NULL, 0);

    if (c->nick_change)
        (*c->nick_change)(m, groupnumber, peernumber, nick, length, c->nick_change_userdata);

    memcpy(chat->group[peernumber].nick, nick, length);
    chat->group[peernumber].nick_len = length;

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

 /* Copies topic to topicbuffer and returns the topic length. */
int gc_get_topic(const GC_Chat *chat, uint8_t *topicbuffer)
{
    memcpy(topicbuffer, chat->topic, chat->topic_len);
    return chat->topic_len;
}

 /* Returns topic length. */
uint16_t gc_get_topic_size(const GC_Chat *chat)
{
    return chat->topic_len;
}

static int handle_bc_change_topic(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                  uint32_t length)
{
    if (length > MAX_GC_TOPIC_SIZE)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    memcpy(chat->topic, data, length);
    chat->topic_len = length;

    if (c->topic_change)
        (*c->topic_change)(m, groupnumber, peernumber, data, length, c->topic_change_userdata);

    return 0;
}

/* Copies group name to groupname and returns the group name length */
int gc_get_group_name(const GC_Chat *chat, uint8_t *groupname)
{
    memcpy(groupname, chat->shared_state.group_name, chat->shared_state.group_name_len);
    return chat->shared_state.group_name_len;
}

/* Returns group name length */
uint16_t gc_get_group_name_size(const GC_Chat *chat)
{
    return chat->shared_state.group_name_len;
}

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if caller is not the group founder.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *passwd, uint16_t passwd_len)
{
    if (chat->group[0].role != GR_FOUNDER)
        return -2;

    uint16_t oldlen = chat->shared_state.passwd_len;
    uint8_t oldpasswd[oldlen];
    memcpy(oldpasswd, chat->shared_state.passwd, oldlen);

    if (set_gc_password_local(chat, passwd, passwd_len) == -1)
        return -1;

    if (sign_gc_shared_state(chat) == -1) {
        set_gc_password_local(chat, oldpasswd, oldlen);
        return -1;
    }

    return broadcast_gc_shared_state(chat);
}

/* If role is GR_MODERATOR peernumber is promoted to moderator and added to mod_list.
 * If role is GR_USER or GR_OBSERVER peernumber is demoted to respective role and removed from mod_list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int set_peer_moderator(GC_Chat *chat, uint32_t peernumber, uint8_t role)
{
    if (role == GR_FOUNDER || role >= GR_INVALID)
        return -1;

    if (role == GR_MODERATOR) {
        if (chat->group[peernumber].role <= GR_MODERATOR)
            return -1;

        if (add_gc_moderator(chat, peernumber) == -1)
            return -1;

        return 0;
    }

    return remove_gc_moderator(chat, peernumber, role);
}

static uint8_t map_gc_role_mod_event(uint8_t role)
{
    if (role == GR_MODERATOR)
        return MV_MODERATOR;

    if (role == GR_USER)
        return MV_USER;

    if (role == GR_OBSERVER)
        return MV_OBSERVER;

    return MV_INVALID;
}

static int handle_bc_peer_role(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                               uint32_t length)
{
    if (length != sizeof(uint8_t) + ENC_PUBLIC_KEY)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[peernumber].role >= GR_USER)
        return -1;

    uint8_t role = data[0];

    if (role == GR_FOUNDER || role >= GR_INVALID)
        return -1;

    uint8_t target_pk[ENC_PUBLIC_KEY];
    memcpy(target_pk, data + sizeof(uint8_t), ENC_PUBLIC_KEY);

    int target_peernum = peer_in_chat(chat, target_pk);

    if (target_peernum == -1)
        return -1;

    /* Promote a user or observer to moderator, or demote a moderator to user or observer */
    if (role == GR_MODERATOR || (role >= GR_USER && chat->group[target_peernum].role == GR_MODERATOR)) {
        if (chat->group[peernumber].role != GR_FOUNDER)
            return -1;

        if (set_peer_moderator(chat, target_peernum, role) == -1)
            return -1;

        uint8_t mod_event = map_gc_role_mod_event(role);

        if (c->moderation)
            (*c->moderation)(m, groupnumber, peernumber, target_peernum, mod_event, c->moderation_userdata);

        return 0;
    }

    /* Promote an observer to user */
    if (chat->group[target_peernum].role == GR_OBSERVER && role == GR_USER) {
        return -1;
    }

    /* Demote a peer to observer */
    if (role == GR_OBSERVER) {
        return -1;
    }

    return -1;
}

static int send_gc_peer_role(GC_Chat *chat, uint32_t peernumber, uint8_t role)
{
    uint32_t length = sizeof(uint8_t) + ENC_PUBLIC_KEY;
    uint8_t data[length];
    data[0] = role;
    memcpy(data + sizeof(uint8_t), chat->gcc[peernumber].addr.public_key, ENC_PUBLIC_KEY);

    return send_gc_broadcast_packet(chat, data, length, GM_SET_ROLE);
}

/* Sets the role of peernumber. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * If the mod_list is changed a new hash of the updated mod_list will be created
 * and the new shared state will be re-signed and re-distributed to the group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if caller does not have the required permissions.
 */
int gc_set_peer_role(GC_Chat *chat, uint32_t peernumber, uint8_t role)
{
    if (role != GR_MODERATOR && role != GR_USER && role != GR_OBSERVER)
        return -1;

    if (peernumber == 0 || !peernumber_valid(chat, peernumber))
        return -1;

    if (chat->group[0].role >= GR_USER)
        return -2;

    if (chat->group[peernumber].role == GR_FOUNDER)
        return -2;

    /* Promote peer to moderator or demote moderator to user or observer */
    if (role == GR_MODERATOR || (role >= GR_USER && chat->group[peernumber].role == GR_MODERATOR)) {
        if (chat->group[0].role != GR_FOUNDER)
            return -2;

        if (set_peer_moderator(chat, peernumber, role) == -1) {
            fprintf(stderr, "failed to set peer moderator\n");
            return -1;
        }

        // TODO: mod_list hash

        if (sign_gc_shared_state(chat) == -1)
            return -1;

        if (broadcast_gc_shared_state(chat) == -1)
            return -1;
    } else {
        return -1; // TODO other roles
    }

    return send_gc_peer_role(chat, peernumber, role);
}

/* Returns group privacy state */
uint8_t gc_get_privacy_state(const GC_Chat *chat)
{
    return chat->shared_state.privacy_state;
}

/* Sets the group privacy state and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if caller is not the group founder.
 */
int gc_founder_set_privacy_state(Messenger *m, int groupnumber, uint8_t new_privacy_state)
{
    if (new_privacy_state >= GI_INVALID)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[0].role != GR_FOUNDER)
        return -2;

    uint8_t old_privacy_state = chat->shared_state.privacy_state;

    if (new_privacy_state == old_privacy_state)
        return 0;

    chat->shared_state.privacy_state = new_privacy_state;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.privacy_state = old_privacy_state;
        return -1;
    }

    if (new_privacy_state == GI_PRIVATE)
        gca_cleanup(c->announce, CHAT_ID(chat->chat_public_key));
    else
        group_announce_request(c, chat);

    return broadcast_gc_shared_state(chat);
}

/* Returns the group peer limit. */
uint32_t gc_get_max_peers(const GC_Chat *chat)
{
    return chat->shared_state.maxpeers;
}

/* Sets the peer limit to maxpeers and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if caller is not the group founder.
 */
int gc_founder_set_max_peers(GC_Chat *chat, int groupnumber, uint32_t maxpeers)
{
    if (chat->group[0].role != GR_FOUNDER)
        return -2;

    maxpeers = MIN(maxpeers, MAX_GC_NUM_PEERS);
    uint32_t old_maxpeers = chat->shared_state.maxpeers;

    if (maxpeers == chat->shared_state.maxpeers)
        return 0;

    chat->shared_state.maxpeers = maxpeers;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.maxpeers = old_maxpeers;
        return -1;
    }

    return broadcast_gc_shared_state(chat);
}

/* Sends a plain message or an action, depending on type.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
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

    if (chat->gcc[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    if (type == GM_PLAIN_MESSAGE && c->message) {
        (*c->message)(m, groupnumber, peernumber, data, length, c->message_userdata);
    } else if (type == GM_ACTION_MESSAGE && c->action) {
        (*c->action)(m, groupnumber, peernumber, data, length, c->action_userdata);
    }

    return 0;
}

/* Sends a private message to peernumber.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
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

    if (send_lossless_group_packet(chat, peernumber, packet, packet_len, GP_BROADCAST) == -1)
        return -1;

    return 0;
}

static int handle_bc_private_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                     uint32_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE || length == 0)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->gcc[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER)
        return 0;

    if (c->private_message)
        (*c->private_message)(m, groupnumber, peernumber, data, length, c->private_message_userdata);

    return 0;
}

static int handle_bc_mod_event(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                               uint32_t length)
{
    if (length != sizeof(uint8_t) + ENC_PUBLIC_KEY)
        return -1;

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[peernumber].role >= GR_USER)
        return -1;

    uint8_t mod_event = data[0];

    if (mod_event != MV_KICK)  // TODO: other types
        return -1;

    uint8_t target_pk[ENC_PUBLIC_KEY];
    memcpy(target_pk, data + sizeof(uint8_t), ENC_PUBLIC_KEY);

    int target_peernum = peer_in_chat(chat, target_pk);

    if (!peernumber_valid(chat, target_peernum))
        return -1;

    if (chat->group[target_peernum].role == GR_FOUNDER)
        return 0;

    if (chat->group[target_peernum].role == GR_MODERATOR && chat->group[peernumber].role != GR_FOUNDER)
        return 0;

    if (target_peernum == 0) {
        group_delete(c, chat);
        return 0;
    }

    if (c->moderation)
        (*c->moderation)(m, groupnumber, peernumber, target_peernum, MV_KICK, c->moderation_userdata);

    chat->gcc[target_peernum].confirmed = false;  /* prevents the normal peer exit callback */

    return gc_peer_delete(m, groupnumber, target_peernum, NULL, 0);
}

static int send_gc_mod_event(GC_Chat *chat, uint32_t peernumber, uint8_t mod_event)
{
    uint32_t length = sizeof(uint8_t) + ENC_PUBLIC_KEY;
    uint8_t packet[length];
    packet[0] = mod_event;
    memcpy(packet + sizeof(uint8_t), chat->gcc[peernumber].addr.public_key, ENC_PUBLIC_KEY);
    return send_gc_broadcast_packet(chat, packet, length, GM_MOD_EVENT);
}

/* Instructs all peers to remove peernumber from their peerlist.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if the caller does not have kick permissions.
 */
int send_gc_kick_peer(Messenger *m, int groupnumber, uint32_t peernumber)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->group[0].role >= GR_USER || chat->group[peernumber].role == GR_FOUNDER)
        return -2;

    if (peernumber == 0)
        return -1;

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (send_gc_mod_event(chat, peernumber, MV_KICK) == -1)
        return -1;

    return gc_peer_delete(m, groupnumber, peernumber, NULL, 0);
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

    if (chat->group[0].role > GR_MODERATOR)
        return -1;

    uint8_t certificate[ROLE_CERT_SIGNED_SIZE];
    if (make_role_cert(chat->self_secret_key, chat->self_public_key, chat->gcc[peernumber].addr.public_key,
                       certificate, cert_type) == -1)
        return -1;

    return send_gc_broadcast_packet(chat, certificate, ROLE_CERT_SIGNED_SIZE, GM_OP_CERTIFICATE);

}

static int process_role_cert(Messenger *m, int groupnumber, const uint8_t *certificate);

static int handle_bc_op_certificate(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    if (length != ROLE_CERT_SIGNED_SIZE)
        return -1;

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

    return 0;
}

#define VALID_GC_MESSAGE_ACK(a, b) (((a) == 0) || ((b) == 0))

/* If read_id is non-zero sends a read-receipt for read_id's packet.
 * If request_id is non-zero sends a request for the respective id's packet.
 */
int gc_send_message_ack(const GC_Chat *chat, uint32_t peernumber, uint64_t read_id, uint64_t request_id)
{
    if (!VALID_GC_MESSAGE_ACK(read_id, request_id))
        return -1;

    uint32_t length = HASH_ID_BYTES + (MESSAGE_ID_BYTES * 2);
    uint8_t data[length];
    U32_to_bytes(data, chat->self_public_key_hash);
    U64_to_bytes(data + HASH_ID_BYTES, read_id);
    U64_to_bytes(data + HASH_ID_BYTES + MESSAGE_ID_BYTES, request_id);

    return send_lossy_group_packet(chat, peernumber, data, length, GP_MESSAGE_ACK);
}

/* If packet contains a non-zero request_id we try to resend its respective packet.
 * If packet contains a non-zero read_id we remove the packet from our send array.
 *
 * Returns non-negative value on success.
 * Return -1 if error or we fail to send a packet in case of a request response.
 */
static int handle_gc_message_ack(GC_Chat *chat, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    if (length != MESSAGE_ID_BYTES * 2)
        return -1;

    uint64_t read_id, request_id;
    bytes_to_U64(&read_id, data);
    bytes_to_U64(&request_id, data + MESSAGE_ID_BYTES);

    if (!VALID_GC_MESSAGE_ACK(read_id, request_id))
        return -1;

    if (read_id > 0)
        return gcc_handle_ack(&chat->gcc[peernumber], read_id);

    GC_Connection *gconn = &chat->gcc[peernumber];
    uint64_t tm = unix_time();
    uint16_t idx = get_ary_index(request_id);

    /* re-send requested packet */
    if (gconn->send_ary[idx].message_id == request_id
        && (gconn->send_ary[idx].last_send_try != tm || gconn->send_ary[idx].time_added == tm)) {
        gconn->send_ary[idx].last_send_try = tm;
        return sendpacket(chat->net, gconn->addr.ip_port, gconn->send_ary[idx].data, gconn->send_ary[idx].data_length);
    }

    return -1;
}

/* Sends a handshake response ack to peernumber.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int gc_send_hs_response_ack(GC_Chat *chat, uint32_t peernumber)
{
    uint32_t length = HASH_ID_BYTES;
    uint8_t data[length];
    U32_to_bytes(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, peernumber, data, length, GP_HS_RESPONSE_ACK);
}

/* Handles a handshake response ack.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_hs_response_ack(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                     uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    GC_Connection *gconn = &chat->gcc[peernumber];
    gconn->handshaked = true;

    return gcc_handle_ack(gconn, 1);
}

int gc_toggle_ignore(GC_Chat *chat, uint32_t peernumber, bool ignore)
{
    if (!peernumber_valid(chat, peernumber))
        return -1;

    chat->gcc[peernumber].ignore = ignore;
    return 0;
}

static int handle_gc_broadcast(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                               uint32_t length)
{
    if (length < 1 + TIME_STAMP_SIZE)
        return -1;

    GC_Session *c = m->group_handler;

    if (!c)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (chat->connection_state != CS_CONNECTED)
        return -1;

    uint8_t broadcast_type;
    memcpy(&broadcast_type, data, sizeof(uint8_t));

    if (!chat->gcc[peernumber].confirmed)
        return -1;

    uint32_t m_len = length - (1 + TIME_STAMP_SIZE);
    uint8_t message[m_len];
    memcpy(message, data + 1 + TIME_STAMP_SIZE, m_len);

    switch (broadcast_type) {
        case GM_STATUS:
            return handle_bc_change_status(m, groupnumber, peernumber, message, m_len);
        case GM_CHANGE_NICK:
            return handle_bc_nick_change(m, groupnumber, peernumber, message, m_len);
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
        case GM_MOD_EVENT:
            return handle_bc_mod_event(m, groupnumber, peernumber, message, m_len);
        case GM_SET_ROLE:
            return handle_bc_peer_role(m, groupnumber, peernumber, message, m_len);
        default:
            fprintf(stderr, "Warning: handle_gc_broadcast received an invalid broadcast type %u\n", broadcast_type);
            return -1;
    }

    return -1;
}

/* Decrypts data of length using self secret key and sender's public key.
 * data must have room for GC_PLAIN_HS_PACKET_SIZE bytes.
 *
 * Returns length of plaintext data on success.
 * Returns -1 on failure.
 */
static int uwrap_group_handshake_packet(const uint8_t *self_sk, uint8_t *sender_pk, uint8_t *plain,
                                        const uint8_t *packet, uint16_t length)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(sender_pk, packet + sizeof(uint8_t) + HASH_ID_BYTES, ENC_PUBLIC_KEY);
    memcpy(nonce, packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);

    int plain_len = decrypt_data(sender_pk, self_sk, nonce,
                                 packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES,
                                 length - (sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES),
                                 plain);

    if (plain_len != GC_PLAIN_HS_PACKET_SIZE) {
        fprintf(stderr, "decrypt handshake request failed (len: %d)\n", plain_len);
        return -1;
    }

    return plain_len;
}

/* Encrypts data of length using the peer's shared key a new nonce. Packet must have room
 * for GC_ENCRYPTED_HS_PACKET_SIZE bytes.
 *
 * Adds plaintext header consisting of: packet identifier, chat_id_hash, self public key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int wrap_group_handshake_packet(const uint8_t *self_pk, const uint8_t *self_sk, const uint8_t *sender_pk,
                                       uint8_t *packet, const uint8_t *data, uint16_t length, uint32_t chat_id_hash)
{
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[length + crypto_box_MACBYTES];
    int enc_len = encrypt_data(sender_pk, self_sk, nonce, data, length, encrypt);

    if (enc_len != sizeof(encrypt)) {
        fprintf(stderr, "encrypt handshake request failed (len: %d)\n", enc_len);
        return -1;
    }

    packet[0] = NET_PACKET_GC_HANDSHAKE;
    U32_to_bytes(packet + sizeof(uint8_t), chat_id_hash);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES, self_pk, ENC_PUBLIC_KEY);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES, encrypt, enc_len);

    return sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + enc_len;
}

/* Sends a handshake packet where handshake_type is GH_REQUEST or GH_RESPONSE.
 *
 * Returns size of packet sent on success.
 * Returns -1 on failure.
 */
static int send_gc_handshake_packet(GC_Chat *chat, uint32_t peernumber, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t join_type)
{
    uint8_t data[GC_PLAIN_HS_PACKET_SIZE];
    data[0] = handshake_type;
    uint16_t length = sizeof(uint8_t);
    U32_to_bytes(data + length, chat->self_public_key_hash);
    length += HASH_ID_BYTES;
    memcpy(data + length, chat->gcc[peernumber].session_public_key, ENC_PUBLIC_KEY);
    length += ENC_PUBLIC_KEY;
    memcpy(data + length, SIG_SK(chat->self_public_key), SIG_PUBLIC_KEY);
    length += SIG_PUBLIC_KEY;
    memcpy(data + length, &request_type, sizeof(uint8_t));
    length += sizeof(uint8_t);
    memcpy(data + length, &join_type, sizeof(uint8_t));
    length += sizeof(uint8_t);

    uint8_t packet[GC_ENCRYPTED_HS_PACKET_SIZE];
    int enc_len = wrap_group_handshake_packet(chat->self_public_key, chat->self_secret_key,
                                              chat->gcc[peernumber].addr.public_key, packet, data, length,
                                              chat->chat_id_hash);
    if (enc_len != GC_ENCRYPTED_HS_PACKET_SIZE)
        return -1;

    if (gcc_add_send_ary(chat, packet, enc_len, peernumber, -1) == -1)
        return -1;

    return sendpacket(chat->net, chat->gcc[peernumber].addr.ip_port, packet, enc_len);
}

/* Initiates a handshake request with a peer.
 * request_type should be one of GROUP_HANDSHAKE_REQUEST_TYPE.
 * join_type should be HJ_PUBLIC if we found the group via DHT, otherwise HJ_PRIVATE.
 *
 * Returns peernumber of newly added peer on success.
 * Returns -1 on failure.
 */
static int send_gc_handshake_request(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *public_key,
                                     uint8_t request_type, uint8_t join_type)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (!chat)
        return -1;

    if (id_equal(chat->self_public_key, public_key))
        return -1;

    int peernumber = peer_add(m, groupnumber, &ipp, public_key);

    if (peernumber == -1)
        return -1;

    if (send_gc_handshake_packet(chat, peernumber, GH_REQUEST, request_type, join_type) == -1)
        return -1;

    return peernumber;
}

/* Handles a handshake response packet and takes appropriate action depending on the value of request_type.
 *
 * Returns the size of packet sent on success.
 * Returns -1 on faillure.
 */
static int handle_gc_handshake_response(Messenger *m, int groupnumber, const uint8_t *sender_pk,
                                        const uint8_t *data, uint16_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (!chat)
        return -1;

    int peernumber = peer_in_chat(chat, sender_pk);

    if (peernumber == -1)
        return -1;

    GC_Connection *gconn = &chat->gcc[peernumber];

    uint8_t sender_session_pk[ENC_PUBLIC_KEY];
    memcpy(sender_session_pk, data, ENC_PUBLIC_KEY);
    encrypt_precompute(sender_session_pk, gconn->session_secret_key, gconn->shared_key);

    memcpy(SIG_PK(chat->gcc[peernumber].addr.public_key), data + ENC_PUBLIC_KEY, SIG_PUBLIC_KEY);
    uint8_t request_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY];

    /* This packet is an implied handshake request acknowledgement */
    gcc_handle_ack(gconn, 1);
    ++gconn->recv_message_id;

    gconn->handshaked = true;
    gc_send_hs_response_ack(chat, peernumber);

    switch (request_type) {
        case HS_INVITE_REQUEST:
            return send_gc_invite_request(chat, peernumber);
        case HS_PEER_INFO_EXCHANGE:
            return send_gc_peer_exchange(m->group_handler, chat, peernumber);
        default:
            fprintf(stderr, "Warning: received invalid request type in handle_gc_handshake_response\n");
            return -1;
    }
}

static int send_gc_handshake_response(GC_Chat *chat, uint32_t peernumber, uint8_t request_type)
{
    return send_gc_handshake_packet(chat, peernumber, GH_RESPONSE, request_type, 0);
}

/* Handles handshake request packets.
 * Peer is added to peerlist and a lossless connection is established.
 *
 * Return non-negative value on success.
 * Return -1 on failure.
 */
#define GC_NEW_PEER_CONNECTION_LIMIT 5
static int handle_gc_handshake_request(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *sender_pk,
                                       const uint8_t *data, uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (!chat)
        return -1;

    if (chat->connection_state == CS_FAILED)
        return -1;

    if (chat->shared_state.version == 0)
        return -1;

    if (chat->connection_O_metre >= GC_NEW_PEER_CONNECTION_LIMIT) {
        chat->block_handshakes = true;
        return -1;
    }

    ++chat->connection_O_metre;

    int peer_exists = peer_in_chat(chat, sender_pk);

    if (peer_exists != -1)
        gc_peer_delete(m, groupnumber, peer_exists, NULL, 0);

    int peernumber = peer_add(m, groupnumber, &ipp, sender_pk);

    if (peernumber == -1) {
        fprintf(stderr, "peer_add failed in handle_gc_handshake_request\n");
        return -1;
    }

    GC_Connection *gconn = &chat->gcc[peernumber];

    uint8_t sender_session_pk[ENC_PUBLIC_KEY];
    memcpy(sender_session_pk, data, ENC_PUBLIC_KEY);

    encrypt_precompute(sender_session_pk, gconn->session_secret_key, gconn->shared_key);

    memcpy(SIG_PK(gconn->addr.public_key), data + ENC_PUBLIC_KEY, SIG_PUBLIC_KEY);

    uint8_t request_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY];
    uint8_t join_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 1];

    if (join_type == HJ_PUBLIC && chat->shared_state.privacy_state != GI_PUBLIC) {
        gc_peer_delete(m, groupnumber, peernumber, NULL, 0);
        return -1;
    }

    ++gconn->recv_message_id;

    return send_gc_handshake_response(chat, peernumber, request_type);
}

static int handle_gc_handshake_packet(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length != GC_ENCRYPTED_HS_PACKET_SIZE)
        return -1;

    uint32_t chat_id_hash;
    bytes_to_U32(&chat_id_hash, packet + 1);

    Messenger *m = object;
    GC_Chat* chat = get_chat_by_hash(m->group_handler, chat_id_hash);

    if (!chat)
        return -1;

    if (chat->connection_state == CS_FAILED)
        return -1;

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    uint8_t data[GC_PLAIN_HS_PACKET_SIZE];

    int plain_len = uwrap_group_handshake_packet(chat->self_secret_key, sender_pk, data, packet, length);

    if (plain_len != GC_PLAIN_HS_PACKET_SIZE)
        return -1;

    uint8_t handshake_type = data[0];

    uint32_t public_key_hash;
    bytes_to_U32(&public_key_hash, data + 1);

    if (public_key_hash != get_peer_key_hash(sender_pk))
        return -1;

    const uint8_t *real_data = data + (sizeof(uint8_t) + HASH_ID_BYTES);
    uint16_t real_len = plain_len - (sizeof(uint8_t) - HASH_ID_BYTES);

    switch (handshake_type) {
        case GH_REQUEST:
            return handle_gc_handshake_request(m, chat->groupnumber, ipp, sender_pk, real_data, real_len);
        case GH_RESPONSE:
            return handle_gc_handshake_response(m, chat->groupnumber, sender_pk, real_data, real_len);
        default:
            return -1;
    }
}

int handle_gc_lossless_helper(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type)
{
    switch (packet_type) {
        case GP_BROADCAST:
            return handle_gc_broadcast(m, groupnumber, peernumber, data, length);
        case GP_PEER_INFO_RESPONSE:
            return handle_gc_peer_info_response(m, groupnumber, peernumber, data, length);
        case GP_PEER_INFO_REQUEST:
            return handle_gc_peer_info_request(m, groupnumber, peernumber);
        case GP_SYNC_REQUEST:
            return handle_gc_sync_request(m, groupnumber, peernumber, data, length);
        case GP_SYNC_RESPONSE:
            return handle_gc_sync_response(m, groupnumber, peernumber, data, length);
        case GP_INVITE_REQUEST:
            return handle_gc_invite_request(m, groupnumber, peernumber, data, length);
        case GP_INVITE_RESPONSE:
            return handle_gc_invite_response(m, groupnumber, peernumber, data, length);
        case GP_SHARED_STATE:
            return handle_gc_shared_state(m, groupnumber, peernumber, data, length);
        case GP_HS_RESPONSE_ACK:
            return handle_gc_hs_response_ack(m, groupnumber, peernumber, data, length);
        default:
            fprintf(stderr, "Warning: handling invalid lossless group packet type %u\n", packet_type);
            return -1;
    }
}

/* Handles lossless groupchat message packets.
 *
 * return non-negative value if packet is handled correctly.
 * return -1 on failure.
 */
static int handle_gc_lossless_message(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_GC_LOSSLESS_PACKET_SIZE || length > MAX_GC_PACKET_SIZE)
        return -1;

    uint32_t chat_id_hash;
    bytes_to_U32(&chat_id_hash, packet + 1);

    Messenger *m = object;
    GC_Chat* chat = get_chat_by_hash(m->group_handler, chat_id_hash);

    if (!chat)
        return -1;

    if (chat->connection_state == CS_FAILED)
        return -1;

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);

    int peernumber = peer_in_chat(chat, sender_pk);

    if (!peernumber_valid(chat, peernumber))
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;
    uint64_t message_id;

    int len = unwrap_group_packet(chat->gcc[peernumber].shared_key, data, &message_id, &packet_type, packet, length);

    if (len <= 0)
        return -1;

    if (packet_type != GP_HS_RESPONSE_ACK && !chat->gcc[peernumber].handshaked)
        return -1;

    uint32_t sender_pk_hash;
    bytes_to_U32(&sender_pk_hash, data);

    if (!peer_pk_hash_match(chat, peernumber, sender_pk_hash)) {
        fprintf(stderr, "peer_pk_hash_match returned false in handle_gc_lossless_message (type %u)\n", packet_type);
        return -1;
    }

    const uint8_t *real_data = data + HASH_ID_BYTES;
    uint16_t real_len = len - HASH_ID_BYTES;

    int lossless_ret = gcc_handle_recv_message(chat, peernumber, data, real_len, packet_type, message_id);

    if (lossless_ret == -1) {
        fprintf(stderr, "failed to handle packet %lu (type %u)\n", message_id, packet_type);
        return -1;
    }

    /* Duplicate packet */
    if (lossless_ret == 0) {
        fprintf(stderr, "got duplicate packet %lu (type %u)\n", message_id, packet_type);
        return gc_send_message_ack(chat, peernumber, message_id, 0);
    }

    /* request missing packet */
    if (lossless_ret == 1) {
        fprintf(stderr, "recieved out of order packet. expeceted %lu, got %lu\n", chat->gcc[peernumber].recv_message_id + 1, message_id);
        return gc_send_message_ack(chat, peernumber, 0, chat->gcc[peernumber].recv_message_id + 1);
    }

    int ret = handle_gc_lossless_helper(m, chat->groupnumber, peernumber, real_data, real_len, message_id, packet_type);

    if (ret == -1) {
        fprintf(stderr, "lossless handler failed (type %u)\n", packet_type);
        return -1;
    }

    if (lossless_ret == 2 && peer_in_chat(chat, sender_pk) != -1) {   /* check again in case peer was deleted */
        gc_send_message_ack(chat, peernumber, message_id, 0);
        gcc_check_recv_ary(m, chat->groupnumber, peernumber);
    }

    return ret;
}

/* Handles lossy groupchat message packets.
 *
 * return non-negative value if packet is handled correctly.
 * return -1 on failure.
 */
static int handle_gc_lossy_message(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length)
{
    if (length < MIN_GC_LOSSY_PACKET_SIZE || length > MAX_GC_PACKET_SIZE)
        return -1;

    uint32_t chat_id_hash;
    bytes_to_U32(&chat_id_hash, packet + 1);

    Messenger *m = object;
    GC_Chat* chat = get_chat_by_hash(m->group_handler, chat_id_hash);

    if (!chat) {
        fprintf(stderr, "get_chat_by_hash failed in handle_gc_lossy_message (type %u)\n", packet[0]);
        return -1;
    }

    if (chat->connection_state == CS_FAILED)
        return -1;

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);

    int peernumber = peer_in_chat(chat, sender_pk);

    if (!peernumber_valid(chat, peernumber))
        return -1;

    if (!chat->gcc[peernumber].handshaked)
        return -1;

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;

    int len = unwrap_group_packet(chat->gcc[peernumber].shared_key, data, NULL, &packet_type, packet, length);
    if (len <= 0)
        return -1;

    uint32_t sender_pk_hash;
    bytes_to_U32(&sender_pk_hash, data);

    const uint8_t *real_data = data + HASH_ID_BYTES;
    len -= HASH_ID_BYTES;

    if (!peer_pk_hash_match(chat, peernumber, sender_pk_hash)) {
        fprintf(stderr, "peer_pk_hash_match returned false in handle_gc_lossy_message\n");
        return -1;
    }

    int ret = -1;

    switch (packet_type) {
        case GP_MESSAGE_ACK:
            ret = handle_gc_message_ack(chat, peernumber, real_data, len);
            break;
        case GP_PING:
            ret = handle_gc_ping(m, chat->groupnumber, peernumber, real_data, len);
            break;
        case GP_INVITE_RESPONSE_REJECT:
            ret = handle_gc_invite_response_reject(m, chat->groupnumber, real_data, len);
            break;
        default:
            fprintf(stderr, "Warning: handling invalid lossy group packet type %u\n", packet_type);
            return -1;
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

void gc_callback_moderation(Messenger *m, void (*function)(Messenger *m, int, uint32_t, uint32_t, unsigned int,
                            void *), void *userdata)
{
    GC_Session *c = m->group_handler;
    c->moderation = function;
    c->moderation_userdata = userdata;
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

/* Make role certificate.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int make_role_cert(const uint8_t *secret_key, const uint8_t *public_key, const uint8_t *target_pub_key,
                          uint8_t *certificate, uint8_t cert_type)
{
    if (cert_type >= GC_INVALID)
        return -1;

    uint8_t buf[ROLE_CERT_SIGNED_SIZE];
    buf[0] = cert_type;
    memcpy(buf + 1, target_pub_key, EXT_PUBLIC_KEY);

    return sign_certificate(buf, 1 + EXT_PUBLIC_KEY, secret_key, public_key, certificate);
}

/* Return -1 if certificate is corrupted
 * Return 0 if certificate is consistent
 */
static int verify_cert_integrity(const uint8_t *certificate)
{
    uint8_t cert_type = certificate[0];

    if (cert_type >= GC_INVALID)
        return -1;

    uint8_t source_pk[SIG_PUBLIC_KEY];
    memcpy(source_pk, SIG_PK(CERT_SOURCE_KEY(certificate)), SIG_PUBLIC_KEY);

    if (crypto_sign_verify_detached(certificate + ROLE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    certificate, ROLE_CERT_SIGNED_SIZE - SIGNATURE_SIZE,
                                    source_pk) != 0)
        return -1;


    return 0;
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
    if (chat->group[src].role > GR_MODERATOR)
        return -1;

    /* Check if certificate is for us.
     * Note: Attempts to circumvent certficiates by modifying this code
     * will not have any effect on other peers in the group.
     */
    if (memcmp(target_pk, chat->self_public_key, EXT_PUBLIC_KEY) == 0) {
        if (chat->group[0].role == GR_FOUNDER)
            return -1;

        switch (cert_type) {
            case GC_PROMOTE_OP:
                if (chat->group[0].role == GR_MODERATOR)
                    return -1;

                chat->group[0].role = GR_MODERATOR;
                break;

            case GC_REVOKE_OP:
                if (chat->group[0].role != GR_MODERATOR)
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
            if (chat->group[trg].role == GR_MODERATOR)
                return -1;

            chat->group[trg].role = GR_MODERATOR;
            break;

        case GC_REVOKE_OP:
            if (chat->group[trg].role != GR_MODERATOR)
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
    if (c->peer_exit && chat->gcc[peernumber].confirmed)
        (*c->peer_exit)(m, groupnumber, peernumber, data, length, c->peer_exit_userdata);

    gca_peer_cleanup(m->group_handler->announce, CHAT_ID(chat->chat_public_key), chat->gcc[peernumber].addr.public_key);
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

/* Updates peernumber's peer info
 *
 * Returns peernumber on success.
 * Returns -1 on failure.
 */
static int peer_update(Messenger *m, int groupnumber, GC_GroupPeer *peer, uint32_t peernumber)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (peer->nick_len == 0)
        return -1;

    int nick_num = get_nick_peernumber(chat, peer->nick, peer->nick_len);

    if (nick_num != -1 && nick_num != peernumber) {   /* duplicate nick */
        if (c->peerlist_update)
            (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

        gc_peer_delete(m, groupnumber, peernumber, NULL, 0);
        return -1;
    }

    memcpy(&chat->group[peernumber], peer, sizeof(GC_GroupPeer));

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return peernumber;
}

/* Adds a new peer to groupnumber's peer list.
 *
 * Return peernumber if success.
 * Return -1 if fail.
 */
static int peer_add(Messenger *m, int groupnumber, IP_Port *ipp, const uint8_t *public_key)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    if (peer_in_chat(chat, public_key) != -1)
        return -1;

    GC_Connection *tmp_gcc = realloc(chat->gcc, sizeof(GC_Connection) * (chat->numpeers + 1));

    if (tmp_gcc == NULL)
        return -1;

    GC_GroupPeer *tmp_group = realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (tmp_group == NULL)
        return -1;

    int peernumber = chat->numpeers++;

    memset(&tmp_group[peernumber], 0, sizeof(GC_GroupPeer));
    memset(&tmp_gcc[peernumber], 0, sizeof(GC_Connection));

    chat->gcc = tmp_gcc;
    chat->group = tmp_group;

    GC_Connection *gconn = &chat->gcc[peernumber];

    if (ipp)
        ipport_copy(&gconn->addr.ip_port, ipp);

    crypto_box_keypair(gconn->session_public_key, gconn->session_secret_key);
    memcpy(gconn->addr.public_key, public_key, ENC_PUBLIC_KEY);  /* we get the sig key in the handshake */
    gconn->public_key_hash = get_peer_key_hash(public_key);
    gconn->last_rcvd_ping = unix_time();
    gconn->time_added = unix_time();
    gconn->send_message_id = 1;
    gconn->send_ary_start = 1;
    gconn->recv_message_id = 0;

    if (c->peerlist_update)
        (*c->peerlist_update)(m, groupnumber, c->peerlist_update_userdata);

    return peernumber;
}

/* Copies own peer data to peer */
static void self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer)
{
    memset(peer, 0, sizeof(GC_GroupPeer));
    memcpy(peer->role_certificate, chat->group[0].role_certificate, ROLE_CERT_SIGNED_SIZE);
    memcpy(peer->nick, chat->group[0].nick, chat->group[0].nick_len);
    peer->nick_len = chat->group[0].nick_len;
    peer->status = chat->group[0].status;
    peer->role = chat->group[0].role;
}

/* Returns true if we haven't received a ping from this peer after T.
 * T depends on whether or not the peer has been confirmed.
 */
static bool peer_timed_out(const GC_Chat *chat, uint32_t peernumber)
{
    return is_timeout(chat->gcc[peernumber].last_rcvd_ping, chat->gcc[peernumber].confirmed
                                                            ? GC_CONFIRMED_PEER_TIMEOUT
                                                            : GC_UNCONFRIMED_PEER_TIMEOUT);
}

static void do_peer_connections(Messenger *m, int groupnumber)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return;

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (peer_timed_out(chat, i)) {
            gc_peer_delete(m, groupnumber, i, (uint8_t *) "Timed out", 9);
        } else {
            try_gc_peer_sync(chat, i);
            gcc_resend_packets(m, chat, i);   // This function may delete the peer
        }

        if (i >= chat->numpeers)
            break;
    }
}

/* Ping packet includes your confirmed peer count and shared state version for syncing purposes */
static void ping_group(GC_Chat *chat)
{
    if (!is_timeout(chat->last_sent_ping_time, GC_PING_INTERVAL))
        return;

    uint32_t length = HASH_ID_BYTES + sizeof(uint32_t) * 2;
    uint8_t data[length];

    uint32_t num_confirmed_peers = get_gc_confirmed_numpeers(chat);
    U32_to_bytes(data, chat->self_public_key_hash);
    U32_to_bytes(data + HASH_ID_BYTES, num_confirmed_peers);
    U32_to_bytes(data + HASH_ID_BYTES + sizeof(uint32_t), chat->shared_state.version);

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed)
            send_lossy_group_packet(chat, i, data, length, GP_PING);
    }

    chat->last_sent_ping_time = unix_time();
}

/* Searches the DHT for nodes belonging to the group periodically in case of a split group.
 * The search frequency is relative to the number of peers in the group.
 */
#define GROUP_SEARCH_ANNOUNCE_INTERVAL 300
static void search_gc_announce(GC_Session *c, GC_Chat *chat)
{
    if (!is_timeout(chat->announce_search_timer, GROUP_SEARCH_ANNOUNCE_INTERVAL))
        return;

    chat->announce_search_timer = unix_time();
    uint32_t cnumpeers = get_gc_confirmed_numpeers(chat);

    if (random_int_range(cnumpeers) == 0) {
        /* DHT response/sync procedure is handled in gc_update_addrs() */
        group_get_nodes_request(c, chat);
    }
}

static void do_new_connection_cooldown(GC_Chat *chat)
{
    if (chat->connection_O_metre == 0)
        return;

    uint64_t tm = unix_time();

    if (chat->connection_cooldown_timer < tm) {
        chat->connection_cooldown_timer = tm;
        --chat->connection_O_metre;

        if (chat->connection_O_metre == 0) {
            chat->block_handshakes = false;
        }
    }
}

#define GROUP_JOIN_ATTEMPT_INTERVAL 3
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
                do_new_connection_cooldown(chat);
                search_gc_announce(c, chat);
                break;
            }

            case CS_CONNECTING: {
                if (chat->get_nodes_attempts > GROUP_MAX_GET_NODES_ATTEMPTS) {
                    self_gc_connected(chat);

                    /* If we can't get an invite we assume the group is empty */
                    if (chat->shared_state.version == 0 || group_announce_request(c, chat) == -1) {
                        if (c->rejected)
                            (*c->rejected)(c->messenger, i, GJ_INVITE_FAILED, c->rejected_userdata);

                        chat->connection_state = CS_FAILED;
                    }

                    break;
                }

                if (is_timeout(chat->last_get_nodes_attempt, GROUP_GET_NEW_NODES_INTERVAL)) {
                    ++chat->get_nodes_attempts;
                    chat->last_get_nodes_attempt = unix_time();
                    group_get_nodes_request(c, chat);
                }

                chat->connection_state = CS_DISCONNECTED;
                break;
            }

            case CS_DISCONNECTED: {
                if (chat->num_addrs && is_timeout(chat->last_join_attempt, GROUP_JOIN_ATTEMPT_INTERVAL)) {
                    send_gc_handshake_request(c->messenger, i, chat->addr_list[chat->addrs_idx].ip_port,
                                              chat->addr_list[chat->addrs_idx].public_key, HS_INVITE_REQUEST,
                                              chat->join_type);

                    chat->last_join_attempt = unix_time();
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
    chat->last_get_nodes_attempt = unix_time();
    chat->last_sent_ping_time = unix_time();
    chat->announce_search_timer = unix_time();

    create_extended_keypair(chat->self_public_key, chat->self_secret_key);

    if (peer_add(m, groupnumber, NULL, chat->self_public_key) != 0) {    /* you are always peernumber/index 0 */
        group_delete(c, chat);
        return -1;
    }

    memcpy(chat->group[0].nick, m->name, m->name_length);
    chat->group[0].nick_len = m->name_length;
    chat->group[0].status = m->userstatus;
    chat->group[0].role = founder ? GR_FOUNDER : GR_USER;
    chat->gcc[0].confirmed = true;
    chat->self_public_key_hash = chat->gcc[0].public_key_hash;

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

    uint64_t tm = unix_time();

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[groupnumber];

    chat->groupnumber = groupnumber;
    chat->numpeers = 0;
    chat->connection_state = CS_DISCONNECTED;
    chat->join_type = HJ_PRIVATE;
    chat->net = m->net;
    chat->last_get_nodes_attempt = tm;
    chat->last_sent_ping_time = tm;
    chat->announce_search_timer = tm;

    memcpy(chat->shared_state.founder_public_key, save->founder_public_key, ENC_PUBLIC_KEY);
    chat->shared_state.group_name_len = ntohs(save->group_name_len);
    memcpy(chat->shared_state.group_name, save->group_name, MAX_GC_GROUP_NAME_SIZE);
    chat->shared_state.privacy_state = save->privacy_state;
    chat->shared_state.maxpeers = ntohs(save->maxpeers);
    chat->shared_state.passwd_len = ntohs(save->passwd_len);
    memcpy(chat->shared_state.passwd, save->passwd, MAX_GC_PASSWD_SIZE);
    memcpy(chat->shared_state.mod_list_hash, save->mod_list_hash, GC_MOD_LIST_HASH_SIZE);
    chat->shared_state.version = ntohl(save->sstate_version);
    memcpy(chat->shared_state_sig, save->sstate_signature, SIGNATURE_SIZE);

    memcpy(chat->chat_public_key, save->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->chat_secret_key, save->chat_secret_key, EXT_SECRET_KEY);
    chat->topic_len = ntohs(save->topic_len);
    memcpy(chat->topic, save->topic, MAX_GC_TOPIC_SIZE);

    memcpy(chat->self_public_key, save->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->self_secret_key, save->self_secret_key, EXT_SECRET_KEY);
    chat->chat_id_hash = get_chat_id_hash(CHAT_ID(chat->chat_public_key));
    chat->self_public_key_hash = get_peer_key_hash(chat->self_public_key);

    if (peer_add(m, groupnumber, NULL, save->self_public_key) != 0)
        return -1;

    memcpy(chat->group[0].role_certificate, save->self_role_cert, ROLE_CERT_SIGNED_SIZE);
    memcpy(chat->group[0].nick, save->self_nick, MAX_GC_NICK_SIZE);
    chat->group[0].nick_len = ntohs(save->self_nick_len);
    chat->group[0].role = save->self_role;
    chat->group[0].status = save->self_status;
    chat->gcc[0].confirmed = true;

    uint16_t i, num = 0, num_addrs = ntohs(save->num_addrs);

    for (i = 0; i < num_addrs && i < MAX_GC_PEER_ADDRS; ++i) {
        if (ipport_isset(&save->addrs[i].ip_port))
            chat->addr_list[num++] = save->addrs[i];
    }

    chat->num_addrs = num;

    return groupnumber;
}

/* Initializes group shared state and creates a signature for it using the chat secret key
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int init_gc_shared_state(GC_Chat *chat, uint8_t privacy_state, const uint8_t *group_name,
                                uint16_t name_length)
{
    memcpy(chat->shared_state.founder_public_key, chat->self_public_key, ENC_PUBLIC_KEY);
    memcpy(chat->shared_state.group_name, group_name, name_length);
    chat->shared_state.group_name_len = name_length;
    chat->shared_state.maxpeers = MAX_GC_NUM_PEERS;
    chat->shared_state.privacy_state = privacy_state;

    return sign_gc_shared_state(chat);
}

/* Creates a new group.
 *
 * Return groupnumber on success.
 * Return -1 on failure.
 */
int gc_group_add(GC_Session *c, uint8_t privacy_state, const uint8_t *group_name, uint16_t length)
{
    if (length > MAX_GC_GROUP_NAME_SIZE || length == 0)
        return -1;

    if (privacy_state >= GI_INVALID)
        return -1;

    int groupnumber = create_new_group(c, true);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    create_extended_keypair(chat->chat_public_key, chat->chat_secret_key);

    if (init_gc_shared_state(chat, privacy_state, group_name, length) == -1) {
        group_delete(c, chat);
        return -1;
    }

    chat->chat_id_hash = get_chat_id_hash(CHAT_ID(chat->chat_public_key));
    chat->join_type = HJ_PRIVATE;
    self_gc_connected(chat);

    if (group_announce_request(c, chat) == -1) {
        group_delete(c, chat);
        return -1;
    }

    return groupnumber;
}

/* Sends an invite request to a public group using the chat_id.
 *
 * If the group is not password protected passwd should be set to NULL and passwd_len should be 0.
 *
 * Return groupnumber on success.
 * Reutrn -1 on failure.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *passwd, uint16_t passwd_len)
{
    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1)
        return -1;

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == NULL)
        return -1;

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = get_chat_id_hash(CHAT_ID(chat->chat_public_key));
    chat->join_type = HJ_PUBLIC;

    if (passwd != NULL) {
        if (passwd_len == 0)
            return -1;

        if (set_gc_password_local(chat, passwd, passwd_len) == -1)
            return -1;
    }

    if (chat->num_addrs == 0)
        group_get_nodes_request(c, chat);

    return groupnumber;
}

/* Resets chat saving all self state and attempts to reconnect to group */
void gc_rejoin_group(GC_Session *c, GC_Chat *chat)
{
    send_gc_self_exit(chat, NULL, 0);

    clear_gc_addrs_list(chat);
    chat->num_addrs = gc_copy_peer_addrs(chat, chat->addr_list, MAX_GC_PEER_ADDRS);

    uint32_t i;

    /* Remove all peers except self. Numpeers decrements with each call to gc_peer_delete */
    for (i = 1; chat->numpeers > 1; )
        if (gc_peer_delete(c->messenger, chat->groupnumber, i, NULL, 0) == -1)
            break;

    chat->connection_state = CS_DISCONNECTED;
    chat->last_get_nodes_attempt = chat->num_addrs > 0 ? unix_time() : 0;  /* Reconnect using saved peers or DHT */
    chat->last_sent_ping_time = unix_time();
    chat->last_join_attempt = unix_time();
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
int gc_accept_invite(GC_Session *c, const uint8_t *data, uint16_t length, const uint8_t *passwd, uint16_t passwd_len)
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
        goto on_error;

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = get_chat_id_hash(CHAT_ID(chat->chat_public_key));
    chat->join_type = HJ_PRIVATE;

    if (passwd != NULL) {
        if (passwd_len == 0)
            goto on_error;

        if (set_gc_password_local(chat, passwd, passwd_len) == -1)
            goto on_error;
    }

    if (send_gc_handshake_request(c->messenger, groupnumber, node.ip_port, node.public_key,
                                  HS_INVITE_REQUEST, chat->join_type) == -1)
        goto on_error;

    return groupnumber;

on_error:
    group_delete(c, chat);
    return -1;
}

GC_Session *new_groupchats(Messenger* m)
{
    GC_Session *c = calloc(sizeof(GC_Session), 1);

    if (c == NULL)
        return NULL;

    c->messenger = m;
    c->announce = m->group_announce;

    networking_registerhandler(m->net, NET_PACKET_GC_LOSSLESS, &handle_gc_lossless_message, m);
    networking_registerhandler(m->net, NET_PACKET_GC_LOSSY, &handle_gc_lossy_message, m);
    networking_registerhandler(m->net, NET_PACKET_GC_HANDSHAKE, &handle_gc_handshake_packet, m);

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
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSY, NULL, NULL);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSLESS, NULL, NULL);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_HANDSHAKE, NULL, NULL);
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
