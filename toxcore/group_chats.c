/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "DHT.h"
#include "mono_time.h"
#include "network.h"
#include "TCP_connection.h"
#include "group_chats.h"
#include "group_announce.h"
#include "group_connection.h"
#include "group_moderation.h"
#include "LAN_discovery.h"
#include "util.h"
#include "Messenger.h"

#ifndef VANILLA_NACL

#include <sodium.h>

enum {
    GC_MAX_PACKET_PADDING = 8,

    GC_PLAIN_HS_PACKET_SIZE = sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + SIG_PUBLIC_KEY
                              + sizeof(uint8_t) + sizeof(uint8_t),

    GC_ENCRYPTED_HS_PACKET_SIZE = sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE
                                  + GC_PLAIN_HS_PACKET_SIZE + CRYPTO_MAC_SIZE,

    GC_PACKED_SHARED_STATE_SIZE = EXT_PUBLIC_KEY + sizeof(uint32_t) + MAX_GC_GROUP_NAME_SIZE + sizeof(uint16_t)
                                  + sizeof(uint8_t) + sizeof(uint16_t) + MAX_GC_PASSWD_SIZE
                                  + GC_MODERATION_HASH_SIZE + sizeof(uint32_t),

    /* Minimum size of a topic packet; includes topic length, public signature key, and the topic version */
    GC_MIN_PACKED_TOPIC_INFO_SIZE = sizeof(uint16_t) + SIG_PUBLIC_KEY + sizeof(uint32_t),

    GC_SHARED_STATE_ENC_PACKET_SIZE = HASH_ID_BYTES + SIGNATURE_SIZE + GC_PACKED_SHARED_STATE_SIZE,

    /* Header information attached to all broadcast messages. broadcast_type, public key hash, timestamp */
    GC_BROADCAST_ENC_HEADER_SIZE = 1 + HASH_ID_BYTES + TIME_STAMP_SIZE,

    MESSAGE_ID_BYTES = sizeof(uint64_t),

    MIN_GC_LOSSLESS_PACKET_SIZE = sizeof(uint8_t) + MESSAGE_ID_BYTES + HASH_ID_BYTES + ENC_PUBLIC_KEY
                                  + CRYPTO_NONCE_SIZE + sizeof(uint8_t) + CRYPTO_MAC_SIZE,

    MIN_GC_LOSSY_PACKET_SIZE = MIN_GC_LOSSLESS_PACKET_SIZE - MESSAGE_ID_BYTES,

    MAX_GC_PACKET_SIZE = 65507,

    /* approximation of the sync response packet size limit */
    MAX_GC_NUM_PEERS = MAX_GC_PACKET_SIZE / (ENC_PUBLIC_KEY + sizeof(IP_Port)),

    /* Size of a ping packet which contains a peer count, the shared state version,
     * the sanctions list version and the topic version
     */
    GC_PING_PACKET_DATA_SIZE = sizeof(uint32_t) * 4,
};

static uint16_t gc_packet_padding_length(uint16_t length)
{
    return (MAX_GC_PACKET_SIZE - length) % GC_MAX_PACKET_PADDING;
}

static int groupnumber_valid(const GC_Session *c, int groupnumber);
static int peer_add(Messenger *m, int groupnumber, IP_Port *ipp, const uint8_t *public_key);
static int peer_update(Messenger *m, int groupnumber, GC_GroupPeer *peer, uint32_t peernumber);
static int group_delete(GC_Session *c, GC_Chat *chat);
static int get_nick_peernumber(const GC_Chat *chat, const uint8_t *nick, uint16_t length);
static int sync_gc_announced_nodes(const GC_Session *c, GC_Chat *chat);
static bool group_exists(const GC_Session *c, const uint8_t *chat_id);

typedef enum Group_Handshake_Packet_Type {
    GH_REQUEST,
    GH_RESPONSE,
} Group_Handshake_Packet_Type;

typedef enum Group_Handshake_Request_Type {
    HS_INVITE_REQUEST,
    HS_PEER_INFO_EXCHANGE,
} Group_Handshake_Request_Type;

// for debugging
void print_peer(const GC_GroupPeer *peer, const GC_Connection *gconn);
void print_peer(const GC_GroupPeer *peer, const GC_Connection *gconn)
{
    char ip_str[IP_NTOA_LEN];
    fprintf(stderr, "ENC PK: %s\n", id_toa(gconn->addr.public_key));
    fprintf(stderr, "SIG PK: %s\n", id_toa(get_sig_pk(gconn->addr.public_key)));
    fprintf(stderr, "IP: %s\n", ip_ntoa(&gconn->addr.ip_port.ip, ip_str, sizeof(ip_str)));
    fprintf(stderr, "Nick: %s\n", peer->nick);
    fprintf(stderr, "Nick len: %u\n", peer->nick_len);
    fprintf(stderr, "Status: %u\n", peer->status);
    fprintf(stderr, "Role: %u\n", peer->role);
    fprintf(stderr, "Ignore: %d\n", peer->ignore);
}

static GC_Chat *get_chat_by_hash(GC_Session *c, uint32_t hash)
{
    if (!c) {
        return nullptr;
    }

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].chat_id_hash == hash) {
            return &c->chats[i];
        }
    }

    return nullptr;
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

/* Check if peer with the public encryption key is in peer list.
 *
 * return peernumber if peer is in chat.
 * return -1 if peer is not in chat.
 */
static int get_peernum_of_enc_pk(const GC_Chat *chat, const uint8_t *public_enc_key)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (memcmp(chat->gcc[i].addr.public_key, public_enc_key, ENC_PUBLIC_KEY) == 0) {
            return i;
        }
    }

    return -1;
}

/* Check if peer with the public signature key is in peer list.
 *
 * return peernumber if peer is in chat.
 * return -1 if peer is not in chat.
 */
static int get_peernum_of_sig_pk(const GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (memcmp(get_sig_pk(chat->gcc[i].addr.public_key), public_sig_key, SIG_PUBLIC_KEY) == 0) {
            return i;
        }
    }

    return -1;
}

/* Validates peer's group role.
 *
 * Returns 0 if role is valid.
 * Returns -1 if role is invalid.
 */
static int validate_gc_peer_role(const GC_Chat *chat, uint32_t peernumber)
{
    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].role >= GR_INVALID) {
        return -1;
    }

    switch (chat->group[peernumber].role) {
        case GR_FOUNDER: {
            if (memcmp(chat->shared_state.founder_public_key, gconn->addr.public_key, ENC_PUBLIC_KEY) != 0) {
                return -1;
            }

            break;
        }

        case GR_MODERATOR: {
            if (mod_list_index_of_sig_pk(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
                return -1;
            }

            break;
        }

        case GR_USER: {
            if (sanctions_list_is_observer(chat, gconn->addr.public_key)) {
                return -1;
            }

            break;
        }

        case GR_OBSERVER: {
            /* Don't validate self as this is called when we don't have the sanctions list yet */
            if (!sanctions_list_is_observer(chat, gconn->addr.public_key) && peernumber != 0) {
                return -1;
            }

            break;
        }

        default: {
            return -1;
        }
    }

    return 0;
}

/* Returns true if peernumber exists */
bool peernumber_valid(const GC_Chat *chat, int peernumber)
{
    return peernumber >= 0 && peernumber < chat->numpeers;
}


/* Returns the peernumber of the peer with peer_id.
 * Returns -1 if peer_id is invalid. */
static int get_peernumber_of_peer_id(const GC_Chat *chat, uint32_t peer_id)
{
    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].peer_id == peer_id) {
            return i;
        }
    }

    return -1;
}

/* Returns a new peer ID.
 *
 * These ID's are permanently assigned to a peer when they join the group and should be
 * considered arbitrary values. TODO: This could probably be done a better way.
 */
static uint32_t get_new_peer_id(const GC_Chat *chat)
{
    uint32_t new_id = random_u32();

    while (get_peernumber_of_peer_id(chat, new_id) != -1) {
        new_id = random_u32();
    }

    return new_id;
}

/* Returns true if sender_pk_hash is equal to peers's public key hash */
static bool peer_pk_hash_match(GC_Connection *gconn, uint32_t sender_pk_hash)
{
    return sender_pk_hash == gconn->public_key_hash;
}

static void self_gc_connected(const Mono_Time *mono_time, GC_Chat *chat)
{
    chat->connection_state = CS_CONNECTED;
    chat->gcc[0].time_added = mono_time_get(mono_time);
}

/* Sets the password for the group (locally only).
 *
 * Returns 0 on success.
 * Returns -1 if the password is too long.
 */
static int set_gc_password_local(GC_Chat *chat, const uint8_t *passwd, uint16_t length)
{
    if (length > MAX_GC_PASSWD_SIZE) {
        return -1;
    }

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
    if (chat->shared_state.version == 0) {
        return -1;
    }

    if (chat->shared_state.privacy_state != GI_PUBLIC) {
        return 0;
    }

    return gca_send_announce_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                     get_chat_id(chat->chat_public_key));
}

/* Sends a get nodes request to the DHT if group is public.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int group_get_nodes_request(GC_Session *c, const GC_Chat *chat)
{
    if (chat->shared_state.privacy_state != GI_PUBLIC) {
        return 0;
    }

    return gca_send_get_nodes_request(c->announce, chat->self_public_key, chat->self_secret_key,
                                      get_chat_id(chat->chat_public_key));
}

/* Expands the chat_id into the extended chat public key (encryption key + signature key)
 * dest must have room for EXT_PUBLIC_KEY bytes.
 */
static int expand_chat_id(uint8_t *dest, const uint8_t *chat_id)
{
    int result = crypto_sign_ed25519_pk_to_curve25519(dest, chat_id);
    memcpy(dest + ENC_PUBLIC_KEY, chat_id, SIG_PUBLIC_KEY);
    return result;
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
        if (chat->gcc[i].confirmed) {
            addrs[num] = chat->gcc[i].addr;
            ++num;
        }
    }

    return num;
}

static void clear_gc_addrs_list(GC_Chat *chat)
{
    memset(chat->addr_list, 0, sizeof(GC_PeerAddress) * MAX_GC_PEER_ADDRS);
    chat->addrs_idx = 0;
    chat->num_addrs = 0;
}

/* This callback is triggered when we receive a get nodes response from DHT.
 * The respective chat_id's addr_list will be updated with the newly announced nodes.
 *
 * Note: All previous entries are cleared.
 */
static void handle_update_gc_addresses(GC_Announce *announce, const uint8_t *chat_id, void *object)
{
    GC_Session *c = (GC_Session *)object;

    uint32_t chat_id_hash = get_chat_id_hash(chat_id);
    GC_Chat *chat = get_chat_by_hash(c, chat_id_hash);

    if (chat == nullptr) {
        return;
    }

    clear_gc_addrs_list(chat);

    GC_Announce_Node nodes[MAX_GCA_SELF_REQUESTS];
    uint32_t num_nodes = gca_get_requested_nodes(announce, get_chat_id(chat->chat_public_key), nodes);
    chat->num_addrs = min_u32(num_nodes, MAX_GC_PEER_ADDRS);

    if (chat->num_addrs == 0) {
        return;
    }

    uint16_t i;

    for (i = 0; i < chat->num_addrs; ++i) {
        ipport_copy(&chat->addr_list[i].ip_port, &nodes[i].ip_port);
        memcpy(chat->addr_list[i].public_key, nodes[i].public_key, ENC_PUBLIC_KEY);
    }

    /* If we're already connected this is part of the DHT sync procedure */
    if (chat->connection_state == CS_CONNECTED) {
        sync_gc_announced_nodes(c, chat);
    }
}

static void group_callback_update_addresses(GC_Announce *announce, update_addresses_cb *function, void *object)
{
    announce->update_addresses = function;
    announce->update_addresses_obj = object;
}

/* Returns the number of confirmed peers in peerlist */
static uint32_t get_gc_confirmed_numpeers(const GC_Chat *chat)
{
    uint32_t i, count = 0;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            ++count;
        }
    }

    return count;
}

static int sign_gc_shared_state(GC_Chat *chat);
static int broadcast_gc_mod_list(GC_Chat *chat);
static int broadcast_gc_shared_state(GC_Chat *chat);
static int update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key);
static int update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key);

/* Removes the first found offline mod from the mod list.
 * Re-broadcasts the shared state and moderator list on success, as well
 * as the updated sanctions list if necessary.
 *
 * TODO: Make this smarter in who to remove (e.g. the mod who hasn't been seen online in the longest time)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if no mods were removed.
 */
static int prune_gc_mod_list(GC_Chat *chat)
{
    if (chat->moderation.num_mods == 0) {
        return 0;
    }

    const uint8_t *public_sig_key = nullptr;
    size_t i;

    for (i = 0; i < chat->moderation.num_mods; ++i) {
        if (get_peernum_of_sig_pk(chat, chat->moderation.mod_list[i]) == -1) {
            public_sig_key = chat->moderation.mod_list[i];

            if (mod_list_remove_index(chat, i) == -1) {
                public_sig_key = nullptr;
                continue;
            }

            break;
        }
    }

    if (public_sig_key == nullptr) {
        return -1;
    }

    mod_list_make_hash(chat, chat->shared_state.mod_list_hash);

    if (sign_gc_shared_state(chat) == -1) {
        return -1;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -1;
    }

    if (broadcast_gc_mod_list(chat) == -1) {
        return -1;
    }

    if (update_gc_sanctions_list(chat,  public_sig_key) == -1) {
        return -1;
    }

    if (update_gc_topic(chat, public_sig_key) == -1) {
        return -1;
    }

    return 0;
}

/* Packs number of peer addresses into data of maxlength length.
 * Note: Only the encryption public key is packed.
 *
 * Return length of packed peer addresses on success.
 * Return -1 on failure.
 */
static int pack_gc_addresses(uint8_t *data, uint16_t length, const GC_PeerAddress *addrs, uint16_t number)
{
    uint16_t i, packed_len = 0;

    for (i = 0; i < number; ++i) {
        int ipp_size = pack_ip_port(data + packed_len, length - packed_len, &addrs[i].ip_port);

        if (ipp_size == -1) {
            return -1;
        }

        packed_len += ipp_size;

        if (packed_len + ENC_PUBLIC_KEY > length) {
            return -1;
        }

        memcpy(data + packed_len, addrs[i].public_key, ENC_PUBLIC_KEY);
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
static int unpack_gc_addresses(GC_PeerAddress *addrs, uint16_t max_num_addrs, uint16_t *processed_data_len,
                               const uint8_t *data, uint16_t length, uint8_t tcp_enabled)
{
    uint16_t num = 0, len_processed = 0;

    while (num < max_num_addrs && len_processed < length) {
        int ipp_size = unpack_ip_port(&addrs[num].ip_port, data + len_processed, length - len_processed, tcp_enabled);

        if (ipp_size == -1) {
            return -1;
        }

        len_processed += ipp_size;

        if (len_processed + ENC_PUBLIC_KEY > length) {
            return -1;
        }

        memcpy(addrs[num].public_key, data + len_processed, ENC_PUBLIC_KEY);
        len_processed += ENC_PUBLIC_KEY;
        ++num;
    }

    if (processed_data_len) {
        *processed_data_len = len_processed;
    }

    return num;
}

/* Size of peer data that we pack for transfer (nick length must be accounted for separately).
 * packed data includes: nick, nick length, status, role
 */
#define PACKED_GC_PEER_SIZE (MAX_GC_NICK_SIZE + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t))

/* Packs peer info into data of maxlength length.
 *
 * Return length of packed peer on success.
 * Return -1 on failure.
 */
static int pack_gc_peer(uint8_t *data, uint16_t length, const GC_GroupPeer *peer)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t packed_len = 0;

    net_pack_u16(data + packed_len, peer->nick_len);
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
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t len_processed = 0;

    net_unpack_u16(data + len_processed, &peer->nick_len);
    len_processed += sizeof(uint16_t);
    peer->nick_len = min_u16(MAX_GC_NICK_SIZE, peer->nick_len);
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
static uint16_t pack_gc_shared_state(uint8_t *data, uint16_t length, const GC_SharedState *shared_state)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    uint16_t packed_len = 0;

    memcpy(data + packed_len, shared_state->founder_public_key, EXT_PUBLIC_KEY);
    packed_len += EXT_PUBLIC_KEY;
    net_pack_u32(data + packed_len, shared_state->maxpeers);
    packed_len += sizeof(uint32_t);
    net_pack_u16(data + packed_len, shared_state->group_name_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->group_name, MAX_GC_GROUP_NAME_SIZE);
    packed_len += MAX_GC_GROUP_NAME_SIZE;
    memcpy(data + packed_len, &shared_state->privacy_state, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    net_pack_u16(data + packed_len, shared_state->passwd_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->passwd, MAX_GC_PASSWD_SIZE);
    packed_len += MAX_GC_PASSWD_SIZE;
    memcpy(data + packed_len, shared_state->mod_list_hash, GC_MODERATION_HASH_SIZE);
    packed_len += GC_MODERATION_HASH_SIZE;
    net_pack_u32(data + packed_len, shared_state->version);
    packed_len += sizeof(uint32_t);

    return packed_len;
}

/* Unpacks shared state data into shared_state. data must contain at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns the length of processed data.
 */
static uint16_t unpack_gc_shared_state(GC_SharedState *shared_state, const uint8_t *data, uint16_t length)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    uint16_t len_processed = 0;

    memcpy(shared_state->founder_public_key, data + len_processed, EXT_PUBLIC_KEY);
    len_processed += EXT_PUBLIC_KEY;
    net_unpack_u32(data + len_processed, &shared_state->maxpeers);
    len_processed += sizeof(uint32_t);
    net_unpack_u16(data + len_processed, &shared_state->group_name_len);
    shared_state->group_name_len = min_u16(shared_state->group_name_len, MAX_GC_GROUP_NAME_SIZE);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->group_name, data + len_processed, MAX_GC_GROUP_NAME_SIZE);
    len_processed += MAX_GC_GROUP_NAME_SIZE;
    memcpy(&shared_state->privacy_state, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    net_unpack_u16(data + len_processed, &shared_state->passwd_len);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->passwd, data + len_processed, MAX_GC_PASSWD_SIZE);
    len_processed += MAX_GC_PASSWD_SIZE;
    memcpy(shared_state->mod_list_hash, data + len_processed, GC_MODERATION_HASH_SIZE);
    len_processed += GC_MODERATION_HASH_SIZE;
    net_unpack_u32(data + len_processed, &shared_state->version);
    len_processed += sizeof(uint32_t);

    return len_processed;
}

/* Packs topic info into data. data must have room for at least
 * topic length + GC_MIN_PACKED_TOPIC_INFO_SIZE bytes.
 *
 * Returns packed data length.
 */
static uint16_t pack_gc_topic_info(uint8_t *data, uint16_t length, const GC_TopicInfo *topic_info)
{
    if (length < topic_info->length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return 0;
    }

    uint16_t packed_len = 0;

    net_pack_u16(data + packed_len, topic_info->length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, topic_info->topic, topic_info->length);
    packed_len += topic_info->length;
    memcpy(data + packed_len, topic_info->public_sig_key, SIG_PUBLIC_KEY);
    packed_len += SIG_PUBLIC_KEY;
    net_pack_u32(data + packed_len, topic_info->version);
    packed_len += sizeof(uint32_t);

    return packed_len;
}

/* Unpacks topic info into topic_info.
 *
 * Returns -1 on failure.
 * Returns the length of the processed data.
 */
static int unpack_gc_topic_info(GC_TopicInfo *topic_info, const uint8_t *data, uint16_t length)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    uint16_t len_processed = 0;

    net_unpack_u16(data + len_processed, &topic_info->length);
    len_processed += sizeof(uint16_t);
    topic_info->length = min_u16(topic_info->length, MAX_GC_TOPIC_SIZE);

    if (length - sizeof(uint16_t) < topic_info->length + SIG_PUBLIC_KEY + sizeof(uint32_t)) {
        return -1;
    }

    memcpy(topic_info->topic, data + len_processed, topic_info->length);
    len_processed += topic_info->length;
    memcpy(topic_info->public_sig_key, data + len_processed, SIG_PUBLIC_KEY);
    len_processed += SIG_PUBLIC_KEY;
    net_unpack_u32(data + len_processed, &topic_info->version);
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
static int make_gc_shared_state_packet(const GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, chat->shared_state_sig, SIGNATURE_SIZE);
    uint16_t packed_len = pack_gc_shared_state(data + HASH_ID_BYTES + SIGNATURE_SIZE,
                          length - HASH_ID_BYTES - SIGNATURE_SIZE,
                          &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        return -1;
    }

    return HASH_ID_BYTES + SIGNATURE_SIZE + packed_len;
}

/* Creates a signature for the group's shared state in packed form and increments the version.
 * This should only be called by the founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sign_gc_shared_state(GC_Chat *chat)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    if (chat->shared_state.version != UINT32_MAX) { /* improbable, but an overflow would break everything */
        ++chat->shared_state.version;
    }

    uint8_t shared_state[GC_PACKED_SHARED_STATE_SIZE];
    uint16_t packed_len = pack_gc_shared_state(shared_state, sizeof(shared_state), &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        --chat->shared_state.version;
        return -1;
    }

    int ret = crypto_sign_detached(chat->shared_state_sig, nullptr, shared_state, packed_len,
                                   get_sig_sk(chat->chat_secret_key));

    if (ret != 0) {
        --chat->shared_state.version;
    }

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
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(nonce, packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, CRYPTO_NONCE_SIZE);

    int plain_len = decrypt_data_symmetric(shared_key, nonce,
                                           packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE,
                                           length - (sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE),
                                           plain);

    if (plain_len <= 0) {
        fprintf(stderr, "decrypt failed: len %d\n", plain_len);
        return -1;
    }

    int min_plain_len = message_id != nullptr ? 1 + MESSAGE_ID_BYTES : 1;

    /* remove padding */
    uint8_t *real_plain = plain;

    while (real_plain[0] == 0) {
        ++real_plain;
        --plain_len;

        if (plain_len < min_plain_len) {
            return -1;
        }
    }

    uint32_t header_len = sizeof(uint8_t);
    *packet_type = real_plain[0];
    plain_len -= sizeof(uint8_t);

    if (message_id != nullptr) {
        net_unpack_u64(real_plain + sizeof(uint8_t), message_id);
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
                             uint32_t packet_size, const uint8_t *data, uint32_t length, uint64_t message_id,
                             uint8_t packet_type, uint32_t chat_id_hash, uint8_t packet_id)
{
    uint16_t padding_len = gc_packet_padding_length(length);

    if (length + padding_len + CRYPTO_MAC_SIZE + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY
            + CRYPTO_NONCE_SIZE > packet_size) {
        return -1;
    }

    uint8_t plain[MAX_GC_PACKET_SIZE];
    memset(plain, 0, padding_len);

    uint32_t enc_header_len = sizeof(uint8_t);
    plain[padding_len] = packet_type;

    if (packet_id == NET_PACKET_GC_LOSSLESS) {
        net_pack_u64(plain + padding_len + sizeof(uint8_t), message_id);
        enc_header_len += MESSAGE_ID_BYTES;
    }

    memcpy(plain + padding_len + enc_header_len, data, length);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    uint16_t plain_len = padding_len + enc_header_len + length;
    VLA(uint8_t, encrypt, plain_len + CRYPTO_MAC_SIZE);

    int enc_len = encrypt_data_symmetric(shared_key, nonce, plain, plain_len, encrypt);

    if (enc_len != SIZEOF_VLA(encrypt)) {
        fprintf(stderr, "encrypt failed. packet type: %d, enc_len: %d\n", packet_type, enc_len);
        return -1;
    }

    packet[0] = packet_id;
    net_pack_u32(packet + sizeof(uint8_t), chat_id_hash);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES, self_pk, ENC_PUBLIC_KEY);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + sizeof(uint8_t) + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    return 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE + enc_len;
}

/* Sends a lossy packet to peernumber in chat instance.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_lossy_group_packet(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                                   uint8_t packet_type)
{
    if (!gconn->handshaked) {
        return -1;
    }

    if (!data || length == 0) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, gconn->shared_key, packet, sizeof(packet),
                                data, length, 0, packet_type, chat->chat_id_hash, NET_PACKET_GC_LOSSY);

    if (len == -1) {
        fprintf(stderr, "wrap_group_packet failed (type: %u, len: %d)\n", packet_type, len);
        return -1;
    }

    if (gcc_send_group_packet(chat, gconn, packet, len, packet_type) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a lossless packet to peernumber in chat instance.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_lossless_group_packet(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                                      uint8_t packet_type)
{
    if (!gconn->handshaked) {
        return -1;
    }

    if (!data || length == 0) {
        return -1;
    }

    uint64_t message_id = gconn->send_message_id;
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int len = wrap_group_packet(chat->self_public_key, gconn->shared_key, packet, sizeof(packet), data, length,
                                message_id, packet_type, chat->chat_id_hash, NET_PACKET_GC_LOSSLESS);

    if (len == -1) {
        fprintf(stderr, "wrap_group_packet failed (type: %u, len: %d)\n", packet_type, len);
        return -1;
    }

    if (gcc_add_send_ary(chat->mono_time, gconn, packet, len, packet_type) == -1) {
        return -1;
    }

    if (gcc_send_group_packet(chat, gconn, packet, len, packet_type) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a group sync request to peer.
 * num_peers should be set to 0 if this is our initial sync request on join.
 */
static int send_gc_sync_request(GC_Chat *chat, GC_Connection *gconn, uint32_t num_peers)
{
    if (gconn->pending_sync_request) {
        return -1;
    }

    gconn->pending_sync_request = true;

    uint32_t length = HASH_ID_BYTES + sizeof(uint32_t) + MAX_GC_PASSWD_SIZE;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u32(data + HASH_ID_BYTES, num_peers);
    memcpy(data + HASH_ID_BYTES + sizeof(uint32_t), chat->shared_state.passwd, MAX_GC_PASSWD_SIZE);

    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_REQUEST);
}

static int send_gc_sync_response(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_RESPONSE);
}

static int send_gc_peer_exchange(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn);
static int send_gc_handshake_request(Messenger *m, int groupnumber, IP_Port ipp, const uint8_t *public_key,
                                     uint8_t request_type, uint8_t join_type);

static int handle_gc_sync_response(Messenger *m, int groupnumber, uint32_t peernumber, GC_Connection *gconn,
                                   const uint8_t *data, uint32_t length)
{
    if (length <= sizeof(uint32_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (!gconn->pending_sync_request) {
        return 0;
    }

    gconn->pending_sync_request = false;

    uint32_t num_peers;
    net_unpack_u32(data, &num_peers);
    uint32_t unpacked_len = sizeof(uint32_t);

    if (num_peers == 0 || num_peers > MAX_GC_NUM_PEERS) {
        return -1;
    }

    GC_PeerAddress *addrs = (GC_PeerAddress *)calloc(1, sizeof(GC_PeerAddress) * num_peers);

    if (addrs == nullptr) {
        return -1;
    }

    uint16_t addrs_len = 0;
    int unpacked_addrs = unpack_gc_addresses(addrs, num_peers, &addrs_len, data + unpacked_len,
                         length - unpacked_len, 1);

    if (unpacked_addrs != num_peers || addrs_len == 0) {
        free(addrs);
        fprintf(stderr, "unpack_gc_addresses failed: got %d expected %u\n", unpacked_addrs, num_peers);
        return -1;
    }

    mono_time_update(m->mono_time);

    unpacked_len += addrs_len;

    uint32_t i;

    for (i = 0; i < num_peers; ++i) {
        if (get_peernum_of_enc_pk(chat, addrs[i].public_key) == -1) {
            send_gc_handshake_request(m, groupnumber, addrs[i].ip_port, addrs[i].public_key,
                                      HS_PEER_INFO_EXCHANGE, chat->join_type);
        }
    }

    for (i = 0; i < chat->numpeers; ++i) {
        chat->gcc[i].pending_sync_request = false;
        chat->gcc[i].pending_state_sync = false;
    }

    free(addrs);

    if (chat->connection_state == CS_CONNECTED) {
        return 0;
    }

    gconn = gcc_get_connection(chat, peernumber);

    self_gc_connected(c->messenger->mono_time, chat);
    send_gc_peer_exchange(c, chat, gconn);
    group_announce_request(c, chat);

    if (chat->num_addrs > 0) {
        sync_gc_announced_nodes(c, chat);
    }

    if (c->self_join) {
        (*c->self_join)(m, groupnumber, c->self_join_userdata);
    }

    return 0;
}

static int send_peer_shared_state(GC_Chat *chat, GC_Connection *gconn);
static int send_peer_mod_list(GC_Chat *chat, GC_Connection *gconn);
static int send_peer_sanctions_list(GC_Chat *chat, GC_Connection *gconn);
static int send_peer_topic(GC_Chat *chat, GC_Connection *gconn);

/* Handles a sync request packet and sends a response containing the peer list.
 * Additionally sends the group topic, shared state, mod list and sanctions list in respective packets.
 *
 * If the group is password protected the password in the request data must first be verified.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_sync_request(const Messenger *m, int groupnumber, GC_Connection *gconn, const uint8_t *data,
                                  uint32_t length)
{
    if (length != sizeof(uint32_t) + MAX_GC_PASSWD_SIZE) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    uint32_t req_num_peers;
    net_unpack_u32(data, &req_num_peers);

    /* Sync is not necessary */
    if (req_num_peers > 0 && req_num_peers >= get_gc_confirmed_numpeers(chat)) {
        return 0;
    }

    if (chat->shared_state.passwd_len > 0) {
        uint8_t passwd[MAX_GC_PASSWD_SIZE];
        memcpy(passwd, data + sizeof(uint32_t), MAX_GC_PASSWD_SIZE);

        if (memcmp(chat->shared_state.passwd, passwd, chat->shared_state.passwd_len) != 0) {
            return -1;
        }
    }

    /* Do not change the order of these four calls or else */
    if (send_peer_shared_state(chat, gconn) == -1) {
        return -1;
    }

    if (send_peer_mod_list(chat, gconn) == -1) {
        return -1;
    }

    if (send_peer_sanctions_list(chat, gconn) == -1) {
        return -1;
    }

    if (send_peer_topic(chat, gconn) == -1) {
        return -1;
    }

    uint8_t response[MAX_GC_PACKET_SIZE];
    net_pack_u32(response, chat->self_public_key_hash);
    uint32_t len = HASH_ID_BYTES;

    size_t packed_addrs_size = (ENC_PUBLIC_KEY + sizeof(IP_Port)) * (chat->numpeers - 1);   /* approx. */

    /* This is the technical limit to the number of peers you can have in a group (TODO: split packet?) */
    if (HASH_ID_BYTES + packed_addrs_size > sizeof(response)) {
        return -1;
    }

    GC_PeerAddress *peer_addrs = (GC_PeerAddress *)calloc(1, sizeof(GC_PeerAddress) * (chat->numpeers - 1));

    if (peer_addrs == nullptr) {
        return -1;
    }

    uint32_t i, num = 0;

    /* must add self separately because reasons */
    GC_PeerAddress self_addr;
    memcpy(&self_addr.public_key, chat->self_public_key, ENC_PUBLIC_KEY);
    ipport_self_copy(m->dht, &self_addr.ip_port);
    copy_gc_peer_addr(&peer_addrs[num], &self_addr);
    ++num;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].public_key_hash != gconn->public_key_hash && chat->gcc[i].confirmed) {
            copy_gc_peer_addr(&peer_addrs[num], &chat->gcc[i].addr);
            ++num;
        }
    }

    net_pack_u32(response + len, num);
    len += sizeof(uint32_t);

    int addrs_len = pack_gc_addresses(response + len, sizeof(response) - len, peer_addrs, num);
    len += addrs_len;

    free(peer_addrs);

    if (addrs_len <= 0) {
        fprintf(stderr, "pack_gc_addresses failed %d\n", addrs_len);
        return -1;
    }

    return send_gc_sync_response(chat, gconn, response, len);
}

static void self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer);
static int send_gc_peer_info_request(GC_Chat *chat, GC_Connection *gconn);

/* Compares our peerlist with our announced nodes and attempts to do a handshake
 * with any nodes that are not in our peerlist.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sync_gc_announced_nodes(const GC_Session *c, GC_Chat *chat)
{
    GC_GroupPeer self;
    self_to_peer(c, chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];
    net_pack_u32(data, chat->self_public_key_hash);
    uint32_t len = HASH_ID_BYTES;

    int peers_len = pack_gc_peer(data + len, sizeof(data) - len, &self);
    len += peers_len;

    if (peers_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in sync_gc_announced_nodes %d\n", peers_len);
        return -1;
    }

    uint16_t i;

    for (i = 0; i < chat->num_addrs; ++i) {
        if (get_peernum_of_enc_pk(chat, chat->addr_list[i].public_key) == -1) {
            send_gc_handshake_request(c->messenger, chat->groupnumber, chat->addr_list[i].ip_port,
                                      chat->addr_list[i].public_key, HS_PEER_INFO_EXCHANGE, HJ_PUBLIC);
        }
    }

    return 0;
}

/* Shares our TCP relays with peer and adds shared relays to our connection with them.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_tcp_relays(const Mono_Time *mono_time, GC_Chat *chat, GC_Connection *gconn)
{
    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    unsigned int i, num = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS);

    if (num == 0) {
        return 0;
    }

    uint8_t data[HASH_ID_BYTES + sizeof(tcp_relays)];
    net_pack_u32(data, chat->self_public_key_hash);
    uint32_t length = HASH_ID_BYTES;

    for (i = 0; i < num; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);
    }

    int nodes_len = pack_nodes(data + length, sizeof(data) - length, tcp_relays, num);

    if (nodes_len <= 0) {
        return -1;
    }

    length += nodes_len;

    if (send_lossy_group_packet(chat, gconn, data, length, GP_TCP_RELAYS) == -1) {
        return -1;
    }

    gconn->last_tcp_relays_shared = mono_time_get(mono_time);
    return 0;
}

/* Adds peer's shared TCP relays to our connection with them.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_tcp_relays(Messenger *m, int groupnumber, GC_Connection *gconn, const uint8_t *data,
                                uint32_t length)
{
    if (length == 0) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    if (!gconn->confirmed) {
        return -1;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS, nullptr, data, length, 1);

    if (num_nodes <= 0) {
        return -1;
    }

    int i;

    for (i = 0; i < num_nodes; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);
    }

    return 0;
}

/* Send invite request to peernumber. Invite packet contains your nick and the group password.
 * If no group password is necessary the password field will be ignored by the invitee.
 *
 * Return -1 if fail
 * Return 0 if success
 */
static int send_gc_invite_request(GC_Chat *chat, GC_Connection *gconn)
{
    uint8_t data[MAX_GC_PACKET_SIZE];
    net_pack_u32(data, chat->self_public_key_hash);
    uint32_t length = HASH_ID_BYTES;
    net_pack_u16(data + length, chat->group[0].nick_len);
    length += sizeof(uint16_t);
    memcpy(data + length, chat->group[0].nick, chat->group[0].nick_len);
    length += chat->group[0].nick_len;
    memcpy(data + length, chat->shared_state.passwd, MAX_GC_PASSWD_SIZE);
    length += MAX_GC_PASSWD_SIZE;

    return send_lossless_group_packet(chat, gconn, data, length, GP_INVITE_REQUEST);
}

/* Return -1 if fail
 * Return 0 if succes
 */
static int send_gc_invite_response(GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t length = HASH_ID_BYTES;
    VLA(uint8_t,  data, length);
    net_pack_u32(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, gconn, data, length, GP_INVITE_RESPONSE);
}

/* Return -1 if fail
 * Return 0 if success
 */
static int handle_gc_invite_response(Messenger *m, int groupnumber, GC_Connection *gconn, const uint8_t *data,
                                     uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state == CS_CONNECTED) {
        return 0;
    }

    return send_gc_sync_request(chat, gconn, 0);
}

static int handle_gc_invite_response_reject(Messenger *m, int groupnumber, const uint8_t *data, uint32_t length)
{
    if (length != sizeof(uint8_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state == CS_CONNECTED) {
        return 0;
    }

    uint8_t type = data[0];

    if (type >= GJ_INVALID) {
        type = GJ_INVITE_FAILED;
    }

    chat->connection_state = CS_FAILED;

    if (c->rejected) {
        (*c->rejected)(m, groupnumber, type, c->rejected_userdata);
    }

    return 0;
}

static int send_gc_invite_response_reject(GC_Chat *chat, GC_Connection *gconn, uint8_t type)
{
    uint32_t length = HASH_ID_BYTES + 1;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, &type, sizeof(uint8_t));

    return send_lossy_group_packet(chat, gconn, data, length, GP_INVITE_RESPONSE_REJECT);
}

/* Handles an invite request.
 *
 * Verifies that the invitee's nick is not already taken, and that the correct password has
 * been supplied if the group is password protected.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_invite_request(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                    uint32_t length)
{
    if (length <= sizeof(uint16_t) + MAX_GC_PASSWD_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    uint8_t invite_error = GJ_INVITE_FAILED;

    if (get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        invite_error = GJ_GROUP_FULL;
        goto FAILED_INVITE;
    }

    uint16_t nick_len;
    net_unpack_u16(data, &nick_len);

    if (nick_len > MAX_GC_NICK_SIZE) {
        goto FAILED_INVITE;
    }

    if (length - sizeof(uint16_t) < nick_len) {
        goto FAILED_INVITE;
    }

    uint8_t nick[MAX_GC_NICK_SIZE];
    memcpy(nick, data + sizeof(uint16_t), nick_len);

    if (get_nick_peernumber(chat, nick, nick_len) != -1) {
        invite_error = GJ_NICK_TAKEN;
        goto FAILED_INVITE;
    }

    if (length - sizeof(uint16_t) - nick_len < MAX_GC_PASSWD_SIZE) {
        goto FAILED_INVITE;
    }

    if (chat->shared_state.passwd_len > 0) {
        uint8_t passwd[MAX_GC_PASSWD_SIZE];
        memcpy(passwd, data + sizeof(uint16_t) + nick_len, MAX_GC_PASSWD_SIZE);

        if (memcmp(chat->shared_state.passwd, passwd, chat->shared_state.passwd_len) != 0) {
            invite_error = GJ_INVALID_PASSWORD;
            goto FAILED_INVITE;
        }
    }

    return send_gc_invite_response(chat, gconn);

FAILED_INVITE:
    send_gc_invite_response_reject(chat, gconn, invite_error);
    gc_peer_delete(m, groupnumber, peernumber, nullptr, 0);

    return -1;
}

/* Creates packet with broadcast header info followed by data of length.
 * Returns length of packet including header.
 */
static uint32_t make_gc_broadcast_header(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t *packet,
        uint8_t bc_type)
{
    uint32_t header_len = 0;
    net_pack_u32(packet, chat->self_public_key_hash);
    header_len += HASH_ID_BYTES;
    packet[header_len] = bc_type;
    header_len += sizeof(uint8_t);
    net_pack_u64(packet + header_len, mono_time_get(chat->mono_time));
    header_len += TIME_STAMP_SIZE;

    if (length > 0) {
        memcpy(packet + header_len, data, length);
    }

    return length + header_len;
}

/* sends a group broadcast packet to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_broadcast_message(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t bc_type)
{
    if (length + GC_BROADCAST_ENC_HEADER_SIZE > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    VLA(uint8_t, packet, length + GC_BROADCAST_ENC_HEADER_SIZE);
    uint32_t packet_len = make_gc_broadcast_header(chat, data, length, packet, bc_type);
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossless_group_packet(chat, &chat->gcc[i], packet, packet_len, GP_BROADCAST);
        }
    }

    return 0;
}

/* Sends a lossless packet of type and length to all confirmed peers. */
static void send_gc_lossless_packet_all_peers(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t type)
{
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossless_group_packet(chat, &chat->gcc[i], data, length, type);
        }
    }
}

/* Sends a lossy packet of type and length to all confirmed peers. */
static void send_gc_lossy_packet_all_peers(GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t type)
{
    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossy_group_packet(chat, &chat->gcc[i], data, length, type);
        }
    }
}

/* Compares a peer's group sync info that we received in a ping packet to our own.
 *
 * If their info appears to be more recent than ours we will first set a sync request flag.
 * If the flag is already set we send a sync request to this peer then set the flag back to false.
 *
 * This function should only be called from handle_gc_ping().
 */
static void do_gc_peer_state_sync(GC_Chat *chat, GC_Connection *gconn, const uint8_t *sync_data, uint32_t length)
{
    if (length != GC_PING_PACKET_DATA_SIZE) {
        return;
    }

    uint32_t other_num_peers, sstate_version, screds_version, topic_version;
    net_unpack_u32(sync_data, &other_num_peers);
    net_unpack_u32(sync_data + sizeof(uint32_t), &sstate_version);
    net_unpack_u32(sync_data + (sizeof(uint32_t) * 2), &screds_version);
    net_unpack_u32(sync_data + (sizeof(uint32_t) * 3), &topic_version);

    if (other_num_peers > get_gc_confirmed_numpeers(chat)
            || sstate_version > chat->shared_state.version
            || screds_version > chat->moderation.sanctions_creds.version
            || topic_version > chat->topic_info.version) {

        if (gconn->pending_state_sync) {
            send_gc_sync_request(chat, gconn, 0);
            gconn->pending_state_sync = false;
            return;
        }

        gconn->pending_state_sync = true;
        return;
    }

    gconn->pending_state_sync = false;
}

/* Handles a ping packet.
 *
 * The packet contains sync information including peer's confirmed peer count,
 * shared state version and sanction credentials version.
 */
static int handle_gc_ping(Messenger *m, int groupnumber, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    if (length != GC_PING_PACKET_DATA_SIZE) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (!gconn->confirmed) {
        return -1;
    }

    do_gc_peer_state_sync(chat, gconn, data, length);
    gconn->last_rcvd_ping = mono_time_get(m->mono_time);

    return 0;
}

/* Sets the caller's status
 *
 * Returns 0 on success.
 * Returns -1 if the groupnumber is invalid.
 * Returns -2 if the status type is invalid.
 * Returns -3 if the packet failed to send.
 */
int gc_set_self_status(Messenger *m, int groupnumber, uint8_t status)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (status >= GS_INVALID) {
        return -2;
    }

    if (c->status_change) {
        (*c->status_change)(m, groupnumber, chat->group[0].peer_id, status, c->status_change_userdata);
    }

    chat->group[0].status = status;
    uint8_t data[1];
    data[0] = chat->group[0].status;

    if (send_gc_broadcast_message(chat, data, 1, GM_STATUS) == -1) {
        return -3;
    }

    return 0;
}

static int handle_bc_status(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    if (length != sizeof(uint8_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    uint8_t status = data[0];

    if (status >= GS_INVALID) {
        return -1;
    }

    if (c->status_change) {
        (*c->status_change)(m, groupnumber, chat->group[peernumber].peer_id, status, c->status_change_userdata);
    }

    chat->group[peernumber].status = status;

    return 0;
}

/* Returns peer_id's status.
 * Returns (uint8_t) -1 on failure.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peer_id)
{
    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    if (!peernumber_valid(chat, peernumber)) {
        return -1;
    }

    return chat->group[peernumber].status;
}

/* Returns peer_id's group role.
 * Returns (uint8_t)-1 on failure.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peer_id)
{
    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    if (!peernumber_valid(chat, peernumber)) {
        return -1;
    }

    return chat->group[peernumber].role;
}

/* Copies the chat_id to dest. */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest)
{
    if (dest) {
        memcpy(dest, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);
    }
}

/* Sends self peer info to peernumber. If the group is password protected the request
 * will contain the group password, which the recipient will validate in the respective
 * group message handler.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_self_to_peer(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn)
{
    GC_GroupPeer self;
    self_to_peer(c, chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];
    net_pack_u32(data, chat->self_public_key_hash);
    memcpy(data + HASH_ID_BYTES, chat->shared_state.passwd, MAX_GC_PASSWD_SIZE);
    uint32_t length = HASH_ID_BYTES + MAX_GC_PASSWD_SIZE;

    int packed_len = pack_gc_peer(data + length, sizeof(data) - length, &self);
    length += packed_len;

    if (packed_len <= 0) {
        fprintf(stderr, "pack_gc_peer failed in handle_gc_peer_info_request_request %d\n", packed_len);
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, data, length, GP_PEER_INFO_RESPONSE);
}

static int handle_gc_peer_info_request(Messenger *m, int groupnumber, GC_Connection *gconn)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -1;
    }

    return send_self_to_peer(c, chat, gconn);
}

static int send_gc_peer_info_request(GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t length = HASH_ID_BYTES;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, gconn, data, length, GP_PEER_INFO_REQUEST);
}

/* Do peer info exchange with peer.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_peer_exchange(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn)
{
    int ret1 = send_self_to_peer(c, chat, gconn);
    int ret2 = send_gc_peer_info_request(chat, gconn);
    return (ret1 == -1 || ret2 == -1) ? -1 : 0;
}

/* Updates peer's info, validates their group role, and sets them as a confirmed peer.
 * If the group is password protected the password must first be validated.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_peer_info_response(Messenger *m, int groupnumber, uint32_t peernumber,
                                        const uint8_t *data, uint32_t length)
{
    if (length <= SIG_PUBLIC_KEY + MAX_GC_PASSWD_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -1;
    }

    if (chat->shared_state.passwd_len > 0) {
        uint8_t passwd[MAX_GC_PASSWD_SIZE];
        memcpy(passwd, data, sizeof(passwd));

        if (memcmp(chat->shared_state.passwd, passwd, chat->shared_state.passwd_len) != 0) {
            return -1;
        }
    }

    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    if (unpack_gc_peer(&peer, data + MAX_GC_PASSWD_SIZE, length - MAX_GC_PASSWD_SIZE) == -1) {
        fprintf(stderr, "unpack_gc_peer failed in handle_gc_peer_info_request\n");
        return -1;
    }

    if (peer_update(m, groupnumber, &peer, peernumber) == -1) {
        fprintf(stderr, "peer_update() failed in handle_gc_peer_info_request\n");
        return -1;
    }

    if (validate_gc_peer_role(chat, peernumber) == -1) {
        gc_peer_delete(m, groupnumber, peernumber, nullptr, 0);
        fprintf(stderr, "failed to validate peer role\n");
        return -1;
    }

    if (c->peer_join && !gconn->confirmed) {
        (*c->peer_join)(m, groupnumber, chat->group[peernumber].peer_id, c->peer_join_userdata);
    }

    gconn->confirmed = true;

    return 0;
}

/* Sends the group shared state and its signature to peernumber.
 *
 * Returns a non-negative integer on success.
 * Returns -1 on failure.
 */
static int send_peer_shared_state(GC_Chat *chat, GC_Connection *gconn)
{
    if (chat->shared_state.version == 0) {
        return -1;
    }

    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    int length = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, length, GP_SHARED_STATE);
}

/* Sends the group shared state and signature to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure
 */
static int broadcast_gc_shared_state(GC_Chat *chat)
{
    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    int packet_len = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (packet_len != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_SHARED_STATE);
    return 0;
}

/* Compares old_shared_state with the chat instance's current shared state and triggers the
 * appropriate callback depending on what piece of state information changed. Also
 * handles DHT announcement/removal if the privacy state changed.
 *
 * The initial retrieval of the shared state on group join will be ignored by this function.
 */
static void do_gc_shared_state_changes(GC_Session *c, const GC_Chat *chat, const GC_SharedState *old_shared_state)
{
    if (old_shared_state->version == 0) {
        return;
    }

    /* Max peers changed */
    if (chat->shared_state.maxpeers != old_shared_state->maxpeers) {
        if (c->peer_limit) {
            (*c->peer_limit)(c->messenger, chat->groupnumber, chat->shared_state.maxpeers, c->peer_limit_userdata);
        }

        return;
    }

    /* privacy state changed */
    if (chat->shared_state.privacy_state != old_shared_state->privacy_state) {
        if (c->privacy_state) {
            (*c->privacy_state)(c->messenger, chat->groupnumber, chat->shared_state.privacy_state,
                                c->privacy_state_userdata);
        }

        if (chat->shared_state.privacy_state == GI_PUBLIC) {
            group_announce_request(c, chat);
        } else if (chat->shared_state.privacy_state == GI_PRIVATE) {
            gca_cleanup(c->announce, get_chat_id(chat->chat_public_key));
        }

        return;
    }

    /* password changed */
    if (chat->shared_state.passwd_len != old_shared_state->passwd_len
            || memcmp(chat->shared_state.passwd, old_shared_state->passwd, old_shared_state->passwd_len) != 0) {

        if (c->password) {
            (*c->password)(c->messenger, chat->groupnumber, chat->shared_state.passwd,
                           chat->shared_state.passwd_len, c->password_userdata);
        }

        return;
    }
}

/* Checks that all shared state values are legal.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int validate_gc_shared_state(const GC_SharedState *state)
{
    if (state->maxpeers > MAX_GC_NUM_PEERS) {
        return -1;
    }

    if (state->passwd_len > MAX_GC_PASSWD_SIZE) {
        return -1;
    }

    if (state->group_name_len == 0 || state->group_name_len > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    return 0;
}

static int handle_gc_shared_state_error(Messenger *m, int groupnumber,
                                        uint32_t peernumber, GC_Chat *chat)
{
    /* If we don't already have a valid shared state we will automatically try to get another invite.
       Otherwise we attempt to ask a different peer for a sync. */
    gc_peer_delete(m, groupnumber, peernumber, (const uint8_t *)"BAD SHARED STATE", 10);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1) {
        return -1;
    }

    return send_gc_sync_request(chat, &chat->gcc[1], 0);
}

/* Handles a shared state packet.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_shared_state(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                  uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE - HASH_ID_BYTES) {
        return handle_gc_shared_state_error(m, groupnumber, peernumber, chat);
    }

    uint8_t signature[SIGNATURE_SIZE];
    memcpy(signature, data, SIGNATURE_SIZE);

    const uint8_t *ss_data = data + SIGNATURE_SIZE;
    uint16_t ss_length = length - SIGNATURE_SIZE;

    if (crypto_sign_verify_detached(signature, ss_data, GC_PACKED_SHARED_STATE_SIZE,
                                    get_sig_pk(chat->chat_public_key)) == -1) {
        return handle_gc_shared_state_error(m, groupnumber, peernumber, chat);
    }

    uint32_t version;
    net_unpack_u32(data + length - sizeof(uint32_t), &version);

    if (version < chat->shared_state.version) {
        return 0;
    }

    GC_SharedState old_shared_state, new_shared_state;
    memcpy(&old_shared_state, &chat->shared_state, sizeof(GC_SharedState));

    if (unpack_gc_shared_state(&new_shared_state, ss_data, ss_length) == 0) {
        return -1;
    }

    if (validate_gc_shared_state(&new_shared_state) == -1) {
        return -1;
    }

    memcpy(&chat->shared_state, &new_shared_state, sizeof(GC_SharedState));
    memcpy(chat->shared_state_sig, signature, SIGNATURE_SIZE);

    do_gc_shared_state_changes(c, chat, &old_shared_state);

    return 0;
}

/* Handles new mod_list and compares its hash against the mod_list_hash in the shared state.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_mod_list(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                              uint32_t length)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[0].role == GR_FOUNDER) {
        return 0;
    }

    uint16_t num_mods;
    net_unpack_u16(data, &num_mods);

    if (num_mods > MAX_GC_MODERATORS) {
        goto ON_ERROR;
    }

    if (mod_list_unpack(chat, data + sizeof(uint16_t), length - sizeof(uint16_t), num_mods) == -1) {
        goto ON_ERROR;
    }

    uint8_t mod_list_hash[GC_MODERATION_HASH_SIZE];
    mod_list_make_hash(chat, mod_list_hash);

    if (memcmp(mod_list_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE) != 0) {
        goto ON_ERROR;
    }

    /* Validate our own role */
    if (validate_gc_peer_role(chat, 0) == -1) {
        chat->group[0].role = GR_USER;
    }

    return 0;

ON_ERROR:
    gc_peer_delete(m, groupnumber, peernumber, (const uint8_t *)"BAD MLIST", 9);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1) {
        return -1;
    }

    return send_gc_sync_request(chat, &chat->gcc[1], 0);
}

static int handle_gc_sanctions_list_error(Messenger *m, int groupnumber,
        uint32_t peernumber, GC_Chat *chat)
{
    if (chat->moderation.sanctions_creds.version > 0) {
        return 0;
    }

    gc_peer_delete(m, groupnumber, peernumber, (const uint8_t *)"BAD SCREDS", 10);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_DISCONNECTED;
        return -1;
    }

    if (chat->numpeers <= 1) {
        return -1;
    }

    return send_gc_sync_request(chat, &chat->gcc[1], 0);
}

static int handle_gc_sanctions_list(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                    uint32_t length)
{
    if (length < sizeof(uint32_t)) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    uint32_t num_sanctions;
    net_unpack_u32(data, &num_sanctions);

    if (num_sanctions > MAX_GC_SANCTIONS) {
        return handle_gc_sanctions_list_error(m, groupnumber, peernumber, chat);
    }

    struct GC_Sanction_Creds creds;

    struct GC_Sanction *sanctions = (struct GC_Sanction *)malloc(num_sanctions * sizeof(struct GC_Sanction));

    if (sanctions == nullptr) {
        return -1;
    }

    int unpacked_num = sanctions_list_unpack(sanctions, &creds, num_sanctions, data + sizeof(uint32_t),
                       length - sizeof(uint32_t), nullptr);

    if (unpacked_num != num_sanctions) {
        fprintf(stderr, "sanctions_list_unpack failed in handle_gc_sanctions_list: %d\n", unpacked_num);
        free(sanctions);
        return handle_gc_sanctions_list_error(m, groupnumber, peernumber, chat);
    }

    if (sanctions_list_check_integrity(chat, &creds, sanctions, num_sanctions) == -1) {
        fprintf(stderr, "sanctions_list_check_integrity failed in handle_gc_sanctions_list\n");
        free(sanctions);
        return handle_gc_sanctions_list_error(m, groupnumber, peernumber, chat);
    }

    sanctions_list_cleanup(chat);

    memcpy(&chat->moderation.sanctions_creds, &creds, sizeof(struct GC_Sanction_Creds));
    chat->moderation.sanctions = sanctions;
    chat->moderation.num_sanctions = num_sanctions;

    /* We cannot verify our own observer role on the initial sync so we do it now */
    if (chat->group[0].role == GR_OBSERVER) {
        if (!sanctions_list_is_observer(chat, chat->self_public_key)) {
            chat->group[0].role = GR_USER;
        }
    }

    return 0;
}

/* Makes a mod_list packet.
 *
 * Returns length of packet data on success.
 * Returns -1 on failure.
 */
static int make_gc_mod_list_packet(const GC_Chat *chat, uint8_t *data, uint32_t maxlen, size_t mod_list_size)
{
    if (maxlen < HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u16(data + HASH_ID_BYTES, chat->moderation.num_mods);

    if (mod_list_size > 0) {
        VLA(uint8_t, packed_mod_list, mod_list_size);
        mod_list_pack(chat, packed_mod_list);
        memcpy(data + HASH_ID_BYTES + sizeof(uint16_t), packed_mod_list, mod_list_size);
    }

    return HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size;
}

/* Sends the moderator list to peer.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
static int send_peer_mod_list(GC_Chat *chat, GC_Connection *gconn)
{
    size_t mod_list_size = chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE;
    uint32_t length = HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size;
    VLA(uint8_t, packet, length);

    int packet_len = make_gc_mod_list_packet(chat, packet, SIZEOF_VLA(packet), mod_list_size);

    if (packet_len != length) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, length, GP_MOD_LIST);
}

/* Makes a sanctions list packet.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_sanctions_list_packet(GC_Chat *chat, uint8_t *data, uint32_t maxlen)
{
    if (maxlen < HASH_ID_BYTES + sizeof(uint32_t)) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u32(data + HASH_ID_BYTES, chat->moderation.num_sanctions);
    uint32_t length = HASH_ID_BYTES + sizeof(uint32_t);

    int packed_len = sanctions_list_pack(data + length, maxlen - length, chat->moderation.sanctions,
                                         &chat->moderation.sanctions_creds, chat->moderation.num_sanctions);

    if (packed_len < 0) {
        return -1;
    }

    return length + packed_len;
}

/* Sends the sanctions list to peer.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_peer_sanctions_list(GC_Chat *chat, GC_Connection *gconn)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int packet_len = make_gc_sanctions_list_packet(chat, packet, sizeof(packet));

    if (packet_len == -1) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, packet_len, GP_SANCTIONS_LIST);
}

/* Sends the sanctions list to all peers in group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int broadcast_gc_sanctions_list(GC_Chat *chat)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    int packet_len = make_gc_sanctions_list_packet(chat, packet, sizeof(packet));

    if (packet_len == -1) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_SANCTIONS_LIST);
    return 0;
}

/* Re-signs all sanctions list entries signed by public_sig_key and broadcasts
 * the updated sanctions list to all group peers.
 *
 * Returns the number of updated entries on success.
 * Returns -1 on failure.
 */
static int update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint32_t num_replaced = sanctions_list_replace_sig(chat, public_sig_key);

    if (num_replaced == 0) {
        return 0;
    }

    if (broadcast_gc_sanctions_list(chat) == -1) {
        return -1;
    }

    return num_replaced;
}

/* Sends mod_list to all peers in group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_mod_list(GC_Chat *chat)
{
    size_t mod_list_size = chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE;
    uint32_t length = HASH_ID_BYTES + sizeof(uint16_t) + mod_list_size;
    VLA(uint8_t, packet, length);

    int packet_len = make_gc_mod_list_packet(chat, packet, SIZEOF_VLA(packet), mod_list_size);

    if (packet_len != length) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_MOD_LIST);
    return 0;
}

/* Sends a parting signal to the group.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the packet failed to send.
 */
static int send_gc_self_exit(GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        return -1;
    }

    if (send_gc_broadcast_message(chat, partmessage, length, GM_PEER_EXIT) == -1) {
        return -2;
    }

    return 0;
}

static int handle_bc_peer_exit(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                               uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        length = MAX_GC_PART_MESSAGE_SIZE;
    }

    return gc_peer_delete(m, groupnumber, peernumber, data, length);
}

/*
 * Sets your own nick.
 *
 * Returns 0 on success.
 * Returns -1 if groupnumber is invalid.
 * Returns -2 if the length is too long.
 * Returns -3 if the length is zero or nick is a NULL pointer.
 * Returns -4 if the nick is already taken.
 * Returns -5 if the packet fails to send.
 */
int gc_set_self_nick(Messenger *m, int groupnumber, const uint8_t *nick, uint16_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (length > MAX_GC_NICK_SIZE) {
        return -2;
    }

    if (length == 0 || nick == nullptr) {
        return -3;
    }

    if (get_nick_peernumber(chat, nick, length) != -1) {
        return -4;
    }

    if (c->nick_change) {
        (*c->nick_change)(m, groupnumber, chat->group[0].peer_id, nick, length, c->nick_change_userdata);
    }

    memcpy(chat->group[0].nick, nick, length);
    chat->group[0].nick_len = length;

    if (send_gc_broadcast_message(chat, nick, length, GM_NICK) == -1) {
        return -5;
    }

    return 0;
}

/* Copies your own nick to nick */
void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    if (nick) {
        memcpy(nick, chat->group[0].nick, chat->group[0].nick_len);
    }
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

/* Returns your own peer id */
uint32_t gc_get_self_peer_id(const GC_Chat *chat)
{
    return chat->group[0].peer_id;
}

/* Copies your own public key to public_key */
void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key)
{
    if (public_key) {
        memcpy(public_key, chat->self_public_key, ENC_PUBLIC_KEY);
    }
}

/* Copies peer_id's nick to name.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peer_id, uint8_t *name)
{
    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    if (!peernumber_valid(chat, peernumber)) {
        return -1;
    }

    if (name) {
        memcpy(name, chat->group[peernumber].nick, chat->group[peernumber].nick_len);
    }

    return 0;
}

/* Returns peer_id's nick length.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peer_id)
{
    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    if (!peernumber_valid(chat, peernumber)) {
        return -1;
    }

    return chat->group[peernumber].nick_len;
}

static int handle_bc_nick(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *nick,
                          uint32_t length)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    /* If this happens malicious behaviour is highly suspect */
    if (length == 0 || length > MAX_GC_NICK_SIZE || get_nick_peernumber(chat, nick, length) != -1) {
        return gc_peer_delete(m, groupnumber, peernumber, nullptr, 0);
    }

    if (c->nick_change) {
        (*c->nick_change)(m, groupnumber, chat->group[peernumber].peer_id, nick, length, c->nick_change_userdata);
    }

    memcpy(chat->group[peernumber].nick, nick, length);
    chat->group[peernumber].nick_len = length;

    return 0;
}

/* Copies peer_id's public key to public_key.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_public_key(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key)
{
    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (public_key) {
        memcpy(public_key, gconn->addr.public_key, ENC_PUBLIC_KEY);
    }

    return 0;
}

/* Creates a topic packet and puts it in data. Packet includes the topic, topic length,
 * public signature key of the setter, topic version, and the signature.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_topic_packet(GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < HASH_ID_BYTES + SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    net_pack_u32(data, chat->self_public_key_hash);
    uint16_t data_length = HASH_ID_BYTES;

    memcpy(data + data_length, chat->topic_sig, SIGNATURE_SIZE);
    data_length += SIGNATURE_SIZE;

    uint16_t packed_len = pack_gc_topic_info(data + data_length, length - data_length, &chat->topic_info);
    data_length += packed_len;

    if (packed_len != chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    return data_length;
}

/* Sends the group topic to peer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_peer_topic(GC_Chat *chat, GC_Connection *gconn)
{
    VLA(uint8_t, packet, HASH_ID_BYTES + SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE);
    int packet_len = make_gc_topic_packet(chat, packet, SIZEOF_VLA(packet));

    if (packet_len != SIZEOF_VLA(packet)) {
        return -1;
    }

    if (send_lossless_group_packet(chat, gconn, packet, packet_len, GP_TOPIC) == -1) {
        return -1;
    }

    return 0;
}

/* Sends the group topic to all group members.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_topic(GC_Chat *chat)
{
    VLA(uint8_t, packet, HASH_ID_BYTES + SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE);
    int packet_len = make_gc_topic_packet(chat, packet, SIZEOF_VLA(packet));

    if (packet_len != SIZEOF_VLA(packet)) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_TOPIC);
    return 0;
}

/* Sets the group topic and broadcasts it to the group. Setter must be a moderator or founder.
 *
 * Returns 0 on success.
 * Returns -1 if the topic is too long.
 * Returns -2 if the caller does not have the required permissions to set the topic.
 * Returns -3 if the packet cannot be created or signing fails.
 * Returns -4 if the packet fails to send.
 */
int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length)
{
    if (length > MAX_GC_TOPIC_SIZE) {
        return -1;
    }

    if (chat->group[0].role > GR_MODERATOR) {
        return -2;
    }

    GC_TopicInfo old_topic_info;
    uint8_t old_topic_sig[SIGNATURE_SIZE];
    memcpy(&old_topic_info, &chat->topic_info, sizeof(GC_TopicInfo));
    memcpy(old_topic_sig, chat->topic_sig, SIGNATURE_SIZE);

    if (chat->topic_info.version !=
            UINT32_MAX) {   /* TODO (jfreegman) improbable, but an overflow would break everything */
        ++chat->topic_info.version;
    }

    chat->topic_info.length = length;
    memcpy(chat->topic_info.topic, topic, length);
    memcpy(chat->topic_info.public_sig_key, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY);

    int err = -3;
    VLA(uint8_t, packed_topic, length + GC_MIN_PACKED_TOPIC_INFO_SIZE);
    uint16_t packed_len = pack_gc_topic_info(packed_topic, SIZEOF_VLA(packed_topic), &chat->topic_info);

    if (packed_len != SIZEOF_VLA(packed_topic)) {
        goto ON_ERROR;
    }

    if (crypto_sign_detached(chat->topic_sig, nullptr, packed_topic, packed_len, get_sig_sk(chat->self_secret_key)) == -1) {
        goto ON_ERROR;
    }

    if (broadcast_gc_topic(chat) == -1) {
        err = -4;
        goto ON_ERROR;
    }

    return 0;

ON_ERROR:
    memcpy(&chat->topic_info, &old_topic_info, sizeof(GC_TopicInfo));
    memcpy(chat->topic_sig, old_topic_sig, SIGNATURE_SIZE);
    return err;
}

/* Copies the group topic to topic. */
void gc_get_topic(const GC_Chat *chat, uint8_t *topic)
{
    if (topic) {
        memcpy(topic, chat->topic_info.topic, chat->topic_info.length);
    }
}

/* Returns topic length. */
uint16_t gc_get_topic_size(const GC_Chat *chat)
{
    return chat->topic_info.length;
}

/* If public_sig_key is equal to the key of the topic setter, replaces topic credentials
 * and re-broadcast the updated topic info to the group.
 *
 * Returns 0 on success
 * Returns -1 on failure.
 */
static int update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key)
{
    if (memcmp(public_sig_key, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY) != 0) {
        return 0;
    }

    if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
        return -1;
    }

    return 0;
}

static int handle_gc_topic(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                           uint32_t length)
{
    if (length > SIGNATURE_SIZE + MAX_GC_TOPIC_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    if (length < SIGNATURE_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    GC_TopicInfo topic_info;
    int unpacked_len = unpack_gc_topic_info(&topic_info, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE);

    if (unpacked_len == -1) {
        return -1;
    }

    if (!mod_list_verify_sig_pk(chat, topic_info.public_sig_key)) {
        return -1;
    }

    uint8_t signature[SIGNATURE_SIZE];
    memcpy(signature, data, SIGNATURE_SIZE);

    if (crypto_sign_verify_detached(signature, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE,
                                    topic_info.public_sig_key) == -1) {
        return -1;
    }

    if (topic_info.version < chat->topic_info.version) {
        return 0;
    }

    /* Prevents sync issues from triggering the callback needlessly. */
    bool skip_callback = chat->topic_info.length == topic_info.length
                         && memcmp(chat->topic_info.topic, topic_info.topic, topic_info.length) == 0;

    memcpy(&chat->topic_info, &topic_info, sizeof(GC_TopicInfo));
    memcpy(chat->topic_sig, signature, SIGNATURE_SIZE);

    if (!skip_callback && chat->connection_state == CS_CONNECTED && c->topic_change) {
        (*c->topic_change)(m, groupnumber, chat->group[peernumber].peer_id, topic_info.topic, topic_info.length,
                           c->topic_change_userdata);
    }

    return 0;
}

/* Copies group name to groupname */
void gc_get_group_name(const GC_Chat *chat, uint8_t *groupname)
{
    if (groupname) {
        memcpy(groupname, chat->shared_state.group_name, chat->shared_state.group_name_len);
    }
}

/* Returns group name length */
uint16_t gc_get_group_name_size(const GC_Chat *chat)
{
    return chat->shared_state.group_name_len;
}

/* Copies the group password to password */
void gc_get_password(const GC_Chat *chat, uint8_t *password)
{
    if (password) {
        memcpy(password, chat->shared_state.passwd, chat->shared_state.passwd_len);
    }
}

/* Returns the group password length */
uint16_t gc_get_password_size(const GC_Chat *chat)
{
    return chat->shared_state.passwd_len;
}

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for the action.
 * Returns -2 if the password is too long.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *passwd, uint16_t passwd_len)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    uint16_t oldlen = chat->shared_state.passwd_len;
    uint8_t *const oldpasswd = (uint8_t *)malloc(oldlen);
    memcpy(oldpasswd, chat->shared_state.passwd, oldlen);

    if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
        free(oldpasswd);
        return -2;
    }

    if (sign_gc_shared_state(chat) == -1) {
        set_gc_password_local(chat, oldpasswd, oldlen);
        free(oldpasswd);
        return -2;
    }

    free(oldpasswd);

    if (broadcast_gc_shared_state(chat) == -1) {
        return -3;
    }

    return 0;
}

static int handle_bc_set_mod(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                             uint32_t length)
{
    if (length < 1 + SIG_PUBLIC_KEY) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].role != GR_FOUNDER) {
        return -1;
    }

    bool add_mod = data[0] != 0;
    uint8_t mod_data[GC_MOD_LIST_ENTRY_SIZE];
    int target_peernum = -1;

    if (add_mod) {
        if (length < 1 + GC_MOD_LIST_ENTRY_SIZE) {
            return -1;
        }

        memcpy(mod_data, data + 1, GC_MODERATION_HASH_SIZE);
        target_peernum = get_peernum_of_sig_pk(chat, mod_data);

        if (peernumber == target_peernum) {
            return -1;
        }

        if (mod_list_add_entry(chat, mod_data) == -1) {
            return -1;
        }
    } else {
        memcpy(mod_data, data + 1, SIG_PUBLIC_KEY);
        target_peernum = get_peernum_of_sig_pk(chat, mod_data);

        if (peernumber == target_peernum) {
            return -1;
        }

        if (mod_list_remove_entry(chat, mod_data) == -1) {
            return -1;
        }
    }

    if (!peernumber_valid(chat, target_peernum)) {
        return 0;
    }

    chat->group[target_peernum].role = add_mod ? GR_MODERATOR : GR_USER;

    if (c->moderation) {
        (*c->moderation)(m, groupnumber, chat->group[peernumber].peer_id, chat->group[target_peernum].peer_id,
                         add_mod ? MV_MODERATOR : MV_USER, c->moderation_userdata);
    }

    return 0;
}

static int send_gc_set_mod(GC_Chat *chat, GC_Connection *gconn, bool add_mod)
{
    uint32_t length = 1 + SIG_PUBLIC_KEY;
    VLA(uint8_t, data, length);
    data[0] = add_mod ? 1 : 0;
    memcpy(data + 1, get_sig_pk(gconn->addr.public_key), SIG_PUBLIC_KEY);

    if (send_gc_broadcast_message(chat, data, length, GM_SET_MOD) == -1) {
        return -1;
    }

    return 0;
}

/* Adds or removes gconn from moderator list if add_mod is true or false respectively.
 * Re-signs and re-distributes an updated mod_list hash.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int founder_gc_set_moderator(GC_Chat *chat, GC_Connection *gconn, bool add_mod)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    if (add_mod) {
        if (chat->moderation.num_mods >= MAX_GC_MODERATORS) {
            prune_gc_mod_list(chat);
        }

        if (mod_list_add_entry(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }
    } else {
        if (mod_list_remove_entry(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }

        if (update_gc_sanctions_list(chat,  get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }

        if (update_gc_topic(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }
    }

    uint8_t old_hash[GC_MODERATION_HASH_SIZE];
    memcpy(old_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE);

    mod_list_make_hash(chat, chat->shared_state.mod_list_hash);

    if (sign_gc_shared_state(chat) == -1) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, GC_MODERATION_HASH_SIZE);
        return -1;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, GC_MODERATION_HASH_SIZE);
        return -1;
    }

    if (send_gc_set_mod(chat, gconn, add_mod) == -1) {
        return -1;
    }

    return 0;
}

static int handle_bc_set_observer(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                  uint32_t length)
{
    if (length <= 1 + EXT_PUBLIC_KEY) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].role >= GR_USER) {
        return -1;
    }

    bool add_obs = data[0] != 0;

    uint8_t public_key[EXT_PUBLIC_KEY];
    memcpy(public_key, data + 1, EXT_PUBLIC_KEY);

    if (mod_list_verify_sig_pk(chat, get_sig_pk(public_key))) {
        return -1;
    }

    int target_peernum = get_peernum_of_enc_pk(chat, public_key);

    if (target_peernum == peernumber) {
        return -1;
    }

    GC_Connection *target_gconn = gcc_get_connection(chat, target_peernum);

    if (add_obs) {
        struct GC_Sanction sanction;
        struct GC_Sanction_Creds creds;

        if (sanctions_list_unpack(&sanction, &creds, 1, data + 1 + EXT_PUBLIC_KEY, length - 1 - EXT_PUBLIC_KEY, nullptr) != 1) {
            return -1;
        }

        if (sanctions_list_add_entry(chat, &sanction, &creds) == -1) {
            return -1;
        }
    } else {
        struct GC_Sanction_Creds creds;

        if (sanctions_creds_unpack(&creds, data + 1 + EXT_PUBLIC_KEY, length - 1 - EXT_PUBLIC_KEY)
                != GC_SANCTIONS_CREDENTIALS_SIZE) {
            return -1;
        }

        if (sanctions_list_remove_observer(chat, public_key, &creds) == -1) {
            return -1;
        }
    }

    if (target_gconn != nullptr) {
        chat->group[target_peernum].role = add_obs ? GR_OBSERVER : GR_USER;

        if (c->moderation) {
            (*c->moderation)(m, groupnumber, chat->group[peernumber].peer_id, chat->group[target_peernum].peer_id,
                             add_obs ? MV_OBSERVER : MV_USER, c->moderation_userdata);
        }
    }

    return 0;
}

/* Broadcasts observer role data to the group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_set_observer(GC_Chat *chat, GC_Connection *gconn, const uint8_t *sanction_data,
                                uint32_t length, bool add_obs)
{
    uint32_t packet_len = 1 + EXT_PUBLIC_KEY + length;
    VLA(uint8_t, packet, packet_len);
    packet[0] = add_obs ? 1 : 0;
    memcpy(packet + 1, gconn->addr.public_key, EXT_PUBLIC_KEY);
    memcpy(packet + 1 + EXT_PUBLIC_KEY, sanction_data, length);

    if (send_gc_broadcast_message(chat, packet, packet_len, GM_SET_OBSERVER) == -1) {
        return -1;
    }

    return 0;
}

/* Adds or removes peernumber from the observer list if add_obs is true or false respectively.
 * Broadcasts this change to the entire group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int mod_gc_set_observer(GC_Chat *chat, uint32_t peernumber, bool add_obs)
{
    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->group[0].role >= GR_USER) {
        return -1;
    }

    uint8_t sanction_data[sizeof(struct GC_Sanction) + sizeof(struct GC_Sanction_Creds)];
    uint32_t length = 0;

    if (add_obs) {
        struct GC_Sanction sanction;

        if (sanctions_list_make_entry(chat, peernumber, &sanction, SA_OBSERVER) == -1) {
            fprintf(stderr, "sanctions_list_make_entry failed in mod_gc_set_observer\n");
            return -1;
        }

        int packed_len = sanctions_list_pack(sanction_data, sizeof(sanction_data), &sanction,
                                             &chat->moderation.sanctions_creds, 1);

        if (packed_len == -1) {
            return -1;
        }

        length += packed_len;
    } else {
        if (sanctions_list_remove_observer(chat, gconn->addr.public_key, nullptr) == -1) {
            return -1;
        }

        uint16_t packed_len = sanctions_creds_pack(&chat->moderation.sanctions_creds, sanction_data,
                              sizeof(sanction_data));

        if (packed_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
            return -1;
        }

        length += packed_len;
    }

    if (send_gc_set_observer(chat, gconn, sanction_data, length, add_obs) == -1) {
        return -1;
    }

    return 0;
}

/* Sets the role of peernumber. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * Returns 0 on success.
 * Returns -1 if the groupnumber is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if caller does not have sufficient permissions for the action.
 * Returns -4 if the role assignment is invalid.
 * Returns -5 if the role failed to be set.
 */
int gc_set_peer_role(Messenger *m, int groupnumber, uint32_t peer_id, uint8_t role)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (role != GR_MODERATOR && role != GR_USER && role != GR_OBSERVER) {
        return -4;
    }

    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (peernumber == 0 || gconn == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return -2;
    }

    if (chat->group[0].role >= GR_USER) {
        return -3;
    }

    if (chat->group[peernumber].role == GR_FOUNDER) {
        return -3;
    }

    if (chat->group[0].role != GR_FOUNDER && (role == GR_MODERATOR || chat->group[peernumber].role <= GR_MODERATOR)) {
        return -3;
    }

    if (chat->group[peernumber].role == role) {
        return -4;
    }

    uint8_t mod_event = MV_USER;

    /* New role must be applied after the old role is removed */
    switch (chat->group[peernumber].role) {
        case GR_MODERATOR: {
            if (founder_gc_set_moderator(chat, gconn, false) == -1) {
                return -5;
            }

            chat->group[peernumber].role = GR_USER;

            if (role == GR_OBSERVER) {
                mod_event = MV_OBSERVER;

                if (mod_gc_set_observer(chat, peernumber, true) == -1) {
                    return -5;
                }
            }

            break;
        }

        case GR_OBSERVER: {
            if (mod_gc_set_observer(chat, peernumber, false) == -1) {
                return -5;
            }

            chat->group[peernumber].role = GR_USER;

            if (role == GR_MODERATOR) {
                mod_event = MV_MODERATOR;

                if (founder_gc_set_moderator(chat, gconn, true) == -1) {
                    return -5;
                }
            }

            break;
        }

        case GR_USER: {
            if (role == GR_MODERATOR) {
                mod_event = MV_MODERATOR;

                if (founder_gc_set_moderator(chat, gconn, true) == -1) {
                    return -5;
                }
            } else if (role == GR_OBSERVER) {
                mod_event = MV_OBSERVER;

                if (mod_gc_set_observer(chat, peernumber, true) == -1) {
                    return -5;
                }
            }

            break;
        }

        default: {
            return -4;
        }
    }

    if (c->moderation) {
        (*c->moderation)(m, groupnumber, chat->group[0].peer_id, chat->group[peernumber].peer_id, mod_event,
                         c->moderation_userdata);
    }

    chat->group[peernumber].role = role;
    return 0;
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
 * Returns -1 if groupnumber is invalid.
 * Returns -2 if the privacy state is an invalid type.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the privacy state could not be set.
 * Returns -5 if the packet failed to send.
 */
int gc_founder_set_privacy_state(Messenger *m, int groupnumber, uint8_t new_privacy_state)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (new_privacy_state >= GI_INVALID) {
        return -2;
    }

    if (chat->group[0].role != GR_FOUNDER) {
        return -3;
    }

    uint8_t old_privacy_state = chat->shared_state.privacy_state;

    if (new_privacy_state == old_privacy_state) {
        return 0;
    }

    chat->shared_state.privacy_state = new_privacy_state;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.privacy_state = old_privacy_state;
        return -4;
    }

    if (new_privacy_state == GI_PRIVATE) {
        gca_cleanup(c->announce, get_chat_id(chat->chat_public_key));
    } else {
        group_announce_request(c, chat);
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -5;
    }

    return 0;
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
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the peer limit could not be set.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_max_peers(GC_Chat *chat, int groupnumber, uint32_t maxpeers)
{
    if (chat->group[0].role != GR_FOUNDER) {
        return -1;
    }

    maxpeers = min_u32(maxpeers, MAX_GC_NUM_PEERS);
    uint32_t old_maxpeers = chat->shared_state.maxpeers;

    if (maxpeers == chat->shared_state.maxpeers) {
        return 0;
    }

    chat->shared_state.maxpeers = maxpeers;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.maxpeers = old_maxpeers;
        return -2;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -3;
    }

    return 0;
}

/* Sends a plain message or an action, depending on type.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the message type is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_message(GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    if (type != GC_MESSAGE_TYPE_NORMAL && type != GC_MESSAGE_TYPE_ACTION) {
        return -3;
    }

    if (chat->group[0].role >= GR_OBSERVER) {
        return -4;
    }

    uint8_t packet_type = type == GC_MESSAGE_TYPE_NORMAL ? GM_PLAIN_MESSAGE : GM_ACTION_MESSAGE;

    if (send_gc_broadcast_message(chat, message, length, packet_type) == -1) {
        return -5;
    }

    return 0;
}

static int handle_bc_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length,
                             uint8_t type)
{
    if (!data || length > MAX_GC_MESSAGE_SIZE || length == 0) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER) {
        return 0;
    }

    if (type != GM_PLAIN_MESSAGE && type != GM_ACTION_MESSAGE) {
        return -1;
    }

    unsigned int cb_type = (type == GM_PLAIN_MESSAGE) ? MESSAGE_NORMAL : MESSAGE_ACTION;

    if (c->message) {
        (*c->message)(m, groupnumber, chat->group[peernumber].peer_id, cb_type, data, length, c->message_userdata);
    }

    return 0;
}

/* Sends a private message to peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the peer_id is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_private_message(GC_Chat *chat, uint32_t peer_id, const uint8_t *message, uint16_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -3;
    }

    if (chat->group[0].role >= GR_OBSERVER) {
        return -4;
    }

    VLA(uint8_t, packet, length + GC_BROADCAST_ENC_HEADER_SIZE);
    uint32_t packet_len = make_gc_broadcast_header(chat, message, length, packet, GM_PRVT_MESSAGE);

    if (send_lossless_group_packet(chat, gconn, packet, packet_len, GP_BROADCAST) == -1) {
        return -5;
    }

    return 0;
}

static int handle_bc_private_message(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                     uint32_t length)
{
    if (!data || length > MAX_GC_MESSAGE_SIZE || length == 0) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER) {
        return 0;
    }

    if (c->private_message) {
        (*c->private_message)(m, groupnumber, chat->group[peernumber].peer_id, data, length, c->private_message_userdata);
    }

    return 0;
}

/* Sends a custom packet to the group. If lossless is true, the packet will be lossless.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the sender has the observer role.
 */
int gc_send_custom_packet(GC_Chat *chat, bool lossless, const uint8_t *data, uint32_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -2;
    }

    if (chat->group[0].role >= GR_OBSERVER) {
        return -3;
    }

    if (lossless) {
        send_gc_lossless_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    } else {
        send_gc_lossy_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    }

    return 0;
}

/* Handles a custom packet.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_custom_packet(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                   uint32_t length)
{
    if (!data || length == 0 || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].ignore || chat->group[peernumber].role >= GR_OBSERVER) {
        return 0;
    }

    if (c->custom_packet) {
        (*c->custom_packet)(m, groupnumber, chat->group[peernumber].peer_id, data, length, c->custom_packet_userdata);
    }

    return 0;
}

static int handle_bc_remove_peer(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                 uint32_t length)
{
    if (length < 1 + ENC_PUBLIC_KEY) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].role >= GR_USER) {
        return -1;
    }

    uint8_t mod_event = data[0];

    if (mod_event != MV_KICK && mod_event != MV_BAN) {
        return -1;
    }

    uint8_t target_pk[ENC_PUBLIC_KEY];
    memcpy(target_pk, data + 1, ENC_PUBLIC_KEY);

    int target_peernum = get_peernum_of_enc_pk(chat, target_pk);

    if (peernumber_valid(chat, target_peernum)) {
        /* Even if they're offline or this guard is removed a ban on a mod or founder won't work */
        if (chat->group[target_peernum].role != GR_USER) {
            return -1;
        }
    }

    if (target_peernum == 0) {
        if (c->moderation) {
            (*c->moderation)(m, groupnumber, chat->group[peernumber].peer_id, chat->group[target_peernum].peer_id,
                             mod_event, c->moderation_userdata);
        }

        group_delete(c, chat);
        return 0;
    }

    struct GC_Sanction_Creds creds;

    if (mod_event == MV_BAN) {
        struct GC_Sanction sanction;

        if (sanctions_list_unpack(&sanction, &creds, 1, data + 1 + ENC_PUBLIC_KEY,
                                  length - 1 - ENC_PUBLIC_KEY, nullptr) != 1) {
            return -1;
        }

        if (sanctions_list_add_entry(chat, &sanction, &creds) == -1) {
            fprintf(stderr, "sanctions_list_add_entry failed in remove peer\n");
            return -1;
        }
    }

    if (target_peernum == -1) {   /* we don't need to/can't kick a peer that isn't in our peerlist */
        return 0;
    }

    if (c->moderation) {
        (*c->moderation)(m, groupnumber, chat->group[peernumber].peer_id, chat->group[target_peernum].peer_id,
                         mod_event, c->moderation_userdata);
    }

    if (gc_peer_delete(m, groupnumber, target_peernum, nullptr, 0) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a packet to instruct all peers to remove gconn from their peerlist.
 *
 * If mod_event is MV_BAN an updated sanctions list along with new credentials will be added to
 * the ban list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_remove_peer(GC_Chat *chat, GC_Connection *gconn, struct GC_Sanction *sanction,
                               uint8_t mod_event, bool send_new_creds)
{
    uint32_t length = 1 + ENC_PUBLIC_KEY;
    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = mod_event;
    memcpy(packet + 1, gconn->addr.public_key, ENC_PUBLIC_KEY);

    if (mod_event == MV_BAN) {
        int packed_len = sanctions_list_pack(packet + length, sizeof(packet) - length, sanction,
                                             &chat->moderation.sanctions_creds, 1);

        if (packed_len < 0) {
            fprintf(stderr, "sanctions_list_pack failed in send_gc_remove_peer\n");
            return -1;
        }

        length += packed_len;
    }

    return send_gc_broadcast_message(chat, packet, length, GM_REMOVE_PEER);
}

/* Instructs all peers to remove peer_id from their peerlist.
 * If set_ban is true peer will be added to the ban list.
 *
 * Returns 0 on success.
 * Returns -1 if the groupnumber is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the action failed.
 * Returns -5 if the packet failed to send.
 */
int gc_remove_peer(Messenger *m, int groupnumber, uint32_t peer_id, bool set_ban)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return -2;
    }

    if (chat->group[0].role >= GR_USER || chat->group[peernumber].role == GR_FOUNDER) {
        return -3;
    }

    if (chat->group[0].role != GR_FOUNDER && chat->group[peernumber].role == GR_MODERATOR) {
        return -3;
    }

    if (peernumber == 0) {
        return -2;
    }

    if (chat->group[peernumber].role == GR_MODERATOR || chat->group[peernumber].role == GR_OBSERVER) {
        /* this first removes peer from any lists they're on and broadcasts new lists to group */
        if (gc_set_peer_role(m, groupnumber, peer_id, GR_USER) < 0) {
            return -4;
        }
    }

    uint8_t mod_event = set_ban ? MV_BAN : MV_KICK;
    struct GC_Sanction sanction;

    if (set_ban) {
        if (sanctions_list_make_entry(chat, peernumber, &sanction, SA_BAN) == -1) {
            fprintf(stderr, "sanctions_list_make_entry failed\n");
            return -4;
        }
    }

    bool send_new_creds = !set_ban && chat->group[peernumber].role == GR_OBSERVER;

    if (send_gc_remove_peer(chat, gconn, &sanction, mod_event, send_new_creds) == -1) {
        return -5;
    }

    if (c->moderation) {
        (*c->moderation)(m, groupnumber, chat->group[0].peer_id, chat->group[peernumber].peer_id, mod_event,
                         c->moderation_userdata);
    }

    if (gc_peer_delete(m, groupnumber, peernumber, nullptr, 0) == -1) {
        return -4;
    }

    return 0;
}

static int handle_bc_remove_ban(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                                uint32_t length)
{
    if (length < sizeof(uint32_t)) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->group[peernumber].role >= GR_USER) {
        return -1;
    }

    uint32_t ban_id;
    net_unpack_u32(data, &ban_id);

    struct GC_Sanction_Creds creds;
    uint16_t unpacked_len = sanctions_creds_unpack(&creds, data + sizeof(uint32_t), length - sizeof(uint32_t));

    if (unpacked_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
        return -1;
    }

    if (sanctions_list_remove_ban(chat, ban_id, &creds) == -1) {
        fprintf(stderr, "sanctions_list_remove_ban failed in handle_bc_remove_ban\n");
    }

    return 0;
}

/* Sends a packet instructing all peers to remove a ban entry from the sanctions list.
 * Additionally sends updated sanctions credentials.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_remove_ban(GC_Chat *chat, uint32_t ban_id)
{
    uint8_t packet[sizeof(uint32_t) + GC_SANCTIONS_CREDENTIALS_SIZE];
    net_pack_u32(packet, ban_id);
    uint32_t length = sizeof(uint32_t);

    uint16_t packed_len = sanctions_creds_pack(&chat->moderation.sanctions_creds, packet + length,
                          sizeof(packet) - length);

    if (packed_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
        return -1;
    }

    length += packed_len;

    return send_gc_broadcast_message(chat, packet, length, GM_REMOVE_BAN);
}

/* Instructs all peers to remove ban_id from their ban list.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the entry could not be removed.
 * Returns -3 if the packet failed to send.
 */
int gc_remove_ban(GC_Chat *chat, uint32_t ban_id)
{
    if (chat->group[0].role >= GR_USER) {
        return -1;
    }

    if (sanctions_list_remove_ban(chat, ban_id, nullptr) == -1) {
        return -2;
    }

    if (send_gc_remove_ban(chat, ban_id) == -1) {
        return -3;
    }

    return 0;
}

static bool valid_gc_message_ack(uint64_t a, uint64_t b)
{
    return a == 0 || b == 0;
}

/* If read_id is non-zero sends a read-receipt for read_id's packet.
 * If request_id is non-zero sends a request for the respective id's packet.
 */
int gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t read_id, uint64_t request_id)
{
    if (!valid_gc_message_ack(read_id, request_id)) {
        return -1;
    }

    uint32_t length = HASH_ID_BYTES + (MESSAGE_ID_BYTES * 2);
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u64(data + HASH_ID_BYTES, read_id);
    net_pack_u64(data + HASH_ID_BYTES + MESSAGE_ID_BYTES, request_id);

    return send_lossy_group_packet(chat, gconn, data, length, GP_MESSAGE_ACK);
}

/* If packet contains a non-zero request_id we try to resend its respective packet.
 * If packet contains a non-zero read_id we remove the packet from our send array.
 *
 * Returns non-negative value on success.
 * Return -1 if error or we fail to send a packet in case of a request response.
 */
static int handle_gc_message_ack(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    if (length != MESSAGE_ID_BYTES * 2) {
        return -1;
    }

    uint64_t read_id, request_id;
    net_unpack_u64(data, &read_id);
    net_unpack_u64(data + MESSAGE_ID_BYTES, &request_id);

    if (!valid_gc_message_ack(read_id, request_id)) {
        return -1;
    }

    if (read_id > 0) {
        return gcc_handle_ack(gconn, read_id);
    }

    uint64_t tm = mono_time_get(chat->mono_time);
    uint16_t idx = get_ary_index(request_id);

    /* re-send requested packet */
    if (gconn->send_ary[idx].message_id == request_id
            && (gconn->send_ary[idx].last_send_try != tm || gconn->send_ary[idx].time_added == tm)) {
        gconn->send_ary[idx].last_send_try = tm;
        return sendpacket(chat->net, gconn->addr.ip_port, gconn->send_ary[idx].data, gconn->send_ary[idx].data_length);
    }

    return -1;
}

/* Sends a handshake response ack to peer.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int gc_send_hs_response_ack(GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t length = HASH_ID_BYTES;
    VLA(uint8_t, data, length);
    net_pack_u32(data, chat->self_public_key_hash);

    return send_lossless_group_packet(chat, gconn, data, length, GP_HS_RESPONSE_ACK);
}

/* Handles a handshake response ack.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_hs_response_ack(Messenger *m, int groupnumber, GC_Connection *gconn, const uint8_t *data,
                                     uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    gconn->handshaked = true;

    if (gcc_handle_ack(gconn, 1) == -1) {
        return -1;
    }

    return 0;
}

/* Toggles ignore for peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the peer_id is invalid.
 */
int gc_toggle_ignore(GC_Chat *chat, uint32_t peer_id, bool ignore)
{
    int peernumber = get_peernumber_of_peer_id(chat, peer_id);

    if (!peernumber_valid(chat, peernumber)) {
        return -1;
    }

    chat->group[peernumber].ignore = ignore;
    return 0;
}

/* Handles a broadcast packet.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int handle_gc_broadcast(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint32_t length)
{
    if (length < 1 + TIME_STAMP_SIZE) {
        return -1;
    }

    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (chat->connection_state != CS_CONNECTED) {
        return -1;
    }

    uint8_t broadcast_type;
    memcpy(&broadcast_type, data, sizeof(uint8_t));

    if (!gconn->confirmed) {
        return -1;
    }

    uint32_t m_len = length - (1 + TIME_STAMP_SIZE);
    VLA(uint8_t, message, m_len);
    memcpy(message, data + 1 + TIME_STAMP_SIZE, m_len);

    switch (broadcast_type) {
        case GM_STATUS:
            return handle_bc_status(m, groupnumber, peernumber, message, m_len);

        case GM_NICK:
            return handle_bc_nick(m, groupnumber, peernumber, message, m_len);

        case GM_ACTION_MESSAGE:  // intentional fallthrough
        case GM_PLAIN_MESSAGE:
            return handle_bc_message(m, groupnumber, peernumber, message, m_len, broadcast_type);

        case GM_PRVT_MESSAGE:
            return handle_bc_private_message(m, groupnumber, peernumber, message, m_len);

        case GM_PEER_EXIT:
            return handle_bc_peer_exit(m, groupnumber, peernumber, message, m_len);

        case GM_REMOVE_PEER:
            return handle_bc_remove_peer(m, groupnumber, peernumber, message, m_len);

        case GM_REMOVE_BAN:
            return handle_bc_remove_ban(m, groupnumber, peernumber, message, m_len);

        case GM_SET_MOD:
            return handle_bc_set_mod(m, groupnumber, peernumber, message, m_len);

        case GM_SET_OBSERVER:
            return handle_bc_set_observer(m, groupnumber, peernumber, message, m_len);

        default:
            fprintf(stderr, "Warning: handle_gc_broadcast received an invalid broadcast type %u\n", broadcast_type);
            return -1;
    }
}

/* Decrypts data of length using self secret key and sender's public key.
 *
 * Returns length of plaintext data on success.
 * Returns -1 on failure.
 */
static int uwrap_group_handshake_packet(const uint8_t *self_sk, uint8_t *sender_pk, uint8_t *plain,
                                        size_t plain_size, const uint8_t *packet, uint16_t length)
{
    if (plain_size < length - 1 - HASH_ID_BYTES - ENC_PUBLIC_KEY - CRYPTO_NONCE_SIZE - CRYPTO_MAC_SIZE) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);
    memcpy(nonce, packet + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY, CRYPTO_NONCE_SIZE);

    int plain_len = decrypt_data(sender_pk, self_sk, nonce,
                                 packet + (1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE),
                                 length - (1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE), plain);

    if (plain_len != plain_size) {
        fprintf(stderr, "decrypt handshake request failed\n");
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
                                       uint8_t *packet, uint32_t packet_size, const uint8_t *data,
                                       uint16_t length, uint32_t chat_id_hash)
{
    if (packet_size != GC_ENCRYPTED_HS_PACKET_SIZE) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    VLA(uint8_t, encrypt, length + CRYPTO_MAC_SIZE);
    int enc_len = encrypt_data(sender_pk, self_sk, nonce, data, length, encrypt);

    if (enc_len != SIZEOF_VLA(encrypt)) {
        fprintf(stderr, "encrypt handshake request failed (len: %d)\n", enc_len);
        return -1;
    }

    packet[0] = NET_PACKET_GC_HANDSHAKE;
    net_pack_u32(packet + 1, chat_id_hash);
    memcpy(packet + 1 + HASH_ID_BYTES, self_pk, ENC_PUBLIC_KEY);
    memcpy(packet + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    return 1 + HASH_ID_BYTES + ENC_PUBLIC_KEY + CRYPTO_NONCE_SIZE + enc_len;
}

/* Makes, wraps and encrypts a group handshake packet (both request and response are the same format).
 *
 * Packet contains the handshake header, the handshake type, self pk hash, session pk, self public signature key,
 * the request type (GROUP_HANDSHAKE_REQUEST_TYPE), the join type (GROUP_HANDSHAKE_JOIN_TYPE),
 * and a list of tcp relay nodes we share with this peer.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int make_gc_handshake_packet(GC_Chat *chat, const GC_Connection *gconn, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t join_type, uint8_t *packet, size_t packet_size)
{
    if (packet_size != GC_ENCRYPTED_HS_PACKET_SIZE) {
        return -1;
    }

    if (!chat || gconn == nullptr) {
        return -1;
    }

    uint8_t data[GC_PLAIN_HS_PACKET_SIZE];

    data[0] = handshake_type;
    uint16_t length = sizeof(uint8_t);
    net_pack_u32(data + length, chat->self_public_key_hash);
    length += HASH_ID_BYTES;
    memcpy(data + length, gconn->session_public_key, ENC_PUBLIC_KEY);
    length += ENC_PUBLIC_KEY;
    memcpy(data + length, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY);
    length += SIG_PUBLIC_KEY;
    memcpy(data + length, &request_type, sizeof(uint8_t));
    length += sizeof(uint8_t);
    memcpy(data + length, &join_type, sizeof(uint8_t));
    length += sizeof(uint8_t);

    int enc_len = wrap_group_handshake_packet(chat->self_public_key, chat->self_secret_key,
                  gconn->addr.public_key, packet, packet_size,
                  data, length, chat->chat_id_hash);

    if (enc_len != GC_ENCRYPTED_HS_PACKET_SIZE) {
        return -1;
    }

    return enc_len;
}

/* Sends a handshake packet where handshake_type is GH_REQUEST or GH_RESPONSE.
 *
 * Returns size of packet sent on success.
 * Returns -1 on failure.
 */
static int send_gc_handshake_packet(GC_Chat *chat, uint32_t peernumber, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t join_type)
{
    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    uint8_t packet[GC_ENCRYPTED_HS_PACKET_SIZE];
    int length = make_gc_handshake_packet(chat, gconn, handshake_type, request_type, join_type, packet, sizeof(packet));

    if (length != sizeof(packet)) {
        return -1;
    }

    if (gcc_add_send_ary(chat->mono_time, gconn, packet, length, -1) == -1) {
        return -1;
    }

    int ret1 = -1, ret2 = -1;

    if (!net_family_is_unspec(gconn->addr.ip_port.ip.family)) {
        ret1 = sendpacket(chat->net, gconn->addr.ip_port, packet, length);
    }

    ret2 = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);

    if (ret1 == -1 && ret2 == -1) {
        return -1;
    }

    return 0;
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

    if (chat == nullptr) {
        return -1;
    }

    if (id_equal(chat->self_public_key, public_key)) {
        return -1;
    }

    int peernumber = peer_add(m, groupnumber, &ipp, public_key);

    if (peernumber == -1) {
        return -1;
    }

    if (peernumber == -2) {
        peernumber = get_peernum_of_enc_pk(chat, public_key);

        if (peernumber == -1) {
            return -1;
        }
    }

    if (send_gc_handshake_packet(chat, peernumber, GH_REQUEST, request_type, join_type) == -1) {
        return -1;
    }

    return peernumber;
}

/* Handles a handshake response packet and takes appropriate action depending on the value of request_type.
 *
 * Returns peernumber of new connected peer on success.
 * Returns -1 on failure.
 */
static int handle_gc_handshake_response(Messenger *m, int groupnumber, const uint8_t *sender_pk,
                                        const uint8_t *data, uint16_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    int peernumber = get_peernum_of_enc_pk(chat, sender_pk);

    if (peernumber == -1) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    uint8_t sender_session_pk[ENC_PUBLIC_KEY];
    memcpy(sender_session_pk, data, ENC_PUBLIC_KEY);
    encrypt_precompute(sender_session_pk, gconn->session_secret_key, gconn->shared_key);

    set_sig_pk(gconn->addr.public_key, data + ENC_PUBLIC_KEY);
    uint8_t request_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY];

    /* This packet is an implied handshake request acknowledgement */
    gcc_handle_ack(gconn, 1);
    ++gconn->recv_message_id;

    gconn->handshaked = true;
    gc_send_hs_response_ack(chat, gconn);

    int ret = -1;

    switch (request_type) {
        case HS_INVITE_REQUEST:
            ret = send_gc_invite_request(chat, gconn);
            break;

        case HS_PEER_INFO_EXCHANGE:
            ret = send_gc_peer_exchange(m->group_handler, chat, gconn);
            break;

        default:
            fprintf(stderr, "Warning: received invalid request type in handle_gc_handshake_response\n");
            return -1;
    }

    if (ret == -1) {
        return -1;
    }

    return peernumber;
}

static int send_gc_handshake_response(GC_Chat *chat, uint32_t peernumber, uint8_t request_type)
{
    if (send_gc_handshake_packet(chat, peernumber, GH_RESPONSE, request_type, 0) == -1) {
        return -1;
    }

    return 0;
}

/* Handles handshake request packets.
 * Peer is added to peerlist and a lossless connection is established.
 *
 * Return new peer's peernumber on success.
 * Return -1 on failure.
 */
#define GC_NEW_PEER_CONNECTION_LIMIT 5
static int handle_gc_handshake_request(Messenger *m, int groupnumber, IP_Port *ipp, const uint8_t *sender_pk,
                                       const uint8_t *data, uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state == CS_FAILED) {
        return -1;
    }

    if (chat->shared_state.version == 0) {
        return -1;
    }

    uint8_t public_sig_key[SIG_PUBLIC_KEY];
    memcpy(public_sig_key, data + ENC_PUBLIC_KEY, SIG_PUBLIC_KEY);

    /* Check if IP is banned and make sure they aren't a moderator or founder */
    if (sanctions_list_ip_banned(chat, ipp) && !mod_list_verify_sig_pk(chat, public_sig_key)) {
        return -1;
    }

    if (chat->connection_O_metre >= GC_NEW_PEER_CONNECTION_LIMIT) {
        chat->block_handshakes = true;
        return -1;
    }

    ++chat->connection_O_metre;

    int peer_exists = get_peernum_of_enc_pk(chat, sender_pk);

    if (peer_exists != -1) {
        gc_peer_delete(m, groupnumber, peer_exists, nullptr, 0);
    }

    int peernumber = peer_add(m, groupnumber, ipp, sender_pk);

    if (peernumber < 0) {
        fprintf(stderr, "peer_add failed in handle_gc_handshake_request\n");
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    uint8_t sender_session_pk[ENC_PUBLIC_KEY];
    memcpy(sender_session_pk, data, ENC_PUBLIC_KEY);

    encrypt_precompute(sender_session_pk, gconn->session_secret_key, gconn->shared_key);

    set_sig_pk(gconn->addr.public_key, public_sig_key);

    uint8_t request_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY];
    uint8_t join_type = data[ENC_PUBLIC_KEY + SIG_PUBLIC_KEY + 1];

    if (join_type == HJ_PUBLIC && chat->shared_state.privacy_state != GI_PUBLIC) {
        gc_peer_delete(m, groupnumber, peernumber, nullptr, 0);
        return -1;
    }

    ++gconn->recv_message_id;

    if (send_gc_handshake_response(chat, peernumber, request_type) == -1) {
        return -1;
    }

    return peernumber;
}

/* Handles handshake request and handshake response packets.
 *
 * Returns peernumber of connecting peer on success.
 * Returns -1 on failure.
 */
static int handle_gc_handshake_packet(Messenger *m, GC_Chat *chat, IP_Port *ipp, const uint8_t *packet,
                                      uint16_t length, bool direct_conn)
{
    if (length != GC_ENCRYPTED_HS_PACKET_SIZE) {
        return -1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    VLA(uint8_t, data, length - 1 - HASH_ID_BYTES - ENC_PUBLIC_KEY - CRYPTO_NONCE_SIZE - CRYPTO_MAC_SIZE);

    int plain_len = uwrap_group_handshake_packet(chat->self_secret_key, sender_pk, data, SIZEOF_VLA(data), packet, length);

    if (plain_len != SIZEOF_VLA(data)) {
        return -1;
    }

    uint8_t handshake_type = data[0];

    uint32_t public_key_hash;
    net_unpack_u32(data + 1, &public_key_hash);

    if (public_key_hash != get_peer_key_hash(sender_pk)) {
        return -1;
    }

    const uint8_t *real_data = data + (sizeof(uint8_t) + HASH_ID_BYTES);
    uint16_t real_len = plain_len - (sizeof(uint8_t) - HASH_ID_BYTES);

    int peernumber = -1;

    if (handshake_type == GH_REQUEST) {
        if (ipp == nullptr) {
            return -1;
        }

        peernumber = handle_gc_handshake_request(m, chat->groupnumber, ipp, sender_pk, real_data, real_len);
    } else if (handshake_type == GH_RESPONSE) {
        peernumber = handle_gc_handshake_response(m, chat->groupnumber, sender_pk, real_data, real_len);
    } else {
        return -1;

    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (peernumber > 0 && direct_conn) {
        gconn->last_recv_direct_time = mono_time_get(chat->mono_time);
    }

    return peernumber;
}

int handle_gc_lossless_helper(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    switch (packet_type) {
        case GP_BROADCAST:
            return handle_gc_broadcast(m, groupnumber, peernumber, data, length);

        case GP_PEER_INFO_RESPONSE:
            return handle_gc_peer_info_response(m, groupnumber, peernumber, data, length);

        case GP_PEER_INFO_REQUEST:
            return handle_gc_peer_info_request(m, groupnumber, gconn);

        case GP_SYNC_REQUEST:
            return handle_gc_sync_request(m, groupnumber, gconn, data, length);

        case GP_SYNC_RESPONSE:
            return handle_gc_sync_response(m, groupnumber, peernumber, gconn, data, length);

        case GP_INVITE_REQUEST:
            return handle_gc_invite_request(m, groupnumber, peernumber, data, length);

        case GP_INVITE_RESPONSE:
            return handle_gc_invite_response(m, groupnumber, gconn, data, length);

        case GP_TOPIC:
            return handle_gc_topic(m, groupnumber, peernumber, data, length);

        case GP_SHARED_STATE:
            return handle_gc_shared_state(m, groupnumber, peernumber, data, length);

        case GP_MOD_LIST:
            return handle_gc_mod_list(m, groupnumber, peernumber, data, length);

        case GP_SANCTIONS_LIST:
            return handle_gc_sanctions_list(m, groupnumber, peernumber, data, length);

        case GP_HS_RESPONSE_ACK:
            return handle_gc_hs_response_ack(m, groupnumber, gconn, data, length);

        case GP_CUSTOM_PACKET:
            return handle_gc_custom_packet(m, groupnumber, peernumber, data, length);

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
static int handle_gc_lossless_message(Messenger *m, GC_Chat *chat, const uint8_t *packet, uint16_t length,
                                      bool direct_conn)
{
    if (length < MIN_GC_LOSSLESS_PACKET_SIZE || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);

    int peernumber = get_peernum_of_enc_pk(chat, sender_pk);

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;
    uint64_t message_id;

    int len = unwrap_group_packet(gconn->shared_key, data, &message_id, &packet_type, packet, length);

    if (len <= 0) {
        return -1;
    }

    if (packet_type != GP_HS_RESPONSE_ACK && !gconn->handshaked) {
        return -1;
    }

    uint32_t sender_pk_hash;
    net_unpack_u32(data, &sender_pk_hash);

    if (!peer_pk_hash_match(gconn, sender_pk_hash)) {
        return -1;
    }

    const uint8_t *real_data = data + HASH_ID_BYTES;
    uint16_t real_len = len - HASH_ID_BYTES;

    int lossless_ret = gcc_handle_recv_message(chat, peernumber, real_data, real_len, packet_type, message_id);

    if (lossless_ret == -1) {
        fprintf(stderr, "failed to handle packet %llu (type %u)\n", (unsigned long long)message_id, packet_type);
        return -1;
    }

    /* Duplicate packet */
    if (lossless_ret == 0) {
        fprintf(stderr, "got duplicate packet %lu (type %u)\n", message_id, packet_type);
        return gc_send_message_ack(chat, gconn, message_id, 0);
    }

    /* request missing packet */
    if (lossless_ret == 1) {
        fprintf(stderr, "recieved out of order packet. expected %lu, got %lu\n", gconn->recv_message_id + 1, message_id);
        return gc_send_message_ack(chat, gconn, 0, gconn->recv_message_id + 1);
    }

    int ret = handle_gc_lossless_helper(m, chat->groupnumber, peernumber, real_data, real_len, message_id, packet_type);

    if (ret == -1) {
        fprintf(stderr, "lossless handler failed (type %u)\n", packet_type);
        return -1;
    }

    /* we need to get the peernumber again because it may have changed */
    peernumber = get_peernum_of_enc_pk(chat, sender_pk);
    // TODO(iphydf): This is fixing one symptom of a problem: objects
    // pointed at by gconn can easily go out of scope because of realloc.
    gconn = gcc_get_connection(chat, peernumber);

    if (lossless_ret == 2 && peernumber != -1) {
        gc_send_message_ack(chat, gconn, message_id, 0);
        gcc_check_recv_ary(m, chat->groupnumber, peernumber);

        if (direct_conn) {
            gconn->last_recv_direct_time = mono_time_get(chat->mono_time);
        }
    }

    return ret;
}

/* Handles lossy groupchat message packets.
 *
 * return non-negative value if packet is handled correctly.
 * return -1 on failure.
 */
static int handle_gc_lossy_message(Messenger *m, GC_Chat *chat, const uint8_t *packet, uint16_t length,
                                   bool direct_conn)
{
    if (length < MIN_GC_LOSSY_PACKET_SIZE || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    uint8_t sender_pk[ENC_PUBLIC_KEY];
    memcpy(sender_pk, packet + 1 + HASH_ID_BYTES, ENC_PUBLIC_KEY);

    int peernumber = get_peernum_of_enc_pk(chat, sender_pk);

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    if (!gconn->handshaked) {
        return -1;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;

    int len = unwrap_group_packet(gconn->shared_key, data, nullptr, &packet_type, packet, length);

    if (len <= 0) {
        return -1;
    }

    uint32_t sender_pk_hash;
    net_unpack_u32(data, &sender_pk_hash);

    const uint8_t *real_data = data + HASH_ID_BYTES;
    len -= HASH_ID_BYTES;

    if (!peer_pk_hash_match(gconn, sender_pk_hash)) {
        return -1;
    }

    int ret = -1;

    switch (packet_type) {
        case GP_MESSAGE_ACK:
            ret = handle_gc_message_ack(chat, gconn, real_data, len);
            break;

        case GP_PING:
            ret = handle_gc_ping(m, chat->groupnumber, gconn, real_data, len);
            break;

        case GP_INVITE_RESPONSE_REJECT:
            ret = handle_gc_invite_response_reject(m, chat->groupnumber, real_data, len);
            break;

        case GP_TCP_RELAYS:
            ret = handle_gc_tcp_relays(m, chat->groupnumber, gconn, real_data, len);
            break;

        case GP_CUSTOM_PACKET:
            ret = handle_gc_custom_packet(m, chat->groupnumber, peernumber, real_data, len);
            break;

        default:
            fprintf(stderr, "Warning: handling invalid lossy group packet type %u\n", packet_type);
            return -1;
    }

    if (ret != -1 && direct_conn) {
        gconn->last_recv_direct_time = mono_time_get(m->mono_time);
    }

    return ret;
}

/* Sends a group packet to appropriate handler function.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_tcp_packet(void *object, int id, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + sizeof(uint32_t)) {
        return -1;
    }

    uint32_t chat_id_hash;
    net_unpack_u32(packet + 1, &chat_id_hash);

    Messenger *m = (Messenger *)object;
    GC_Session *c = m->group_handler;
    GC_Chat *chat = get_chat_by_hash(c, chat_id_hash);

    if (!chat) {
        return -1;
    }

    if (chat->connection_state == CS_FAILED) {
        return -1;
    }

    if (packet[0] == NET_PACKET_GC_LOSSLESS) {
        return handle_gc_lossless_message(m, chat, packet, length, false);
    } else if (packet[0] == NET_PACKET_GC_LOSSY) {
        return handle_gc_lossy_message(m, chat, packet, length, false);
    } else if (packet[0] == NET_PACKET_GC_HANDSHAKE) {
        return handle_gc_handshake_packet(m, chat, nullptr, packet, length, false);
    }

    return -1;
}

static int handle_gc_tcp_oob_packet(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                                    const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + sizeof(uint32_t)) {
        return -1;
    }

    uint32_t chat_id_hash;
    net_unpack_u32(packet + 1, &chat_id_hash);

    Messenger *m = (Messenger *)object;
    GC_Session *c = m->group_handler;
    GC_Chat *chat = get_chat_by_hash(c, chat_id_hash);

    if (!chat) {
        return -1;
    }

    if (chat->connection_state == CS_FAILED) {
        return -1;
    }

    if (packet[0] != NET_PACKET_GC_HANDSHAKE) {
        return -1;
    }

    IP_Port ipp;
    ipp.port = 0;
    ipp.ip.family = net_family_tcp_family;
    ipp.ip.ip.v6.uint32[0] = tcp_connections_number;

    if (handle_gc_handshake_packet(m, chat, &ipp, packet, length, false) == -1) {
        return -1;
    }

    return 0;
}

static int handle_gc_udp_packet(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + sizeof(uint32_t)) {
        return -1;
    }

    uint32_t chat_id_hash;
    net_unpack_u32(packet + 1, &chat_id_hash);

    Messenger *m = (Messenger *)object;
    GC_Chat *chat = get_chat_by_hash(m->group_handler, chat_id_hash);

    if (!chat) {
        fprintf(stderr, "get_chat_by_hash failed in handle_gc_udp_packet (type %u)\n", packet[0]);
        return -1;
    }

    if (chat->connection_state == CS_FAILED) {
        return -1;
    }

    if (packet[0] == NET_PACKET_GC_LOSSLESS) {
        return handle_gc_lossless_message(m, chat, packet, length, true);
    } else if (packet[0] == NET_PACKET_GC_LOSSY) {
        return handle_gc_lossy_message(m, chat, packet, length, true);
    } else if (packet[0] == NET_PACKET_GC_HANDSHAKE) {
        return handle_gc_handshake_packet(m, chat, &ipp, packet, length, true);
    }

    return -1;
}

void gc_callback_message(Messenger *m, gc_message_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->message = function;
    c->message_userdata = userdata;
}

void gc_callback_private_message(Messenger *m, gc_private_message_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->private_message = function;
    c->private_message_userdata = userdata;
}

void gc_callback_custom_packet(Messenger *m, gc_custom_packet_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->custom_packet = function;
    c->custom_packet_userdata = userdata;
}

void gc_callback_moderation(Messenger *m, gc_moderation_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->moderation = function;
    c->moderation_userdata = userdata;
}

void gc_callback_nick_change(Messenger *m, gc_nick_change_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->nick_change = function;
    c->nick_change_userdata = userdata;
}

void gc_callback_status_change(Messenger *m, gc_status_change_cb *function,
                               void *userdata)
{
    GC_Session *c = m->group_handler;
    c->status_change = function;
    c->status_change_userdata = userdata;
}

void gc_callback_topic_change(Messenger *m, gc_topic_change_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->topic_change = function;
    c->topic_change_userdata = userdata;
}

void gc_callback_peer_limit(Messenger *m, gc_peer_limit_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_limit = function;
    c->peer_limit_userdata = userdata;
}

void gc_callback_privacy_state(Messenger *m, gc_privacy_state_cb *function,
                               void *userdata)
{
    GC_Session *c = m->group_handler;
    c->privacy_state = function;
    c->privacy_state_userdata = userdata;
}

void gc_callback_password(Messenger *m, gc_password_cb *function,
                          void *userdata)
{
    GC_Session *c = m->group_handler;
    c->password = function;
    c->password_userdata = userdata;
}

void gc_callback_peer_join(Messenger *m, gc_peer_join_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_join = function;
    c->peer_join_userdata = userdata;
}

void gc_callback_peer_exit(Messenger *m, gc_peer_exit_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->peer_exit = function;
    c->peer_exit_userdata = userdata;
}

void gc_callback_self_join(Messenger *m, gc_self_join_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->self_join = function;
    c->self_join_userdata = userdata;
}

void gc_callback_rejected(Messenger *m, gc_rejected_cb *function, void *userdata)
{
    GC_Session *c = m->group_handler;
    c->rejected = function;
    c->rejected_userdata = userdata;
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

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peernumber);

    if (gconn == nullptr) {
        return -1;
    }

    /* Needs to occur before peer is removed*/
    if (c->peer_exit && gconn->confirmed) {
        (*c->peer_exit)(m, groupnumber, chat->group[peernumber].peer_id, data, length, c->peer_exit_userdata);
    }

    kill_tcp_connection_to(chat->tcp_conn, gconn->tcp_connection_num);
    gca_peer_cleanup(m->group_handler->announce, get_chat_id(chat->chat_public_key), gconn->addr.public_key);
    gcc_peer_cleanup(gconn);

    --chat->numpeers;

    if (chat->numpeers != peernumber) {
        memcpy(&chat->group[peernumber], &chat->group[chat->numpeers], sizeof(GC_GroupPeer));
        memcpy(&chat->gcc[peernumber], &chat->gcc[chat->numpeers], sizeof(GC_Connection));
    }

    memset(&chat->group[chat->numpeers], 0, sizeof(GC_GroupPeer));
    memset(&chat->gcc[chat->numpeers], 0, sizeof(GC_Connection));

    GC_GroupPeer *tmp_group = (GC_GroupPeer *)realloc(chat->group, sizeof(GC_GroupPeer) * chat->numpeers);

    if (tmp_group == nullptr) {
        return -1;
    }

    chat->group = tmp_group;

    GC_Connection *tmp_gcc = (GC_Connection *)realloc(chat->gcc, sizeof(GC_Connection) * chat->numpeers);

    if (tmp_gcc == nullptr) {
        return -1;
    }

    chat->gcc = tmp_gcc;

    return 0;
}

/* Updates peer's peer info and generates a new peer_id.
 *
 * Returns peernumber on success.
 * Returns -1 on failure.
 */
static int peer_update(Messenger *m, int groupnumber, GC_GroupPeer *peer, uint32_t peernumber)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (peer->nick_len == 0) {
        return -1;
    }

    int nick_num = get_nick_peernumber(chat, peer->nick, peer->nick_len);

    if (nick_num != -1 && nick_num != peernumber) {   /* duplicate nick */
        if (c->peer_exit) {
            (*c->peer_exit)(m, groupnumber, chat->group[peernumber].peer_id, nullptr, 0, c->peer_exit_userdata);
        }

        gc_peer_delete(m, groupnumber, peernumber, nullptr, 0);
        return -1;
    }

    memcpy(&chat->group[peernumber], peer, sizeof(GC_GroupPeer));
    chat->group[peernumber].peer_id = get_new_peer_id(chat);
    chat->group[peernumber].ignore = false;

    return peernumber;
}

/* Adds a new peer to groupnumber's peer list.
 *
 * Return peernumber if success.
 * Return -1 on failure.
 * Returns -2 if a peer with public_key is already in our peerlist.
 */
static int peer_add(Messenger *m, int groupnumber, IP_Port *ipp, const uint8_t *public_key)
{
    GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    if (get_peernum_of_enc_pk(chat, public_key) != -1) {
        return -2;
    }

    int tcp_connection_num = -1;

    if (chat->numpeers > 0) {
        tcp_connection_num = new_tcp_connection_to(chat->tcp_conn, public_key, 0);

        if (tcp_connection_num == -1) {
            return -1;
        }
    }

    int peernumber = chat->numpeers;

    GC_Connection *tmp_gcc = (GC_Connection *)realloc(chat->gcc, sizeof(GC_Connection) * (chat->numpeers + 1));

    if (tmp_gcc == nullptr) {
        kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        return -1;
    }

    memset(&tmp_gcc[peernumber], 0, sizeof(GC_Connection));
    chat->gcc = tmp_gcc;

    GC_GroupPeer *tmp_group = (GC_GroupPeer *)realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (tmp_group == nullptr) {
        kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        return -1;
    }

    ++chat->numpeers;
    memset(&tmp_group[peernumber], 0, sizeof(GC_GroupPeer));
    chat->group = tmp_group;

    GC_Connection *gconn = &chat->gcc[peernumber];

    if (ipp) {
        ipport_copy(&gconn->addr.ip_port, ipp);
    }

    chat->group[peernumber].role = GR_INVALID;
    chat->group[peernumber].peer_id = get_new_peer_id(chat);
    chat->group[peernumber].ignore = false;

    crypto_box_keypair(gconn->session_public_key, gconn->session_secret_key);
    memcpy(gconn->addr.public_key, public_key, ENC_PUBLIC_KEY);  /* we get the sig key in the handshake */

    gconn->public_key_hash = get_peer_key_hash(public_key);
    gconn->last_rcvd_ping = mono_time_get(chat->mono_time) + (rand() % GC_PING_INTERVAL);
    gconn->time_added = mono_time_get(chat->mono_time);
    gconn->send_message_id = 1;
    gconn->send_ary_start = 1;
    gconn->recv_message_id = 0;
    gconn->tcp_connection_num = tcp_connection_num;

    return peernumber;
}

/* Copies own peer data to peer */
static void self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_GroupPeer *peer)
{
    memset(peer, 0, sizeof(GC_GroupPeer));
    memcpy(peer->nick, chat->group[0].nick, chat->group[0].nick_len);
    peer->nick_len = chat->group[0].nick_len;
    peer->status = chat->group[0].status;
    peer->role = chat->group[0].role;
}

/* Returns true if we haven't received a ping from this peer after T seconds.
 * T depends on whether or not the peer has been confirmed.
 */
static bool peer_timed_out(const Mono_Time *mono_time, const GC_Chat *chat, GC_Connection *gconn)
{
    return mono_time_is_timeout(mono_time, gconn->last_rcvd_ping, gconn->confirmed
                                ? GC_CONFIRMED_PEER_TIMEOUT
                                : GC_UNCONFRIMED_PEER_TIMEOUT);
}

static void do_peer_connections(Messenger *m, int groupnumber)
{
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        return;
    }

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            if (mono_time_is_timeout(m->mono_time, chat->gcc[i].last_tcp_relays_shared, GCC_TCP_SHARED_RELAYS_TIMEOUT)) {
                send_gc_tcp_relays(m->mono_time, chat, &chat->gcc[i]);
            }
        }

        if (peer_timed_out(m->mono_time, chat, &chat->gcc[i])) {
            gc_peer_delete(m, groupnumber, i, (const uint8_t *)"Timed out", 9);
        } else {
            gcc_resend_packets(m, chat, i);   // This function may delete the peer
        }

        if (i >= chat->numpeers) {
            break;
        }
    }
}

/* Ping packet includes your confirmed peer count, shared state version
 * and sanctions list version for syncing purposes
 */
static void ping_group(GC_Chat *chat)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_sent_ping_time, GC_PING_INTERVAL)) {
        return;
    }

    uint32_t length = HASH_ID_BYTES + GC_PING_PACKET_DATA_SIZE;
    VLA(uint8_t, data, length);

    uint32_t num_confirmed_peers = get_gc_confirmed_numpeers(chat);
    net_pack_u32(data, chat->self_public_key_hash);
    net_pack_u32(data + HASH_ID_BYTES, num_confirmed_peers);
    net_pack_u32(data + HASH_ID_BYTES + sizeof(uint32_t), chat->shared_state.version);
    net_pack_u32(data + HASH_ID_BYTES + (sizeof(uint32_t) * 2), chat->moderation.sanctions_creds.version);
    net_pack_u32(data + HASH_ID_BYTES + (sizeof(uint32_t) * 3), chat->topic_info.version);

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossy_group_packet(chat, &chat->gcc[i], data, length, GP_PING);
        }
    }

    chat->last_sent_ping_time = mono_time_get(chat->mono_time);
}

/* Searches the DHT for nodes belonging to the group periodically in case of a split group.
 * The search frequency is relative to the number of peers in the group.
 */
#define GROUP_SEARCH_ANNOUNCE_INTERVAL 180
static void search_gc_announce(GC_Session *c, GC_Chat *chat)
{
    if (!mono_time_is_timeout(c->messenger->mono_time, chat->announce_search_timer, GROUP_SEARCH_ANNOUNCE_INTERVAL)) {
        return;
    }

    chat->announce_search_timer = mono_time_get(c->messenger->mono_time);
    uint32_t cnumpeers = get_gc_confirmed_numpeers(chat);

    if (random_int_range(cnumpeers) == 0) {
        /* DHT response/sync procedure is handled in gc_update_addresses_cb() */
        group_get_nodes_request(c, chat);
    }
}

static void do_new_connection_cooldown(GC_Chat *chat)
{
    if (chat->connection_O_metre == 0) {
        return;
    }

    uint64_t tm = mono_time_get(chat->mono_time);

    if (chat->connection_cooldown_timer < tm) {
        chat->connection_cooldown_timer = tm;
        --chat->connection_O_metre;

        if (chat->connection_O_metre == 0) {
            chat->block_handshakes = false;
        }
    }
}

static void do_group_tcp(GC_Chat *chat, void *userdata)
{
    if (!chat->tcp_conn) {
        return;
    }

    do_tcp_connections(chat->tcp_conn, userdata);

    uint32_t i;

    for (i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];
        bool tcp_set = gcc_connection_is_direct(chat->mono_time, gconn) ? false : true;
        set_tcp_connection_to_status(chat->tcp_conn, gconn->tcp_connection_num, tcp_set);
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
void do_gc(GC_Session *c, void *userdata)
{
    if (!c) {
        return;
    }

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];
        do_group_tcp(chat, userdata);

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
                    self_gc_connected(c->messenger->mono_time, chat);

                    /* If we can't get an invite we assume the group is empty */
                    if (chat->shared_state.version == 0 || group_announce_request(c, chat) == -1) {
                        if (c->rejected) {
                            (*c->rejected)(c->messenger, i, GJ_INVITE_FAILED, c->rejected_userdata);
                        }

                        chat->connection_state = CS_FAILED;
                    }

                    if (chat->group[0].role == GR_FOUNDER) {
                        if (sign_gc_shared_state(chat) == -1) {
                            chat->connection_state = CS_FAILED;
                        }
                    }

                    break;
                }

                if (mono_time_is_timeout(c->messenger->mono_time, chat->last_get_nodes_attempt, GROUP_GET_NEW_NODES_INTERVAL)) {
                    ++chat->get_nodes_attempts;
                    chat->last_get_nodes_attempt = mono_time_get(c->messenger->mono_time);
                    group_get_nodes_request(c, chat);
                }

                chat->connection_state = CS_DISCONNECTED;
                break;
            }

            case CS_DISCONNECTED: {
                if (chat->num_addrs
                        && mono_time_is_timeout(c->messenger->mono_time, chat->last_join_attempt, GROUP_JOIN_ATTEMPT_INTERVAL)) {
                    send_gc_handshake_request(c->messenger, i, chat->addr_list[chat->addrs_idx].ip_port,
                                              chat->addr_list[chat->addrs_idx].public_key, HS_INVITE_REQUEST,
                                              chat->join_type);

                    chat->last_join_attempt = mono_time_get(c->messenger->mono_time);
                    chat->addrs_idx = (chat->addrs_idx + 1) % chat->num_addrs;
                }

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
        c->chats = nullptr;
        return 0;
    }

    GC_Chat *temp = (GC_Chat *)realloc(c->chats, n * sizeof(GC_Chat));

    if (temp == nullptr) {
        return -1;
    }

    c->chats = temp;
    return 0;
}

static int get_new_group_index(GC_Session *c)
{
    if (c == nullptr) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state == CS_NONE) {
            return i;
        }
    }

    if (realloc_groupchats(c, c->num_chats + 1) != 0) {
        return -1;
    }

    int new_index = c->num_chats;
    memset(&(c->chats[new_index]), 0, sizeof(GC_Chat));

    ++c->num_chats;

    return new_index;
}

static int init_gc_tcp_connection(Messenger *m, GC_Chat *chat)
{
    chat->tcp_conn = new_tcp_connections(m->mono_time, chat->self_secret_key, &m->options.proxy_info);

    if (chat->tcp_conn == nullptr) {
        return -1;
    }

    uint16_t num_relays = tcp_connections_count(nc_get_tcp_c(m->net_crypto));

    if (num_relays == 0) {
        // TODO(iphydf): This should be an error, but for now TCP isn't working.
        return 0;
    }

    VLA(Node_format, tcp_relays, num_relays);
    unsigned int i, num = tcp_copy_connected_relays(nc_get_tcp_c(m->net_crypto), tcp_relays, num_relays);

    for (i = 0; i < num; ++i) {
        add_tcp_relay_global(chat->tcp_conn, tcp_relays[i].ip_port, tcp_relays[i].public_key);
    }

    set_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_packet, m);
    set_oob_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_oob_packet, m);
    return 0;
}

static int create_new_group(GC_Session *c, bool founder)
{
    int groupnumber = get_new_group_index(c);

    if (groupnumber == -1) {
        return -1;
    }

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[groupnumber];

    create_extended_keypair(chat->self_public_key, chat->self_secret_key);

    if (init_gc_tcp_connection(m, chat) == -1) {
        group_delete(c, chat);
        return -1;
    }

    chat->groupnumber = groupnumber;
    chat->numpeers = 0;
    chat->connection_state = CS_DISCONNECTED;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->last_get_nodes_attempt = mono_time_get(m->mono_time);
    chat->last_sent_ping_time = mono_time_get(m->mono_time);
    chat->announce_search_timer = mono_time_get(m->mono_time);

    if (peer_add(m, groupnumber, nullptr, chat->self_public_key) != 0) {    /* you are always peernumber/index 0 */
        group_delete(c, chat);
        return -1;
    }

    memcpy(chat->group[0].nick, m->name, m->name_length);
    chat->group[0].nick_len = m->name_length;
    chat->group[0].status = m->userstatus;
    chat->group[0].role = founder ? GR_FOUNDER : GR_USER;
    chat->gcc[0].confirmed = true;
    chat->self_public_key_hash = chat->gcc[0].public_key_hash;
    memcpy(chat->gcc[0].addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY);

    return groupnumber;
}

/* Initializes group shared state and creates a signature for it using the chat secret key.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int init_gc_shared_state(GC_Chat *chat, uint8_t privacy_state, const uint8_t *group_name,
                                uint16_t name_length)
{
    memcpy(chat->shared_state.founder_public_key, chat->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->shared_state.group_name, group_name, name_length);
    chat->shared_state.group_name_len = name_length;
    chat->shared_state.maxpeers = MAX_GC_NUM_PEERS;
    chat->shared_state.privacy_state = privacy_state;

    return sign_gc_shared_state(chat);
}

/* Inits the sanctions list credentials. This should be called by the group founder on creation.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int init_gc_sanctions_creds(GC_Chat *chat)
{
    if (sanctions_list_make_creds(chat) == -1) {
        return -1;
    }

    return 0;
}

/* Loads a previously saved group and attempts to connect to it.
 *
 * Returns groupnumber on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, struct Saved_Group *save)
{
    int groupnumber = get_new_group_index(c);

    if (groupnumber == -1) {
        return -1;
    }

    uint64_t tm = mono_time_get(c->messenger->mono_time);

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[groupnumber];

    if (init_gc_tcp_connection(m, chat) == -1) {
        return -1;
    }

    chat->groupnumber = groupnumber;
    chat->numpeers = 0;
    chat->connection_state = CS_DISCONNECTED;
    chat->join_type = HJ_PRIVATE;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->last_get_nodes_attempt = tm;
    chat->last_sent_ping_time = tm;
    chat->announce_search_timer = tm;

    memcpy(chat->shared_state.founder_public_key, save->founder_public_key, EXT_PUBLIC_KEY);
    chat->shared_state.group_name_len = net_ntohs(save->group_name_len);
    memcpy(chat->shared_state.group_name, save->group_name, MAX_GC_GROUP_NAME_SIZE);
    chat->shared_state.privacy_state = save->privacy_state;
    chat->shared_state.maxpeers = net_ntohs(save->maxpeers);
    chat->shared_state.passwd_len = net_ntohs(save->passwd_len);
    memcpy(chat->shared_state.passwd, save->passwd, MAX_GC_PASSWD_SIZE);
    memcpy(chat->shared_state.mod_list_hash, save->mod_list_hash, GC_MODERATION_HASH_SIZE);
    chat->shared_state.version = net_ntohl(save->sstate_version);
    memcpy(chat->shared_state_sig, save->sstate_signature, SIGNATURE_SIZE);

    chat->topic_info.length = net_ntohs(save->topic_len);
    memcpy(chat->topic_info.topic, save->topic, MAX_GC_TOPIC_SIZE);
    memcpy(chat->topic_info.public_sig_key, save->topic_public_sig_key, SIG_PUBLIC_KEY);
    chat->topic_info.version = net_ntohl(save->topic_version);
    memcpy(chat->topic_sig, save->topic_signature, SIGNATURE_SIZE);

    memcpy(chat->chat_public_key, save->chat_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->chat_secret_key, save->chat_secret_key, EXT_SECRET_KEY);

    uint16_t num_mods = net_ntohs(save->num_mods);

    if (mod_list_unpack(chat, save->mod_list, num_mods * GC_MOD_LIST_ENTRY_SIZE, num_mods) == -1) {
        return -1;
    }

    memcpy(chat->self_public_key, save->self_public_key, EXT_PUBLIC_KEY);
    memcpy(chat->self_secret_key, save->self_secret_key, EXT_SECRET_KEY);
    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->self_public_key_hash = get_peer_key_hash(chat->self_public_key);

    if (peer_add(m, groupnumber, nullptr, save->self_public_key) != 0) {
        return -1;
    }

    memcpy(chat->group[0].nick, save->self_nick, MAX_GC_NICK_SIZE);
    chat->group[0].nick_len = net_ntohs(save->self_nick_len);
    chat->group[0].role = save->self_role;
    chat->group[0].status = save->self_status;
    chat->gcc[0].confirmed = true;
    memcpy(chat->gcc[0].addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY);

    if (save->self_role == GR_FOUNDER) {
        if (init_gc_sanctions_creds(chat) == -1) {
            return -1;
        }
    }

    uint16_t i, num = 0, num_addrs = net_ntohs(save->num_addrs);

    for (i = 0; i < num_addrs && i < MAX_GC_PEER_ADDRS; ++i) {
        if (ipport_isset(&save->addrs[i].ip_port)) {
            chat->addr_list[num] = save->addrs[i];
            ++num;
        }
    }

    chat->num_addrs = num;

    return groupnumber;
}

/* Creates a new group.
 *
 * Return groupnumber on success.
 * Return -1 if the group name is too long.
 * Return -2 if the group name is empty.
 * Return -3 if the privacy state is an invalid type.
 * Return -4 if the the group object fails to initialize.
 * Return -5 if the group state fails to initialize.
 * Return -6 if the group fails to announce to the DHT.
 */
int gc_group_add(GC_Session *c, uint8_t privacy_state, const uint8_t *group_name, uint16_t length)
{
    if (length > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    if (length == 0 || group_name == nullptr) {
        return -2;
    }

    if (privacy_state >= GI_INVALID) {
        return -3;
    }

    int groupnumber = create_new_group(c, true);

    if (groupnumber == -1) {
        return -4;
    }

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -4;
    }

    create_extended_keypair(chat->chat_public_key, chat->chat_secret_key);

    if (init_gc_shared_state(chat, privacy_state, group_name, length) == -1) {
        group_delete(c, chat);
        return -5;
    }

    if (init_gc_sanctions_creds(chat) == -1) {
        group_delete(c, chat);
        return -5;
    }

    if (gc_set_topic(chat, (const uint8_t *)" ", 1) != 0) {
        group_delete(c, chat);
        return -5;
    }

    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->join_type = HJ_PRIVATE;
    self_gc_connected(c->messenger->mono_time, chat);

    if (group_announce_request(c, chat) == -1) {
        group_delete(c, chat);
        return -6;
    }

    return groupnumber;
}

/* Sends an invite request to a public group using the chat_id.
 *
 * If the group is not password protected passwd should be set to NULL and passwd_len should be 0.
 *
 * Return groupnumber on success.
 * Reutrn -1 if the group object fails to initialize.
 * Return -2 if chat_id is NULL or a group with chat_id already exists in the chats array.
 * Return -3 if there is an error setting the group password.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *passwd, uint16_t passwd_len)
{
    if (chat_id == nullptr || group_exists(c, chat_id)) {
        return -2;
    }

    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        return -1;
    }

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->join_type = HJ_PUBLIC;

    if (passwd != nullptr && passwd_len > 0) {
        if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
            return -3;
        }
    }

    if (chat->num_addrs == 0) {
        group_get_nodes_request(c, chat);
    }

    return groupnumber;
}

/* Resets chat saving all self state and attempts to reconnect to group */
void gc_rejoin_group(GC_Session *c, GC_Chat *chat)
{
    send_gc_self_exit(chat, nullptr, 0);

    clear_gc_addrs_list(chat);
    chat->num_addrs = gc_copy_peer_addrs(chat, chat->addr_list, MAX_GC_PEER_ADDRS);

    uint32_t i;

    /* Remove all peers except self. Numpeers decrements with each call to gc_peer_delete */
    for (i = 1; chat->numpeers > 1;) {
        if (gc_peer_delete(c->messenger, chat->groupnumber, i, nullptr, 0) == -1) {
            break;
        }
    }

    chat->connection_state = CS_DISCONNECTED;
    chat->last_get_nodes_attempt = chat->num_addrs > 0 ? mono_time_get(c->messenger->mono_time) :
                                   0;  /* Reconnect using saved peers or DHT */
    chat->last_sent_ping_time = mono_time_get(c->messenger->mono_time);
    chat->last_join_attempt = mono_time_get(c->messenger->mono_time);
    chat->announce_search_timer = mono_time_get(c->messenger->mono_time);
    chat->get_nodes_attempts = 0;
}

/* Invites friendnumber to chat. Packet includes: Type, chat_id, node
 *
 * Return 0 on success.
 * Return -1 if friendnumber does not exist.
 * Return -2 on failure to create the invite data.
 * Return -3 if the packet fails to send.
 */
int gc_invite_friend(GC_Session *c, GC_Chat *chat, int32_t friendnumber,
                     gc_send_group_invite_packet_cb *send_group_invite_packet)
{
    if (friend_not_valid(c->messenger, friendnumber)) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;

    memcpy(packet + 1, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);

    GC_Announce_Node self_node;

    if (make_self_gca_node(c->messenger->dht, &self_node, chat->self_public_key) == -1) {
        return -1;
    }

    int node_len = pack_gca_nodes(packet + 1 + CHAT_ID_SIZE, sizeof(GC_Announce_Node), &self_node, 1);

    if (node_len <= 0) {
        fprintf(stderr, "pack_gca_nodes failed in gc_invite_friend (%d)\n", node_len);
        return -1;
    }

    uint16_t length = 1 + CHAT_ID_SIZE + node_len;

    if (send_group_invite_packet(c->messenger, friendnumber, packet, length) == -1) {
        return -2;
    }

    return 0;
}

/* Joins a group using the invite data received in a friend's group invite.
 *
 * Return groupnumber on success.
 * Return -1 if the invite data is malformed.
 * Return -2 if the group object fails to initialize.
 * Return -3 if there is an error setting the password.
 */
int gc_accept_invite(GC_Session *c, const uint8_t *data, uint16_t length, const uint8_t *passwd, uint16_t passwd_len)
{
    uint8_t chat_id[CHAT_ID_SIZE];
    memcpy(chat_id, data, CHAT_ID_SIZE);

    GC_Announce_Node node;

    if (unpack_gca_nodes(&node, 1, nullptr, data + CHAT_ID_SIZE, length - CHAT_ID_SIZE, 0) != 1) {
        return -1;
    }

    int err = -2;
    int groupnumber = create_new_group(c, false);

    if (groupnumber == -1) {
        return err;
    }

    GC_Chat *chat = gc_get_group(c, groupnumber);

    if (chat == nullptr) {
        goto ON_ERROR;
    }

    expand_chat_id(chat->chat_public_key, chat_id);
    chat->chat_id_hash = get_chat_id_hash(get_chat_id(chat->chat_public_key));
    chat->join_type = HJ_PRIVATE;
    chat->last_join_attempt = mono_time_get(c->messenger->mono_time);

    if (passwd != nullptr && passwd_len > 0) {
        err = -3;

        if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
            goto ON_ERROR;
        }
    }

    memcpy(&chat->addr_list[0].ip_port, &node.ip_port, sizeof(IP_Port));
    memcpy(&chat->addr_list[0].public_key, node.public_key, ENC_PUBLIC_KEY);
    chat->num_addrs = 1;

    send_gc_handshake_request(c->messenger, groupnumber, node.ip_port, node.public_key, HS_INVITE_REQUEST,
                              chat->join_type);
    return groupnumber;

ON_ERROR:
    group_delete(c, chat);
    return err;
}

GC_Session *new_dht_groupchats(Messenger *m)
{
    GC_Session *c = (GC_Session *)calloc(sizeof(GC_Session), 1);

    if (c == nullptr) {
        return nullptr;
    }

    c->messenger = m;
    c->announce = m->group_announce;

    networking_registerhandler(m->net, NET_PACKET_GC_LOSSLESS, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_LOSSY, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_HANDSHAKE, &handle_gc_udp_packet, m);
    group_callback_update_addresses(c->announce, handle_update_gc_addresses, c);

    return c;
}

/* Deletes chat from group chat array and cleans up.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int group_delete(GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr) {
        return -1;
    }

    mod_list_cleanup(chat);
    sanctions_list_cleanup(chat);
    kill_tcp_connections(chat->tcp_conn);
    gca_cleanup(c->announce, get_chat_id(chat->chat_public_key));
    gcc_cleanup(chat);

    if (chat->group) {
        free(chat->group);
    }

    memset(&(c->chats[chat->groupnumber]), 0, sizeof(GC_Chat));

    uint32_t i;

    for (i = c->num_chats; i > 0; --i) {
        if (c->chats[i - 1].connection_state != CS_NONE) {
            break;
        }
    }

    if (c->num_chats != i) {
        c->num_chats = i;

        if (realloc_groupchats(c, c->num_chats) != 0) {
            return -1;
        }
    }

    return 0;
}

/* Sends parting message to group and deletes group.
 *
 * Return 0 on success.
 * Return -1 if the parting message is too long.
 * Return -2 if the parting message failed to send.
 * Return -3 if the group instance failed delete.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length)
{
    int ret = send_gc_self_exit(chat, message, length);

    if (group_delete(c, chat) == -1) {
        ret = -3;
    }

    return ret;
}

void kill_dht_groupchats(GC_Session *c)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state != CS_NONE) {
            GC_Chat *chat = &c->chats[i];
            send_gc_self_exit(chat, nullptr, 0);
            kill_tcp_connections(chat->tcp_conn);
        }
    }

    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSY, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSLESS, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_HANDSHAKE, nullptr, nullptr);
    group_callback_update_addresses(c->announce, nullptr, nullptr);
    free(c);
}

/* Return 1 if groupnumber is a valid group chat index
 * Return 0 otherwise
 */
static int groupnumber_valid(const GC_Session *c, int groupnumber)
{
    if (groupnumber < 0 || groupnumber >= c->num_chats) {
        return 0;
    }

    if (c->chats == nullptr) {
        return 0;
    }

    return c->chats[groupnumber].connection_state != CS_NONE;
}

/* Count number of active groups.
 *
 * Returns the count.
 */
uint32_t gc_count_groups(const GC_Session *c)
{
    uint32_t i, count = 0;

    for (i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state > CS_NONE && c->chats[i].connection_state < CS_INVALID) {
            ++count;
        }
    }

    return count;
}

/* Return groupnumber's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session *c, int groupnumber)
{
    if (!groupnumber_valid(c, groupnumber)) {
        return nullptr;
    }

    return &c->chats[groupnumber];
}

/* Return peernumber of peer with nick if nick is taken.
 * Return -1 if nick is not taken.
 */
static int get_nick_peernumber(const GC_Chat *chat, const uint8_t *nick, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    uint32_t i;

    for (i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].nick_len == length && memcmp(chat->group[i].nick, nick, length) == 0) {
            return i;
        }
    }

    return -1;
}

/* Return True if chat_id exists in the session chat array */
static bool group_exists(const GC_Session *c, const uint8_t *chat_id)
{
    uint32_t i;

    for (i = 0; i < c->num_chats; ++i) {
        if (memcmp(get_chat_id(c->chats[i].chat_public_key), chat_id, CHAT_ID_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

#endif /* VANILLA_NACL */
