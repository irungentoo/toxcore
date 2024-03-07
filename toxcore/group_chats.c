/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#include "group_chats.h"

#include <sodium.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "Messenger.h"
#include "TCP_connection.h"
#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "friend_connection.h"
#include "group_announce.h"
#include "group_common.h"
#include "group_connection.h"
#include "group_moderation.h"
#include "group_pack.h"
#include "logger.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "network.h"
#include "onion_announce.h"
#include "onion_client.h"
#include "util.h"

/* The minimum size of a plaintext group handshake packet */
#define GC_MIN_HS_PACKET_PAYLOAD_SIZE (1 + ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1 + 1)

/* The minimum size of an encrypted group handshake packet. */
#define GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE (1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE +\
                                          GC_MIN_HS_PACKET_PAYLOAD_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE)

/* Size of a group's shared state in packed format */
#define GC_PACKED_SHARED_STATE_SIZE (EXT_PUBLIC_KEY_SIZE + sizeof(uint16_t) + MAX_GC_GROUP_NAME_SIZE +\
                                     sizeof(uint16_t) + 1 + sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE +\
                                     MOD_MODERATION_HASH_SIZE + sizeof(uint32_t) + sizeof(uint32_t) + 1)

/* Minimum size of a topic packet; includes topic length, public signature key, topic version and checksum */
#define GC_MIN_PACKED_TOPIC_INFO_SIZE (sizeof(uint16_t) + SIG_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint16_t))

#define GC_SHARED_STATE_ENC_PACKET_SIZE (SIGNATURE_SIZE + GC_PACKED_SHARED_STATE_SIZE)

/* Header information attached to all broadcast messages: broadcast_type */
#define GC_BROADCAST_ENC_HEADER_SIZE 1

/* Size of a group packet message ID */
#define GC_MESSAGE_ID_BYTES sizeof(uint64_t)

/* Size of a lossless ack packet */
#define GC_LOSSLESS_ACK_PACKET_SIZE (GC_MESSAGE_ID_BYTES + 1)

/* Smallest possible size of an encrypted lossless payload.
 *
 * Data includes the message_id, group packet type, and the nonce and MAC for decryption.
 */
#define GC_MIN_LOSSLESS_PAYLOAD_SIZE (GC_MESSAGE_ID_BYTES + CRYPTO_NONCE_SIZE + 1 + CRYPTO_MAC_SIZE)

/* Smallest possible size of a lossy group packet */
#define GC_MIN_LOSSY_PAYLOAD_SIZE (GC_MIN_LOSSLESS_PAYLOAD_SIZE - GC_MESSAGE_ID_BYTES)

/* Maximum number of bytes to pad packets with.
 *
 * Packets are padded with a random number of zero bytes between zero and this value in order to hide
 * the true length of the message, which reduces the amount of metadata leaked through packet analysis.
 *
 * Note: This behaviour was copied from the toxcore encryption implementation in net_crypto.c.
 */
#define GC_MAX_PACKET_PADDING 8

/* Minimum size of a ping packet, which contains the peer count, peer list checksum, shared state version,
 * sanctions list version, sanctions list checksum, topic version, and topic checksum
 */
#define GC_PING_PACKET_MIN_DATA_SIZE ((sizeof(uint16_t) * 4) + (sizeof(uint32_t) * 3))

/* How often in seconds we can send a group sync request packet */
#define GC_SYNC_REQUEST_LIMIT (GC_PING_TIMEOUT + 1)

/* How often in seconds we can send the peer list to any peer in the group in a sync response */
#define GC_SYNC_RESPONSE_PEER_LIST_LIMIT 3

/* How often in seconds we try to handshake with an unconfirmed peer */
#define GC_SEND_HANDSHAKE_INTERVAL 3

/* How often in seconds we rotate session encryption keys with a peer */
#define GC_KEY_ROTATION_TIMEOUT (5 * 60)

/* How often in seconds we try to reconnect to peers that recently timed out */
#define GC_TIMED_OUT_RECONN_TIMEOUT (GC_UNCONFIRMED_PEER_TIMEOUT * 3)

/* How long in seconds before we stop trying to reconnect with a timed out peer */
#define GC_TIMED_OUT_STALE_TIMEOUT (60 * 15)

/* The value the topic lock is set to when the topic lock is enabled. */
#define GC_TOPIC_LOCK_ENABLED 0

static_assert(GCC_BUFFER_SIZE <= UINT16_MAX,
              "GCC_BUFFER_SIZE must be <= UINT16_MAX)");

static_assert(MAX_GC_PACKET_CHUNK_SIZE < MAX_GC_PACKET_SIZE,
              "MAX_GC_PACKET_CHUNK_SIZE must be < MAX_GC_PACKET_SIZE");

static_assert(MAX_GC_PACKET_INCOMING_CHUNK_SIZE < MAX_GC_PACKET_SIZE,
              "MAX_GC_PACKET_INCOMING_CHUNK_SIZE must be < MAX_GC_PACKET_SIZE");

static_assert(MAX_GC_PACKET_INCOMING_CHUNK_SIZE >= MAX_GC_PACKET_CHUNK_SIZE,
              "MAX_GC_PACKET_INCOMING_CHUNK_SIZE must be >= MAX_GC_PACKET_CHUNK_SIZE");

// size of a lossless handshake packet - lossless packets can't/shouldn't be split up
static_assert(MAX_GC_PACKET_CHUNK_SIZE >= 171,
              "MAX_GC_PACKET_CHUNK_SIZE must be >= 171");

static_assert(MAX_GC_PACKET_INCOMING_CHUNK_SIZE >= 171,
              "MAX_GC_PACKET_INCOMING_CHUNK_SIZE must be >= 171");

// group_moderation constants assume this is the max packet size.
static_assert(MAX_GC_PACKET_SIZE >= 50000,
              "MAX_GC_PACKET_SIZE doesn't match constants in group_moderation.h");

static_assert(MAX_GC_PACKET_SIZE <= UINT16_MAX - MAX_GC_PACKET_CHUNK_SIZE,
              "MAX_GC_PACKET_SIZE must be <= UINT16_MAX - MAX_GC_PACKET_CHUNK_SIZE");

static_assert(MAX_GC_PACKET_SIZE <= UINT16_MAX - MAX_GC_PACKET_INCOMING_CHUNK_SIZE,
              "MAX_GC_PACKET_SIZE must be <= UINT16_MAX - MAX_GC_PACKET_INCOMING_CHUNK_SIZE");

/** Types of broadcast messages. */
typedef enum Group_Message_Type {
    GC_MESSAGE_TYPE_NORMAL = 0x00,
    GC_MESSAGE_TYPE_ACTION = 0x01,
} Group_Message_Type;

/** Types of handshake request packets. */
typedef enum Group_Handshake_Packet_Type {
    GH_REQUEST  = 0x00,  // Requests a handshake
    GH_RESPONSE = 0x01,  // Responds to a handshake request
} Group_Handshake_Packet_Type;

/** Types of handshake requests (within a handshake request packet). */
typedef enum Group_Handshake_Request_Type {
    HS_INVITE_REQUEST     = 0x00,   // Requests an invite to the group
    HS_PEER_INFO_EXCHANGE = 0x01,   // Requests a peer info exchange
} Group_Handshake_Request_Type;

/** These bitmasks determine what group state info a peer is requesting in a sync request */
typedef enum Group_Sync_Flags {
    GF_PEERS      = (1 << 0), // 1
    GF_TOPIC      = (1 << 1), // 2
    GF_STATE      = (1 << 2), // 4
} Group_Sync_Flags;

non_null() static bool self_gc_is_founder(const GC_Chat *chat);
non_null() static bool group_number_valid(const GC_Session *c, int group_number);
non_null() static int peer_update(const GC_Chat *chat, const GC_Peer *peer, uint32_t peer_number);
non_null() static void group_delete(GC_Session *c, GC_Chat *chat);
non_null() static void group_cleanup(const GC_Session *c, GC_Chat *chat);
non_null() static bool group_exists(const GC_Session *c, const uint8_t *chat_id);
non_null() static void add_tcp_relays_to_chat(const GC_Session *c, GC_Chat *chat);
non_null(1, 2) nullable(4)
static bool peer_delete(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, void *userdata);
non_null() static void create_gc_session_keypair(const Logger *log, const Random *rng, uint8_t *public_key,
        uint8_t *secret_key);
non_null() static size_t load_gc_peers(GC_Chat *chat, const GC_SavedPeerInfo *addrs, uint16_t num_addrs);
non_null() static bool saved_peer_is_valid(const GC_SavedPeerInfo *saved_peer);

static const GC_Chat empty_gc_chat = {nullptr};

#define GC_INVALID_PEER_ID_VALUE ((force GC_Peer_Id_Value)-1)

static GC_Peer_Id gc_invalid_peer_id(void)
{
    const GC_Peer_Id invalid = {GC_INVALID_PEER_ID_VALUE};
    return invalid;
}

static bool gc_peer_id_is_valid(GC_Peer_Id peer_id)
{
    return peer_id.value != GC_INVALID_PEER_ID_VALUE;
}

GC_Peer_Id gc_peer_id_from_int(uint32_t value)
{
    const GC_Peer_Id peer_id = {(force GC_Peer_Id_Value)value};
    return peer_id;
}

uint32_t gc_peer_id_to_int(GC_Peer_Id peer_id)
{
    return (force uint32_t)peer_id.value;
}

static GC_Peer_Id gc_unknown_peer_id(void)
{
    return gc_peer_id_from_int(0);
}

non_null()
static void kill_group_friend_connection(const GC_Session *c, const GC_Chat *chat)
{
    if (chat->friend_connection_id != -1) {
        m_kill_group_connection(c->messenger, chat);
    }
}

uint16_t gc_get_wrapped_packet_size(uint16_t length, Net_Packet_Type packet_type)
{
    assert(length <= (packet_type == NET_PACKET_GC_LOSSY ? MAX_GC_CUSTOM_LOSSY_PACKET_SIZE : MAX_GC_PACKET_CHUNK_SIZE));

    const uint16_t min_header_size = packet_type == NET_PACKET_GC_LOSSY
                                     ? GC_MIN_LOSSY_PAYLOAD_SIZE
                                     : GC_MIN_LOSSLESS_PAYLOAD_SIZE;
    const uint16_t header_size = ENC_PUBLIC_KEY_SIZE + GC_MAX_PACKET_PADDING + min_header_size;

    assert(length <= UINT16_MAX - header_size);

    return length + header_size;
}

/** Return true if `peer_number` is our own. */
static bool peer_number_is_self(int peer_number)
{
    return peer_number == 0;
}

bool gc_peer_number_is_valid(const GC_Chat *chat, int peer_number)
{
    return peer_number >= 0 && peer_number < (int)chat->numpeers;
}

non_null()
static GC_Peer *get_gc_peer(const GC_Chat *chat, int peer_number)
{
    if (!gc_peer_number_is_valid(chat, peer_number)) {
        return nullptr;
    }

    return &chat->group[peer_number];
}

GC_Connection *get_gc_connection(const GC_Chat *chat, int peer_number)
{
    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return nullptr;
    }

    return &peer->gconn;
}

/** Returns the max packet size, not wrapped */
static uint16_t group_packet_max_packet_size(Net_Packet_Type net_packet_type)
{
    if (net_packet_type == NET_PACKET_GC_LOSSY) {
        return MAX_GC_CUSTOM_LOSSY_PACKET_SIZE;
    } else {
        return MAX_GC_PACKET_CHUNK_SIZE;
    }
}

/** Returns the amount of empty padding a packet of designated length should have. */
static uint16_t group_packet_padding_length(uint16_t length, uint16_t max_length)
{
    return (max_length - length) % GC_MAX_PACKET_PADDING;
}

void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    if (nick != nullptr) {
        const GC_Peer *peer = get_gc_peer(chat, 0);
        assert(peer != nullptr);
        assert(peer->nick_length > 0);

        memcpy(nick, peer->nick, peer->nick_length);
    }
}

uint16_t gc_get_self_nick_size(const GC_Chat *chat)
{
    const GC_Peer *peer = get_gc_peer(chat, 0);
    assert(peer != nullptr);

    return peer->nick_length;
}

/** @brief Sets self nick to `nick`.
 *
 * Returns false if `nick` is null or `length` is greater than MAX_GC_NICK_SIZE.
 */
non_null()
static bool self_gc_set_nick(const GC_Chat *chat, const uint8_t *nick, uint16_t length)
{
    if (nick == nullptr || length > MAX_GC_NICK_SIZE) {
        return false;
    }

    GC_Peer *peer = get_gc_peer(chat, 0);
    assert(peer != nullptr);

    memcpy(peer->nick, nick, length);
    peer->nick_length = length;

    return true;
}

Group_Role gc_get_self_role(const GC_Chat *chat)
{

    const GC_Peer *peer = get_gc_peer(chat, 0);
    assert(peer != nullptr);

    return peer->role;
}

/** Sets self role. If role is invalid this function has no effect. */
non_null()
static void self_gc_set_role(const GC_Chat *chat, Group_Role role)
{
    if (role <= GR_OBSERVER) {
        GC_Peer *peer = get_gc_peer(chat, 0);
        assert(peer != nullptr);

        peer->role = role;
    }
}

uint8_t gc_get_self_status(const GC_Chat *chat)
{
    const GC_Peer *peer = get_gc_peer(chat, 0);
    assert(peer != nullptr);

    return peer->status;
}

/** Sets self status. If status is invalid this function has no effect. */
non_null()
static void self_gc_set_status(const GC_Chat *chat, Group_Peer_Status status)
{
    if (status == GS_NONE || status == GS_AWAY || status == GS_BUSY) {
        GC_Peer *peer = get_gc_peer(chat, 0);
        assert(peer != nullptr);
        peer->status = status;
        return;
    }

    LOGGER_WARNING(chat->log, "Attempting to set user status with invalid status: %u", (uint8_t)status);
}

GC_Peer_Id gc_get_self_peer_id(const GC_Chat *chat)
{
    const GC_Peer *peer = get_gc_peer(chat, 0);
    assert(peer != nullptr);

    return peer->peer_id;
}

/** Sets self confirmed status. */
non_null()
static void self_gc_set_confirmed(const GC_Chat *chat, bool confirmed)
{
    GC_Connection *gconn = get_gc_connection(chat, 0);
    assert(gconn != nullptr);

    gconn->confirmed = confirmed;
}

/** Returns true if self has the founder role */
non_null()
static bool self_gc_is_founder(const GC_Chat *chat)
{
    return gc_get_self_role(chat) == GR_FOUNDER;
}

void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key)
{
    if (public_key != nullptr) {
        memcpy(public_key, chat->self_public_key.enc, ENC_PUBLIC_KEY_SIZE);
    }
}

/** @brief Sets self extended public key to `ext_public_key`.
 *
 * If `ext_public_key` is null this function has no effect.
 */
non_null()
static void self_gc_set_ext_public_key(const GC_Chat *chat, const Extended_Public_Key *ext_public_key)
{
    if (ext_public_key != nullptr) {
        GC_Connection *gconn = get_gc_connection(chat, 0);
        assert(gconn != nullptr);
        gconn->addr.public_key = *ext_public_key;
    }
}

/**
 * Return true if `peer` has permission to speak according to the `voice_state`.
 */
non_null()
static bool peer_has_voice(const GC_Peer *peer, Group_Voice_State voice_state)
{
    const Group_Role role = peer->role;

    switch (voice_state) {
        case GV_ALL:
            return role <= GR_USER;

        case GV_MODS:
            return role <= GR_MODERATOR;

        case GV_FOUNDER:
            return role == GR_FOUNDER;

        default:
            return false;
    }
}

int pack_gc_saved_peers(const GC_Chat *chat, uint8_t *data, uint16_t length, uint16_t *processed)
{
    uint16_t packed_len = 0;
    uint16_t count = 0;

    for (uint32_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        if (!saved_peer_is_valid(saved_peer)) {
            continue;
        }

        int packed_ipp_len = 0;
        int packed_tcp_len = 0;

        if (ipport_isset(&saved_peer->ip_port)) {
            if (packed_len > length) {
                return -1;
            }

            packed_ipp_len = pack_ip_port(chat->log, data + packed_len, length - packed_len, &saved_peer->ip_port);

            if (packed_ipp_len > 0) {
                packed_len += packed_ipp_len;
            }
        }

        if (ipport_isset(&saved_peer->tcp_relay.ip_port)) {
            if (packed_len > length) {
                return -1;
            }

            packed_tcp_len = pack_nodes(chat->log, data + packed_len, length - packed_len, &saved_peer->tcp_relay, 1);

            if (packed_tcp_len > 0) {
                packed_len += packed_tcp_len;
            }
        }

        if (packed_len + ENC_PUBLIC_KEY_SIZE > length) {
            return -1;
        }

        if (packed_tcp_len > 0 || packed_ipp_len > 0) {
            memcpy(data + packed_len, chat->saved_peers[i].public_key, ENC_PUBLIC_KEY_SIZE);
            packed_len += ENC_PUBLIC_KEY_SIZE;
            ++count;
        } else {
            LOGGER_WARNING(chat->log, "Failed to pack saved peer");
        }
    }

    if (processed != nullptr) {
        *processed = packed_len;
    }

    return count;
}

int unpack_gc_saved_peers(GC_Chat *chat, const uint8_t *data, uint16_t length)
{
    uint16_t count = 0;
    uint16_t unpacked_len = 0;

    for (size_t i = 0; unpacked_len < length; ++i) {
        GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        const int ipp_len = unpack_ip_port(&saved_peer->ip_port, data + unpacked_len, length - unpacked_len, false);

        if (ipp_len > 0) {
            unpacked_len += ipp_len;
        }

        if (unpacked_len > length) {
            return -1;
        }

        uint16_t tcp_len_processed = 0;
        const int tcp_len = unpack_nodes(&saved_peer->tcp_relay, 1, &tcp_len_processed, data + unpacked_len,
                                         length - unpacked_len, true);

        if (tcp_len == 1 && tcp_len_processed > 0) {
            unpacked_len += tcp_len_processed;
        } else if (ipp_len <= 0) {
            LOGGER_WARNING(chat->log, "Failed to unpack saved peer: Invalid connection info.");
            return -1;
        }

        if (unpacked_len + ENC_PUBLIC_KEY_SIZE > length) {
            return -1;
        }

        if (tcp_len > 0 || ipp_len > 0) {
            memcpy(saved_peer->public_key, data + unpacked_len, ENC_PUBLIC_KEY_SIZE);
            unpacked_len += ENC_PUBLIC_KEY_SIZE;
            ++count;
        } else {
            LOGGER_ERROR(chat->log, "Unpacked peer with bad connection info");
            return -1;
        }
    }

    return count;
}

/** Returns true if chat privacy state is set to public. */
non_null()
static bool is_public_chat(const GC_Chat *chat)
{
    return chat->shared_state.privacy_state == GI_PUBLIC;
}

/** Returns true if group is password protected */
non_null()
static bool chat_is_password_protected(const GC_Chat *chat)
{
    return chat->shared_state.password_length > 0;
}

/** Returns true if `password` matches the current group password. */
non_null()
static bool validate_password(const GC_Chat *chat, const uint8_t *password, uint16_t length)
{
    if (length > MAX_GC_PASSWORD_SIZE) {
        return false;
    }

    if (length != chat->shared_state.password_length) {
        return false;
    }

    return memcmp(chat->shared_state.password, password, length) == 0;
}

/** @brief Returns the chat object that contains a peer with a public key equal to `id`.
 *
 * `id` must be at least ENC_PUBLIC_KEY_SIZE bytes in length.
 */
non_null()
static GC_Chat *get_chat_by_id(const GC_Session *c, const uint8_t *id)
{
    if (c == nullptr) {
        return nullptr;
    }

    for (uint32_t i = 0; i < c->chats_index; ++i) {
        GC_Chat *chat = &c->chats[i];

        if (chat->connection_state == CS_NONE) {
            continue;
        }

        if (memcmp(id, chat->self_public_key.enc, ENC_PUBLIC_KEY_SIZE) == 0) {
            return chat;
        }

        if (get_peer_number_of_enc_pk(chat, id, false) != -1) {
            return chat;
        }
    }

    return nullptr;
}

/** @brief Returns the jenkins hash of a 32 byte public encryption key. */
uint32_t gc_get_pk_jenkins_hash(const uint8_t *public_key)
{
    return jenkins_one_at_a_time_hash(public_key, ENC_PUBLIC_KEY_SIZE);
}

/** @brief Sets the sum of the public_key_hash of all confirmed peers.
 *
 * Must be called every time a peer is confirmed or deleted.
 */
non_null()
static void set_gc_peerlist_checksum(GC_Chat *chat)
{
    uint16_t sum = 0;

    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        if (gconn->confirmed) {
            sum += gconn->public_key_hash;
        }
    }

    chat->peers_checksum = sum;
}

/** Returns a checksum of the topic currently set in `topic_info`. */
non_null()
static uint16_t get_gc_topic_checksum(const GC_TopicInfo *topic_info)
{
    return data_checksum(topic_info->topic, topic_info->length);
}

int get_peer_number_of_enc_pk(const GC_Chat *chat, const uint8_t *public_enc_key, bool confirmed)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        if (gconn->pending_delete) {
            continue;
        }

        if (confirmed && !gconn->confirmed) {
            continue;
        }

        if (memcmp(gconn->addr.public_key.enc, public_enc_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

/** @brief Check if peer associated with `public_sig_key` is in peer list.
 *
 * Returns the peer number if peer is in the peer list.
 * Returns -1 if peer is not in the peer list.
 */
non_null()
static int get_peer_number_of_sig_pk(const GC_Chat *chat, const uint8_t *public_sig_key)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        if (memcmp(get_sig_pk(&gconn->addr.public_key), public_sig_key, SIG_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

non_null()
static bool gc_get_enc_pk_from_sig_pk(const GC_Chat *chat, uint8_t *public_key, const uint8_t *public_sig_key)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        const Extended_Public_Key *full_pk = &gconn->addr.public_key;

        if (memcmp(public_sig_key, get_sig_pk(full_pk), SIG_PUBLIC_KEY_SIZE) == 0) {
            memcpy(public_key, get_enc_key(full_pk), ENC_PUBLIC_KEY_SIZE);
            return true;
        }
    }

    return false;
}

non_null()
static GC_Connection *random_gc_connection(const GC_Chat *chat)
{
    if (chat->numpeers <= 1) {
        return nullptr;
    }

    const uint32_t base = random_range_u32(chat->rng, chat->numpeers - 1);

    for (uint32_t i = 0; i < chat->numpeers - 1; ++i) {
        const uint32_t index = 1 + (base + i) % (chat->numpeers - 1);
        GC_Connection *rand_gconn = get_gc_connection(chat, index);

        if (rand_gconn == nullptr) {
            return nullptr;
        }

        if (!rand_gconn->pending_delete && rand_gconn->confirmed) {
            return rand_gconn;
        }
    }

    return nullptr;
}

/** @brief Returns the peer number associated with peer_id.
 * Returns -1 if peer_id is invalid.
 */
non_null()
static int get_peer_number_of_peer_id(const GC_Chat *chat, GC_Peer_Id peer_id)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].peer_id.value == peer_id.value) {
            return i;
        }
    }

    return -1;
}

/** @brief Returns a unique peer ID.
 * Returns UINT32_MAX if all possible peer ID's are taken.
 *
 * These ID's are permanently assigned to a peer when they join the group and should be
 * considered arbitrary values.
 */
non_null()
static GC_Peer_Id get_new_peer_id(const GC_Chat *chat)
{
    for (uint32_t i = 0; i < UINT32_MAX - 1; ++i) {
        const GC_Peer_Id peer_id = gc_peer_id_from_int(i);
        if (get_peer_number_of_peer_id(chat, peer_id) == -1) {
            return peer_id;
        }
    }

    return gc_invalid_peer_id();
}

/** @brief Sets the password for the group (locally only).
 *
 * Return true on success.
 */
non_null(1) nullable(2)
static bool set_gc_password_local(GC_Chat *chat, const uint8_t *passwd, uint16_t length)
{
    if (length > MAX_GC_PASSWORD_SIZE) {
        return false;
    }

    if (passwd == nullptr || length == 0) {
        chat->shared_state.password_length = 0;
        memzero(chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    } else {
        chat->shared_state.password_length = length;
        crypto_memlock(chat->shared_state.password, sizeof(chat->shared_state.password));
        memcpy(chat->shared_state.password, passwd, length);
    }

    return true;
}

/** @brief Sets the local shared state to `version`.
 *
 * This should always be called instead of setting the variables manually.
 */
non_null()
static void set_gc_shared_state_version(GC_Chat *chat, uint32_t version)
{
    chat->shared_state.version = version;
    chat->moderation.shared_state_version = version;
}

/** @brief Expands the chat_id into the extended chat public key (encryption key + signature key).
 *
 * @param dest must have room for EXT_PUBLIC_KEY_SIZE bytes.
 *
 * Return true on success.
 */
non_null()
static bool expand_chat_id(Extended_Public_Key *dest, const uint8_t *chat_id)
{
    assert(dest != nullptr);

    const int ret = crypto_sign_ed25519_pk_to_curve25519(dest->enc, chat_id);
    memcpy(dest->sig, chat_id, SIG_PUBLIC_KEY_SIZE);

    return ret != -1;
}

/** Copies peer connect info from `gconn` to `addr`. */
non_null()
static void copy_gc_saved_peer(const Random *rng, const GC_Connection *gconn, GC_SavedPeerInfo *addr)
{
    if (!gcc_copy_tcp_relay(rng, &addr->tcp_relay, gconn)) {
        addr->tcp_relay = (Node_format) {
            0
        };
    }

    addr->ip_port = gconn->addr.ip_port;
    memcpy(addr->public_key, gconn->addr.public_key.enc, ENC_PUBLIC_KEY_SIZE);
}

/** Return true if `saved_peer` has either a valid IP_Port or a valid TCP relay. */
non_null()
static bool saved_peer_is_valid(const GC_SavedPeerInfo *saved_peer)
{
    return ipport_isset(&saved_peer->ip_port) || ipport_isset(&saved_peer->tcp_relay.ip_port);
}

/** @brief Returns the index of the saved peers entry for `public_key`.
 * Returns -1 if key is not found.
 */
non_null()
static int saved_peer_index(const GC_Chat *chat, const uint8_t *public_key)
{
    for (uint16_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        if (memcmp(saved_peer->public_key, public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

/** @brief Returns the index of the first vacant entry in saved peers list.
 *
 * If `public_key` is non-null and already exists in the list, its index will be returned.
 *
 * A vacant entry is an entry that does not have either an IP_port or tcp relay set (invalid),
 * or an entry containing info on a peer that is not presently online (offline).
 *
 * Invalid entries are given priority over offline entries.
 *
 * Returns -1 if there are no vacant indices.
 */
non_null(1) nullable(2)
static int saved_peers_get_new_index(const GC_Chat *chat, const uint8_t *public_key)
{
    if (public_key != nullptr) {
        const int idx = saved_peer_index(chat, public_key);

        if (idx != -1) {
            return idx;
        }
    }

    // first check for invalid spots
    for (uint16_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        if (!saved_peer_is_valid(saved_peer)) {
            return i;
        }
    }

    // now look for entries with offline peers
    for (uint16_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        const int peernumber = get_peer_number_of_enc_pk(chat, saved_peer->public_key, true);

        if (peernumber < 0) {
            return i;
        }
    }

    return -1;
}

/** @brief Attempts to add `gconn` to the saved peer list.
 *
 * If an entry already exists it will be updated.
 *
 * Older peers will only be overwritten if the peer is no longer
 * present in the chat. This gives priority to more stable connections.
 *
 * This function should be called every time a new peer joins the group.
 */
non_null()
static void add_gc_saved_peers(GC_Chat *chat, const GC_Connection *gconn)
{
    const int idx = saved_peers_get_new_index(chat, gconn->addr.public_key.enc);

    if (idx == -1) {
        return;
    }

    GC_SavedPeerInfo *saved_peer = &chat->saved_peers[idx];
    copy_gc_saved_peer(chat->rng, gconn, saved_peer);
}

/** @brief Finds the first vacant spot in the saved peers list and fills it with a present
 * peer who isn't already in the list.
 *
 * This function should be called after a confirmed peer exits the group.
 */
non_null()
static void refresh_gc_saved_peers(GC_Chat *chat)
{
    const int idx = saved_peers_get_new_index(chat, nullptr);

    if (idx == -1) {
        return;
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        if (gconn == nullptr) {
            continue;
        }

        if (!gconn->confirmed) {
            continue;
        }

        if (saved_peer_index(chat, gconn->addr.public_key.enc) == -1) {
            GC_SavedPeerInfo *saved_peer = &chat->saved_peers[idx];
            copy_gc_saved_peer(chat->rng, gconn, saved_peer);
            return;
        }
    }
}

/** Returns the number of confirmed peers in peerlist. */
non_null()
static uint16_t get_gc_confirmed_numpeers(const GC_Chat *chat)
{
    uint16_t count = 0;

    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        if (gconn->confirmed) {
            ++count;
        }
    }

    return count;
}

non_null() static bool sign_gc_shared_state(GC_Chat *chat);
non_null() static bool broadcast_gc_mod_list(const GC_Chat *chat);
non_null() static bool broadcast_gc_shared_state(const GC_Chat *chat);
non_null() static bool update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key);
non_null() static bool update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key);
non_null() static bool send_gc_set_observer(const GC_Chat *chat, const Extended_Public_Key *target_ext_pk,
        const uint8_t *sanction_data, uint16_t length, bool add_obs);

/** Returns true if peer designated by `peer_number` is in the sanctions list as an observer. */
non_null()
static bool peer_is_observer(const GC_Chat *chat, uint32_t peer_number)
{
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    return sanctions_list_is_observer(&chat->moderation, get_enc_key(&gconn->addr.public_key));
}

/** Returns true if peer designated by `peer_number` is the group founder. */
non_null()
static bool peer_is_founder(const GC_Chat *chat, uint32_t peer_number)
{

    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    return memcmp(chat->shared_state.founder_public_key.enc, gconn->addr.public_key.enc, ENC_PUBLIC_KEY_SIZE) == 0;
}

/** Returns true if peer designated by `peer_number` is in the moderator list or is the founder. */
non_null()
static bool peer_is_moderator(const GC_Chat *chat, uint32_t peer_number)
{
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    if (peer_is_founder(chat, peer_number)) {
        return false;
    }

    return mod_list_verify_sig_pk(&chat->moderation, get_sig_pk(&gconn->addr.public_key));
}

/** @brief Iterates through the peerlist and updates group roles according to the
 * current group state.
 *
 * Also updates the roles checksum. If any role conflicts exist the shared state
 * version is set to zero in order to force a sync update.
 *
 * This should be called every time the moderator list or sanctions list changes,
 * and after a new peer is marked as confirmed.
 */
non_null()
static void update_gc_peer_roles(GC_Chat *chat)
{
    chat->roles_checksum = 0;
    bool conflicts = false;

    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        if (gconn == nullptr) {
            continue;
        }

        if (!gconn->confirmed) {
            continue;
        }

        const uint8_t first_byte = gconn->addr.public_key.enc[0];
        const bool is_founder = peer_is_founder(chat, i);

        if (is_founder) {
            chat->group[i].role = GR_FOUNDER;
            chat->roles_checksum += GR_FOUNDER + first_byte;
            continue;
        }

        const bool is_observer  = peer_is_observer(chat, i);
        const bool is_moderator = peer_is_moderator(chat, i);
        const bool is_user = !(is_founder || is_moderator || is_observer);

        if (is_observer && is_moderator) {
            conflicts = true;
        }

        if (is_user) {
            chat->group[i].role = GR_USER;
            chat->roles_checksum += GR_USER + first_byte;
            continue;
        }

        if (is_moderator) {
            chat->group[i].role = GR_MODERATOR;
            chat->roles_checksum += GR_MODERATOR + first_byte;
            continue;
        }

        if (is_observer) {
            chat->group[i].role = GR_OBSERVER;
            chat->roles_checksum += GR_OBSERVER + first_byte;
            continue;
        }
    }

    if (conflicts && !self_gc_is_founder(chat)) {
        set_gc_shared_state_version(chat, 0);  // need a new shared state
    }
}

/** @brief Removes the first found offline mod from the mod list.
 *
 * Broadcasts the shared state and moderator list on success, as well as the updated
 * sanctions list if necessary.
 *
 * TODO(Jfreegman): Make this smarter in who to remove (e.g. the mod who hasn't been seen online in the longest time)
 *
 * Returns false on failure.
 */
non_null()
static bool prune_gc_mod_list(GC_Chat *chat)
{
    if (chat->moderation.num_mods == 0) {
        return true;
    }

    uint8_t public_sig_key[SIG_PUBLIC_KEY_SIZE];
    bool pruned_mod = false;

    for (uint16_t i = 0; i < chat->moderation.num_mods; ++i) {
        if (get_peer_number_of_sig_pk(chat, chat->moderation.mod_list[i]) == -1) {
            memcpy(public_sig_key, chat->moderation.mod_list[i], SIG_PUBLIC_KEY_SIZE);

            if (!mod_list_remove_index(&chat->moderation, i)) {
                continue;
            }

            pruned_mod = true;
            break;
        }
    }

    return pruned_mod
           && mod_list_make_hash(&chat->moderation, chat->shared_state.mod_list_hash)
           && sign_gc_shared_state(chat)
           && broadcast_gc_shared_state(chat)
           && broadcast_gc_mod_list(chat)
           && update_gc_sanctions_list(chat, public_sig_key)
           && update_gc_topic(chat, public_sig_key);
}

non_null()
static bool prune_gc_sanctions_list_inner(
    GC_Chat *chat, const Mod_Sanction *sanction,
    const Extended_Public_Key *target_ext_pk)
{
    if (!sanctions_list_remove_observer(&chat->moderation, sanction->target_public_enc_key, nullptr)) {
        LOGGER_WARNING(chat->log, "Failed to remove entry from observer list");
        return false;
    }

    uint8_t data[MOD_SANCTIONS_CREDS_SIZE];
    const uint16_t length = sanctions_creds_pack(&chat->moderation.sanctions_creds, data);

    if (length != MOD_SANCTIONS_CREDS_SIZE) {
        LOGGER_ERROR(chat->log, "Failed to pack credentials (invalid length: %u)", length);
        return false;
    }

    if (!send_gc_set_observer(chat, target_ext_pk, data, length, false)) {
        LOGGER_WARNING(chat->log, "Failed to broadcast set observer");
        return false;
    }

    return true;
}

/** @brief Removes the first found offline sanctioned peer from the sanctions list and sends the
 * event to the rest of the group.
 *
 * @retval false on failure or if no presently sanctioned peer is offline.
 */
non_null()
static bool prune_gc_sanctions_list(GC_Chat *chat)
{
    if (chat->moderation.num_sanctions == 0) {
        return true;
    }

    for (uint16_t i = 0; i < chat->moderation.num_sanctions; ++i) {
        const int peer_number = get_peer_number_of_enc_pk(chat, chat->moderation.sanctions[i].target_public_enc_key, true);

        if (peer_number == -1) {
            const Mod_Sanction *sanction = &chat->moderation.sanctions[i];
            Extended_Public_Key target_ext_pk;
            memcpy(target_ext_pk.enc, sanction->target_public_enc_key, ENC_PUBLIC_KEY_SIZE);
            memcpy(target_ext_pk.sig, sanction->setter_public_sig_key, SIG_PUBLIC_KEY_SIZE);
            return prune_gc_sanctions_list_inner(chat, sanction, &target_ext_pk);
        }
    }

    return false;
}

/** @brief Size of peer data that we pack for transfer (nick length must be accounted for separately).
 * packed data consists of: nick length, nick, and status.
 */
#define PACKED_GC_PEER_SIZE (sizeof(uint16_t) + MAX_GC_NICK_SIZE + sizeof(uint8_t))

/** @brief Packs peer info into data of maxlength length.
 *
 * Return length of packed peer on success.
 * Return -1 on failure.
 */
non_null()
static int pack_gc_peer(uint8_t *data, uint16_t length, const GC_Peer *peer)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t packed_len = 0;

    net_pack_u16(data + packed_len, peer->nick_length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, peer->nick, MAX_GC_NICK_SIZE);
    packed_len += MAX_GC_NICK_SIZE;
    memcpy(data + packed_len, &peer->status, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);

    return packed_len;
}

/** @brief Unpacks peer info of size length into peer.
 *
 * Returns the length of processed data on success.
 * Returns -1 on failure.
 */
non_null()
static int unpack_gc_peer(GC_Peer *peer, const uint8_t *data, uint16_t length)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint16_t len_processed = 0;

    net_unpack_u16(data + len_processed, &peer->nick_length);
    len_processed += sizeof(uint16_t);
    peer->nick_length = min_u16(MAX_GC_NICK_SIZE, peer->nick_length);
    memcpy(peer->nick, data + len_processed, MAX_GC_NICK_SIZE);
    len_processed += MAX_GC_NICK_SIZE;
    memcpy(&peer->status, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    return len_processed;
}

/** @brief Packs shared_state into data.
 *
 * @param data must have room for at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns packed data length.
 */
non_null()
static uint16_t pack_gc_shared_state(uint8_t *data, uint16_t length, const GC_SharedState *shared_state)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    const uint8_t privacy_state = shared_state->privacy_state;
    const uint8_t voice_state = shared_state->voice_state;

    uint16_t packed_len = 0;

    // version is always first
    net_pack_u32(data + packed_len, shared_state->version);
    packed_len += sizeof(uint32_t);

    memcpy(data + packed_len, shared_state->founder_public_key.enc, ENC_PUBLIC_KEY_SIZE);
    packed_len += ENC_PUBLIC_KEY_SIZE;
    memcpy(data + packed_len, shared_state->founder_public_key.sig, SIG_PUBLIC_KEY_SIZE);
    packed_len += SIG_PUBLIC_KEY_SIZE;
    net_pack_u16(data + packed_len, shared_state->maxpeers);
    packed_len += sizeof(uint16_t);
    net_pack_u16(data + packed_len, shared_state->group_name_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->group_name, MAX_GC_GROUP_NAME_SIZE);
    packed_len += MAX_GC_GROUP_NAME_SIZE;
    memcpy(data + packed_len, &privacy_state, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    net_pack_u16(data + packed_len, shared_state->password_length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->password, MAX_GC_PASSWORD_SIZE);
    packed_len += MAX_GC_PASSWORD_SIZE;
    memcpy(data + packed_len, shared_state->mod_list_hash, MOD_MODERATION_HASH_SIZE);
    packed_len += MOD_MODERATION_HASH_SIZE;
    net_pack_u32(data + packed_len, shared_state->topic_lock);
    packed_len += sizeof(uint32_t);
    memcpy(data + packed_len, &voice_state, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);

    return packed_len;
}

/** @brief Unpacks shared state data into shared_state.
 *
 * @param data must contain at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns the length of processed data.
 */
non_null()
static uint16_t unpack_gc_shared_state(GC_SharedState *shared_state, const uint8_t *data, uint16_t length)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    uint16_t len_processed = 0;

    // version is always first
    net_unpack_u32(data + len_processed, &shared_state->version);
    len_processed += sizeof(uint32_t);

    memcpy(shared_state->founder_public_key.enc, data + len_processed, ENC_PUBLIC_KEY_SIZE);
    len_processed += ENC_PUBLIC_KEY_SIZE;
    memcpy(shared_state->founder_public_key.sig, data + len_processed, SIG_PUBLIC_KEY_SIZE);
    len_processed += SIG_PUBLIC_KEY_SIZE;
    net_unpack_u16(data + len_processed, &shared_state->maxpeers);
    len_processed += sizeof(uint16_t);
    net_unpack_u16(data + len_processed, &shared_state->group_name_len);
    shared_state->group_name_len = min_u16(shared_state->group_name_len, MAX_GC_GROUP_NAME_SIZE);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->group_name, data + len_processed, MAX_GC_GROUP_NAME_SIZE);
    len_processed += MAX_GC_GROUP_NAME_SIZE;

    uint8_t privacy_state;
    memcpy(&privacy_state, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    net_unpack_u16(data + len_processed, &shared_state->password_length);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->password, data + len_processed, MAX_GC_PASSWORD_SIZE);
    len_processed += MAX_GC_PASSWORD_SIZE;
    memcpy(shared_state->mod_list_hash, data + len_processed, MOD_MODERATION_HASH_SIZE);
    len_processed += MOD_MODERATION_HASH_SIZE;
    net_unpack_u32(data + len_processed, &shared_state->topic_lock);
    len_processed += sizeof(uint32_t);

    uint8_t voice_state;
    memcpy(&voice_state, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    group_voice_state_from_int(voice_state, &shared_state->voice_state);
    group_privacy_state_from_int(privacy_state, &shared_state->privacy_state);

    return len_processed;
}

/** @brief Packs topic info into data.
 *
 * @param data must have room for at least topic length + GC_MIN_PACKED_TOPIC_INFO_SIZE bytes.
 *
 * Returns packed data length.
 */
non_null()
static uint16_t pack_gc_topic_info(uint8_t *data, uint16_t length, const GC_TopicInfo *topic_info)
{
    if (length < topic_info->length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return 0;
    }

    uint16_t packed_len = 0;

    net_pack_u32(data + packed_len, topic_info->version);
    packed_len += sizeof(uint32_t);
    net_pack_u16(data + packed_len, topic_info->checksum);
    packed_len += sizeof(uint16_t);
    net_pack_u16(data + packed_len, topic_info->length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, topic_info->topic, topic_info->length);
    packed_len += topic_info->length;
    memcpy(data + packed_len, topic_info->public_sig_key, SIG_PUBLIC_KEY_SIZE);
    packed_len += SIG_PUBLIC_KEY_SIZE;

    return packed_len;
}

/** @brief Unpacks topic info into `topic_info`.
 *
 * Returns -1 on failure.
 * Returns the length of the processed data on success.
 */
non_null()
static int unpack_gc_topic_info(GC_TopicInfo *topic_info, const uint8_t *data, uint16_t length)
{
    if (length < sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t)) {
        return -1;
    }

    uint16_t len_processed = 0;

    net_unpack_u32(data + len_processed, &topic_info->version);
    len_processed += sizeof(uint32_t);
    net_unpack_u16(data + len_processed, &topic_info->checksum);
    len_processed += sizeof(uint16_t);
    net_unpack_u16(data + len_processed, &topic_info->length);
    len_processed += sizeof(uint16_t);

    if (topic_info->length > MAX_GC_TOPIC_SIZE) {
        topic_info->length = MAX_GC_TOPIC_SIZE;
    }

    if (length - len_processed < topic_info->length + SIG_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (topic_info->length > 0) {
        memcpy(topic_info->topic, data + len_processed, topic_info->length);
        len_processed += topic_info->length;
    }

    memcpy(topic_info->public_sig_key, data + len_processed, SIG_PUBLIC_KEY_SIZE);
    len_processed += SIG_PUBLIC_KEY_SIZE;

    return len_processed;
}

/** @brief Creates a shared state packet and puts it in data.
 * Packet includes self pk hash, shared state signature, and packed shared state info.
 * data must have room for at least GC_SHARED_STATE_ENC_PACKET_SIZE bytes.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
non_null()
static int make_gc_shared_state_packet(const GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    memcpy(data, chat->shared_state_sig, SIGNATURE_SIZE);
    const uint16_t header_len = SIGNATURE_SIZE;

    const uint16_t packed_len = pack_gc_shared_state(data + header_len, length - header_len, &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        return -1;
    }

    return header_len + packed_len;
}

/** @brief Creates a signature for the group's shared state in packed form.
 *
 * This function only works for the Founder.
 *
 * Returns true on success and increments the shared state version.
 */
non_null()
static bool sign_gc_shared_state(GC_Chat *chat)
{
    if (!self_gc_is_founder(chat)) {
        LOGGER_ERROR(chat->log, "Failed to sign shared state (invalid permission)");
        return false;
    }

    if (chat->shared_state.version != UINT32_MAX) {
        /* improbable, but an overflow would break everything */
        set_gc_shared_state_version(chat, chat->shared_state.version + 1);
    } else {
        LOGGER_WARNING(chat->log, "Shared state version wraparound");
    }

    uint8_t shared_state[GC_PACKED_SHARED_STATE_SIZE];
    const uint16_t packed_len = pack_gc_shared_state(shared_state, sizeof(shared_state), &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        set_gc_shared_state_version(chat, chat->shared_state.version - 1);
        LOGGER_ERROR(chat->log, "Failed to pack shared state");
        return false;
    }

    const int ret = crypto_sign_detached(chat->shared_state_sig, nullptr, shared_state, packed_len,
                                         get_sig_sk(&chat->chat_secret_key));

    if (ret != 0) {
        set_gc_shared_state_version(chat, chat->shared_state.version - 1);
        LOGGER_ERROR(chat->log, "Failed to sign shared state (%d)", ret);
        return false;
    }

    return true;
}

/** @brief Decrypts data using the shared key associated with `gconn`.
 *
 * The packet payload should begin with a nonce.
 *
 * @param message_id should be set to NULL for lossy packets.
 *
 * Returns length of the plaintext data on success.
 * Return -1 if encrypted payload length is invalid.
 * Return -2 on decryption failure.
 * Return -3 if plaintext payload length is invalid.
 */
non_null(1, 2, 3, 5, 6) nullable(4)
static int group_packet_unwrap(const Logger *log, const GC_Connection *gconn, uint8_t *data, uint64_t *message_id,
                               uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    assert(data != nullptr);
    assert(packet != nullptr);

    if (length <= CRYPTO_NONCE_SIZE) {
        LOGGER_FATAL(log, "Invalid packet length: %u", length);
        return -1;
    }

    uint8_t *plain = (uint8_t *)malloc(length);

    if (plain == nullptr) {
        LOGGER_ERROR(log, "Failed to allocate memory for plain data buffer");
        return -1;
    }

    int plain_len = decrypt_data_symmetric(gconn->session_shared_key, packet, packet + CRYPTO_NONCE_SIZE,
                                           length - CRYPTO_NONCE_SIZE, plain);

    if (plain_len <= 0) {
        free(plain);
        return plain_len == 0 ? -3 : -2;
    }

    const int min_plain_len = message_id != nullptr ? 1 + GC_MESSAGE_ID_BYTES : 1;

    /* remove padding */
    const uint8_t *real_plain = plain;

    while (real_plain[0] == 0) {
        ++real_plain;
        --plain_len;

        if (plain_len < min_plain_len) {
            free(plain);
            return -3;
        }
    }

    uint32_t header_len = sizeof(uint8_t);
    *packet_type = real_plain[0];
    plain_len -= sizeof(uint8_t);

    if (message_id != nullptr) {
        net_unpack_u64(real_plain + sizeof(uint8_t), message_id);
        plain_len -= GC_MESSAGE_ID_BYTES;
        header_len += GC_MESSAGE_ID_BYTES;
    }

    memcpy(data, real_plain + header_len, plain_len);

    free(plain);

    return plain_len;
}

int group_packet_wrap(
    const Logger *log, const Random *rng, const uint8_t *self_pk, const uint8_t *shared_key, uint8_t *packet,
    uint16_t packet_size, const uint8_t *data, uint16_t length, uint64_t message_id,
    uint8_t gp_packet_type, Net_Packet_Type net_packet_type)
{
    const uint16_t max_packet_size = group_packet_max_packet_size(net_packet_type);
    const uint16_t padding_len = group_packet_padding_length(length, max_packet_size);
    const uint16_t min_packet_size = net_packet_type == NET_PACKET_GC_LOSSLESS
                                     ? length + padding_len + CRYPTO_MAC_SIZE + 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + GC_MESSAGE_ID_BYTES + 1
                                     : length + padding_len + CRYPTO_MAC_SIZE + 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + 1;

    if (min_packet_size > packet_size) {
        LOGGER_ERROR(log, "Invalid packet buffer size: %u", packet_size);
        return -1;
    }

    if (length > max_packet_size) {
        LOGGER_ERROR(log, "Packet payload size (%u) exceeds maximum (%u)", length, max_packet_size);
        return -1;
    }

    uint8_t *plain = (uint8_t *)malloc(packet_size);

    if (plain == nullptr) {
        return -1;
    }

    assert(padding_len < packet_size);

    memzero(plain, padding_len);

    uint16_t enc_header_len = sizeof(uint8_t);
    plain[padding_len] = gp_packet_type;

    if (net_packet_type == NET_PACKET_GC_LOSSLESS) {
        net_pack_u64(plain + padding_len + sizeof(uint8_t), message_id);
        enc_header_len += GC_MESSAGE_ID_BYTES;
    }

    if (length > 0 && data != nullptr) {
        memcpy(plain + padding_len + enc_header_len, data, length);
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(rng, nonce);

    const uint16_t plain_len = padding_len + enc_header_len + length;
    const uint16_t encrypt_buf_size = plain_len + CRYPTO_MAC_SIZE;

    uint8_t *encrypt = (uint8_t *)malloc(encrypt_buf_size);

    if (encrypt == nullptr) {
        free(plain);
        return -2;
    }

    const int enc_len = encrypt_data_symmetric(shared_key, nonce, plain, plain_len, encrypt);

    free(plain);

    if (enc_len != encrypt_buf_size) {
        LOGGER_ERROR(log, "encryption failed. packet type: 0x%02x, enc_len: %d", gp_packet_type, enc_len);
        free(encrypt);
        return -3;
    }

    packet[0] = net_packet_type;
    memcpy(packet + 1, self_pk, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    free(encrypt);

    return 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + enc_len;
}

/** @brief Sends a lossy packet to peer_number in chat instance.
 *
 * Returns true on success.
 */
non_null()
static bool send_lossy_group_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *data,
                                    uint16_t length, uint8_t packet_type)
{
    assert(length <= MAX_GC_CUSTOM_LOSSY_PACKET_SIZE);

    if (!gconn->handshaked || gconn->pending_delete) {
        return false;
    }

    if (data == nullptr || length == 0) {
        return false;
    }

    const uint16_t packet_size = gc_get_wrapped_packet_size(length, NET_PACKET_GC_LOSSY);
    uint8_t *packet = (uint8_t *)malloc(packet_size);

    if (packet == nullptr) {
        return false;
    }

    const int len = group_packet_wrap(
                        chat->log, chat->rng, chat->self_public_key.enc, gconn->session_shared_key, packet,
                        packet_size, data, length, 0, packet_type, NET_PACKET_GC_LOSSY);

    if (len < 0) {
        LOGGER_ERROR(chat->log, "Failed to encrypt packet (type: 0x%02x, error: %d)", packet_type, len);
        free(packet);
        return false;
    }

    const bool ret = gcc_send_packet(chat, gconn, packet, (uint16_t)len);

    free(packet);

    return ret;
}

/** @brief Sends a lossless packet to peer_number in chat instance.
 *
 * Returns true on success.
 */
non_null(1, 2) nullable(3)
static bool send_lossless_group_packet(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length,
                                       uint8_t packet_type)
{
    assert(length <= MAX_GC_PACKET_SIZE);

    if (!gconn->handshaked || gconn->pending_delete) {
        return false;
    }

    if (length > MAX_GC_PACKET_CHUNK_SIZE) {
        return gcc_send_lossless_packet_fragments(chat, gconn, data, length, packet_type);
    }

    return gcc_send_lossless_packet(chat, gconn, data, length, packet_type) == 0;
}

/** @brief Sends a group sync request to peer.
 *
 * Returns true on success or if sync request timeout has not expired.
 */
non_null()
static bool send_gc_sync_request(GC_Chat *chat, GC_Connection *gconn, uint16_t sync_flags)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        return true;
    }

    chat->last_sync_request = mono_time_get(chat->mono_time);

    uint8_t data[(sizeof(uint16_t) * 2) + MAX_GC_PASSWORD_SIZE];
    uint16_t length = sizeof(uint16_t);

    net_pack_u16(data, sync_flags);

    if (chat_is_password_protected(chat)) {
        net_pack_u16(data + length, chat->shared_state.password_length);
        length += sizeof(uint16_t);

        memcpy(data + length, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
        length += MAX_GC_PASSWORD_SIZE;
    }

    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_REQUEST);
}

/** @brief Sends a sync response packet to peer designated by `gconn`.
 *
 * Return true on success.
 */
non_null(1, 2) nullable(3)
static bool send_gc_sync_response(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length)
{
    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_RESPONSE);
}

non_null() static bool send_gc_peer_exchange(const GC_Chat *chat, GC_Connection *gconn);
non_null() static bool send_gc_handshake_packet(const GC_Chat *chat, GC_Connection *gconn, uint8_t handshake_type,
        uint8_t request_type, uint8_t join_type);
non_null() static bool send_gc_oob_handshake_request(const GC_Chat *chat, const GC_Connection *gconn);

/** @brief Unpacks a sync announce.
 *
 * If the announced peer is not already in our peer list, we attempt to
 * initiate a peer info exchange with them.
 *
 * Return true on success (whether or not the peer was added).
 */
non_null()
static bool unpack_gc_sync_announce(GC_Chat *chat, const uint8_t *data, const uint16_t length)
{
    GC_Announce announce = {0};

    const int unpacked_announces = gca_unpack_announces_list(chat->log, data, length, &announce, 1);

    if (unpacked_announces <= 0) {
        LOGGER_WARNING(chat->log, "Failed to unpack announces: %d", unpacked_announces);
        return false;
    }

    if (memcmp(announce.peer_public_key, chat->self_public_key.enc, ENC_PUBLIC_KEY_SIZE) == 0) {
        LOGGER_WARNING(chat->log, "Attempted to unpack our own announce");
        return true;
    }

    if (!gca_is_valid_announce(&announce)) {
        LOGGER_WARNING(chat->log, "got invalid announce");
        return false;
    }

    const IP_Port *ip_port = announce.ip_port_is_set ? &announce.ip_port : nullptr;
    const int new_peer_number = peer_add(chat, ip_port, announce.peer_public_key);

    if (new_peer_number == -1) {
        LOGGER_ERROR(chat->log, "peer_add() failed");
        return false;
    }

    if (new_peer_number == -2) {  // peer already added
        return true;
    }

    if (new_peer_number > 0) {
        GC_Connection *new_gconn = get_gc_connection(chat, new_peer_number);

        if (new_gconn == nullptr) {
            return false;
        }

        uint32_t added_tcp_relays = 0;

        for (uint8_t i = 0; i < announce.tcp_relays_count; ++i) {
            const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, new_gconn->tcp_connection_num,
                                       &announce.tcp_relays[i].ip_port,
                                       announce.tcp_relays[i].public_key);

            if (add_tcp_result == -1) {
                continue;
            }

            if (gcc_save_tcp_relay(chat->rng, new_gconn, &announce.tcp_relays[i]) == 0) {
                ++added_tcp_relays;
            }
        }

        if (!announce.ip_port_is_set && added_tcp_relays == 0) {
            gcc_mark_for_deletion(new_gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
            LOGGER_ERROR(chat->log, "Sync error: Invalid peer connection info");
            return false;
        }

        new_gconn->pending_handshake_type = HS_PEER_INFO_EXCHANGE;

        return true;
    }

    LOGGER_FATAL(chat->log, "got impossible return value %d", new_peer_number);

    return false;
}

/** @brief Handles a sync response packet.
 *
 * Note: This function may change peer numbers.
 *
 * Return 0 on success.
 * Return -1 if the group is full or the peer failed to unpack.
 * Return -2 if `peer_number` does not designate a valid peer.
 */
non_null(1, 2) nullable(4, 6)
static int handle_gc_sync_response(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, const uint8_t *data,
                                   uint16_t length, void *userdata)
{
    if (chat->connection_state == CS_CONNECTED && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers
            && !peer_is_founder(chat, peer_number)) {
        return -1;
    }

    if (length > 0) {
        if (!unpack_gc_sync_announce(chat, data, length)) {
            return -1;
        }
    }

    chat->connection_state = CS_CONNECTED;

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -2;
    }

    if (!send_gc_peer_exchange(chat, gconn)) {
        LOGGER_WARNING(chat->log, "Failed to send peer exchange on sync response");
    }

    if (c->self_join != nullptr && chat->time_connected == 0) {
        c->self_join(c->messenger, chat->group_number, userdata);
        chat->time_connected = mono_time_get(chat->mono_time);
    }

    return 0;
}

non_null() static int get_gc_peer_public_key(const GC_Chat *chat, uint32_t peer_number, uint8_t *public_key);
non_null() static bool send_peer_shared_state(const GC_Chat *chat, GC_Connection *gconn);
non_null() static bool send_peer_mod_list(const GC_Chat *chat, GC_Connection *gconn);
non_null() static bool send_peer_sanctions_list(const GC_Chat *chat, GC_Connection *gconn);
non_null() static bool send_peer_topic(const GC_Chat *chat, GC_Connection *gconn);

/** @brief Creates a sync announce for peer designated by `gconn` and puts it in `announce`, which
 * must be zeroed by the caller.
 *
 * Returns true if announce was successfully created.
 */
non_null()
static bool create_sync_announce(const GC_Chat *chat, const GC_Connection *gconn, uint32_t peer_number,
                                 GC_Announce *announce)
{
    if (chat == nullptr || gconn == nullptr) {
        return false;
    }

    if (gconn->tcp_relays_count > 0) {
        if (gcc_copy_tcp_relay(chat->rng, &announce->tcp_relays[0], gconn)) {
            announce->tcp_relays_count = 1;
        }
    }

    get_gc_peer_public_key(chat, peer_number, announce->peer_public_key);

    if (gcc_ip_port_is_set(gconn)) {
        announce->ip_port = gconn->addr.ip_port;
        announce->ip_port_is_set = true;
    }

    return true;
}

non_null()
static bool sync_response_send_peers(GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number, bool first_sync)
{
    // Always respond to a peer's first sync request
    if (!first_sync && !mono_time_is_timeout(chat->mono_time,
            chat->last_sync_response_peer_list,
            GC_SYNC_RESPONSE_PEER_LIST_LIMIT)) {
        return true;
    }

    uint8_t *response = (uint8_t *)malloc(MAX_GC_PACKET_CHUNK_SIZE);

    if (response == nullptr) {
        return false;
    }

    size_t num_announces = 0;

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        const GC_Connection *peer_gconn = get_gc_connection(chat, i);

        if (peer_gconn == nullptr || !peer_gconn->confirmed) {
            continue;
        }

        if (peer_gconn->public_key_hash == gconn->public_key_hash || i == peer_number) {
            continue;
        }

        GC_Announce announce = {0};

        if (!create_sync_announce(chat, peer_gconn, i, &announce)) {
            continue;
        }

        const int packed_length = gca_pack_announce(chat->log, response, MAX_GC_PACKET_CHUNK_SIZE, &announce);

        if (packed_length <= 0) {
            LOGGER_WARNING(chat->log, "Failed to pack announce: %d", packed_length);
            continue;
        }

        if (!send_gc_sync_response(chat, gconn, response, packed_length)) {
            LOGGER_WARNING(chat->log, "Failed to send peer announce info");
            continue;
        }

        ++num_announces;
    }

    free(response);

    if (num_announces == 0) {
        // we send an empty sync response even if we didn't send any peers as an acknowledgement
        if (!send_gc_sync_response(chat, gconn, nullptr, 0)) {
            LOGGER_WARNING(chat->log, "Failed to send peer announce info");
            return false;
        }
    } else {
        chat->last_sync_response_peer_list = mono_time_get(chat->mono_time);
    }

    return true;
}

/** @brief Sends group state specified by `sync_flags` peer designated by `peer_number`.
 *
 * Return true on success.
 */
non_null()
static bool sync_response_send_state(GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number,
                                     uint16_t sync_flags)
{
    const bool first_sync = gconn->last_sync_response == 0;

    // Do not change the order of these four send calls. See: https://toktok.ltd/spec.html#sync_request-0xf8
    if ((sync_flags & GF_STATE) > 0 && chat->shared_state.version > 0) {
        if (!send_peer_shared_state(chat, gconn)) {
            LOGGER_WARNING(chat->log, "Failed to send shared state");
            return false;
        }

        if (!send_peer_mod_list(chat, gconn)) {
            LOGGER_WARNING(chat->log, "Failed to send mod list");
            return false;
        }

        if (!send_peer_sanctions_list(chat, gconn)) {
            LOGGER_WARNING(chat->log, "Failed to send sanctions list");
            return false;
        }

        gconn->last_sync_response = mono_time_get(chat->mono_time);
    }

    if ((sync_flags & GF_TOPIC) > 0 && chat->time_connected > 0 && chat->topic_info.version > 0) {
        if (!send_peer_topic(chat, gconn)) {
            LOGGER_WARNING(chat->log, "Failed to send topic");
            return false;
        }

        gconn->last_sync_response = mono_time_get(chat->mono_time);
    }

    if ((sync_flags & GF_PEERS) > 0) {
        if (!sync_response_send_peers(chat, gconn, peer_number, first_sync)) {
            return false;
        }

        gconn->last_sync_response = mono_time_get(chat->mono_time);
    }

    return true;
}

/** @brief Handles a sync request packet and sends a response containing the peer list.
 *
 * May send additional group info in separate packets, including the topic, shared state, mod list,
 * and sanctions list, if respective sync flags are set.
 *
 * If the group is password protected the password in the request data must first be verified.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if password is invalid.
 * Return -3 if we fail to send a response packet.
 * Return -4 if `peer_number` does not designate a valid peer.
 */
non_null()
static int handle_gc_sync_request(GC_Chat *chat, uint32_t peer_number, const uint8_t *data, uint16_t length)
{
    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -4;
    }

    if (length < sizeof(uint16_t)) {
        return -1;
    }

    if (chat->numpeers <= 1) {
        return 0;
    }

    if (chat->shared_state.version == 0) {
        LOGGER_DEBUG(chat->log, "Got sync request with uninitialized state");
        return 0;
    }

    if (!mono_time_is_timeout(chat->mono_time, gconn->last_sync_response, GC_PING_TIMEOUT)) {
        LOGGER_DEBUG(chat->log, "sync request rate limit for peer %d", peer_number);
        return 0;
    }

    uint16_t sync_flags;
    net_unpack_u16(data, &sync_flags);

    if (chat_is_password_protected(chat)) {
        if (length < (sizeof(uint16_t) * 2) + MAX_GC_PASSWORD_SIZE) {
            return -2;
        }

        uint16_t password_length;
        net_unpack_u16(data + sizeof(uint16_t), &password_length);

        const uint8_t *password = data + (sizeof(uint16_t) * 2);

        if (!validate_password(chat, password, password_length)) {
            LOGGER_DEBUG(chat->log, "Invalid password");
            return -2;
        }
    }

    if (!sync_response_send_state(chat, gconn, peer_number, sync_flags)) {
        return -3;
    }

    return 0;
}

non_null() static void copy_self(const GC_Chat *chat, GC_Peer *peer);
non_null() static bool send_gc_peer_info_request(const GC_Chat *chat, GC_Connection *gconn);

/** @brief Shares our TCP relays with peer and adds shared relays to our connection with them.
 *
 * Returns true on success or if we're not connected to any TCP relays.
 */
non_null()
static bool send_gc_tcp_relays(const GC_Chat *chat, GC_Connection *gconn)
{

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    uint8_t data[GCC_MAX_TCP_SHARED_RELAYS * PACKED_NODE_SIZE_IP6];

    const uint32_t n = tcp_copy_connected_relays_index(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS,
                       gconn->tcp_relay_share_index);

    if (n == 0) {
        return true;
    }

    gconn->tcp_relay_share_index += GCC_MAX_TCP_SHARED_RELAYS;

    for (uint32_t i = 0; i < n; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, &tcp_relays[i].ip_port,
                                 tcp_relays[i].public_key);
    }

    const int nodes_len = pack_nodes(chat->log, data, sizeof(data), tcp_relays, n);

    if (nodes_len <= 0 || (uint32_t)nodes_len > sizeof(data)) {
        LOGGER_ERROR(chat->log, "Failed to pack tcp relays (nodes_len: %d)", nodes_len);
        return false;
    }

    if (!send_lossless_group_packet(chat, gconn, data, (uint16_t)nodes_len, GP_TCP_RELAYS)) {
        LOGGER_ERROR(chat->log, "Failed to send tcp relays");
        return false;
    }

    return true;
}

/** @brief Adds a peer's shared TCP relays to our connection with them.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if packet contains invalid data.
 */
non_null()
static int handle_gc_tcp_relays(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS, nullptr, data, length, true);

    if (num_nodes <= 0) {
        return -2;
    }

    for (int i = 0; i < num_nodes; ++i) {
        const Node_format *tcp_node = &tcp_relays[i];

        if (add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, &tcp_node->ip_port,
                                     tcp_node->public_key) == 0) {
            gcc_save_tcp_relay(chat->rng, gconn, tcp_node);

            if (gconn->tcp_relays_count == 1) {
                add_gc_saved_peers(chat, gconn);  // make sure we save at least one tcp relay
            }
        }
    }

    return 0;
}

/** @brief Send invite request to peer_number.
 *
 * If the group requires a password, the packet will
 * contain the password supplied by the invite requestor.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_invite_request(const GC_Chat *chat, GC_Connection *gconn)
{
    if (!chat_is_password_protected(chat)) {
        return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_INVITE_REQUEST);
    }

    uint8_t data[sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE];

    net_pack_u16(data, chat->shared_state.password_length);
    uint16_t length = sizeof(uint16_t);

    memcpy(data + length, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    length += MAX_GC_PASSWORD_SIZE;

    return send_lossless_group_packet(chat, gconn, data, length, GP_INVITE_REQUEST);
}

non_null()
static bool send_gc_invite_response(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_INVITE_RESPONSE);
}

/** @brief Handles an invite response packet.
 *
 * Return 0 if packet is correctly handled.
 * Return -1 if we fail to send a sync request.
 */
non_null()
static int handle_gc_invite_response(GC_Chat *chat, GC_Connection *gconn)
{
    const uint16_t flags = GF_PEERS | GF_TOPIC | GF_STATE;

    if (!send_gc_sync_request(chat, gconn, flags)) {
        return -1;
    }

    return 0;
}

/**
 * @brief Handles an invite response reject packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 */
non_null(1, 2, 3) nullable(5)
static int handle_gc_invite_response_reject(const GC_Session *c, GC_Chat *chat, const uint8_t *data, uint16_t length,
        void *userdata)
{
    if (length < sizeof(uint8_t)) {
        return -1;
    }

    if (chat->connection_state == CS_CONNECTED) {
        return 0;
    }

    if (gc_get_self_role(chat) == GR_FOUNDER) {
        return 0;
    }

    uint8_t type = data[0];

    if (type >= GJ_INVALID) {
        type = GJ_INVITE_FAILED;
    }

    chat->connection_state = CS_DISCONNECTED;

    if (c->rejected != nullptr) {
        c->rejected(c->messenger, chat->group_number, type, userdata);
    }

    return 0;
}

/** @brief Sends an invite response rejection packet to peer designated by `gconn`.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_invite_response_reject(const GC_Chat *chat, const GC_Connection *gconn, uint8_t type)
{
    if (type >= GJ_INVALID) {
        type = GJ_INVITE_FAILED;
    }

    uint8_t data[1];
    data[0] = type;
    const uint16_t length = 1;

    return send_lossy_group_packet(chat, gconn, data, length, GP_INVITE_RESPONSE_REJECT);
}

/** @brief Handles an invite request and verifies that the correct password has been supplied
 * if the group is password protected.
 *
 * Return 0 if invite request is successfully handled.
 * Return -1 if the group is full.
 * Return -2 if the supplied password is invalid.
 * Return -3 if we fail to send an invite response.
 * Return -4 if peer_number does not designate a valid peer.
 */
non_null(1) nullable(3)
static int handle_gc_invite_request(GC_Chat *chat, uint32_t peer_number, const uint8_t *data, uint16_t length)
{
    if (chat->shared_state.version == 0) {  // we aren't synced yet; ignore request
        return 0;
    }

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -4;
    }

    int ret = -1;

    uint8_t invite_error;

    if (get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers && !peer_is_founder(chat, peer_number)) {
        invite_error = GJ_GROUP_FULL;
        goto FAILED_INVITE;
    }

    if (chat_is_password_protected(chat)) {
        invite_error = GJ_INVALID_PASSWORD;
        ret = -2;

        if (length < sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE) {
            goto FAILED_INVITE;
        }

        uint16_t password_length;
        net_unpack_u16(data, &password_length);

        const uint8_t *password = data + sizeof(uint16_t);

        if (!validate_password(chat, password, password_length)) {
            goto FAILED_INVITE;
        }
    }

    if (!send_gc_invite_response(chat, gconn)) {
        return -3;
    }

    return 0;

FAILED_INVITE:
    send_gc_invite_response_reject(chat, gconn, invite_error);
    gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);

    return ret;
}

/** @brief Sends a lossless packet of type and length to all confirmed peers.
 *
 * Return true if packet is successfully sent to at least one peer or the
 * group is empty.
 */
non_null()
static bool send_gc_lossless_packet_all_peers(const GC_Chat *chat, const uint8_t *data, uint16_t length, uint8_t type)
{
    uint32_t sent = 0;
    uint32_t confirmed_peers = 0;

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        if (!gconn->confirmed) {
            continue;
        }

        ++confirmed_peers;

        if (send_lossless_group_packet(chat, gconn, data, length, type)) {
            ++sent;
        }
    }

    return sent > 0 || confirmed_peers == 0;
}

/** @brief Sends a lossy packet of type and length to all confirmed peers.
 *
 * Return true if packet is successfully sent to at least one peer or the
 * group is empty.
 */
non_null()
static bool send_gc_lossy_packet_all_peers(const GC_Chat *chat, const uint8_t *data, uint16_t length, uint8_t type)
{
    uint32_t sent = 0;
    uint32_t confirmed_peers = 0;

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);

        assert(gconn != nullptr);

        if (!gconn->confirmed) {
            continue;
        }

        ++confirmed_peers;

        if (send_lossy_group_packet(chat, gconn, data, length, type)) {
            ++sent;
        }
    }

    return sent > 0 || confirmed_peers == 0;
}

/** @brief Creates packet with broadcast header info followed by data of length.
 *
 * Returns length of packet including header.
 */
non_null(3) nullable(1)
static uint16_t make_gc_broadcast_header(const uint8_t *data, uint16_t length, uint8_t *packet, uint8_t bc_type)
{
    packet[0] = bc_type;
    const uint16_t header_len = sizeof(uint8_t);

    if (data != nullptr && length > 0) {
        memcpy(packet + header_len, data, length);
    }

    return length + header_len;
}

/** @brief sends a group broadcast packet to all confirmed peers.
 *
 * Returns true on success.
 */
non_null(1) nullable(2)
static bool send_gc_broadcast_message(const GC_Chat *chat, const uint8_t *data, uint16_t length, uint8_t bc_type)
{
    if (length + GC_BROADCAST_ENC_HEADER_SIZE > MAX_GC_PACKET_SIZE) {
        LOGGER_ERROR(chat->log, "Failed to broadcast message: invalid length %u", length);
        return false;
    }

    uint8_t *packet = (uint8_t *)malloc(length + GC_BROADCAST_ENC_HEADER_SIZE);

    if (packet == nullptr) {
        return false;
    }

    const uint16_t packet_len = make_gc_broadcast_header(data, length, packet, bc_type);

    const bool ret = send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_BROADCAST);

    free(packet);

    return ret;
}

non_null()
static bool group_topic_lock_enabled(const GC_Chat *chat);

/** @brief Compares the supplied values with our own state and returns the appropriate
 * sync flags for a sync request.
 */
non_null()
static uint16_t get_sync_flags(const GC_Chat *chat, uint16_t peers_checksum, uint16_t peer_count,
                               uint32_t sstate_version, uint32_t screds_version, uint16_t roles_checksum,
                               uint32_t topic_version, uint16_t topic_checksum)
{
    uint16_t sync_flags = 0;

    if (peers_checksum != chat->peers_checksum && peer_count >= get_gc_confirmed_numpeers(chat)) {
        sync_flags |= GF_PEERS;
    }

    if (sstate_version > 0) {
        const uint16_t self_roles_checksum = chat->moderation.sanctions_creds.checksum + chat->roles_checksum;

        if ((sstate_version > chat->shared_state.version || screds_version > chat->moderation.sanctions_creds.version)
                || (screds_version == chat->moderation.sanctions_creds.version
                    && roles_checksum != self_roles_checksum)) {
            sync_flags |= GF_STATE;
        }
    }

    if (group_topic_lock_enabled(chat)) {
        if (topic_version > chat->topic_info.version ||
                (topic_version == chat->topic_info.version && topic_checksum > chat->topic_info.checksum)) {
            sync_flags |= GF_TOPIC;
        }
    } else if (topic_checksum > chat->topic_info.checksum) {
        sync_flags |= GF_TOPIC;
    }

    return sync_flags;
}

/** @brief Compares a peer's group sync info that we received in a ping packet to our own.
 *
 * If their info appears to be more recent than ours we send them a sync request.
 *
 * This function should only be called from `handle_gc_ping()`.
 *
 * Returns true if a sync request packet is successfully sent.
 */
non_null()
static bool do_gc_peer_state_sync(GC_Chat *chat, GC_Connection *gconn, const uint8_t *sync_data,
                                  const uint16_t length)
{
    if (length < GC_PING_PACKET_MIN_DATA_SIZE) {
        return false;
    }

    uint16_t peers_checksum;
    uint16_t peer_count;
    uint32_t sstate_version;
    uint32_t screds_version;
    uint16_t roles_checksum;
    uint32_t topic_version;
    uint16_t topic_checksum;

    size_t unpacked_len = 0;

    net_unpack_u16(sync_data, &peers_checksum);
    unpacked_len += sizeof(uint16_t);

    net_unpack_u16(sync_data + unpacked_len, &peer_count);
    unpacked_len += sizeof(uint16_t);

    net_unpack_u32(sync_data + unpacked_len, &sstate_version);
    unpacked_len += sizeof(uint32_t);

    net_unpack_u32(sync_data + unpacked_len, &screds_version);
    unpacked_len += sizeof(uint32_t);

    net_unpack_u16(sync_data + unpacked_len, &roles_checksum);
    unpacked_len += sizeof(uint16_t);

    net_unpack_u32(sync_data + unpacked_len, &topic_version);
    unpacked_len += sizeof(uint32_t);

    net_unpack_u16(sync_data + unpacked_len, &topic_checksum);
    unpacked_len += sizeof(uint16_t);

    if (unpacked_len != GC_PING_PACKET_MIN_DATA_SIZE) {
        LOGGER_FATAL(chat->log, "Unpacked length is impossible (%zu)", unpacked_len);
        return false;
    }

    const uint16_t sync_flags = get_sync_flags(chat, peers_checksum, peer_count, sstate_version, screds_version,
                                roles_checksum, topic_version, topic_checksum);

    if (sync_flags > 0) {
        return send_gc_sync_request(chat, gconn, sync_flags);
    }

    return false;
}

/** @brief Handles a ping packet.
 *
 * The packet contains sync information including peer's peer list checksum,
 * shared state version, topic version, and sanction credentials version.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size or peer is not confirmed.
 */
non_null()
static int handle_gc_ping(GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length)
{
    if (length < GC_PING_PACKET_MIN_DATA_SIZE) {
        return -1;
    }

    if (!gconn->confirmed) {
        return -1;
    }

    do_gc_peer_state_sync(chat, gconn, data, length);

    if (length > GC_PING_PACKET_MIN_DATA_SIZE) {
        IP_Port ip_port = {{{0}}};

        if (unpack_ip_port(&ip_port, data + GC_PING_PACKET_MIN_DATA_SIZE,
                           length - GC_PING_PACKET_MIN_DATA_SIZE, false) > 0) {
            gcc_set_ip_port(gconn, &ip_port);
            add_gc_saved_peers(chat, gconn);
        }
    }

    return 0;
}

int gc_set_self_status(const Messenger *m, int group_number, Group_Peer_Status status)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    self_gc_set_status(chat, status);

    uint8_t data[1];
    data[0] = gc_get_self_status(chat);

    if (!send_gc_broadcast_message(chat, data, 1, GM_STATUS)) {
        return -2;
    }

    return 0;
}

/** @brief Handles a status broadcast from `peer`.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid length.
 */
non_null(1, 2, 3, 4) nullable(6)
static int handle_gc_status(const GC_Session *c, const GC_Chat *chat, GC_Peer *peer, const uint8_t *data,
                            uint16_t length, void *userdata)
{
    if (length < sizeof(uint8_t)) {
        return -1;
    }

    const Group_Peer_Status status = (Group_Peer_Status)data[0];

    if (status > GS_BUSY) {
        LOGGER_WARNING(chat->log, "Received invalid status %u", status);
        return 0;
    }

    peer->status = status;

    if (c->status_change != nullptr) {
        c->status_change(c->messenger, chat->group_number, peer->peer_id, status, userdata);
    }

    return 0;
}

uint8_t gc_get_status(const GC_Chat *chat, GC_Peer_Id peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    const GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return UINT8_MAX;
    }

    return peer->status;
}

uint8_t gc_get_role(const GC_Chat *chat, GC_Peer_Id peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    const GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return UINT8_MAX;
    }

    return peer->role;
}

void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest)
{
    if (dest != nullptr) {
        memcpy(dest, get_chat_id(&chat->chat_public_key), CHAT_ID_SIZE);
    }
}

/** @brief Sends self peer info to `gconn`.
 *
 * If the group is password protected the request will contain the group
 * password, which the recipient will validate in the respective
 * group message handler.
 *
 * Returns true on success.
 */
non_null()
static bool send_self_to_peer(const GC_Chat *chat, GC_Connection *gconn)
{
    GC_Peer *self = (GC_Peer *)calloc(1, sizeof(GC_Peer));

    if (self == nullptr) {
        return false;
    }

    copy_self(chat, self);

    const uint16_t data_size = PACKED_GC_PEER_SIZE + sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE;
    uint8_t *data = (uint8_t *)malloc(data_size);

    if (data == nullptr) {
        free(self);
        return false;
    }

    uint16_t length = 0;

    if (chat_is_password_protected(chat)) {
        net_pack_u16(data, chat->shared_state.password_length);
        length += sizeof(uint16_t);

        memcpy(data + sizeof(uint16_t), chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
        length += MAX_GC_PASSWORD_SIZE;
    }

    const int packed_len = pack_gc_peer(data + length, data_size - length, self);
    length += packed_len;

    free(self);

    if (packed_len <= 0) {
        LOGGER_DEBUG(chat->log, "pack_gc_peer failed in handle_gc_peer_info_request_request %d", packed_len);
        free(data);
        return false;
    }

    const bool ret = send_lossless_group_packet(chat, gconn, data, length, GP_PEER_INFO_RESPONSE);

    free(data);

    return ret;
}

/** @brief Handles a peer info request packet.
 *
 * Return 0 on success.
 * Return -1 if unconfirmed peer is trying to join a full group.
 * Return -2 if response fails.
 * Return -3 if `peer_number` does not designate a valid peer.
 */
non_null()
static int handle_gc_peer_info_request(const GC_Chat *chat, uint32_t peer_number)
{
    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers
            && !peer_is_founder(chat, peer_number)) {
        return -1;
    }

    if (!send_self_to_peer(chat, gconn)) {
        return -2;
    }

    return 0;
}

/** @brief Sends a peer info request to peer designated by `gconn`.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_peer_info_request(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_PEER_INFO_REQUEST);
}

/** @brief Do peer info exchange with peer designated by `gconn`.
 *
 * This function sends two packets to a peer. The first packet is a peer info response containing our own info,
 * and the second packet is a peer info request.
 *
 * Return false if either packet fails to send.
 */
static bool send_gc_peer_exchange(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_self_to_peer(chat, gconn) && send_gc_peer_info_request(chat, gconn);
}

/** @brief Updates peer's info, validates their group role, and sets them as a confirmed peer.
 * If the group is password protected the password must first be validated.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if peer number is invalid.
 * Return -4 if unconfirmed peer is trying to join a full group.
 * Return -5 if supplied group password is invalid.
 * Return -6 if we fail to add the peer to the peer list.
 * Return -7 if peer's role cannot be validated.
 * Return -8 if malloc fails.
 */
non_null(1, 2, 4) nullable(6)
static int handle_gc_peer_info_response(const GC_Session *c, GC_Chat *chat, uint32_t peer_number,
                                        const uint8_t *data, uint16_t length, void *userdata)
{
    if (length < PACKED_GC_PEER_SIZE) {
        return -1;
    }

    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return -3;
    }

    GC_Connection *gconn = &peer->gconn;

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers
            && !peer_is_founder(chat, peer_number)) {
        return -4;
    }

    uint16_t unpacked_len = 0;

    if (chat_is_password_protected(chat)) {
        if (length < sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE) {
            return -5;
        }

        uint16_t password_length;
        net_unpack_u16(data, &password_length);
        unpacked_len += sizeof(uint16_t);

        if (!validate_password(chat, data + unpacked_len, password_length)) {
            return -5;
        }

        unpacked_len += MAX_GC_PASSWORD_SIZE;
    }

    if (length <= unpacked_len) {
        return -1;
    }

    GC_Peer *peer_info = (GC_Peer *)calloc(1, sizeof(GC_Peer));

    if (peer_info == nullptr) {
        return -8;
    }

    if (unpack_gc_peer(peer_info, data + unpacked_len, length - unpacked_len) == -1) {
        LOGGER_ERROR(chat->log, "unpack_gc_peer() failed");
        free(peer_info);
        return -6;
    }

    if (peer_update(chat, peer_info, peer_number) == -1) {
        LOGGER_WARNING(chat->log, "peer_update() failed");
        free(peer_info);
        return -6;
    }

    free(peer_info);

    const bool was_confirmed = gconn->confirmed;
    gconn->confirmed = true;

    update_gc_peer_roles(chat);

    add_gc_saved_peers(chat, gconn);

    set_gc_peerlist_checksum(chat);

    if (c->peer_join != nullptr && !was_confirmed) {
        c->peer_join(c->messenger, chat->group_number, peer->peer_id, userdata);
    }

    return 0;
}

/** @brief Sends the group shared state and its signature to peer_number.
 *
 * Returns true on success.
 */
non_null()
static bool send_peer_shared_state(const GC_Chat *chat, GC_Connection *gconn)
{
    if (chat->shared_state.version == 0) {
        return false;
    }

    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    const int length = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return false;
    }

    return send_lossless_group_packet(chat, gconn, packet, (uint16_t)length, GP_SHARED_STATE);
}

/** @brief Sends the group shared state and signature to all confirmed peers.
 *
 * Returns true on success.
 */
non_null()
static bool broadcast_gc_shared_state(const GC_Chat *chat)
{
    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    const int packet_len = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (packet_len != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return false;
    }

    return send_gc_lossless_packet_all_peers(chat, packet, (uint16_t)packet_len, GP_SHARED_STATE);
}

/** @brief Helper function for `do_gc_shared_state_changes()`.
 *
 * If the privacy state has been set to private, we kill our group's connection to the DHT.
 * Otherwise, we create a new connection with the DHT and flag an announcement.
 */
non_null(1, 2) nullable(3)
static void do_privacy_state_change(const GC_Session *c, GC_Chat *chat, void *userdata)
{
    if (is_public_chat(chat)) {
        if (!m_create_group_connection(c->messenger, chat)) {
            LOGGER_ERROR(chat->log, "Failed to initialize group friend connection");
        } else {
            chat->update_self_announces = true;
            chat->join_type = HJ_PUBLIC;
        }
    } else {
        kill_group_friend_connection(c, chat);
        cleanup_gca(c->announces_list, get_chat_id(&chat->chat_public_key));
        chat->join_type = HJ_PRIVATE;
    }

    if (c->privacy_state != nullptr) {
        c->privacy_state(c->messenger, chat->group_number, chat->shared_state.privacy_state, userdata);
    }
}

/**
 * Compares old_shared_state with the chat instance's current shared state and triggers the
 * appropriate callbacks depending on what pieces of state information changed. Also
 * handles DHT announcement/removal if the privacy state changed.
 *
 * The initial retrieval of the shared state on group join will be ignored by this function.
 */
non_null(1, 2, 3) nullable(4)
static void do_gc_shared_state_changes(const GC_Session *c, GC_Chat *chat, const GC_SharedState *old_shared_state,
                                       void *userdata)
{
    /* Max peers changed */
    if (chat->shared_state.maxpeers != old_shared_state->maxpeers && c->peer_limit != nullptr) {
        c->peer_limit(c->messenger, chat->group_number, chat->shared_state.maxpeers, userdata);
    }

    /* privacy state changed */
    if (chat->shared_state.privacy_state != old_shared_state->privacy_state) {
        do_privacy_state_change(c, chat, userdata);
    }

    /* password changed */
    if (chat->shared_state.password_length != old_shared_state->password_length
            || memcmp(chat->shared_state.password, old_shared_state->password, old_shared_state->password_length) != 0) {

        if (c->password != nullptr) {
            c->password(c->messenger, chat->group_number, chat->shared_state.password,
                        chat->shared_state.password_length, userdata);
        }
    }

    /* topic lock state changed */
    if (chat->shared_state.topic_lock != old_shared_state->topic_lock && c->topic_lock != nullptr) {
        const Group_Topic_Lock lock_state = group_topic_lock_enabled(chat) ? TL_ENABLED : TL_DISABLED;
        c->topic_lock(c->messenger, chat->group_number, lock_state, userdata);
    }

    /* voice state changed */
    if (chat->shared_state.voice_state != old_shared_state->voice_state && c->voice_state != nullptr) {
        c->voice_state(c->messenger, chat->group_number, chat->shared_state.voice_state, userdata);
    }
}

/** @brief Sends a sync request to a random peer in the group with the specificed sync flags.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_random_sync_request(GC_Chat *chat, uint16_t sync_flags)
{
    GC_Connection *rand_gconn = random_gc_connection(chat);

    if (rand_gconn == nullptr) {
        return false;
    }

    return send_gc_sync_request(chat, rand_gconn, sync_flags);
}

/** @brief Returns true if all shared state values are legal. */
non_null()
static bool validate_gc_shared_state(const GC_SharedState *state)
{
    return state->maxpeers > 0
           && state->password_length <= MAX_GC_PASSWORD_SIZE
           && state->group_name_len > 0
           && state->group_name_len <= MAX_GC_GROUP_NAME_SIZE
           && state->privacy_state <= GI_PRIVATE
           && state->voice_state <= GV_FOUNDER;
}

/** @brief Handles a shared state error and attempts to send a sync request to a random peer.
 *
 * Return 0 if error is currectly handled.
 * Return -1 on failure.
 */
non_null()
static int handle_gc_shared_state_error(GC_Chat *chat, GC_Connection *gconn)
{
    gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SYNC_ERR, nullptr, 0);

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_CONNECTING;
        return 0;
    }

    if (chat->numpeers <= 1) {
        return 0;
    }

    if (!send_gc_random_sync_request(chat, GF_STATE)) {
        return -1;
    }

    return 0;
}

/** @brief Handles a shared state packet and validates the new shared state.
 *
 * Return 0 if packet is successfully handled.
 * Return -1 if packet is invalid and this is not successfully handled.
 */
non_null(1, 2, 3, 4) nullable(6)
static int handle_gc_shared_state(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, const uint8_t *data,
                                  uint16_t length, void *userdata)
{
    if (length < GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return handle_gc_shared_state_error(chat, gconn);
    }

    const uint8_t *signature = data;
    const uint8_t *ss_data = data + SIGNATURE_SIZE;
    const uint16_t ss_length = length - SIGNATURE_SIZE;

    if (crypto_sign_verify_detached(signature, ss_data, GC_PACKED_SHARED_STATE_SIZE,
                                    get_sig_pk(&chat->chat_public_key)) == -1) {
        LOGGER_DEBUG(chat->log, "Failed to validate shared state signature");
        return handle_gc_shared_state_error(chat, gconn);
    }

    uint32_t version;
    net_unpack_u32(ss_data, &version);  // version is the first 4 bytes of shared state data payload

    if (version == 0 || version < chat->shared_state.version) {
        LOGGER_DEBUG(chat->log, "Invalid shared state version (got %u, expected >= %u)",
                     version, chat->shared_state.version);
        return 0;
    }

    const GC_SharedState old_shared_state = chat->shared_state;
    GC_SharedState new_shared_state;

    if (unpack_gc_shared_state(&new_shared_state, ss_data, ss_length) == 0) {
        LOGGER_WARNING(chat->log, "Failed to unpack shared state");
        return 0;
    }

    if (!validate_gc_shared_state(&new_shared_state)) {
        LOGGER_WARNING(chat->log, "Failed to validate shared state");
        return 0;
    }

    if (chat->shared_state.version == 0) {  // init founder public sig key in moderation object
        memcpy(chat->moderation.founder_public_sig_key,
               get_sig_pk(&new_shared_state.founder_public_key), SIG_PUBLIC_KEY_SIZE);
    }

    chat->shared_state = new_shared_state;

    memcpy(chat->shared_state_sig, signature, sizeof(chat->shared_state_sig));

    set_gc_shared_state_version(chat, chat->shared_state.version);

    do_gc_shared_state_changes(c, chat, &old_shared_state, userdata);

    return 0;
}

/** @brief Validates `data` containing a moderation list and unpacks it into the
 * shared state of `chat`.
 *
 * Return 1 if data is valid but mod list doesn't match shared state.
 * Return 0 if data is valid.
 * Return -1 if data is invalid.
 */
non_null()
static int validate_unpack_mod_list(GC_Chat *chat, const uint8_t *data, uint16_t length, uint16_t num_mods)
{
    if (num_mods > MOD_MAX_NUM_MODERATORS) {
        return -1;
    }

    uint8_t mod_list_hash[MOD_MODERATION_HASH_SIZE] = {0};

    if (length > 0) {
        mod_list_get_data_hash(mod_list_hash, data, length);
    }

    // we make sure that this mod list's hash matches the one we got in our last shared state update
    if (chat->shared_state.version > 0
            && memcmp(mod_list_hash, chat->shared_state.mod_list_hash, MOD_MODERATION_HASH_SIZE) != 0) {
        LOGGER_WARNING(chat->log, "failed to validate mod list hash");
        return 1;
    }

    if (mod_list_unpack(&chat->moderation, data, length, num_mods) == -1) {
        LOGGER_WARNING(chat->log, "failed to unpack mod list");
        return -1;
    }

    return 0;
}

/** @brief Handles new mod_list and compares its hash against the mod_list_hash in the shared state.
 *
 * If the new list fails validation, we attempt to send a sync request to a random peer.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if packet contained invalid data or validation failed.
 */
non_null(1, 2, 3) nullable(5)
static int handle_gc_mod_list(const GC_Session *c, GC_Chat *chat, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    // only the founder can modify the list; the founder can never be out of sync
    if (self_gc_is_founder(chat)) {
        return 0;
    }

    uint16_t num_mods;
    net_unpack_u16(data, &num_mods);

    const int unpack_ret = validate_unpack_mod_list(chat, data + sizeof(uint16_t), length - sizeof(uint16_t), num_mods);

    if (unpack_ret == 0) {
        update_gc_peer_roles(chat);

        if (chat->connection_state == CS_CONNECTED && c->moderation != nullptr) {
            c->moderation(c->messenger, chat->group_number, gc_invalid_peer_id(), gc_invalid_peer_id(), MV_MOD, userdata);
        }

        return 0;
    }

    if (unpack_ret == 1) {
        return 0;
    }

    // unpack/validation failed: handle error

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_CONNECTING;
        return -2;
    }

    if (chat->numpeers <= 1) {
        return 0;
    }

    send_gc_random_sync_request(chat, GF_STATE);

    return 0;
}

/** @brief Handles a sanctions list validation error and attempts to send a sync request to a random peer.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
non_null()
static int handle_gc_sanctions_list_error(GC_Chat *chat)
{
    if (chat->moderation.sanctions_creds.version > 0) {
        return 0;
    }

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_CONNECTING;
        return 0;
    }

    if (chat->numpeers <= 1) {
        return 0;
    }

    if (!send_gc_random_sync_request(chat, GF_STATE)) {
        return -1;
    }

    return 0;
}

/** @brief Handles a sanctions list packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if we failed to gracefully handle a sanctions list error.
 * Return -2 if packet has invalid size.
 */
non_null(1, 2, 3) nullable(5)
static int handle_gc_sanctions_list(const GC_Session *c, GC_Chat *chat, const uint8_t *data, uint16_t length,
                                    void *userdata)
{
    if (length < sizeof(uint16_t)) {
        return -2;
    }

    uint16_t num_sanctions;
    net_unpack_u16(data, &num_sanctions);

    if (num_sanctions > MOD_MAX_NUM_SANCTIONS) {
        LOGGER_DEBUG(chat->log, "num_sanctions: %u exceeds maximum", num_sanctions);
        return handle_gc_sanctions_list_error(chat);
    }

    Mod_Sanction_Creds creds;

    Mod_Sanction *sanctions = (Mod_Sanction *)calloc(num_sanctions, sizeof(Mod_Sanction));

    if (sanctions == nullptr) {
        return -1;
    }

    const int unpacked_num = sanctions_list_unpack(sanctions, &creds, num_sanctions, data + sizeof(uint16_t),
                             length - sizeof(uint16_t), nullptr);

    if (unpacked_num != num_sanctions) {
        LOGGER_WARNING(chat->log, "Failed to unpack sanctions list: %d", unpacked_num);
        free(sanctions);
        return handle_gc_sanctions_list_error(chat);
    }

    if (!sanctions_list_check_integrity(&chat->moderation, &creds, sanctions, num_sanctions)) {
        LOGGER_WARNING(chat->log, "Sanctions list failed integrity check");
        free(sanctions);
        return handle_gc_sanctions_list_error(chat);
    }

    if (creds.version < chat->moderation.sanctions_creds.version) {
        free(sanctions);
        return 0;
    }

    // this may occur if two mods change the sanctions list at the exact same time
    if (creds.version == chat->moderation.sanctions_creds.version
            && creds.checksum <= chat->moderation.sanctions_creds.checksum) {
        free(sanctions);
        return 0;
    }

    sanctions_list_cleanup(&chat->moderation);

    chat->moderation.sanctions_creds = creds;
    chat->moderation.sanctions = sanctions;
    chat->moderation.num_sanctions = num_sanctions;

    update_gc_peer_roles(chat);

    if (chat->connection_state == CS_CONNECTED) {
        if (c->moderation != nullptr) {
            c->moderation(c->messenger, chat->group_number, gc_invalid_peer_id(), gc_invalid_peer_id(), MV_OBSERVER, userdata);
        }
    }

    return 0;
}

/** @brief Makes a mod_list packet.
 *
 * Returns length of packet data on success.
 * Returns -1 on failure.
 */
non_null()
static int make_gc_mod_list_packet(const GC_Chat *chat, uint8_t *data, uint32_t maxlen, uint16_t mod_list_size)
{
    if (maxlen < sizeof(uint16_t) + mod_list_size) {
        return -1;
    }

    net_pack_u16(data, chat->moderation.num_mods);
    const uint16_t length = sizeof(uint16_t) + mod_list_size;

    if (mod_list_size > 0) {
        uint8_t *packed_mod_list = (uint8_t *)malloc(mod_list_size);

        if (packed_mod_list == nullptr) {
            return -1;
        }

        mod_list_pack(&chat->moderation, packed_mod_list);
        memcpy(data + sizeof(uint16_t), packed_mod_list, mod_list_size);

        free(packed_mod_list);
    }

    return length;
}

/** @brief Sends the moderator list to peer.
 *
 * Return true on success.
 */
non_null()
static bool send_peer_mod_list(const GC_Chat *chat, GC_Connection *gconn)
{
    const uint16_t mod_list_size = chat->moderation.num_mods * MOD_LIST_ENTRY_SIZE;
    const uint16_t length = sizeof(uint16_t) + mod_list_size;
    uint8_t *packet = (uint8_t *)malloc(length);

    if (packet == nullptr) {
        return false;
    }

    const int packet_len = make_gc_mod_list_packet(chat, packet, length, mod_list_size);

    if (packet_len != length) {
        free(packet);
        return false;
    }

    const bool ret = send_lossless_group_packet(chat, gconn, packet, length, GP_MOD_LIST);

    free(packet);

    return ret;
}

/** @brief Makes a sanctions list packet.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
non_null()
static int make_gc_sanctions_list_packet(const GC_Chat *chat, uint8_t *data, uint16_t maxlen)
{
    if (maxlen < sizeof(uint16_t)) {
        return -1;
    }

    net_pack_u16(data, chat->moderation.num_sanctions);
    const uint16_t length = sizeof(uint16_t);

    const int packed_len = sanctions_list_pack(data + length, maxlen - length, chat->moderation.sanctions,
                           chat->moderation.num_sanctions, &chat->moderation.sanctions_creds);

    if (packed_len < 0) {
        return -1;
    }

    return length + packed_len;
}

/** @brief Sends the sanctions list to peer.
 *
 * Returns true on success.
 */
non_null()
static bool send_peer_sanctions_list(const GC_Chat *chat, GC_Connection *gconn)
{
    if (chat->moderation.sanctions_creds.version == 0) {
        return true;
    }

    const uint16_t packet_size = MOD_SANCTION_PACKED_SIZE * chat->moderation.num_sanctions +
                                 sizeof(uint16_t) + MOD_SANCTIONS_CREDS_SIZE;

    uint8_t *packet = (uint8_t *)malloc(packet_size);

    if (packet == nullptr) {
        return false;
    }

    const int packet_len = make_gc_sanctions_list_packet(chat, packet, packet_size);

    if (packet_len == -1) {
        free(packet);
        return false;
    }

    const bool ret = send_lossless_group_packet(chat, gconn, packet, (uint16_t)packet_len, GP_SANCTIONS_LIST);

    free(packet);

    return ret;
}

/** @brief Sends the sanctions list to all peers in group.
 *
 * Returns true on success.
 */
non_null()
static bool broadcast_gc_sanctions_list(const GC_Chat *chat)
{
    const uint16_t packet_size = MOD_SANCTION_PACKED_SIZE * chat->moderation.num_sanctions +
                                 sizeof(uint16_t) + MOD_SANCTIONS_CREDS_SIZE;

    uint8_t *packet = (uint8_t *)malloc(packet_size);

    if (packet == nullptr) {
        return false;
    }

    const int packet_len = make_gc_sanctions_list_packet(chat, packet, packet_size);

    if (packet_len == -1) {
        free(packet);
        return false;
    }

    const bool ret = send_gc_lossless_packet_all_peers(chat, packet, (uint16_t)packet_len, GP_SANCTIONS_LIST);

    free(packet);

    return ret;
}

/** @brief Re-signs all sanctions list entries signed by public_sig_key and broadcasts
 * the updated sanctions list to all group peers.
 *
 * Returns true on success.
 */
non_null()
static bool update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key)
{
    const uint16_t num_replaced = sanctions_list_replace_sig(&chat->moderation, public_sig_key);

    if (num_replaced == 0) {
        return true;
    }

    return broadcast_gc_sanctions_list(chat);
}

/** @brief Sends mod_list to all peers in group.
 *
 * Returns true on success.
 */
non_null()
static bool broadcast_gc_mod_list(const GC_Chat *chat)
{
    const uint16_t mod_list_size = chat->moderation.num_mods * MOD_LIST_ENTRY_SIZE;
    const uint16_t length = sizeof(uint16_t) + mod_list_size;
    uint8_t *packet = (uint8_t *)malloc(length);

    if (packet == nullptr) {
        return false;
    }

    const int packet_len = make_gc_mod_list_packet(chat, packet, length, mod_list_size);

    if (packet_len != length) {
        free(packet);
        return false;
    }

    const bool ret = send_gc_lossless_packet_all_peers(chat, packet, length, GP_MOD_LIST);

    free(packet);

    return ret;
}

/** @brief Sends a parting signal to the group.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the packet failed to send.
 */
non_null(1) nullable(2)
static int send_gc_self_exit(const GC_Chat *chat, const uint8_t *partmessage, uint16_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        return -1;
    }

    if (!send_gc_broadcast_message(chat, partmessage, length, GM_PEER_EXIT)) {
        return -2;
    }

    return 0;
}

/** @brief Handles a peer exit broadcast. */
non_null(1, 2) nullable(3)
static void handle_gc_peer_exit(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        length = MAX_GC_PART_MESSAGE_SIZE;
    }

    gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_QUIT, data, length);
}

int gc_set_self_nick(const Messenger *m, int group_number, const uint8_t *nick, uint16_t length)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length > MAX_GC_NICK_SIZE) {
        return -2;
    }

    if (length == 0 || nick == nullptr) {
        return -3;
    }

    if (!self_gc_set_nick(chat, nick, length)) {
        return -2;
    }

    if (!send_gc_broadcast_message(chat, nick, length, GM_NICK)) {
        return -4;
    }

    return 0;
}

bool gc_get_peer_nick(const GC_Chat *chat, GC_Peer_Id peer_id, uint8_t *name)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    const GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return false;
    }

    if (name != nullptr) {
        memcpy(name, peer->nick, peer->nick_length);
    }

    return true;
}

int gc_get_peer_nick_size(const GC_Chat *chat, GC_Peer_Id peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    const GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return -1;
    }

    return peer->nick_length;
}

/** @brief Handles a nick change broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 on failure.
 */
non_null(1, 2, 3, 4) nullable(6)
static int handle_gc_nick(const GC_Session *c, GC_Chat *chat, GC_Peer *peer, const uint8_t *nick,
                          uint16_t length,  void *userdata)
{
    /* If this happens malicious behaviour is highly suspect */
    if (length == 0 || length > MAX_GC_NICK_SIZE) {
        GC_Connection *gconn = &peer->gconn;
        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SYNC_ERR, nullptr, 0);
        LOGGER_WARNING(chat->log, "Invalid nick length for nick: %s (%u)", nick, length);
        return -1;
    }

    memcpy(peer->nick, nick, length);
    peer->nick_length = length;

    if (c->nick_change != nullptr) {
        c->nick_change(c->messenger, chat->group_number, peer->peer_id, nick, length, userdata);
    }

    return 0;
}

/** @brief Copies peer_number's public key to `public_key`.
 *
 * Returns 0 on success.
 * Returns -1 if peer_number is invalid.
 * Returns -2 if `public_key` is null.
 */
non_null()
static int get_gc_peer_public_key(const GC_Chat *chat, uint32_t peer_number, uint8_t *public_key)
{
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (public_key == nullptr) {
        return -2;
    }

    memcpy(public_key, gconn->addr.public_key.enc, ENC_PUBLIC_KEY_SIZE);

    return 0;
}

int gc_get_peer_public_key_by_peer_id(const GC_Chat *chat, GC_Peer_Id peer_id, uint8_t *public_key)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (public_key == nullptr) {
        return -2;
    }

    memcpy(public_key, gconn->addr.public_key.enc, ENC_PUBLIC_KEY_SIZE);

    return 0;
}

/** @brief Puts a string of the IP associated with `ip_port` in `ip_str` if the
 * connection is direct, otherwise puts a placeholder in the buffer indicating that
 * the IP cannot be displayed.
 */
non_null()
static void get_gc_ip_ntoa(const IP_Port *ip_port, Ip_Ntoa *ip_str)
{
    net_ip_ntoa(&ip_port->ip, ip_str);

    if (!ip_str->ip_is_valid) {
        ip_str->buf[0] = '-';
        ip_str->buf[1] = '\0';
        ip_str->length = 1;
    }
}

int gc_get_peer_ip_address_size(const GC_Chat *chat, GC_Peer_Id peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    const IP_Port *ip_port = peer_number == 0 ? &chat->self_ip_port : &gconn->addr.ip_port;

    Ip_Ntoa ip_str;
    get_gc_ip_ntoa(ip_port, &ip_str);

    return ip_str.length;
}

int gc_get_peer_ip_address(const GC_Chat *chat, GC_Peer_Id peer_id, uint8_t *ip_addr)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (ip_addr == nullptr) {
        return -2;
    }

    const IP_Port *ip_port = peer_number == 0 ? &chat->self_ip_port : &gconn->addr.ip_port;

    Ip_Ntoa ip_str;
    get_gc_ip_ntoa(ip_port, &ip_str);

    assert(ip_str.length <= IP_NTOA_LEN);
    memcpy(ip_addr, ip_str.buf, ip_str.length);

    return 0;
}

unsigned int gc_get_peer_connection_status(const GC_Chat *chat, GC_Peer_Id peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (peer_number_is_self(peer_number)) {
        return chat->self_udp_status ==  SELF_UDP_STATUS_NONE ? 1 : 2;
    }

    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return 0;
    }

    if (gcc_conn_is_direct(chat->mono_time, gconn)) {
        return 2;
    }

    return 1;
}

/** @brief Creates a topic packet and puts it in data.
 *
 * Packet includes the topic, topic length, public signature key of the
 * setter, topic version, and the signature.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
non_null()
static int make_gc_topic_packet(const GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    memcpy(data, chat->topic_sig, SIGNATURE_SIZE);
    uint16_t data_length = SIGNATURE_SIZE;

    const uint16_t packed_len = pack_gc_topic_info(data + data_length, length - data_length, &chat->topic_info);
    data_length += packed_len;

    if (packed_len != chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    return data_length;
}

/** @brief Sends the group topic to peer.
 *
 * Returns true on success.
 */
non_null()
static bool send_peer_topic(const GC_Chat *chat, GC_Connection *gconn)
{
    const uint16_t packet_buf_size = SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE;
    uint8_t *packet = (uint8_t *)malloc(packet_buf_size);

    if (packet == nullptr) {
        return false;
    }

    const int packet_len = make_gc_topic_packet(chat, packet, packet_buf_size);

    if (packet_len != packet_buf_size) {
        free(packet);
        return false;
    }

    if (!send_lossless_group_packet(chat, gconn, packet, packet_buf_size, GP_TOPIC)) {
        free(packet);
        return false;
    }

    free(packet);

    return true;
}

/**
 * @brief Initiates a session key rotation with peer designated by `gconn`.
 *
 * Return true on success.
 */
non_null()
static bool send_peer_key_rotation_request(const GC_Chat *chat, GC_Connection *gconn)
{
    // Only the peer closest to the chat_id sends requests. This is to prevent both peers from sending
    // requests at the same time and ending up with a different resulting shared key
    if (!gconn->self_is_closer) {
        // if this peer hasn't sent us a rotation request in a reasonable timeframe we drop their connection
        if (mono_time_is_timeout(chat->mono_time, gconn->last_key_rotation, GC_KEY_ROTATION_TIMEOUT + GC_PING_TIMEOUT)) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_TIMEOUT, nullptr, 0);
        }

        return true;
    }

    uint8_t packet[1 + ENC_PUBLIC_KEY_SIZE];

    net_pack_bool(&packet[0], false); // request type

    create_gc_session_keypair(chat->log, chat->rng, gconn->session_public_key, gconn->session_secret_key);

    // copy new session public key to packet
    memcpy(packet + 1, gconn->session_public_key, ENC_PUBLIC_KEY_SIZE);

    if (!send_lossless_group_packet(chat, gconn, packet, sizeof(packet), GP_KEY_ROTATION)) {
        return false;
    }

    gconn->pending_key_rotation_request = true;

    return true;
}

/** @brief Sends the group topic to all group members.
 *
 * Returns true on success.
 */
non_null()
static bool broadcast_gc_topic(const GC_Chat *chat)
{
    const uint16_t packet_buf_size = SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE;
    uint8_t *packet = (uint8_t *)malloc(packet_buf_size);

    if (packet == nullptr) {
        return false;
    }

    const int packet_len = make_gc_topic_packet(chat, packet, packet_buf_size);

    if (packet_len != packet_buf_size) {
        free(packet);
        return false;
    }

    const bool ret = send_gc_lossless_packet_all_peers(chat, packet, packet_buf_size, GP_TOPIC);

    free(packet);

    return ret;
}

int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length)
{
    if (length > MAX_GC_TOPIC_SIZE) {
        return -1;
    }

    const bool topic_lock_enabled = group_topic_lock_enabled(chat);

    if (topic_lock_enabled && gc_get_self_role(chat) > GR_MODERATOR) {
        return -2;
    }

    if (gc_get_self_role(chat) > GR_USER) {
        return -2;
    }

    const GC_TopicInfo old_topic_info = chat->topic_info;

    uint8_t old_topic_sig[SIGNATURE_SIZE];
    memcpy(old_topic_sig, chat->topic_sig, SIGNATURE_SIZE);

    // TODO(jfreegman): improbable, but an overflow would break topic setting
    if (chat->topic_info.version == UINT32_MAX) {
        return -3;
    }

    // only increment topic version when lock is enabled
    if (topic_lock_enabled) {
        ++chat->topic_info.version;
    }

    chat->topic_info.length = length;

    if (length > 0) {
        assert(topic != nullptr);
        memcpy(chat->topic_info.topic, topic, length);
    } else {
        memzero(chat->topic_info.topic, sizeof(chat->topic_info.topic));
    }

    memcpy(chat->topic_info.public_sig_key, get_sig_pk(&chat->self_public_key), SIG_PUBLIC_KEY_SIZE);

    chat->topic_info.checksum = get_gc_topic_checksum(&chat->topic_info);

    const uint16_t packet_buf_size = length + GC_MIN_PACKED_TOPIC_INFO_SIZE;
    uint8_t *packed_topic = (uint8_t *)malloc(packet_buf_size);

    if (packed_topic == nullptr) {
        return -3;
    }

    int err = -3;

    const uint16_t packed_len = pack_gc_topic_info(packed_topic, packet_buf_size, &chat->topic_info);

    if (packed_len != packet_buf_size) {
        goto ON_ERROR;
    }

    if (crypto_sign_detached(chat->topic_sig, nullptr, packed_topic, packet_buf_size,
                             get_sig_sk(&chat->self_secret_key)) == -1) {
        goto ON_ERROR;
    }

    if (!broadcast_gc_topic(chat)) {
        err = -4;
        goto ON_ERROR;
    }

    chat->topic_prev_checksum = old_topic_info.checksum;
    chat->topic_time_set = mono_time_get(chat->mono_time);

    free(packed_topic);
    return 0;

ON_ERROR:
    chat->topic_info = old_topic_info;
    memcpy(chat->topic_sig, old_topic_sig, SIGNATURE_SIZE);
    free(packed_topic);
    return err;
}

void gc_get_topic(const GC_Chat *chat, uint8_t *topic)
{
    if (topic != nullptr) {
        memcpy(topic, chat->topic_info.topic, chat->topic_info.length);
    }
}

uint16_t gc_get_topic_size(const GC_Chat *chat)
{
    return chat->topic_info.length;
}

/**
 * If public_sig_key is equal to the key of the topic setter, replaces topic credentials
 * and re-broadcasts the updated topic info to the group.
 *
 * Returns true on success
 */
non_null()
static bool update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key)
{
    if (memcmp(public_sig_key, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE) != 0) {
        return true;
    }

    LOGGER_TRACE(chat->log, "founder is re-signing topic");
    return gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) == 0;
}

/** @brief Validates `topic_info`.
 *
 * Return true if topic info is valid.
 */
non_null()
static bool handle_gc_topic_validate(const GC_Chat *chat, const GC_Peer *peer, const GC_TopicInfo *topic_info,
                                     bool topic_lock_enabled)
{
    if (topic_info->checksum != get_gc_topic_checksum(topic_info)) {
        LOGGER_WARNING(chat->log, "received invalid topic checksum");
        return false;
    }

    if (topic_lock_enabled) {
        if (!mod_list_verify_sig_pk(&chat->moderation, topic_info->public_sig_key)) {
            LOGGER_DEBUG(chat->log, "Invalid topic signature (bad credentials)");
            return false;
        }

        if (topic_info->version < chat->topic_info.version) {
            return false;
        }
    } else {
        uint8_t public_enc_key[ENC_PUBLIC_KEY_SIZE];

        if (gc_get_enc_pk_from_sig_pk(chat, public_enc_key, topic_info->public_sig_key)) {
            if (sanctions_list_is_observer(&chat->moderation, public_enc_key)) {
                LOGGER_DEBUG(chat->log, "Invalid topic signature (sanctioned peer attempted to change topic)");
                return false;
            }
        }

        if (topic_info->version == chat->shared_state.topic_lock) {
            // always accept topic on initial connection
            if (!mono_time_is_timeout(chat->mono_time, chat->time_connected, GC_PING_TIMEOUT)) {
                return true;
            }

            if (chat->topic_prev_checksum == topic_info->checksum &&
                    !mono_time_is_timeout(chat->mono_time, chat->topic_time_set, GC_CONFIRMED_PEER_TIMEOUT)) {
                LOGGER_DEBUG(chat->log, "Topic reversion (probable sync error)");
                return false;
            }

            return true;
        }

        // the topic version should never change when the topic lock is disabled except when
        // the founder changes the topic prior to enabling the lock
        if (!(peer->role == GR_FOUNDER && topic_info->version == chat->shared_state.topic_lock + 1)) {
            LOGGER_ERROR(chat->log, "topic version %u differs from topic lock %u", topic_info->version,
                         chat->shared_state.topic_lock);
            return false;
        }
    }

    return true;
}

/** @brief Handles a topic packet.
 *
 * Return 0 if packet is correctly handled.
 * Return -1 if packet has invalid size.
 */
non_null(1, 2, 3, 4) nullable(6)
static int handle_gc_topic(const GC_Session *c, GC_Chat *chat, const GC_Peer *peer, const uint8_t *data,
                           uint16_t length, void *userdata)
{
    if (length < SIGNATURE_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    const uint16_t old_checksum = chat->topic_info.checksum;

    GC_TopicInfo topic_info;

    if (unpack_gc_topic_info(&topic_info, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE) == -1) {
        LOGGER_WARNING(chat->log, "failed to unpack topic");
        return 0;
    }

    const uint8_t *signature = data;

    if (crypto_sign_verify_detached(signature, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE,
                                    topic_info.public_sig_key) == -1) {
        LOGGER_WARNING(chat->log, "failed to verify topic signature");
        return 0;
    }

    const bool topic_lock_enabled = group_topic_lock_enabled(chat);

    if (!handle_gc_topic_validate(chat, peer, &topic_info, topic_lock_enabled)) {
        return 0;
    }

    // prevents sync issues from triggering the callback needlessly
    const bool skip_callback = chat->topic_info.length == topic_info.length
                               && memcmp(chat->topic_info.topic, topic_info.topic, topic_info.length) == 0;

    chat->topic_prev_checksum = old_checksum;
    chat->topic_time_set = mono_time_get(chat->mono_time);
    chat->topic_info = topic_info;
    memcpy(chat->topic_sig, signature, SIGNATURE_SIZE);

    if (!skip_callback && chat->connection_state == CS_CONNECTED && c->topic_change != nullptr) {
        const int setter_peer_number = get_peer_number_of_sig_pk(chat, topic_info.public_sig_key);
        const GC_Peer_Id peer_id = setter_peer_number >= 0 ? chat->group[setter_peer_number].peer_id : gc_unknown_peer_id();

        c->topic_change(c->messenger, chat->group_number, peer_id, topic_info.topic, topic_info.length, userdata);
    }

    return 0;
}

/** @brief Handles a key exchange packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if length is invalid.
 * Return -2 if we fail to create a new session keypair.
 * Return -3 if response packet fails to send.
 */
non_null()
static int handle_gc_key_exchange(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length)
{
    if (length < 1 + ENC_PUBLIC_KEY_SIZE) {
        return -1;
    }

    bool is_response;
    net_unpack_bool(&data[0], &is_response);

    const uint8_t *sender_public_session_key = data + 1;

    if (is_response) {
        if (!gconn->pending_key_rotation_request) {
            LOGGER_WARNING(chat->log, "got unsolicited key rotation response from peer %u", gconn->public_key_hash);
            return 0;
        }

        // now that we have response we can compute our new shared key and begin using it
        gcc_make_session_shared_key(gconn, sender_public_session_key);

        gconn->pending_key_rotation_request = false;

        return 0;
    }

    // key generation is pretty cpu intensive so we make sure a peer can't DOS us by spamming requests
    if (!mono_time_is_timeout(chat->mono_time, gconn->last_key_rotation, GC_KEY_ROTATION_TIMEOUT / 2)) {
        return 0;
    }

    uint8_t response[1 + ENC_PUBLIC_KEY_SIZE];
    uint8_t new_session_pk[ENC_PUBLIC_KEY_SIZE];
    uint8_t new_session_sk[ENC_SECRET_KEY_SIZE];

    net_pack_bool(&response[0], true);

    crypto_memlock(new_session_sk, sizeof(new_session_sk));

    create_gc_session_keypair(chat->log, chat->rng, new_session_pk, new_session_sk);

    memcpy(response + 1, new_session_pk, ENC_PUBLIC_KEY_SIZE);

    if (!send_lossless_group_packet(chat, gconn, response, sizeof(response), GP_KEY_ROTATION)) {
        // Don't really care about zeroing the secret key here, because we failed, but
        // we're doing it anyway for symmetry with the memzero+munlock below, where we
        // really do care about it.
        crypto_memzero(new_session_sk, sizeof(new_session_sk));
        crypto_memunlock(new_session_sk, sizeof(new_session_sk));
        return -3;
    }

    // save new keys and compute new shared key AFTER sending response packet with old key
    memcpy(gconn->session_public_key, new_session_pk, sizeof(gconn->session_public_key));
    memcpy(gconn->session_secret_key, new_session_sk, sizeof(gconn->session_secret_key));

    gcc_make_session_shared_key(gconn, sender_public_session_key);

    crypto_memzero(new_session_sk, sizeof(new_session_sk));
    crypto_memunlock(new_session_sk, sizeof(new_session_sk));

    gconn->last_key_rotation = mono_time_get(chat->mono_time);

    return 0;
}

void gc_get_group_name(const GC_Chat *chat, uint8_t *group_name)
{
    if (group_name != nullptr) {
        memcpy(group_name, chat->shared_state.group_name, chat->shared_state.group_name_len);
    }
}

uint16_t gc_get_group_name_size(const GC_Chat *chat)
{
    return chat->shared_state.group_name_len;
}

void gc_get_password(const GC_Chat *chat, uint8_t *password)
{
    if (password != nullptr) {
        memcpy(password, chat->shared_state.password, chat->shared_state.password_length);
    }
}

uint16_t gc_get_password_size(const GC_Chat *chat)
{
    return chat->shared_state.password_length;
}

int gc_founder_set_password(GC_Chat *chat, const uint8_t *password, uint16_t password_length)
{
    if (!self_gc_is_founder(chat)) {
        return -1;
    }

    const uint16_t oldlen = chat->shared_state.password_length;
    uint8_t *oldpasswd = memdup(chat->shared_state.password, oldlen);

    if (oldpasswd == nullptr && oldlen > 0) {
        return -4;
    }

    if (!set_gc_password_local(chat, password, password_length)) {
        free(oldpasswd);
        return -2;
    }

    if (!sign_gc_shared_state(chat)) {
        set_gc_password_local(chat, oldpasswd, oldlen);
        free(oldpasswd);
        return -2;
    }

    free(oldpasswd);

    if (!broadcast_gc_shared_state(chat)) {
        return -3;
    }

    return 0;
}

/** @brief Validates change to moderator list and either adds or removes peer from our moderator list.
 *
 * Return target's peer number on success.
 * Return -1 on packet handle failure.
 * Return -2 if target peer is not online.
 * Return -3 if target peer is not a valid role (probably indicates sync issues).
 * Return -4 on validation failure.
 */
non_null()
static int validate_unpack_gc_set_mod(GC_Chat *chat, uint32_t peer_number, const uint8_t *data, uint16_t length,
                                      bool add_mod)
{
    int target_peer_number;
    uint8_t mod_data[MOD_LIST_ENTRY_SIZE];

    if (add_mod) {
        if (length < 1 + MOD_LIST_ENTRY_SIZE) {
            return -1;
        }

        memcpy(mod_data, data + 1, MOD_MODERATION_HASH_SIZE);
        target_peer_number = get_peer_number_of_sig_pk(chat, mod_data);

        if (!gc_peer_number_is_valid(chat, target_peer_number)) {
            return -2;
        }

        const Group_Role target_role = chat->group[target_peer_number].role;

        if (target_role != GR_USER) {
            return -3;
        }

        if (!mod_list_add_entry(&chat->moderation, mod_data)) {
            return -4;
        }
    } else {
        memcpy(mod_data, data + 1, SIG_PUBLIC_KEY_SIZE);
        target_peer_number = get_peer_number_of_sig_pk(chat, mod_data);

        if (!gc_peer_number_is_valid(chat, target_peer_number)) {
            return -2;
        }

        const Group_Role target_role = chat->group[target_peer_number].role;

        if (target_role != GR_MODERATOR) {
            return -3;
        }

        if (!mod_list_remove_entry(&chat->moderation, mod_data)) {
            return -4;
        }
    }

    update_gc_peer_roles(chat);

    return target_peer_number;
}

/** @brief Handles a moderator set broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if the packet contains invalid data.
 * Return -3 if `peer_number` does not designate a valid peer.
 */
non_null(1, 2, 4) nullable(6)
static int handle_gc_set_mod(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, const uint8_t *data,
                             uint16_t length, void *userdata)
{
    if (length < 1 + SIG_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const GC_Peer *setter_peer = get_gc_peer(chat, peer_number);

    if (setter_peer == nullptr) {
        return -3;
    }

    if (setter_peer->role != GR_FOUNDER) {
        return 0;
    }

    bool add_mod;
    net_unpack_bool(&data[0], &add_mod);

    const int target_peer_number = validate_unpack_gc_set_mod(chat, peer_number, data, length, add_mod);

    if (target_peer_number == -1) {
        return -2;
    }

    const GC_Peer *target_peer = get_gc_peer(chat, target_peer_number);

    if (target_peer == nullptr) {
        return 0;
    }

    if (c->moderation != nullptr) {
        c->moderation(c->messenger, chat->group_number, setter_peer->peer_id, target_peer->peer_id,
                      add_mod ? MV_MOD : MV_USER, userdata);
    }

    return 0;
}

/** @brief Sends a set mod broadcast to the group.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_set_mod(const GC_Chat *chat, const GC_Connection *gconn, bool add_mod)
{
    const uint16_t length = 1 + SIG_PUBLIC_KEY_SIZE;
    uint8_t *data = (uint8_t *)malloc(length);

    if (data == nullptr) {
        return false;
    }

    net_pack_bool(&data[0], add_mod);

    memcpy(data + 1, get_sig_pk(&gconn->addr.public_key), SIG_PUBLIC_KEY_SIZE);

    if (!send_gc_broadcast_message(chat, data, length, GM_SET_MOD)) {
        free(data);
        return false;
    }

    free(data);

    return true;
}

/**
 * Adds or removes the peer designated by gconn from moderator list if `add_mod` is true or false respectively.
 * Re-signs and re-distributes an updated mod_list hash.
 *
 * Returns true on success.
 */
non_null()
static bool founder_gc_set_moderator(GC_Chat *chat, const GC_Connection *gconn, bool add_mod)
{
    if (!self_gc_is_founder(chat)) {
        return false;
    }

    if (add_mod) {
        if (chat->moderation.num_mods >= MOD_MAX_NUM_MODERATORS) {
            if (!prune_gc_mod_list(chat)) {
                return false;
            }
        }

        if (!mod_list_add_entry(&chat->moderation, get_sig_pk(&gconn->addr.public_key))) {
            return false;
        }
    } else {
        if (!mod_list_remove_entry(&chat->moderation, get_sig_pk(&gconn->addr.public_key))) {
            return false;
        }

        if (!update_gc_sanctions_list(chat,  get_sig_pk(&gconn->addr.public_key))
                || !update_gc_topic(chat, get_sig_pk(&gconn->addr.public_key))) {
            return false;
        }
    }

    uint8_t old_hash[MOD_MODERATION_HASH_SIZE];
    memcpy(old_hash, chat->shared_state.mod_list_hash, MOD_MODERATION_HASH_SIZE);

    if (!mod_list_make_hash(&chat->moderation, chat->shared_state.mod_list_hash)) {
        return false;
    }

    if (!sign_gc_shared_state(chat) || !broadcast_gc_shared_state(chat)) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, MOD_MODERATION_HASH_SIZE);
        return false;
    }

    return send_gc_set_mod(chat, gconn, add_mod);
}

/** @brief Validates `data` containing a change for the sanction list and unpacks it
 * into the sanctions list for `chat`.
 *
 * if `add_obs` is true we're adding an observer to the list.
 *
 * Return 1 if sanctions list is not modified.
 * Return 0 if data is valid and sanctions list is successfully modified.
 * Return -1 if data is invalid format.
 */
non_null()
static int validate_unpack_observer_entry(GC_Chat *chat, const uint8_t *data, uint16_t length,
        const uint8_t *public_key, bool add_obs)
{
    Mod_Sanction_Creds creds;

    if (add_obs) {
        Mod_Sanction sanction;

        if (sanctions_list_unpack(&sanction, &creds, 1, data, length, nullptr) != 1) {
            return -1;
        }

        // this may occur if two mods change the sanctions list at the exact same time
        if (creds.version == chat->moderation.sanctions_creds.version
                && creds.checksum <= chat->moderation.sanctions_creds.checksum) {
            return 1;
        }

        if (sanctions_list_entry_exists(&chat->moderation, &sanction)
                || !sanctions_list_add_entry(&chat->moderation, &sanction, &creds)) {
            return -1;
        }
    } else {
        if (length < MOD_SANCTIONS_CREDS_SIZE) {
            return -1;
        }

        if (sanctions_creds_unpack(&creds, data) != MOD_SANCTIONS_CREDS_SIZE) {
            return -1;
        }

        if (creds.version == chat->moderation.sanctions_creds.version
                && creds.checksum <= chat->moderation.sanctions_creds.checksum) {
            return 1;
        }

        if (!sanctions_list_is_observer(&chat->moderation, public_key)
                || !sanctions_list_remove_observer(&chat->moderation, public_key, &creds)) {
            return 1;
        }
    }

    return 0;
}

/** @brief Handles a set observer broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if the packet contains invalid data.
 * Return -3 if `peer_number` does not designate a valid peer.
 */
non_null(1, 2, 4) nullable(6)
static int handle_gc_set_observer(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, const uint8_t *data,
                                  uint16_t length, void *userdata)
{
    if (length <= 1 + EXT_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const GC_Peer *setter_peer = get_gc_peer(chat, peer_number);

    if (setter_peer == nullptr) {
        return -3;
    }

    if (setter_peer->role > GR_MODERATOR) {
        LOGGER_DEBUG(chat->log, "peer with insufficient permissions tried to modify sanctions list");
        return 0;
    }

    bool add_obs;
    net_unpack_bool(&data[0], &add_obs);

    const uint8_t *public_key = data + 1;

    const int target_peer_number = get_peer_number_of_enc_pk(chat, public_key, false);

    if (target_peer_number >= 0 && (uint32_t)target_peer_number == peer_number) {
        return -2;
    }

    const GC_Peer *target_peer = get_gc_peer(chat, target_peer_number);

    if (target_peer != nullptr) {
        if ((add_obs && target_peer->role != GR_USER) || (!add_obs && target_peer->role != GR_OBSERVER)) {
            return 0;
        }
    }

    const int ret = validate_unpack_observer_entry(chat,
                    data + 1 + EXT_PUBLIC_KEY_SIZE,
                    length - 1 - EXT_PUBLIC_KEY_SIZE,
                    public_key, add_obs);

    if (ret == -1) {
        return -2;
    }

    if (ret == 1) {
        return 0;
    }

    update_gc_peer_roles(chat);

    if (target_peer != nullptr) {
        if (c->moderation != nullptr) {
            c->moderation(c->messenger, chat->group_number, setter_peer->peer_id, target_peer->peer_id,
                          add_obs ? MV_OBSERVER : MV_USER, userdata);
        }
    }

    return 0;
}

/** @brief Broadcasts observer role data to the group.
 *
 * Returns true on success.
 */
non_null()
static bool send_gc_set_observer(const GC_Chat *chat, const Extended_Public_Key *target_ext_pk,
                                 const uint8_t *sanction_data, uint16_t length, bool add_obs)
{
    const uint16_t packet_len = 1 + ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + length;
    uint8_t *packet = (uint8_t *)malloc(packet_len);

    if (packet == nullptr) {
        return false;
    }

    net_pack_bool(&packet[0], add_obs);

    memcpy(packet + 1, target_ext_pk->enc, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE, target_ext_pk->sig, SIG_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE, sanction_data, length);

    if (!send_gc_broadcast_message(chat, packet, packet_len, GM_SET_OBSERVER)) {
        free(packet);
        return false;
    }

    free(packet);

    return true;
}

/** @brief Adds or removes peer_number from the observer list if add_obs is true or false respectively.
 * Broadcasts this change to the entire group.
 *
 * Returns true on success.
 */
non_null()
static bool mod_gc_set_observer(GC_Chat *chat, uint32_t peer_number, bool add_obs)
{
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    if (gc_get_self_role(chat) >= GR_USER) {
        return false;
    }

    uint8_t sanction_data[MOD_SANCTION_PACKED_SIZE + MOD_SANCTIONS_CREDS_SIZE];
    uint16_t length = 0;

    if (add_obs) {
        if (chat->moderation.num_sanctions >= MOD_MAX_NUM_SANCTIONS) {
            if (!prune_gc_sanctions_list(chat)) {
                return false;
            }
        }

        // if sanctioned peer set the topic we need to overwrite his signature and redistribute
        // topic info
        const int setter_peer_number = get_peer_number_of_sig_pk(chat, chat->topic_info.public_sig_key);

        if (setter_peer_number >= 0 && (uint32_t)setter_peer_number == peer_number) {
            if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
                return false;
            }
        }

        Mod_Sanction sanction;

        if (!sanctions_list_make_entry(&chat->moderation, gconn->addr.public_key.enc, &sanction, SA_OBSERVER)) {
            LOGGER_WARNING(chat->log, "sanctions_list_make_entry failed in mod_gc_set_observer");
            return false;
        }

        const int packed_len = sanctions_list_pack(sanction_data, sizeof(sanction_data), &sanction, 1,
                               &chat->moderation.sanctions_creds);

        if (packed_len == -1) {
            return false;
        }

        length += packed_len;
    } else {
        if (!sanctions_list_remove_observer(&chat->moderation, gconn->addr.public_key.enc, nullptr)) {
            LOGGER_WARNING(chat->log, "failed to remove sanction");
            return false;
        }

        const uint16_t packed_len = sanctions_creds_pack(&chat->moderation.sanctions_creds, sanction_data);

        if (packed_len != MOD_SANCTIONS_CREDS_SIZE) {
            return false;
        }

        length += packed_len;
    }

    if (length > sizeof(sanction_data)) {
        LOGGER_FATAL(chat->log, "Invalid sanction data length: %u", length);
        return false;
    }

    update_gc_peer_roles(chat);

    return send_gc_set_observer(chat, &gconn->addr.public_key, sanction_data, length, add_obs);
}

/** @brief Sets the role of `peer_number` to `new_role`. If necessary this function will first
 * remove the peer's current role before applying the new one.
 *
 * Return true on success.
 */
non_null()
static bool apply_new_gc_role(GC_Chat *chat, uint32_t peer_number, Group_Role current_role, Group_Role new_role)
{
    const GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    switch (current_role) {
        case GR_MODERATOR: {
            if (!founder_gc_set_moderator(chat, gconn, false)) {
                return false;
            }

            update_gc_peer_roles(chat);

            if (new_role == GR_OBSERVER) {
                return mod_gc_set_observer(chat, peer_number, true);
            }

            break;
        }

        case GR_OBSERVER: {
            if (!mod_gc_set_observer(chat, peer_number, false)) {
                return false;
            }

            update_gc_peer_roles(chat);

            if (new_role == GR_MODERATOR) {
                return founder_gc_set_moderator(chat, gconn, true);
            }

            break;
        }

        case GR_USER: {
            if (new_role == GR_MODERATOR) {
                return founder_gc_set_moderator(chat, gconn, true);
            } else if (new_role == GR_OBSERVER) {
                return mod_gc_set_observer(chat, peer_number, true);
            }

            break;
        }

        case GR_FOUNDER:

        // Intentional fallthrough
        default: {
            return false;
        }
    }

    return true;
}

int gc_set_peer_role(const Messenger *m, int group_number, GC_Peer_Id peer_id, Group_Role new_role)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    const GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return -2;
    }

    const GC_Connection *gconn = &peer->gconn;

    if (!gconn->confirmed) {
        return -2;
    }

    const Group_Role current_role = peer->role;

    if (new_role == GR_FOUNDER || peer->role == new_role) {
        return -4;
    }

    if (peer_number_is_self(peer_number)) {
        return -6;
    }

    if (current_role == GR_FOUNDER || gc_get_self_role(chat) >= GR_USER) {
        return -3;
    }

    // moderators can't demote moderators or promote peers to moderator
    if (!self_gc_is_founder(chat) && (new_role == GR_MODERATOR || current_role == GR_MODERATOR)) {
        return -3;
    }

    if (!apply_new_gc_role(chat, peer_number, current_role, new_role)) {
        return -5;
    }

    update_gc_peer_roles(chat);

    return 0;
}

/** @brief Return true if topic lock is enabled */
non_null()
static bool group_topic_lock_enabled(const GC_Chat *chat)
{
    return chat->shared_state.topic_lock == GC_TOPIC_LOCK_ENABLED;
}

Group_Privacy_State gc_get_privacy_state(const GC_Chat *chat)
{
    return chat->shared_state.privacy_state;
}

Group_Topic_Lock gc_get_topic_lock_state(const GC_Chat *chat)
{
    return group_topic_lock_enabled(chat) ? TL_ENABLED : TL_DISABLED;
}

Group_Voice_State gc_get_voice_state(const GC_Chat *chat)
{
    return chat->shared_state.voice_state;
}

int gc_founder_set_topic_lock(const Messenger *m, int group_number, Group_Topic_Lock new_lock_state)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (new_lock_state > TL_DISABLED) {
        return -2;
    }

    if (!self_gc_is_founder(chat)) {
        return -3;
    }

    if (chat->connection_state <= CS_DISCONNECTED) {
        return -4;
    }

    const Group_Topic_Lock old_lock_state = gc_get_topic_lock_state(chat);

    if (new_lock_state == old_lock_state) {
        return 0;
    }

    const uint32_t old_topic_lock = chat->shared_state.topic_lock;

    // If we're enabling the lock the founder needs to sign the current topic and re-broadcast
    // it with a new version. This needs to happen before we re-broadcast the shared state because
    // if it fails we don't want to enable the topic lock with an invalid topic signature or version.
    if (new_lock_state == TL_ENABLED) {
        chat->shared_state.topic_lock = GC_TOPIC_LOCK_ENABLED;

        if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
            chat->shared_state.topic_lock = old_topic_lock;
            return -6;
        }
    } else {
        chat->shared_state.topic_lock = chat->topic_info.version;
    }

    if (!sign_gc_shared_state(chat)) {
        chat->shared_state.topic_lock = old_topic_lock;
        return -5;
    }

    if (!broadcast_gc_shared_state(chat)) {
        return -6;
    }

    return 0;
}

int gc_founder_set_voice_state(const Messenger *m, int group_number, Group_Voice_State new_voice_state)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!self_gc_is_founder(chat)) {
        return -2;
    }

    if (chat->connection_state == CS_DISCONNECTED || chat->connection_state == CS_NONE) {
        return -3;
    }

    const Group_Voice_State old_voice_state = chat->shared_state.voice_state;

    if (new_voice_state == old_voice_state) {
        return 0;
    }

    chat->shared_state.voice_state = new_voice_state;

    if (!sign_gc_shared_state(chat)) {
        chat->shared_state.voice_state = old_voice_state;
        return -4;
    }

    if (!broadcast_gc_shared_state(chat)) {
        return -5;
    }

    return 0;
}

int gc_founder_set_privacy_state(const Messenger *m, int group_number, Group_Privacy_State new_privacy_state)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!self_gc_is_founder(chat)) {
        return -2;
    }

    if (chat->connection_state == CS_DISCONNECTED || chat->connection_state == CS_NONE) {
        return -3;
    }

    const Group_Privacy_State old_privacy_state = chat->shared_state.privacy_state;

    if (new_privacy_state == old_privacy_state) {
        return 0;
    }

    chat->shared_state.privacy_state = new_privacy_state;

    if (!sign_gc_shared_state(chat)) {
        chat->shared_state.privacy_state = old_privacy_state;
        return -4;
    }

    if (new_privacy_state == GI_PRIVATE) {
        cleanup_gca(c->announces_list, get_chat_id(&chat->chat_public_key));
        kill_group_friend_connection(c, chat);
        chat->join_type = HJ_PRIVATE;
    } else {
        if (!m_create_group_connection(c->messenger, chat)) {
            LOGGER_ERROR(chat->log, "Failed to initialize group friend connection");
        } else {
            chat->update_self_announces = true;
            chat->join_type = HJ_PUBLIC;
        }
    }

    if (!broadcast_gc_shared_state(chat)) {
        return -5;
    }

    return 0;
}

uint16_t gc_get_max_peers(const GC_Chat *chat)
{
    return chat->shared_state.maxpeers;
}

int gc_founder_set_max_peers(GC_Chat *chat, uint16_t max_peers)
{
    if (!self_gc_is_founder(chat)) {
        return -1;
    }

    const uint16_t old_maxpeers = chat->shared_state.maxpeers;

    if (max_peers == chat->shared_state.maxpeers) {
        return 0;
    }

    chat->shared_state.maxpeers = max_peers;

    if (!sign_gc_shared_state(chat)) {
        chat->shared_state.maxpeers = old_maxpeers;
        return -2;
    }

    if (!broadcast_gc_shared_state(chat)) {
        return -3;
    }

    return 0;
}

int gc_send_message(const GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type, uint32_t *message_id)
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

    const GC_Peer *self = get_gc_peer(chat, 0);
    assert(self != nullptr);

    if (gc_get_self_role(chat) >= GR_OBSERVER || !peer_has_voice(self, chat->shared_state.voice_state)) {
        return -4;
    }

    const uint8_t packet_type = type == GC_MESSAGE_TYPE_NORMAL ? GM_PLAIN_MESSAGE : GM_ACTION_MESSAGE;

    const uint16_t length_raw = length + GC_MESSAGE_PSEUDO_ID_SIZE;
    uint8_t *message_raw = (uint8_t *)malloc(length_raw);

    if (message_raw == nullptr) {
        return -5;
    }

    const uint32_t pseudo_msg_id = random_u32(chat->rng);

    net_pack_u32(message_raw, pseudo_msg_id);
    memcpy(message_raw + GC_MESSAGE_PSEUDO_ID_SIZE, message, length);

    if (!send_gc_broadcast_message(chat, message_raw, length_raw, packet_type)) {
        free(message_raw);
        return -5;
    }

    free(message_raw);

    if (message_id != nullptr) {
        *message_id = pseudo_msg_id;
    }

    return 0;
}

/** @brief Handles a message broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 */
non_null(1, 2, 3, 4) nullable(7)
static int handle_gc_message(const GC_Session *c, const GC_Chat *chat, const GC_Peer *peer, const uint8_t *data,
                             uint16_t length, uint8_t type, void *userdata)
{
    if (data == nullptr || length > MAX_GC_MESSAGE_RAW_SIZE || length <= GC_MESSAGE_PSEUDO_ID_SIZE) {
        return -1;
    }

    if (peer->ignore || peer->role >= GR_OBSERVER || !peer_has_voice(peer, chat->shared_state.voice_state)) {
        return 0;
    }

    if (type != GM_PLAIN_MESSAGE && type != GM_ACTION_MESSAGE) {
        LOGGER_WARNING(chat->log, "received invalid message type: %u", type);
        return 0;
    }

    const uint8_t cb_type = (type == GM_PLAIN_MESSAGE) ? MESSAGE_NORMAL : MESSAGE_ACTION;

    uint32_t pseudo_msg_id;
    net_unpack_u32(data, &pseudo_msg_id);

    if (c->message != nullptr) {
        c->message(c->messenger, chat->group_number, peer->peer_id, cb_type, data + GC_MESSAGE_PSEUDO_ID_SIZE,
                   length - GC_MESSAGE_PSEUDO_ID_SIZE, pseudo_msg_id, userdata);
    }

    return 0;
}

int gc_send_private_message(const GC_Chat *chat, GC_Peer_Id peer_id, uint8_t type, const uint8_t *message,
                            uint16_t length, uint32_t *message_id)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    if (type > MESSAGE_ACTION) {
        return -4;
    }

    if (gc_get_self_role(chat) >= GR_OBSERVER) {
        return -5;
    }

    const uint16_t raw_length = 1 + length + GC_MESSAGE_PSEUDO_ID_SIZE;
    uint8_t *message_with_type = (uint8_t *)malloc(raw_length);

    if (message_with_type == nullptr) {
        return -6;
    }

    message_with_type[0] = type;

    const uint32_t pseudo_msg_id = random_u32(chat->rng);
    net_pack_u32(message_with_type + 1, pseudo_msg_id);

    memcpy(message_with_type + 1 + GC_MESSAGE_PSEUDO_ID_SIZE, message, length);

    uint8_t *packet = (uint8_t *)malloc(raw_length + GC_BROADCAST_ENC_HEADER_SIZE);

    if (packet == nullptr) {
        free(message_with_type);
        return -6;
    }

    const uint16_t packet_len = make_gc_broadcast_header(message_with_type, raw_length, packet, GM_PRIVATE_MESSAGE);

    free(message_with_type);

    if (!send_lossless_group_packet(chat, gconn, packet, packet_len, GP_BROADCAST)) {
        free(packet);
        return -6;
    }

    free(packet);

    if (message_id != nullptr) {
        *message_id = pseudo_msg_id;
    }

    return 0;
}

/** @brief Handles a private message.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 */
non_null(1, 2, 3, 4) nullable(6)
static int handle_gc_private_message(const GC_Session *c, const GC_Chat *chat, const GC_Peer *peer, const uint8_t *data,
                                     uint16_t length, void *userdata)
{
    if (data == nullptr || length > MAX_GC_MESSAGE_SIZE || length <= 1 + GC_MESSAGE_PSEUDO_ID_SIZE) {
        return -1;
    }

    if (peer->ignore || peer->role >= GR_OBSERVER) {
        return 0;
    }

    const uint8_t message_type = data[0];

    if (message_type > MESSAGE_ACTION) {
        LOGGER_WARNING(chat->log, "Received invalid private message type: %u", message_type);
        return 0;
    }

    uint32_t message_id;
    net_unpack_u32(data + 1, &message_id);

    if (c->private_message != nullptr) {
        c->private_message(c->messenger, chat->group_number, peer->peer_id, message_type,
                           data + 1 + GC_MESSAGE_PSEUDO_ID_SIZE, length - 1 - GC_MESSAGE_PSEUDO_ID_SIZE,
                           message_id, userdata);
    }

    return 0;
}

/** @brief Returns false if a custom packet is too large. */
static bool custom_gc_packet_length_is_valid(uint16_t length, bool lossless)
{
    return length <= (lossless ? MAX_GC_CUSTOM_LOSSLESS_PACKET_SIZE : MAX_GC_CUSTOM_LOSSY_PACKET_SIZE);
}

int gc_send_custom_private_packet(const GC_Chat *chat, bool lossless, GC_Peer_Id peer_id, const uint8_t *message,
                                  uint16_t length)
{
    if (!custom_gc_packet_length_is_valid(length, lossless)) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    bool ret;

    if (lossless) {
        ret = send_lossless_group_packet(chat, gconn, message, length, GP_CUSTOM_PRIVATE_PACKET);
    } else {
        ret = send_lossy_group_packet(chat, gconn, message, length, GP_CUSTOM_PRIVATE_PACKET);
    }

    return ret ? 0 : -4;
}

/** @brief Handles a custom private packet.
 *
 * @retval 0 if packet is handled correctly.
 * @retval -1 if packet has invalid size.
 */
non_null(1, 2, 3, 4) nullable(7)
static int handle_gc_custom_private_packet(const GC_Session *c, const GC_Chat *chat, const GC_Peer *peer,
        const uint8_t *data, uint16_t length, bool lossless, void *userdata)
{
    if (!custom_gc_packet_length_is_valid(length, lossless)) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -1;
    }

    if (c->custom_private_packet != nullptr) {
        c->custom_private_packet(c->messenger, chat->group_number, peer->peer_id, data, length, userdata);
    }

    return 0;
}

int gc_send_custom_packet(const GC_Chat *chat, bool lossless, const uint8_t *data, uint16_t length)
{
    if (!custom_gc_packet_length_is_valid(length, lossless)) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -2;
    }

    bool success;

    if (lossless) {
        success = send_gc_lossless_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    } else {
        success = send_gc_lossy_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    }

    return success ? 0 : -3;
}

/** @brief Handles a custom packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 */
non_null(1, 2, 3, 4) nullable(7)
static int handle_gc_custom_packet(const GC_Session *c, const GC_Chat *chat, const GC_Peer *peer, const uint8_t *data,
                                   uint16_t length, bool lossless, void *userdata)
{
    if (!custom_gc_packet_length_is_valid(length, lossless)) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -1;
    }

    if (c->custom_packet != nullptr) {
        c->custom_packet(c->messenger, chat->group_number, peer->peer_id, data, length, userdata);
    }

    return 0;
}

/** @brief Handles a peer kick broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 */
non_null(1, 2, 3, 4) nullable(6)
static int handle_gc_kick_peer(const GC_Session *c, GC_Chat *chat, const GC_Peer *setter_peer, const uint8_t *data,
                               uint16_t length, void *userdata)
{
    if (length < ENC_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (setter_peer->role >= GR_USER) {
        return 0;
    }

    const uint8_t *target_pk = data;

    const int target_peer_number = get_peer_number_of_enc_pk(chat, target_pk, false);
    GC_Peer *target_peer = get_gc_peer(chat, target_peer_number);

    if (target_peer != nullptr) {
        if (target_peer->role != GR_USER) {
            return 0;
        }
    }

    if (peer_number_is_self(target_peer_number)) {
        assert(target_peer != nullptr);

        for (uint32_t i = 1; i < chat->numpeers; ++i) {
            GC_Connection *gconn = get_gc_connection(chat, i);
            assert(gconn != nullptr);

            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SELF_DISCONNECTED, nullptr, 0);
        }

        chat->connection_state = CS_DISCONNECTED;

        if (c->moderation != nullptr) {
            c->moderation(c->messenger, chat->group_number, setter_peer->peer_id, target_peer->peer_id,
                          MV_KICK, userdata);
        }

        return 0;
    }

    if (target_peer == nullptr) {   /** we don't need to/can't kick a peer that isn't in our peerlist */
        return 0;
    }

    gcc_mark_for_deletion(&target_peer->gconn, chat->tcp_conn, GC_EXIT_TYPE_KICKED, nullptr, 0);

    if (c->moderation != nullptr) {
        c->moderation(c->messenger, chat->group_number, setter_peer->peer_id, target_peer->peer_id, MV_KICK, userdata);
    }

    return 0;
}

/** @brief Sends a packet to instruct all peers to remove gconn from their peerlist.
 *
 * Returns true on success.
 */
non_null()
static bool send_gc_kick_peer(const GC_Chat *chat, const GC_Connection *gconn)
{
    uint8_t packet[ENC_PUBLIC_KEY_SIZE];
    memcpy(packet, gconn->addr.public_key.enc, ENC_PUBLIC_KEY_SIZE);

    return send_gc_broadcast_message(chat, packet, ENC_PUBLIC_KEY_SIZE, GM_KICK_PEER);
}

int gc_kick_peer(const Messenger *m, int group_number, GC_Peer_Id peer_id)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (peer_number_is_self(peer_number)) {
        return -6;
    }

    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return -2;
    }

    if (gc_get_self_role(chat) >= GR_USER || peer->role == GR_FOUNDER) {
        return -3;
    }

    if (!self_gc_is_founder(chat) && peer->role == GR_MODERATOR) {
        return -3;
    }

    if (peer->role == GR_MODERATOR || peer->role == GR_OBSERVER) {
        // this first removes peer from any lists they're on and broadcasts new lists to group
        if (gc_set_peer_role(c->messenger, chat->group_number, peer_id, GR_USER) < 0) {
            return -4;
        }
    }

    if (!send_gc_kick_peer(chat, &peer->gconn)) {
        return -5;
    }

    gcc_mark_for_deletion(&peer->gconn, chat->tcp_conn, GC_EXIT_TYPE_NO_CALLBACK, nullptr, 0);

    return 0;
}

bool gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t message_id, Group_Message_Ack_Type type)
{
    if (gconn->pending_delete) {
        return true;
    }

    if (type == GR_ACK_REQ) {
        const uint64_t tm = mono_time_get(chat->mono_time);

        if (gconn->last_requested_packet_time == tm) {
            return true;
        }

        gconn->last_requested_packet_time = tm;
    } else if (type != GR_ACK_RECV) {
        return false;
    }

    uint8_t data[GC_LOSSLESS_ACK_PACKET_SIZE];
    data[0] = (uint8_t) type;
    net_pack_u64(data + 1, message_id);

    return send_lossy_group_packet(chat, gconn, data, GC_LOSSLESS_ACK_PACKET_SIZE, GP_MESSAGE_ACK);
}

/** @brief Handles a lossless message acknowledgement.
 *
 * If the type is GR_ACK_RECV we remove the packet from our
 * send array. If the type is GR_ACK_REQ we re-send the packet
 * associated with the requested message_id.
 *
 * Returns 0 if packet is handled correctly.
 * Return -1 if packet has invalid size.
 * Return -2 if we failed to handle the ack (may be caused by connection issues).
 * Return -3 if we failed to re-send a requested packet.
 */
non_null()
static int handle_gc_message_ack(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint16_t length)
{
    if (length < GC_LOSSLESS_ACK_PACKET_SIZE) {
        return -1;
    }

    uint64_t message_id;
    net_unpack_u64(data + 1, &message_id);

    const Group_Message_Ack_Type type = (Group_Message_Ack_Type) data[0];

    if (type == GR_ACK_RECV) {
        if (!gcc_handle_ack(chat->log, gconn, message_id)) {
            return -2;
        }

        return 0;
    }

    if (type != GR_ACK_REQ) {
        return 0;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);
    const uint16_t idx = gcc_get_array_index(message_id);

    /* re-send requested packet */
    if (gconn->send_array[idx].message_id == message_id) {
        if (gcc_encrypt_and_send_lossless_packet(chat, gconn, gconn->send_array[idx].data,
                gconn->send_array[idx].data_length,
                gconn->send_array[idx].message_id,
                gconn->send_array[idx].packet_type) == 0) {
            gconn->send_array[idx].last_send_try = tm;
            LOGGER_DEBUG(chat->log, "Re-sent requested packet %llu", (unsigned long long)message_id);
        } else {
            return -3;
        }
    }

    return 0;
}

/** @brief Sends a handshake response ack to peer.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_hs_response_ack(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_HS_RESPONSE_ACK);
}

/** @brief Handles a handshake response ack.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if we failed to respond with an invite request.
 */
non_null()
static int handle_gc_hs_response_ack(const GC_Chat *chat, GC_Connection *gconn)
{
    gconn->handshaked = true;  // has to be true before we can send a lossless packet

    if (!send_gc_invite_request(chat, gconn)) {
        gconn->handshaked = false;
        return -1;
    }

    return 0;
}

int gc_set_ignore(const GC_Chat *chat, GC_Peer_Id peer_id, bool ignore)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return -1;
    }

    if (peer_number_is_self(peer_number)) {
        return -2;
    }

    peer->ignore = ignore;

    return 0;
}

/** @brief Handles a broadcast packet.
 *
 * Returns 0 if packet is handled correctly.
 * Returns -1 on failure.
 */
non_null(1, 2, 4) nullable(6)
static int handle_gc_broadcast(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, const uint8_t *data,
                               uint16_t length, void *userdata)
{
    if (length < GC_BROADCAST_ENC_HEADER_SIZE) {
        return -1;
    }

    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return -1;
    }

    GC_Connection *gconn = &peer->gconn;

    if (!gconn->confirmed) {
        return -1;
    }

    const uint8_t broadcast_type = data[0];

    const uint16_t m_len = length - 1;
    const uint8_t *message = data + 1;

    int ret = 0;

    switch (broadcast_type) {
        case GM_STATUS: {
            ret = handle_gc_status(c, chat, peer, message, m_len, userdata);
            break;
        }

        case GM_NICK: {
            ret = handle_gc_nick(c, chat, peer, message, m_len, userdata);
            break;
        }

        case GM_ACTION_MESSAGE:

        // intentional fallthrough
        case GM_PLAIN_MESSAGE: {
            ret = handle_gc_message(c, chat, peer, message, m_len, broadcast_type, userdata);
            break;
        }

        case GM_PRIVATE_MESSAGE: {
            ret = handle_gc_private_message(c, chat, peer, message, m_len, userdata);
            break;
        }

        case GM_PEER_EXIT: {
            handle_gc_peer_exit(chat, gconn, message, m_len);
            ret = 0;
            break;
        }

        case GM_KICK_PEER: {
            ret = handle_gc_kick_peer(c, chat, peer, message, m_len, userdata);
            break;
        }

        case GM_SET_MOD: {
            ret = handle_gc_set_mod(c, chat, peer_number, message, m_len, userdata);
            break;
        }

        case GM_SET_OBSERVER: {
            ret = handle_gc_set_observer(c, chat, peer_number, message, m_len, userdata);
            break;
        }

        default: {
            LOGGER_DEBUG(chat->log, "Received an invalid broadcast type 0x%02x", broadcast_type);
            break;
        }
    }

    if (ret < 0) {
        LOGGER_DEBUG(chat->log, "Broadcast handle error %d: type: 0x%02x, peernumber: %u",
                     ret, broadcast_type, peer_number);
        return -1;
    }

    return 0;
}

/** @brief Decrypts data of size `length` using self secret key and sender's public key.
 *
 * The packet payload should begin with a nonce.
 *
 * Returns length of plaintext data on success.
 * Return -1 if length is invalid.
 * Return -2 if decryption fails.
 */
non_null()
static int unwrap_group_handshake_packet(const Logger *log, const uint8_t *self_sk, const uint8_t *sender_pk,
        uint8_t *plain, size_t plain_size, const uint8_t *packet, uint16_t length)
{
    if (length <= CRYPTO_NONCE_SIZE) {
        LOGGER_FATAL(log, "Invalid handshake packet length %u", length);
        return -1;
    }

    const int plain_len = decrypt_data(sender_pk, self_sk, packet, packet + CRYPTO_NONCE_SIZE,
                                       length - CRYPTO_NONCE_SIZE, plain);

    if (plain_len < 0 || (uint32_t)plain_len != plain_size) {
        LOGGER_DEBUG(log, "decrypt handshake request failed: len: %d, size: %zu", plain_len, plain_size);
        return -2;
    }

    return plain_len;
}

/** @brief Encrypts data of length using the peer's shared key a new nonce.
 *
 * Adds plaintext header consisting of: packet identifier, target public encryption key,
 * self public encryption key, nonce.
 *
 * Return length of encrypted packet on success.
 * Return -1 if packet size is invalid.
 * Return -2 on malloc failure.
 * Return -3 if encryption fails.
 */
non_null()
static int wrap_group_handshake_packet(
    const Logger *log, const Random *rng, const uint8_t *self_pk, const uint8_t *self_sk,
    const uint8_t *target_pk, uint8_t *packet, uint32_t packet_size,
    const uint8_t *data, uint16_t length)
{
    if (packet_size != GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)) {
        LOGGER_FATAL(log, "Invalid packet size: %u", packet_size);
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(rng, nonce);

    const size_t encrypt_buf_size = length + CRYPTO_MAC_SIZE;
    uint8_t *encrypt = (uint8_t *)malloc(encrypt_buf_size);

    if (encrypt == nullptr) {
        return -2;
    }

    const int enc_len = encrypt_data(target_pk, self_sk, nonce, data, length, encrypt);

    if (enc_len < 0 || (size_t)enc_len != encrypt_buf_size) {
        LOGGER_ERROR(log, "Failed to encrypt group handshake packet (len: %d)", enc_len);
        free(encrypt);
        return -3;
    }

    packet[0] = NET_PACKET_GC_HANDSHAKE;
    memcpy(packet + 1, self_pk, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE, target_pk, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    free(encrypt);

    return 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + enc_len;
}

/** @brief Makes, wraps and encrypts a group handshake packet (both request and response are the same format).
 *
 * Packet contains the packet header, handshake type, self public encryption key, self public signature key,
 * request type, and a single TCP relay node.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
non_null()
static int make_gc_handshake_packet(const GC_Chat *chat, const GC_Connection *gconn, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t join_type, uint8_t *packet, size_t packet_size,
                                    const Node_format *node)
{
    if (chat == nullptr || gconn == nullptr || node == nullptr) {
        return -1;
    }

    if (packet_size != GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)) {
        LOGGER_FATAL(chat->log, "invalid packet size: %zu", packet_size);
        return -1;
    }

    uint8_t data[GC_MIN_HS_PACKET_PAYLOAD_SIZE + sizeof(Node_format)];

    uint16_t length = sizeof(uint8_t);

    data[0] = handshake_type;
    memcpy(data + length, gconn->session_public_key, ENC_PUBLIC_KEY_SIZE);
    length += ENC_PUBLIC_KEY_SIZE;
    memcpy(data + length, get_sig_pk(&chat->self_public_key), SIG_PUBLIC_KEY_SIZE);
    length += SIG_PUBLIC_KEY_SIZE;
    memcpy(data + length, &request_type, sizeof(uint8_t));
    length += sizeof(uint8_t);
    memcpy(data + length, &join_type, sizeof(uint8_t));
    length += sizeof(uint8_t);

    int nodes_size = pack_nodes(chat->log, data + length, sizeof(Node_format), node, MAX_SENT_GC_NODES);

    if (nodes_size > 0) {
        length += nodes_size;
    } else {
        nodes_size = 0;
    }

    const int enc_len = wrap_group_handshake_packet(
                            chat->log, chat->rng, chat->self_public_key.enc, chat->self_secret_key.enc,
                            gconn->addr.public_key.enc, packet, (uint16_t)packet_size, data, length);

    if (enc_len != GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + nodes_size) {
        LOGGER_WARNING(chat->log, "Failed to wrap handshake packet: %d", enc_len);
        return -1;
    }

    return enc_len;
}

/** @brief Sends a handshake packet to `gconn`.
 *
 * Handshake_type should be GH_REQUEST or GH_RESPONSE.
 *
 * Returns true on success.
 */
non_null()
static bool send_gc_handshake_packet(const GC_Chat *chat, GC_Connection *gconn, uint8_t handshake_type,
                                     uint8_t request_type, uint8_t join_type)
{
    if (gconn == nullptr) {
        return false;
    }

    Node_format node = {{0}};

    if (!gcc_copy_tcp_relay(chat->rng, &node, gconn)) {
        LOGGER_TRACE(chat->log, "Failed to copy TCP relay during handshake (%u TCP relays)", gconn->tcp_relays_count);
    }

    uint8_t packet[GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)];
    const int length = make_gc_handshake_packet(chat, gconn, handshake_type, request_type, join_type, packet,
                       sizeof(packet), &node);

    if (length < 0) {
        return false;
    }

    const bool try_tcp_fallback = gconn->handshake_attempts % 2 == 1 && gconn->tcp_relays_count > 0;
    ++gconn->handshake_attempts;

    int ret = -1;

    if (!try_tcp_fallback && gcc_direct_conn_is_possible(chat, gconn)) {
        ret = sendpacket(chat->net, &gconn->addr.ip_port, packet, (uint16_t)length);
    }

    if (ret != length && gconn->tcp_relays_count == 0) {
        LOGGER_WARNING(chat->log, "UDP handshake failed and no TCP relays to fall back on");
        return false;
    }

    // Send a TCP handshake if UDP fails, or if UDP succeeded last time but we never got a response
    if (gconn->tcp_relays_count > 0 && (ret != length || try_tcp_fallback)) {
        if (send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, (uint16_t)length) == -1) {
            LOGGER_DEBUG(chat->log, "Send handshake packet failed. Type 0x%02x", request_type);
            return false;
        }
    }

    if (gconn->is_pending_handshake_response) {
        gcc_set_send_message_id(gconn, 3);  // handshake response is always second packet
    }  else {
        gcc_set_send_message_id(gconn, 2);  // handshake request is always first packet
    }

    return true;
}

/** @brief Sends an out-of-band TCP handshake request packet to `gconn`.
 *
 * Return true on success.
 */
static bool send_gc_oob_handshake_request(const GC_Chat *chat, const GC_Connection *gconn)
{
    if (gconn == nullptr) {
        return false;
    }

    Node_format node = {{0}};

    if (!gcc_copy_tcp_relay(chat->rng, &node, gconn)) {
        LOGGER_WARNING(chat->log, "Failed to copy TCP relay");
        return false;
    }

    uint8_t packet[GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)];
    const int length = make_gc_handshake_packet(chat, gconn, GH_REQUEST, gconn->pending_handshake_type, chat->join_type,
                       packet, sizeof(packet), &node);

    if (length < 0) {
        LOGGER_WARNING(chat->log, "Failed to make handshake packet");
        return false;
    }

    return tcp_send_oob_packet_using_relay(chat->tcp_conn, gconn->oob_relay_pk, gconn->addr.public_key.enc,
                                           packet, (uint16_t)length) == 0;
}

/** @brief Handles a handshake response packet and takes appropriate action depending on the value of request_type.
 *
 * This function assumes the length has already been validated.
 *
 * Returns peer_number of new connected peer on success.
 * Returns -1 on failure.
 */
non_null()
static int handle_gc_handshake_response(const GC_Chat *chat, const uint8_t *sender_pk, const uint8_t *data,
                                        uint16_t length)
{
    // this should be checked at lower level; this is a redundant defense check. Ideally we should
    // guarantee that this can never happen in the future.
    if (length < ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1) {
        LOGGER_FATAL(chat->log, "Invalid handshake response size (%u)", length);
        return -1;
    }

    const int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);

    if (peer_number == -1) {
        return -1;
    }

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    const uint8_t *sender_session_pk = data;

    gcc_make_session_shared_key(gconn, sender_session_pk);

    set_sig_pk(&gconn->addr.public_key, data + ENC_PUBLIC_KEY_SIZE);

    gcc_set_recv_message_id(gconn, 2);  // handshake response is always second packet

    gconn->handshaked = true;

    send_gc_hs_response_ack(chat, gconn);

    const uint8_t request_type = data[ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE];

    switch (request_type) {
        case HS_INVITE_REQUEST: {
            if (!send_gc_invite_request(chat, gconn)) {
                return -1;
            }

            break;
        }

        case HS_PEER_INFO_EXCHANGE: {
            if (!send_gc_peer_exchange(chat, gconn)) {
                return -1;
            }

            break;
        }

        default: {
            return -1;
        }
    }

    return peer_number;
}

/** @brief Sends a handshake response packet of type `request_type` to `gconn`.
 *
 * Return true on success.
 */
non_null()
static bool send_gc_handshake_response(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_gc_handshake_packet(chat, gconn, GH_RESPONSE, gconn->pending_handshake_type, 0);
}

/** @brief Handles handshake request packets.
 *
 * Peer is added to peerlist and a lossless connection is established.
 *
 * This function assumes the length has already been validated.
 *
 * Return new peer's peer_number on success.
 * Return -1 on failure.
 */
#define GC_NEW_PEER_CONNECTION_LIMIT 10
non_null(1, 3, 4) nullable(2)
static int handle_gc_handshake_request(GC_Chat *chat, const IP_Port *ipp, const uint8_t *sender_pk,
                                       const uint8_t *data, uint16_t length)
{
    // this should be checked at lower level; this is a redundant defense check. Ideally we should
    // guarantee that this can never happen in the future.
    if (length < ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1 + 1) {
        LOGGER_FATAL(chat->log, "Invalid length (%u)", length);
        return -1;
    }

    if (chat->connection_state <= CS_DISCONNECTED) {
        LOGGER_DEBUG(chat->log, "Handshake request ignored; state is disconnected");
        return -1;
    }

    if (chat->connection_o_metre >= GC_NEW_PEER_CONNECTION_LIMIT) {
        chat->block_handshakes = true;
        LOGGER_DEBUG(chat->log, "Handshake overflow. Blocking handshakes.");
        return -1;
    }

    ++chat->connection_o_metre;

    const uint8_t *public_sig_key = data + ENC_PUBLIC_KEY_SIZE;

    const uint8_t request_type = data[ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE];
    const uint8_t join_type = data[ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1];

    int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    const bool is_new_peer = peer_number < 0;

    if (is_new_peer) {
        peer_number = peer_add(chat, ipp, sender_pk);

        if (peer_number < 0) {
            LOGGER_WARNING(chat->log, "Failed to add peer during handshake request");
            return -1;
        }
    } else  {
        GC_Connection *gconn = get_gc_connection(chat, peer_number);

        if (gconn == nullptr) {
            LOGGER_WARNING(chat->log, "Invalid peer number");
            return -1;
        }

        if (gconn->handshaked) {
            gconn->handshaked = false;
            LOGGER_DEBUG(chat->log, "Handshaked peer sent a handshake request");
            return -1;
        }

        // peers sent handshake request at same time so the closer peer becomes the requestor
        // and ignores the request packet while further peer continues on with the response
        if (gconn->self_is_closer) {
            LOGGER_DEBUG(chat->log, "Simultaneous handshake requests; other peer is closer");
            return 0;
        }
    }

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        LOGGER_DEBUG(chat->log, "Peer connection invalid");
        return -1;
    }

    gcc_set_ip_port(gconn, ipp);

    Node_format node[GCA_MAX_ANNOUNCED_TCP_RELAYS];
    const int processed = ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1 + 1;

    const int nodes_count = unpack_nodes(node, GCA_MAX_ANNOUNCED_TCP_RELAYS, nullptr,
                                         data + processed, length - processed, true);

    if (nodes_count <= 0 && ipp == nullptr) {
        if (is_new_peer) {
            LOGGER_WARNING(chat->log, "Broken tcp relay for new peer");
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
        }

        return -1;
    }

    if (nodes_count > 0) {
        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                   &node->ip_port, node->public_key);

        if (add_tcp_result < 0 && is_new_peer && ipp == nullptr) {
            LOGGER_WARNING(chat->log, "Broken tcp relay for new peer");
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
            return -1;
        }

        if (add_tcp_result == 0) {
            gcc_save_tcp_relay(chat->rng, gconn, node);
        }
    }

    const uint8_t *sender_session_pk = data;

    gcc_make_session_shared_key(gconn, sender_session_pk);

    set_sig_pk(&gconn->addr.public_key, public_sig_key);

    if (join_type == HJ_PUBLIC && !is_public_chat(chat)) {
        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
        LOGGER_DEBUG(chat->log, "Ignoring invalid invite request");
        return -1;
    }

    gcc_set_recv_message_id(gconn, 1);  // handshake request is always first packet

    gconn->is_pending_handshake_response = true;
    gconn->pending_handshake_type = request_type;

    return peer_number;
}

/** @brief Handles handshake request and handshake response packets.
 *
 * Returns the peer_number of the connecting peer on success.
 * Returns -1 on failure.
 */
non_null(1, 2, 4) nullable(3, 7)
static int handle_gc_handshake_packet(GC_Chat *chat, const uint8_t *sender_pk, const IP_Port *ipp,
                                      const uint8_t *packet, uint16_t length, bool direct_conn, void *userdata)
{
    if (length < GC_MIN_HS_PACKET_PAYLOAD_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE) {
        return -1;
    }

    const size_t data_buf_size = length - CRYPTO_NONCE_SIZE - CRYPTO_MAC_SIZE;
    uint8_t *data = (uint8_t *)malloc(data_buf_size);

    if (data == nullptr) {
        return -1;
    }

    const int plain_len = unwrap_group_handshake_packet(chat->log, chat->self_secret_key.enc, sender_pk, data,
                          data_buf_size, packet, length);

    if (plain_len < GC_MIN_HS_PACKET_PAYLOAD_SIZE)  {
        LOGGER_DEBUG(chat->log, "Failed to unwrap handshake packet (probably a stale request using an old key)");
        free(data);
        return -1;
    }

    const uint8_t handshake_type = data[0];

    const uint8_t *real_data = data + 1;
    const uint16_t real_len = (uint16_t)plain_len - 1;

    int peer_number;

    if (handshake_type == GH_REQUEST) {
        peer_number = handle_gc_handshake_request(chat, ipp, sender_pk, real_data, real_len);
    } else if (handshake_type == GH_RESPONSE) {
        peer_number = handle_gc_handshake_response(chat, sender_pk, real_data, real_len);
    } else {
        free(data);
        return -1;
    }

    free(data);

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (direct_conn) {
        gconn->last_received_direct_time = mono_time_get(chat->mono_time);
    }

    return peer_number;
}

bool handle_gc_lossless_helper(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, const uint8_t *data,
                               uint16_t length, uint8_t packet_type, void *userdata)
{
    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return false;
    }

    GC_Connection *gconn = &peer->gconn;

    int ret;

    switch (packet_type) {
        case GP_BROADCAST: {
            ret = handle_gc_broadcast(c, chat, peer_number, data, length, userdata);
            break;
        }

        case GP_PEER_INFO_REQUEST: {
            ret = handle_gc_peer_info_request(chat, peer_number);
            break;
        }

        case GP_PEER_INFO_RESPONSE: {
            ret = handle_gc_peer_info_response(c, chat, peer_number, data, length, userdata);
            break;
        }

        case GP_SYNC_REQUEST: {
            ret = handle_gc_sync_request(chat, peer_number, data, length);
            break;
        }

        case GP_SYNC_RESPONSE: {
            ret = handle_gc_sync_response(c, chat, peer_number, data, length, userdata);
            break;
        }

        case GP_INVITE_REQUEST: {
            ret = handle_gc_invite_request(chat, peer_number, data, length);
            break;
        }

        case GP_INVITE_RESPONSE: {
            ret = handle_gc_invite_response(chat, gconn);
            break;
        }

        case GP_TOPIC: {
            ret = handle_gc_topic(c, chat, peer, data, length, userdata);
            break;
        }

        case GP_SHARED_STATE: {
            ret = handle_gc_shared_state(c, chat, gconn, data, length, userdata);
            break;
        }

        case GP_MOD_LIST: {
            ret = handle_gc_mod_list(c, chat, data, length, userdata);
            break;
        }

        case GP_SANCTIONS_LIST: {
            ret = handle_gc_sanctions_list(c, chat, data, length, userdata);
            break;
        }

        case GP_HS_RESPONSE_ACK: {
            ret = handle_gc_hs_response_ack(chat, gconn);
            break;
        }

        case GP_TCP_RELAYS: {
            ret = handle_gc_tcp_relays(chat, gconn, data, length);
            break;
        }

        case GP_KEY_ROTATION: {
            ret = handle_gc_key_exchange(chat, gconn, data, length);
            break;
        }

        case GP_CUSTOM_PACKET: {
            ret = handle_gc_custom_packet(c, chat, peer, data, length, true, userdata);
            break;
        }

        case GP_CUSTOM_PRIVATE_PACKET: {
            ret = handle_gc_custom_private_packet(c, chat, peer, data, length, true, userdata);
            break;
        }

        default: {
            LOGGER_DEBUG(chat->log, "Handling invalid lossless group packet type 0x%02x", packet_type);
            return false;
        }
    }

    if (ret < 0) {
        LOGGER_DEBUG(chat->log, "Lossless packet handle error %d: type: 0x%02x, peernumber: %d",
                     ret, packet_type, peer_number);
        return false;
    }

    peer = get_gc_peer(chat, peer_number);

    if (peer != nullptr) {
        peer->gconn.last_requested_packet_time = mono_time_get(chat->mono_time);
    }

    return true;
}

/** @brief Handles a packet fragment.
 *
 * If the fragment is the last one in a sequence we send an ack. Otherwise we
 * store the fragment in the receive array and wait for the next segment.
 *
 * Segments must be processed in correct sequence, and we cannot handle
 * non-fragment packets while a sequence is incomplete.
 *
 * Return true if packet is handled successfully.
 */
non_null(1, 2, 4) nullable(5, 9)
static bool handle_gc_packet_fragment(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, GC_Connection *gconn,
                                      const uint8_t *data, uint16_t length, uint8_t packet_type, uint64_t message_id,
                                      void *userdata)
{
    if (gconn->last_chunk_id != 0 && message_id != gconn->last_chunk_id + 1) {
        return gc_send_message_ack(chat, gconn, gconn->last_chunk_id + 1, GR_ACK_REQ);
    }

    if (gconn->last_chunk_id == 0 && message_id != gconn->received_message_id + 1) {
        return gc_send_message_ack(chat, gconn, gconn->received_message_id + 1, GR_ACK_REQ);
    }

    const int frag_ret = gcc_handle_packet_fragment(c, chat, peer_number, gconn, data, length, packet_type,
                         message_id, userdata);

    if (frag_ret == -1) {
        return false;
    }

    if (frag_ret == 0) {
        gc_send_message_ack(chat, gconn, message_id, GR_ACK_RECV);
    }

    gconn->last_received_packet_time = mono_time_get(chat->mono_time);

    return true;
}

/** @brief Handles lossless groupchat packets.
 *
 * This function assumes the length has already been validated.
 *
 * Returns true if packet is successfully handled.
 */
non_null(1, 2, 3, 4) nullable(7)
static bool handle_gc_lossless_packet(const GC_Session *c, GC_Chat *chat, const uint8_t *sender_pk,
                                      const uint8_t *packet, uint16_t length, bool direct_conn, void *userdata)
{
    if (length < GC_MIN_LOSSLESS_PAYLOAD_SIZE) {
        return false;
    }

    int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    if (gconn->pending_delete) {
        return true;
    }

    uint8_t *data = (uint8_t *)malloc(length);

    if (data == nullptr) {
        LOGGER_DEBUG(chat->log, "Failed to allocate memory for packet data buffer");
        return false;
    }

    uint8_t packet_type;
    uint64_t message_id;

    const int len = group_packet_unwrap(chat->log, gconn, data, &message_id, &packet_type, packet, length);

    if (len < 0) {
        Ip_Ntoa ip_str;
        LOGGER_DEBUG(chat->log, "Failed to unwrap lossless packet from %s:%d: %d",
                     net_ip_ntoa(&gconn->addr.ip_port.ip, &ip_str), net_ntohs(gconn->addr.ip_port.port), len);
        free(data);
        return false;
    }

    if (!gconn->handshaked && (packet_type != GP_HS_RESPONSE_ACK && packet_type != GP_INVITE_REQUEST)) {
        LOGGER_DEBUG(chat->log, "Got lossless packet type 0x%02x from unconfirmed peer", packet_type);
        free(data);
        return false;
    }

    const bool is_invite_packet = packet_type == GP_INVITE_REQUEST || packet_type == GP_INVITE_RESPONSE
                                  || packet_type == GP_INVITE_RESPONSE_REJECT;

    if (message_id == 3 && is_invite_packet && gconn->received_message_id <= 1) {
        // we missed initial handshake request. Drop this packet and wait for another handshake request.
        LOGGER_DEBUG(chat->log, "Missed handshake packet, type: 0x%02x", packet_type);
        free(data);
        return false;
    }

    const int lossless_ret = gcc_handle_received_message(chat->log, chat->mono_time, gconn, data, (uint16_t) len,
                             packet_type, message_id, direct_conn);

    if (packet_type == GP_INVITE_REQUEST && !gconn->handshaked) {  // Both peers sent request at same time
        free(data);
        return true;
    }

    if (lossless_ret < 0) {
        LOGGER_DEBUG(chat->log, "failed to handle packet %llu (type: 0x%02x, id: %llu)",
                     (unsigned long long)message_id, packet_type, (unsigned long long)message_id);
        free(data);
        return false;
    }

    /* Duplicate packet */
    if (lossless_ret == 0) {
        free(data);
        return gc_send_message_ack(chat, gconn, message_id, GR_ACK_RECV);
    }

    /* request missing packet */
    if (lossless_ret == 1) {
        LOGGER_TRACE(chat->log, "received out of order packet from peer %u. expected %llu, got %llu", peer_number,
                     (unsigned long long)gconn->received_message_id + 1, (unsigned long long)message_id);
        free(data);
        return gc_send_message_ack(chat, gconn, gconn->received_message_id + 1, GR_ACK_REQ);
    }

    /* handle packet fragment */
    if (lossless_ret == 3) {
        const bool frag_ret = handle_gc_packet_fragment(c, chat, peer_number, gconn, data, (uint16_t)len, packet_type,
                              message_id, userdata);
        free(data);
        return frag_ret;
    }

    const bool ret = handle_gc_lossless_helper(c, chat, peer_number, data, (uint16_t)len, packet_type, userdata);

    free(data);

    if (!ret) {
        return false;
    }

    /* peer number can change from peer add operations in packet handlers */
    peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    gconn = get_gc_connection(chat, peer_number);

    if (gconn != nullptr && lossless_ret == 2) {
        gc_send_message_ack(chat, gconn, message_id, GR_ACK_RECV);
    }

    return true;
}

non_null(1, 2, 3, 4, 6) nullable(8)
static int handle_gc_lossy_packet_decoded(
    const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, const GC_Peer *peer,
    uint8_t packet_type, const uint8_t *data, uint16_t payload_len, void *userdata)
{
    switch (packet_type) {
        case GP_MESSAGE_ACK: {
            return handle_gc_message_ack(chat, gconn, data, payload_len);
        }

        case GP_PING: {
            return handle_gc_ping(chat, gconn, data, payload_len);
        }

        case GP_INVITE_RESPONSE_REJECT: {
            return handle_gc_invite_response_reject(c, chat, data, payload_len, userdata);
        }

        case GP_CUSTOM_PACKET: {
            return handle_gc_custom_packet(c, chat, peer, data, payload_len, false, userdata);
        }

        case GP_CUSTOM_PRIVATE_PACKET: {
            return handle_gc_custom_private_packet(c, chat, peer, data, payload_len, false, userdata);
        }

        default: {
            LOGGER_WARNING(chat->log, "Warning: handling invalid lossy group packet type 0x%02x", packet_type);
            return -1;
        }
    }
}

/** @brief Handles lossy groupchat message packets.
 *
 * This function assumes the length has already been validated.
 *
 * Return true if packet is handled successfully.
 */
non_null(1, 2, 3, 4) nullable(7)
static bool handle_gc_lossy_packet(const GC_Session *c, GC_Chat *chat, const uint8_t *sender_pk,
                                   const uint8_t *packet, uint16_t length, bool direct_conn, void *userdata)
{
    if (length < GC_MIN_LOSSY_PAYLOAD_SIZE) {
        return false;
    }

    const int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);

    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return false;
    }

    GC_Connection *gconn = &peer->gconn;

    if (!gconn->handshaked || gconn->pending_delete) {
        LOGGER_DEBUG(chat->log, "Got lossy packet from invalid peer");
        return false;
    }

    uint8_t *data = (uint8_t *)malloc(length);

    if (data == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for packet buffer");
        return false;
    }

    uint8_t packet_type;

    const int len = group_packet_unwrap(chat->log, gconn, data, nullptr, &packet_type, packet, length);

    if (len <= 0) {
        Ip_Ntoa ip_str;
        LOGGER_DEBUG(chat->log, "Failed to unwrap lossy packet from %s:%d: %d",
                     net_ip_ntoa(&gconn->addr.ip_port.ip, &ip_str), net_ntohs(gconn->addr.ip_port.port), len);
        free(data);
        return false;
    }

    const int ret = handle_gc_lossy_packet_decoded(c, chat, gconn, peer, packet_type, data, (uint16_t)len, userdata);

    free(data);

    if (ret < 0) {
        LOGGER_DEBUG(chat->log, "Lossy packet handle error %d: type: 0x%02x, peernumber %d", ret, packet_type,
                     peer_number);
        return false;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    if (direct_conn) {
        gconn->last_received_direct_time = tm;
    }

    gconn->last_received_packet_time = tm;

    return true;
}

/** @brief Return true if group is either connected or attempting to connect. */
non_null()
static bool group_can_handle_packets(const GC_Chat *chat)
{
    const GC_Conn_State state = chat->connection_state;
    return state == CS_CONNECTING || state == CS_CONNECTED;
}

/** @brief Sends a group packet to appropriate handler function.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
#define MIN_TCP_PACKET_SIZE (1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE)
non_null(1, 3) nullable(5)
static int handle_gc_tcp_packet(void *object, int crypt_connection_id, const uint8_t *packet, uint16_t length, void *userdata)
{
    const Messenger *m = (Messenger *)object;

    if (m == nullptr) {
        return -1;
    }

    if (length <= MIN_TCP_PACKET_SIZE) {
        LOGGER_WARNING(m->log, "Got tcp packet with invalid length: %u (expected %u to %u)", length,
                       MIN_TCP_PACKET_SIZE, MAX_GC_PACKET_INCOMING_CHUNK_SIZE + MIN_TCP_PACKET_SIZE + ENC_PUBLIC_KEY_SIZE);
        return -1;
    }

    if (length > MAX_GC_PACKET_INCOMING_CHUNK_SIZE + MIN_TCP_PACKET_SIZE + ENC_PUBLIC_KEY_SIZE) {
        LOGGER_WARNING(m->log, "Got tcp packet with invalid length: %u (expected %u to %u)", length,
                       MIN_TCP_PACKET_SIZE, MAX_GC_PACKET_INCOMING_CHUNK_SIZE + MIN_TCP_PACKET_SIZE + ENC_PUBLIC_KEY_SIZE);
        return -1;
    }

    const uint8_t packet_type = packet[0];

    const uint8_t *sender_pk = packet + 1;

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = nullptr;

    if (packet_type == NET_PACKET_GC_HANDSHAKE) {
        chat = get_chat_by_id(c, packet + 1 + ENC_PUBLIC_KEY_SIZE);
    } else {
        chat = get_chat_by_id(c, sender_pk);
    }

    if (chat == nullptr) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t *payload = packet + 1 + ENC_PUBLIC_KEY_SIZE;
    uint16_t payload_len = length - 1 - ENC_PUBLIC_KEY_SIZE;

    switch (packet_type) {
        case NET_PACKET_GC_LOSSLESS: {
            if (!handle_gc_lossless_packet(c, chat, sender_pk, payload, payload_len, false, userdata)) {
                return -1;
            }

            return 0;
        }

        case NET_PACKET_GC_LOSSY: {
            if (!handle_gc_lossy_packet(c, chat, sender_pk, payload, payload_len, false, userdata)) {
                return -1;
            }

            return 0;
        }

        case NET_PACKET_GC_HANDSHAKE: {
            // handshake packets have an extra public key in plaintext header
            if (length <= 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE) {
                return -1;
            }

            payload_len = payload_len - ENC_PUBLIC_KEY_SIZE;
            payload = payload + ENC_PUBLIC_KEY_SIZE;

            return handle_gc_handshake_packet(chat, sender_pk, nullptr, payload, payload_len, false, userdata);
        }

        default: {
            return -1;
        }
    }
}

non_null(1, 2, 4) nullable(6)
static int handle_gc_tcp_oob_packet(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                                    const uint8_t *packet, uint16_t length, void *userdata)
{
    const Messenger *m = (Messenger *)object;

    if (m == nullptr) {
        return -1;
    }

    if (length <= GC_MIN_HS_PACKET_PAYLOAD_SIZE) {
        LOGGER_WARNING(m->log, "Got tcp oob packet with invalid length: %u (expected %u to %u)", length,
                       GC_MIN_HS_PACKET_PAYLOAD_SIZE, MAX_GC_PACKET_INCOMING_CHUNK_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE);
        return -1;
    }

    if (length > MAX_GC_PACKET_INCOMING_CHUNK_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE) {
        LOGGER_WARNING(m->log, "Got tcp oob packet with invalid length: %u (expected %u to %u)", length,
                       GC_MIN_HS_PACKET_PAYLOAD_SIZE, MAX_GC_PACKET_INCOMING_CHUNK_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE);
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = get_chat_by_id(c, packet + 1 + ENC_PUBLIC_KEY_SIZE);

    if (chat == nullptr) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t packet_type = packet[0];

    if (packet_type != NET_PACKET_GC_HANDSHAKE) {
        return -1;
    }

    const uint8_t *sender_pk = packet + 1;

    const uint8_t *payload = packet + 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE;
    const uint16_t payload_len = length - 1 - ENC_PUBLIC_KEY_SIZE - ENC_PUBLIC_KEY_SIZE;

    if (payload_len < GC_MIN_HS_PACKET_PAYLOAD_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE) {
        return -1;
    }

    if (handle_gc_handshake_packet(chat, sender_pk, nullptr, payload, payload_len, false, userdata) == -1) {
        return -1;
    }

    return 0;
}

#define MIN_UDP_PACKET_SIZE (1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE)
non_null(1, 2, 3) nullable(5)
static int handle_gc_udp_packet(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                void *userdata)
{
    const Messenger *m = (Messenger *)object;

    if (m == nullptr) {
        return -1;
    }

    if (length <= MIN_UDP_PACKET_SIZE) {
        LOGGER_WARNING(m->log, "Got UDP packet with invalid length: %u (expected %u to %u)", length,
                       MIN_UDP_PACKET_SIZE, MAX_GC_PACKET_INCOMING_CHUNK_SIZE + MIN_UDP_PACKET_SIZE + ENC_PUBLIC_KEY_SIZE);
        return -1;
    }

    if (length > MAX_GC_PACKET_INCOMING_CHUNK_SIZE + MIN_UDP_PACKET_SIZE + ENC_PUBLIC_KEY_SIZE) {
        LOGGER_WARNING(m->log, "Got UDP packet with invalid length: %u (expected %u to %u)", length,
                       MIN_UDP_PACKET_SIZE, MAX_GC_PACKET_INCOMING_CHUNK_SIZE + MIN_UDP_PACKET_SIZE + ENC_PUBLIC_KEY_SIZE);
        return -1;
    }

    const uint8_t packet_type = packet[0];
    const uint8_t *sender_pk = packet + 1;

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = nullptr;

    if (packet_type == NET_PACKET_GC_HANDSHAKE) {
        chat = get_chat_by_id(c, packet + 1 + ENC_PUBLIC_KEY_SIZE);
    } else {
        chat = get_chat_by_id(c, sender_pk);
    }

    if (chat == nullptr) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t *payload = packet + 1 + ENC_PUBLIC_KEY_SIZE;
    uint16_t payload_len = length - 1 - ENC_PUBLIC_KEY_SIZE;
    bool ret = false;

    switch (packet_type) {
        case NET_PACKET_GC_LOSSLESS: {
            ret = handle_gc_lossless_packet(c, chat, sender_pk, payload, payload_len, true, userdata);
            break;
        }

        case NET_PACKET_GC_LOSSY: {
            ret = handle_gc_lossy_packet(c, chat, sender_pk, payload, payload_len, true, userdata);
            break;
        }

        case NET_PACKET_GC_HANDSHAKE: {
            // handshake packets have an extra public key in plaintext header
            if (length <= 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE) {
                return -1;
            }

            payload_len = payload_len - ENC_PUBLIC_KEY_SIZE;
            payload = payload + ENC_PUBLIC_KEY_SIZE;

            ret = handle_gc_handshake_packet(chat, sender_pk, source, payload, payload_len, true, userdata) != -1;
            break;
        }

        default: {
            return -1;
        }
    }

    return ret ? 0 : -1;
}

void gc_callback_message(const Messenger *m, gc_message_cb *function)
{
    GC_Session *c = m->group_handler;
    c->message = function;
}

void gc_callback_private_message(const Messenger *m, gc_private_message_cb *function)
{
    GC_Session *c = m->group_handler;
    c->private_message = function;
}

void gc_callback_custom_packet(const Messenger *m, gc_custom_packet_cb *function)
{
    GC_Session *c = m->group_handler;
    c->custom_packet = function;
}

void gc_callback_custom_private_packet(const Messenger *m, gc_custom_private_packet_cb *function)
{
    GC_Session *c = m->group_handler;
    c->custom_private_packet = function;
}

void gc_callback_moderation(const Messenger *m, gc_moderation_cb *function)
{
    GC_Session *c = m->group_handler;
    c->moderation = function;
}

void gc_callback_nick_change(const Messenger *m, gc_nick_change_cb *function)
{
    GC_Session *c = m->group_handler;
    c->nick_change = function;
}

void gc_callback_status_change(const Messenger *m, gc_status_change_cb *function)
{
    GC_Session *c = m->group_handler;
    c->status_change = function;
}

void gc_callback_topic_change(const Messenger *m, gc_topic_change_cb *function)
{
    GC_Session *c = m->group_handler;
    c->topic_change = function;
}

void gc_callback_topic_lock(const Messenger *m, gc_topic_lock_cb *function)
{
    GC_Session *c = m->group_handler;
    c->topic_lock = function;
}

void gc_callback_voice_state(const Messenger *m, gc_voice_state_cb *function)
{
    GC_Session *c = m->group_handler;
    c->voice_state = function;
}

void gc_callback_peer_limit(const Messenger *m, gc_peer_limit_cb *function)
{
    GC_Session *c = m->group_handler;
    c->peer_limit = function;
}

void gc_callback_privacy_state(const Messenger *m, gc_privacy_state_cb *function)
{
    GC_Session *c = m->group_handler;
    c->privacy_state = function;
}

void gc_callback_password(const Messenger *m, gc_password_cb *function)
{
    GC_Session *c = m->group_handler;
    c->password = function;
}

void gc_callback_peer_join(const Messenger *m, gc_peer_join_cb *function)
{
    GC_Session *c = m->group_handler;
    c->peer_join = function;
}

void gc_callback_peer_exit(const Messenger *m, gc_peer_exit_cb *function)
{
    GC_Session *c = m->group_handler;
    c->peer_exit = function;
}

void gc_callback_self_join(const Messenger *m, gc_self_join_cb *function)
{
    GC_Session *c = m->group_handler;
    c->self_join = function;
}

void gc_callback_rejected(const Messenger *m, gc_rejected_cb *function)
{
    GC_Session *c = m->group_handler;
    c->rejected = function;
}

/** @brief Deletes peer_number from group.
 *
 * `no_callback` should be set to true if the `peer_exit` callback
 * should not be triggered.
 *
 * Return true on success.
 */
static bool peer_delete(const GC_Session *c, GC_Chat *chat, uint32_t peer_number, void *userdata)
{
    GC_Peer *peer = get_gc_peer(chat, peer_number);

    if (peer == nullptr) {
        return false;
    }

    // We need to save some peer info for the callback before deleting it
    const bool peer_confirmed = peer->gconn.confirmed;
    const GC_Peer_Id peer_id = peer->peer_id;
    uint8_t nick[MAX_GC_NICK_SIZE];
    const uint16_t nick_length = peer->nick_length;
    const GC_Exit_Info exit_info = peer->gconn.exit_info;

    assert(nick_length <= MAX_GC_NICK_SIZE);
    memcpy(nick, peer->nick, nick_length);

    gcc_peer_cleanup(&peer->gconn);

    --chat->numpeers;

    if (chat->numpeers != peer_number) {
        chat->group[peer_number] = chat->group[chat->numpeers];
    }

    chat->group[chat->numpeers] = (GC_Peer) {
        0
    };

    GC_Peer *tmp_group = (GC_Peer *)realloc(chat->group, chat->numpeers * sizeof(GC_Peer));

    if (tmp_group == nullptr) {
        return false;
    }

    chat->group = tmp_group;

    set_gc_peerlist_checksum(chat);

    if (peer_confirmed) {
        refresh_gc_saved_peers(chat);
    }

    if (exit_info.exit_type != GC_EXIT_TYPE_NO_CALLBACK && c->peer_exit != nullptr && peer_confirmed) {
        c->peer_exit(c->messenger, chat->group_number, peer_id, exit_info.exit_type, nick,
                     nick_length, exit_info.part_message, exit_info.length, userdata);
    }

    return true;
}

/** @brief Updates peer_number with info from `peer` and validates peer data.
 *
 * Returns peer_number on success.
 * Returns -1 on failure.
 */
static int peer_update(const GC_Chat *chat, const GC_Peer *peer, uint32_t peer_number)
{
    if (peer->nick_length == 0) {
        return -1;
    }

    if (peer->status > GS_BUSY) {
        return -1;
    }

    if (peer->role > GR_OBSERVER) {
        return -1;
    }

    GC_Peer *curr_peer = get_gc_peer(chat, peer_number);
    assert(curr_peer != nullptr);

    curr_peer->status = peer->status;
    curr_peer->nick_length = peer->nick_length;

    memcpy(curr_peer->nick, peer->nick, peer->nick_length);

    return peer_number;
}

int peer_add(GC_Chat *chat, const IP_Port *ipp, const uint8_t *public_key)
{
    if (get_peer_number_of_enc_pk(chat, public_key, false) != -1) {
        return -2;
    }

    const GC_Peer_Id peer_id = get_new_peer_id(chat);

    if (!gc_peer_id_is_valid(peer_id)) {
        LOGGER_WARNING(chat->log, "Failed to add peer: all peer ID's are taken?");
        return -1;
    }

    const int peer_number = chat->numpeers;
    int tcp_connection_num = -1;

    if (peer_number > 0) {  // we don't need a connection to ourself
        tcp_connection_num = new_tcp_connection_to(chat->tcp_conn, public_key, 0);

        if (tcp_connection_num == -1) {
            LOGGER_WARNING(chat->log, "Failed to init tcp connection for peer %d", peer_number);
        }
    }

    GC_Message_Array_Entry *send = (GC_Message_Array_Entry *)calloc(GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry));
    GC_Message_Array_Entry *recv = (GC_Message_Array_Entry *)calloc(GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry));

    if (send == nullptr || recv == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for gconn buffers");

        if (tcp_connection_num != -1) {
            kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        }

        free(send);
        free(recv);
        return -1;
    }

    GC_Peer *tmp_group = (GC_Peer *)realloc(chat->group, (chat->numpeers + 1) * sizeof(GC_Peer));

    if (tmp_group == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for group realloc");

        if (tcp_connection_num != -1) {
            kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        }

        free(send);
        free(recv);
        return -1;
    }

    ++chat->numpeers;
    chat->group = tmp_group;

    chat->group[peer_number] = (GC_Peer) {
        0
    };

    GC_Connection *gconn = &chat->group[peer_number].gconn;

    gconn->send_array = send;
    gconn->recv_array = recv;

    gcc_set_ip_port(gconn, ipp);
    chat->group[peer_number].role = GR_USER;
    chat->group[peer_number].peer_id = peer_id;
    chat->group[peer_number].ignore = false;

    crypto_memlock(gconn->session_secret_key, sizeof(gconn->session_secret_key));

    create_gc_session_keypair(chat->log, chat->rng, gconn->session_public_key, gconn->session_secret_key);

    if (peer_number > 0) {
        memcpy(gconn->addr.public_key.enc, public_key, ENC_PUBLIC_KEY_SIZE);  // we get the sig key in the handshake
    } else {
        gconn->addr.public_key = chat->self_public_key;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    gcc_set_send_message_id(gconn, 1);
    gconn->public_key_hash = gc_get_pk_jenkins_hash(public_key);
    gconn->last_received_packet_time = tm;
    gconn->last_key_rotation = tm;
    gconn->tcp_connection_num = tcp_connection_num;
    gconn->last_sent_ip_time = tm;
    gconn->last_sent_ping_time = tm - (GC_PING_TIMEOUT / 2) + (peer_number % (GC_PING_TIMEOUT / 2));
    gconn->self_is_closer = id_closest(get_chat_id(&chat->chat_public_key),
                                       get_enc_key(&chat->self_public_key),
                                       get_enc_key(&gconn->addr.public_key)) == 1;
    return peer_number;
}

/** @brief Copies own peer data to `peer`. */
non_null()
static void copy_self(const GC_Chat *chat, GC_Peer *peer)
{
    *peer = (GC_Peer) {
        0
    };

    peer->status = gc_get_self_status(chat);
    gc_get_self_nick(chat, peer->nick);
    peer->nick_length = gc_get_self_nick_size(chat);
    peer->role = gc_get_self_role(chat);
}

/** @brief Returns true if we haven't received a ping from this peer after n seconds.
 * n depends on whether or not the peer has been confirmed.
 */
non_null()
static bool peer_timed_out(const Mono_Time *mono_time, const GC_Connection *gconn)
{
    return mono_time_is_timeout(mono_time, gconn->last_received_packet_time, gconn->confirmed
                                ? GC_CONFIRMED_PEER_TIMEOUT
                                : GC_UNCONFIRMED_PEER_TIMEOUT);
}

/** @brief Attempts to send pending handshake packets to peer designated by `gconn`.
 *
 * One request of each type can be sent per `GC_SEND_HANDSHAKE_INTERVAL` seconds.
 *
 * Return true on success.
 */
non_null()
static bool send_pending_handshake(const GC_Chat *chat, GC_Connection *gconn)
{
    if (chat == nullptr || gconn == nullptr) {
        return false;
    }

    if (gconn->is_pending_handshake_response) {
        if (!mono_time_is_timeout(chat->mono_time, gconn->last_handshake_response, GC_SEND_HANDSHAKE_INTERVAL)) {
            return true;
        }

        gconn->last_handshake_response = mono_time_get(chat->mono_time);

        return send_gc_handshake_response(chat, gconn);
    }

    if (!mono_time_is_timeout(chat->mono_time, gconn->last_handshake_request, GC_SEND_HANDSHAKE_INTERVAL)) {
        return true;
    }

    gconn->last_handshake_request = mono_time_get(chat->mono_time);

    if (gconn->is_oob_handshake) {
        return send_gc_oob_handshake_request(chat, gconn);
    }

    return send_gc_handshake_packet(chat, gconn, GH_REQUEST, gconn->pending_handshake_type, chat->join_type);
}

#define GC_TCP_RELAY_SEND_INTERVAL (60 * 3)
non_null(1, 2) nullable(3)
static void do_peer_connections(const GC_Session *c, GC_Chat *chat, void *userdata)
{
    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        if (gconn->pending_delete) {
            continue;
        }

        if (peer_timed_out(chat->mono_time, gconn)) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_TIMEOUT, nullptr, 0);
            continue;
        }

        gcc_resend_packets(chat, gconn);

        if (gconn->tcp_relays_count > 0 &&
                mono_time_is_timeout(chat->mono_time, gconn->last_sent_tcp_relays_time, GC_TCP_RELAY_SEND_INTERVAL)) {
            if (gconn->confirmed) {
                send_gc_tcp_relays(chat, gconn);
                gconn->last_sent_tcp_relays_time = mono_time_get(chat->mono_time);
            }
        }

        gcc_check_recv_array(c, chat, gconn, i, userdata);   // may change peer numbers
    }
}

/** @brief Executes pending handshakes for peers.
 *
 * If our peerlist is empty we periodically try to
 * load peers from our saved peers list and initiate handshake requests with them.
 */
#define LOAD_PEERS_TIMEOUT (GC_UNCONFIRMED_PEER_TIMEOUT + 10)
non_null()
static void do_handshakes(GC_Chat *chat)
{
    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        if (gconn->handshaked || gconn->pending_delete) {
            continue;
        }

        send_pending_handshake(chat, gconn);
    }

    if (chat->numpeers <= 1) {
        const uint64_t tm = mono_time_get(chat->mono_time);

        if (mono_time_is_timeout(chat->mono_time, chat->last_time_peers_loaded, LOAD_PEERS_TIMEOUT)) {
            load_gc_peers(chat, chat->saved_peers, GC_MAX_SAVED_PEERS);
            chat->last_time_peers_loaded = tm;
        }
    }
}

/** @brief Adds `gconn` to the group timeout list. */
non_null()
static void add_gc_peer_timeout_list(GC_Chat *chat, const GC_Connection *gconn)
{
    const size_t idx = chat->timeout_list_index;
    const uint64_t tm = mono_time_get(chat->mono_time);

    copy_gc_saved_peer(chat->rng, gconn, &chat->timeout_list[idx].addr);

    chat->timeout_list[idx].last_seen = tm;
    chat->timeout_list[idx].last_reconn_try = 0;
    chat->timeout_list_index = (idx + 1) % MAX_GC_SAVED_TIMEOUTS;
}

non_null(1, 2) nullable(3)
static void do_peer_delete(const GC_Session *c, GC_Chat *chat, void *userdata)
{
    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        if (!gconn->pending_delete) {
            continue;
        }

        if (!gconn->delete_this_iteration) {
            gconn->delete_this_iteration = true;
            continue;
        }

        const GC_Exit_Info *exit_info = &gconn->exit_info;

        if (exit_info->exit_type == GC_EXIT_TYPE_TIMEOUT && gconn->confirmed) {
            add_gc_peer_timeout_list(chat, gconn);
        }

        if (!peer_delete(c, chat, i, userdata)) {
            LOGGER_ERROR(chat->log, "Failed to delete peer %u", i);
        }

        if (i >= chat->numpeers) {
            break;
        }
    }
}

/** @brief Constructs and sends a ping packet to `gconn` containing info needed for group syncing
 * and connection maintenance.
 *
 * Return true on success.
 */
non_null()
static bool ping_peer(const GC_Chat *chat, const GC_Connection *gconn)
{
    const uint16_t buf_size = GC_PING_PACKET_MIN_DATA_SIZE + sizeof(IP_Port);
    uint8_t *data = (uint8_t *)malloc(buf_size);

    if (data == nullptr) {
        return false;
    }

    const uint16_t roles_checksum = chat->moderation.sanctions_creds.checksum + chat->roles_checksum;
    uint16_t packed_len = 0;

    net_pack_u16(data, chat->peers_checksum);
    packed_len += sizeof(uint16_t);

    net_pack_u16(data + packed_len, get_gc_confirmed_numpeers(chat));
    packed_len += sizeof(uint16_t);

    net_pack_u32(data + packed_len, chat->shared_state.version);
    packed_len += sizeof(uint32_t);

    net_pack_u32(data + packed_len, chat->moderation.sanctions_creds.version);
    packed_len += sizeof(uint32_t);

    net_pack_u16(data + packed_len, roles_checksum);
    packed_len += sizeof(uint16_t);

    net_pack_u32(data + packed_len, chat->topic_info.version);
    packed_len += sizeof(uint32_t);

    net_pack_u16(data + packed_len, chat->topic_info.checksum);
    packed_len += sizeof(uint16_t);

    if (packed_len != GC_PING_PACKET_MIN_DATA_SIZE) {
        LOGGER_FATAL(chat->log, "Packed length is impossible");
    }

    if (chat->self_udp_status == SELF_UDP_STATUS_WAN && !gcc_conn_is_direct(chat->mono_time, gconn)
            && mono_time_is_timeout(chat->mono_time, gconn->last_sent_ip_time, GC_SEND_IP_PORT_INTERVAL)) {

        const int packed_ipp_len = pack_ip_port(chat->log, data + buf_size - sizeof(IP_Port), sizeof(IP_Port),
                                                &chat->self_ip_port);

        if (packed_ipp_len > 0) {
            packed_len += packed_ipp_len;
        }
    }

    if (!send_lossy_group_packet(chat, gconn, data, packed_len, GP_PING)) {
        free(data);
        return false;
    }

    free(data);

    return true;
}

/**
 * Sends a ping packet to peers that haven't been pinged in at least GC_PING_TIMEOUT seconds, and
 * a key rotation request to peers with whom we haven't refreshed keys in at least GC_KEY_ROTATION_TIMEOUT
 * seconds.
 *
 * Ping packet always includes your confirmed peer count, a peer list checksum, your shared state and sanctions
 * list version for syncing purposes. We also occasionally try to send our own IP info to peers that we
 * do not have a direct connection with.
 */
#define GC_DO_PINGS_INTERVAL 2
non_null()
static void do_gc_ping_and_key_rotation(GC_Chat *chat)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_ping_interval, GC_DO_PINGS_INTERVAL)) {
        return;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        if (!gconn->confirmed) {
            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, gconn->last_sent_ping_time, GC_PING_TIMEOUT)) {
            if (ping_peer(chat, gconn)) {
                gconn->last_sent_ping_time = tm;
            }
        }

        if (mono_time_is_timeout(chat->mono_time, gconn->last_key_rotation, GC_KEY_ROTATION_TIMEOUT)) {
            if (send_peer_key_rotation_request(chat, gconn)) {
                gconn->last_key_rotation = tm;
            }
        }
    }

    chat->last_ping_interval = tm;
}

non_null()
static void do_new_connection_cooldown(GC_Chat *chat)
{
    if (chat->connection_o_metre == 0) {
        return;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    if (chat->connection_cooldown_timer < tm) {
        chat->connection_cooldown_timer = tm;
        --chat->connection_o_metre;

        if (chat->connection_o_metre == 0 && chat->block_handshakes) {
            chat->block_handshakes = false;
            LOGGER_DEBUG(chat->log, "Unblocking handshakes");
        }
    }
}

#define TCP_RELAYS_CHECK_INTERVAL 10
non_null(1, 2) nullable(3)
static void do_gc_tcp(const GC_Session *c, GC_Chat *chat, void *userdata)
{
    if (chat->tcp_conn == nullptr || !group_can_handle_packets(chat)) {
        return;
    }

    do_tcp_connections(chat->log, chat->tcp_conn, userdata);

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        const bool tcp_set = !gcc_conn_is_direct(chat->mono_time, gconn);
        set_tcp_connection_to_status(chat->tcp_conn, gconn->tcp_connection_num, tcp_set);
    }

    if (mono_time_is_timeout(chat->mono_time, chat->last_checked_tcp_relays, TCP_RELAYS_CHECK_INTERVAL)
            && tcp_connected_relays_count(chat->tcp_conn) != chat->connected_tcp_relays) {
        add_tcp_relays_to_chat(c, chat);
        chat->connected_tcp_relays = tcp_connected_relays_count(chat->tcp_conn);
        chat->last_checked_tcp_relays = mono_time_get(chat->mono_time);
    }
}

/**
 * Updates our TCP and UDP connection status and flags a new announcement if our connection has
 * changed and we have either a UDP or TCP connection.
 */
#define GC_SELF_CONNECTION_CHECK_INTERVAL 5  // how often in seconds we should run this function
#define GC_SELF_REFRESH_ANNOUNCE_INTERVAL (60 * 20)  // how often in seconds we force refresh our group announcement
non_null()
static void do_self_connection(const GC_Session *c, GC_Chat *chat)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_self_announce_check, GC_SELF_CONNECTION_CHECK_INTERVAL)) {
        return;
    }

    const unsigned int self_udp_status = ipport_self_copy(c->messenger->dht, &chat->self_ip_port);
    const bool udp_change = (chat->self_udp_status != self_udp_status) && (self_udp_status != SELF_UDP_STATUS_NONE);

    // We flag a group announce if our UDP status has changed since last run, or if our last announced TCP
    // relay is no longer valid. Additionally, we will always flag an announce in the specified interval
    // regardless of the prior conditions. Private groups are never announced.
    if (is_public_chat(chat) &&
            ((udp_change || !tcp_relay_is_valid(chat->tcp_conn, chat->announced_tcp_relay_pk))
             || mono_time_is_timeout(chat->mono_time, chat->last_time_self_announce, GC_SELF_REFRESH_ANNOUNCE_INTERVAL))) {
        chat->update_self_announces = true;
    }

    chat->self_udp_status = (Self_UDP_Status) self_udp_status;
    chat->last_self_announce_check = mono_time_get(chat->mono_time);
}

/** @brief Attempts to initiate a new connection with peers in the timeout list.
 *
 * This function is not used for public groups as the DHT and group sync mechanism
 * should automatically do this for us.
 */
#define TIMED_OUT_RECONN_INTERVAL 2
non_null()
static void do_timed_out_reconn(GC_Chat *chat)
{
    if (is_public_chat(chat)) {
        return;
    }

    if (!mono_time_is_timeout(chat->mono_time, chat->last_timed_out_reconn_try, TIMED_OUT_RECONN_INTERVAL)) {
        return;
    }

    const uint64_t curr_time = mono_time_get(chat->mono_time);

    for (size_t i = 0; i < MAX_GC_SAVED_TIMEOUTS; ++i) {
        GC_TimedOutPeer *timeout = &chat->timeout_list[i];

        if (timeout->last_seen == 0 || timeout->last_seen == curr_time) {
            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, timeout->last_seen, GC_TIMED_OUT_STALE_TIMEOUT)
                || get_peer_number_of_enc_pk(chat, timeout->addr.public_key, true) != -1) {
            *timeout = (GC_TimedOutPeer) {
                {{
                        0
                    }
                }
            };
            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, timeout->last_reconn_try, GC_TIMED_OUT_RECONN_TIMEOUT)) {
            if (load_gc_peers(chat, &timeout->addr, 1) != 1) {
                LOGGER_WARNING(chat->log, "Failed to load timed out peer");
            }

            timeout->last_reconn_try = curr_time;
        }
    }

    chat->last_timed_out_reconn_try = curr_time;
}

void do_gc(GC_Session *c, void *userdata)
{
    if (c == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < c->chats_index; ++i) {
        GC_Chat *chat = &c->chats[i];

        const GC_Conn_State state = chat->connection_state;

        if (state == CS_NONE) {
            continue;
        }

        if (state != CS_DISCONNECTED) {
            do_peer_connections(c, chat, userdata);
            do_gc_tcp(c, chat, userdata);
            do_handshakes(chat);
            do_self_connection(c, chat);
        }

        if (chat->connection_state == CS_CONNECTED) {
            do_gc_ping_and_key_rotation(chat);
            do_timed_out_reconn(chat);
        }

        do_new_connection_cooldown(chat);
        do_peer_delete(c, chat, userdata);

        if (chat->flag_exit) {  // should always come last as it modifies the chats array
            group_delete(c, chat);
        }
    }
}

/** @brief Set the size of the groupchat list to n.
 *
 * Return true on success.
 */
non_null()
static bool realloc_groupchats(GC_Session *c, uint32_t n)
{
    if (n == 0) {
        free(c->chats);
        c->chats = nullptr;
        return true;
    }

    GC_Chat *temp = (GC_Chat *)realloc(c->chats, n * sizeof(GC_Chat));

    if (temp == nullptr) {
        return false;
    }

    c->chats = temp;
    return true;
}

non_null()
static int get_new_group_index(GC_Session *c)
{
    if (c == nullptr) {
        return -1;
    }

    for (uint32_t i = 0; i < c->chats_index; ++i) {
        if (c->chats[i].connection_state == CS_NONE) {
            return i;
        }
    }

    if (!realloc_groupchats(c, c->chats_index + 1)) {
        return -1;
    }

    const int new_index = c->chats_index;

    c->chats[new_index] = empty_gc_chat;

    for (size_t i = 0; i < sizeof(c->chats[new_index].saved_invites) / sizeof(*c->chats[new_index].saved_invites); ++i) {
        c->chats[new_index].saved_invites[i] = -1;
    }

    ++c->chats_index;

    return new_index;
}

/** Attempts to associate new TCP relays with our group connection. */
static void add_tcp_relays_to_chat(const GC_Session *c, GC_Chat *chat)
{
    const Messenger *m = c->messenger;

    const uint32_t num_relays = tcp_connections_count(nc_get_tcp_c(m->net_crypto));

    if (num_relays == 0) {
        return;
    }

    Node_format *tcp_relays = (Node_format *)calloc(num_relays, sizeof(Node_format));

    if (tcp_relays == nullptr) {
        return;
    }

    const uint32_t num_copied = tcp_copy_connected_relays(nc_get_tcp_c(m->net_crypto), tcp_relays, (uint16_t)num_relays);

    for (uint32_t i = 0; i < num_copied; ++i) {
        add_tcp_relay_global(chat->tcp_conn, &tcp_relays[i].ip_port, tcp_relays[i].public_key);
    }

    free(tcp_relays);
}

non_null()
static bool init_gc_tcp_connection(const GC_Session *c, GC_Chat *chat)
{
    const Messenger *m = c->messenger;

    chat->tcp_conn = new_tcp_connections(chat->log, chat->mem, chat->rng, m->ns, chat->mono_time, chat->self_secret_key.enc,
                                         &m->options.proxy_info);

    if (chat->tcp_conn == nullptr) {
        return false;
    }

    add_tcp_relays_to_chat(c, chat);

    set_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_packet, c->messenger);
    set_oob_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_oob_packet, c->messenger);

    return true;
}

/** Initializes default shared state values. */
non_null()
static void init_gc_shared_state(GC_Chat *chat, Group_Privacy_State privacy_state)
{
    chat->shared_state.maxpeers = MAX_GC_PEERS_DEFAULT;
    chat->shared_state.privacy_state = privacy_state;
    chat->shared_state.topic_lock = GC_TOPIC_LOCK_ENABLED;
    chat->shared_state.voice_state = GV_ALL;
}

/** @brief Initializes the group shared state for the founder.
 *
 * Return true on success.
 */
non_null()
static bool init_gc_shared_state_founder(GC_Chat *chat, Group_Privacy_State privacy_state, const uint8_t *group_name,
        uint16_t name_length)
{
    chat->shared_state.founder_public_key = chat->self_public_key;
    memcpy(chat->shared_state.group_name, group_name, name_length);
    chat->shared_state.group_name_len = name_length;
    chat->shared_state.privacy_state = privacy_state;

    return sign_gc_shared_state(chat);
}

/** @brief Initializes shared state for moderation object.
 *
 * This must be called before any moderation
 * or sanctions related operations.
 */
non_null()
static void init_gc_moderation(GC_Chat *chat)
{
    memcpy(chat->moderation.founder_public_sig_key,
           get_sig_pk(&chat->shared_state.founder_public_key), SIG_PUBLIC_KEY_SIZE);
    memcpy(chat->moderation.self_public_sig_key, get_sig_pk(&chat->self_public_key), SIG_PUBLIC_KEY_SIZE);
    memcpy(chat->moderation.self_secret_sig_key, get_sig_sk(&chat->self_secret_key), SIG_SECRET_KEY_SIZE);
    chat->moderation.shared_state_version = chat->shared_state.version;
    chat->moderation.log = chat->log;
    chat->moderation.mem = chat->mem;
}

non_null()
static bool create_new_chat_ext_keypair(GC_Chat *chat);

non_null()
static int create_new_group(GC_Session *c, const uint8_t *nick, size_t nick_length, bool founder,
                            const Group_Privacy_State privacy_state)
{
    if (nick == nullptr || nick_length == 0) {
        return -1;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -1;
    }

    const int group_number = get_new_group_index(c);

    if (group_number == -1) {
        return -1;
    }

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[group_number];

    chat->log = m->log;
    chat->mem = m->mem;
    chat->rng = m->rng;

    const uint64_t tm = mono_time_get(m->mono_time);

    chat->group_number = group_number;
    chat->numpeers = 0;
    chat->connection_state = CS_CONNECTING;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->last_ping_interval = tm;
    chat->friend_connection_id = -1;

    if (!create_new_chat_ext_keypair(chat)) {
        LOGGER_ERROR(chat->log, "Failed to create extended keypair");
        group_delete(c, chat);
        return -1;
    }

    init_gc_shared_state(chat, privacy_state);
    init_gc_moderation(chat);

    if (!init_gc_tcp_connection(c, chat)) {
        group_delete(c, chat);
        return -1;
    }

    if (peer_add(chat, nullptr, chat->self_public_key.enc) != 0) {    /* you are always peer_number/index 0 */
        group_delete(c, chat);
        return -1;
    }

    if (!self_gc_set_nick(chat, nick, (uint16_t)nick_length)) {
        group_delete(c, chat);
        return -1;
    }

    self_gc_set_status(chat, GS_NONE);
    self_gc_set_role(chat, founder ? GR_FOUNDER : GR_USER);
    self_gc_set_confirmed(chat, true);
    self_gc_set_ext_public_key(chat, &chat->self_public_key);

    return group_number;
}

/** @brief Inits the sanctions list credentials.
 *
 * This should be called by the group founder on creation.
 *
 * This function must be called after `init_gc_moderation()`.
 *
 * Return true on success.
 */
non_null()
static bool init_gc_sanctions_creds(GC_Chat *chat)
{
    return sanctions_list_make_creds(&chat->moderation);
}

/** @brief Attempts to add `num_addrs` peers from `addrs` to our peerlist and initiate invite requests
 * for all of them.
 *
 * Returns the number of peers successfully loaded.
 */
static size_t load_gc_peers(GC_Chat *chat, const GC_SavedPeerInfo *addrs, uint16_t num_addrs)
{
    size_t count = 0;

    for (size_t i = 0; i < num_addrs; ++i) {
        if (!saved_peer_is_valid(&addrs[i])) {
            continue;
        }

        const bool ip_port_is_set = ipport_isset(&addrs[i].ip_port);
        const IP_Port *ip_port = ip_port_is_set ? &addrs[i].ip_port : nullptr;

        const int peer_number = peer_add(chat, ip_port, addrs[i].public_key);

        GC_Connection *gconn = get_gc_connection(chat, peer_number);

        if (gconn == nullptr) {
            continue;
        }

        add_tcp_relay_global(chat->tcp_conn, &addrs[i].tcp_relay.ip_port, addrs[i].tcp_relay.public_key);

        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                   &addrs[i].tcp_relay.ip_port,
                                   addrs[i].tcp_relay.public_key);

        if (add_tcp_result == -1 && !ip_port_is_set) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
            continue;
        }

        if (add_tcp_result == 0) {
            const int save_tcp_result = gcc_save_tcp_relay(chat->rng, gconn, &addrs[i].tcp_relay);

            if (save_tcp_result == -1) {
                gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
                continue;
            }

            memcpy(gconn->oob_relay_pk, addrs[i].tcp_relay.public_key, CRYPTO_PUBLIC_KEY_SIZE);
        }

        const uint64_t tm = mono_time_get(chat->mono_time);

        gconn->is_oob_handshake = !gcc_direct_conn_is_possible(chat, gconn);
        gconn->is_pending_handshake_response = false;
        gconn->pending_handshake_type = HS_INVITE_REQUEST;
        gconn->last_received_packet_time = tm;
        gconn->last_key_rotation = tm;

        ++count;
    }

    update_gc_peer_roles(chat);

    return count;
}

void gc_group_save(const GC_Chat *chat, Bin_Pack *bp)
{
    gc_save_pack_group(chat, bp);
}

int gc_group_load(GC_Session *c, Bin_Unpack *bu)
{
    const int group_number = get_new_group_index(c);

    if (group_number < 0) {
        return -1;
    }

    const uint64_t tm = mono_time_get(c->messenger->mono_time);

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[group_number];

    chat->group_number = group_number;
    chat->numpeers = 0;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->log = m->log;
    chat->mem = m->mem;
    chat->rng = m->rng;
    chat->last_ping_interval = tm;
    chat->friend_connection_id = -1;

    // Initialise these first, because we may need to log/dealloc things on cleanup.
    chat->moderation.log = m->log;
    chat->moderation.mem = m->mem;

    if (!gc_load_unpack_group(chat, bu)) {
        LOGGER_ERROR(chat->log, "Failed to unpack group");
        return -1;
    }

    init_gc_moderation(chat);

    if (!init_gc_tcp_connection(c, chat)) {
        LOGGER_ERROR(chat->log, "Failed to init tcp connection");
        return -1;
    }

    if (chat->connection_state == CS_DISCONNECTED) {
        return group_number;
    }

    if (is_public_chat(chat)) {
        if (!m_create_group_connection(m, chat)) {
            LOGGER_ERROR(chat->log, "Failed to initialize group friend connection");
        }
    }

    return group_number;
}

int gc_group_add(GC_Session *c, Group_Privacy_State privacy_state,
                 const uint8_t *group_name, uint16_t group_name_length,
                 const uint8_t *nick, size_t nick_length)
{
    if (group_name_length > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -1;
    }

    if (group_name_length == 0 || group_name == nullptr) {
        return -2;
    }

    if (nick_length == 0 || nick == nullptr) {
        return -2;
    }

    const int group_number = create_new_group(c, nick, nick_length, true, privacy_state);

    if (group_number == -1) {
        return -3;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -3;
    }

    crypto_memlock(&chat->chat_secret_key, sizeof(chat->chat_secret_key));

    create_extended_keypair(&chat->chat_public_key, &chat->chat_secret_key, chat->rng);

    if (!init_gc_shared_state_founder(chat, privacy_state, group_name, group_name_length)) {
        group_delete(c, chat);
        return -4;
    }

    init_gc_moderation(chat);

    if (!init_gc_sanctions_creds(chat)) {
        group_delete(c, chat);
        return -4;
    }

    if (gc_set_topic(chat, nullptr, 0) != 0) {
        group_delete(c, chat);
        return -4;
    }

    chat->join_type = HJ_PRIVATE;
    chat->connection_state = CS_CONNECTED;
    chat->time_connected = mono_time_get(c->messenger->mono_time);

    if (is_public_chat(chat)) {
        if (!m_create_group_connection(c->messenger, chat)) {
            LOGGER_ERROR(chat->log, "Failed to initialize group friend connection");
            group_delete(c, chat);
            return -5;
        }

        chat->join_type = HJ_PUBLIC;
    }

    update_gc_peer_roles(chat);

    return group_number;
}

int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *nick, size_t nick_length, const uint8_t *passwd,
                  uint16_t passwd_len)
{
    if (chat_id == nullptr || group_exists(c, chat_id) || getfriend_id(c->messenger, chat_id) != -1) {
        return -2;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -3;
    }

    if (nick == nullptr || nick_length == 0) {
        return -4;
    }

    const int group_number = create_new_group(c, nick, nick_length, false, GI_PUBLIC);

    if (group_number == -1) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!expand_chat_id(&chat->chat_public_key, chat_id)) {
        group_delete(c, chat);
        return -1;
    }

    chat->connection_state = CS_CONNECTING;

    if (passwd != nullptr && passwd_len > 0) {
        if (!set_gc_password_local(chat, passwd, passwd_len)) {
            group_delete(c, chat);
            return -5;
        }
    }

    if (!m_create_group_connection(c->messenger, chat)) {
        group_delete(c, chat);
        return -6;
    }

    update_gc_peer_roles(chat);

    return group_number;
}

bool gc_disconnect_from_group(const GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr || chat == nullptr) {
        return false;
    }

    chat->connection_state = CS_DISCONNECTED;

    if (!send_gc_broadcast_message(chat, nullptr, 0, GM_PEER_EXIT)) {
        LOGGER_DEBUG(chat->log, "Failed to broadcast group exit packet");
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SELF_DISCONNECTED, nullptr, 0);
    }

    return true;
}

int gc_rejoin_group(GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr || chat == nullptr) {
        return -1;
    }

    chat->time_connected = 0;

    if (group_can_handle_packets(chat)) {
        send_gc_self_exit(chat, nullptr, 0);
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SELF_DISCONNECTED, nullptr, 0);
    }

    if (is_public_chat(chat)) {
        kill_group_friend_connection(c, chat);

        if (!m_create_group_connection(c->messenger, chat)) {
            LOGGER_WARNING(chat->log, "Failed to create new messenger connection for group");
            return -2;
        }

        chat->update_self_announces = true;
    }

    chat->connection_state = CS_CONNECTING;

    return 0;
}

bool group_not_added(const GC_Session *c, const uint8_t *chat_id, uint32_t length)
{
    if (length < CHAT_ID_SIZE) {
        return false;
    }

    return !group_exists(c, chat_id);
}

int gc_invite_friend(const GC_Session *c, GC_Chat *chat, int32_t friend_number,
                     gc_send_group_invite_packet_cb *callback)
{
    if (!friend_is_valid(c->messenger, friend_number)) {
        return -1;
    }

    const uint16_t group_name_length = chat->shared_state.group_name_len;

    assert(group_name_length <= MAX_GC_GROUP_NAME_SIZE);

    uint8_t *packet = (uint8_t *)malloc(2 + CHAT_ID_SIZE + ENC_PUBLIC_KEY_SIZE + group_name_length);

    if (packet == nullptr) {
        return -1;
    }

    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE;

    memcpy(packet + 2, get_chat_id(&chat->chat_public_key), CHAT_ID_SIZE);
    uint16_t length = 2 + CHAT_ID_SIZE;

    memcpy(packet + length, chat->self_public_key.enc, ENC_PUBLIC_KEY_SIZE);
    length += ENC_PUBLIC_KEY_SIZE;

    memcpy(packet + length, chat->shared_state.group_name, group_name_length);
    length += group_name_length;

    assert(length <= MAX_GC_PACKET_SIZE);

    if (!callback(c->messenger, friend_number, packet, length)) {
        free(packet);
        return -2;
    }

    free(packet);

    chat->saved_invites[chat->saved_invites_index] = friend_number;
    chat->saved_invites_index = (chat->saved_invites_index + 1) % MAX_GC_SAVED_INVITES;

    return 0;
}

/** @brief Sends an invite accepted packet to `friend_number`.
 *
 * Return 0 on success.
 * Return -1 if `friend_number` does not designate a valid friend.
 * Return -2 if `chat `is null.
 * Return -3 if packet failed to send.
 */
non_null()
static int send_gc_invite_accepted_packet(const Messenger *m, const GC_Chat *chat, uint32_t friend_number)
{
    if (!friend_is_valid(m, friend_number)) {
        return -1;
    }

    if (chat == nullptr) {
        return -2;
    }

    uint8_t packet[1 + 1 + CHAT_ID_SIZE + ENC_PUBLIC_KEY_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE_ACCEPTED;

    memcpy(packet + 2, get_chat_id(&chat->chat_public_key), CHAT_ID_SIZE);
    uint16_t length = 2 + CHAT_ID_SIZE;

    memcpy(packet + length, chat->self_public_key.enc, ENC_PUBLIC_KEY_SIZE);
    length += ENC_PUBLIC_KEY_SIZE;

    if (!send_group_invite_packet(m, friend_number, packet, length)) {
        LOGGER_ERROR(chat->log, "Failed to send group invite packet.");
        return -3;
    }

    return 0;
}

/** @brief Sends an invite confirmed packet to friend designated by `friend_number`.
 *
 * `data` must contain the group's Chat ID, the sender's public encryption key,
 * and either the sender's packed IP_Port, or at least one packed TCP node that
 * the sender can be connected to through (or both).
 *
 * Return true on success.
 */
non_null()
static bool send_gc_invite_confirmed_packet(const Messenger *m, const GC_Chat *chat, uint32_t friend_number,
        const uint8_t *data, uint16_t length)
{
    if (!friend_is_valid(m, friend_number)) {
        return false;
    }

    if (chat == nullptr) {
        return false;
    }

    if (length > MAX_GC_PACKET_SIZE) {
        return false;
    }

    const uint16_t packet_length = 2 + length;
    uint8_t *packet = (uint8_t *)malloc(packet_length);

    if (packet == nullptr) {
        return false;
    }

    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE_CONFIRMATION;

    memcpy(packet + 2, data, length);

    if (!send_group_invite_packet(m, friend_number, packet, packet_length)) {
        free(packet);
        return false;
    }

    free(packet);

    return true;
}

/** @brief Adds `num_nodes` tcp relays from `tcp_relays` to tcp relays list associated with `gconn`
 *
 * Returns the number of relays successfully added.
 */
non_null()
static uint32_t add_gc_tcp_relays(const GC_Chat *chat, GC_Connection *gconn, const Node_format *tcp_relays,
                                  size_t num_nodes)
{
    uint32_t relays_added = 0;

    for (size_t i = 0; i < num_nodes; ++i) {
        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn,
                                   gconn->tcp_connection_num, &tcp_relays[i].ip_port,
                                   tcp_relays[i].public_key);

        if (add_tcp_result == 0) {
            if (gcc_save_tcp_relay(chat->rng, gconn, &tcp_relays[i]) == 0) {
                ++relays_added;
            }
        }
    }

    return relays_added;
}

non_null()
static bool copy_friend_ip_port_to_gconn(const Messenger *m, int friend_number, GC_Connection *gconn)
{
    if (!friend_is_valid(m, friend_number)) {
        return false;
    }

    const Friend *f = &m->friendlist[friend_number];
    const int friend_connection_id = f->friendcon_id;
    const Friend_Conn *connection = get_conn(m->fr_c, friend_connection_id);

    if (connection == nullptr) {
        return false;
    }

    const IP_Port *friend_ip_port = friend_conn_get_dht_ip_port(connection);

    if (!ipport_isset(friend_ip_port)) {
        return false;
    }

    gconn->addr.ip_port = *friend_ip_port;

    return true;
}

int handle_gc_invite_confirmed_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint16_t length)
{
    if (length < GC_JOIN_DATA_LENGTH) {
        return -1;
    }

    if (!friend_is_valid(c->messenger, friend_number)) {
        return -4;
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t invite_chat_pk[ENC_PUBLIC_KEY_SIZE];

    memcpy(chat_id, data, CHAT_ID_SIZE);
    memcpy(invite_chat_pk, data + CHAT_ID_SIZE, ENC_PUBLIC_KEY_SIZE);

    const GC_Chat *chat = gc_get_group_by_public_key(c, chat_id);

    if (chat == nullptr) {
        return -2;
    }

    const int peer_number = get_peer_number_of_enc_pk(chat, invite_chat_pk, false);

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS,
                                       nullptr, data + ENC_PUBLIC_KEY_SIZE + CHAT_ID_SIZE,
                                       length - GC_JOIN_DATA_LENGTH, true);

    const bool copy_ip_port_result = copy_friend_ip_port_to_gconn(c->messenger, friend_number, gconn);

    uint32_t tcp_relays_added = 0;

    if (num_nodes > 0) {
        tcp_relays_added = add_gc_tcp_relays(chat, gconn, tcp_relays, num_nodes);
    } else {
        LOGGER_WARNING(chat->log, "Invite confirm packet did not contain any TCP relays");
    }

    if (tcp_relays_added == 0 && !copy_ip_port_result) {
        LOGGER_ERROR(chat->log, "Got invalid connection info from peer");
        return -5;
    }

    gconn->pending_handshake_type = HS_INVITE_REQUEST;

    return 0;
}

/** Return true if we have a pending sent invite for our friend designated by `friend_number`. */
non_null()
static bool friend_was_invited(const Messenger *m, GC_Chat *chat, int friend_number)
{
    for (size_t i = 0; i < MAX_GC_SAVED_INVITES; ++i) {
        if (chat->saved_invites[i] == friend_number) {
            chat->saved_invites[i] = -1;
            return friend_is_valid(m, friend_number);
        }
    }

    return false;
}

bool handle_gc_invite_accepted_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint16_t length)
{
    if (length < GC_JOIN_DATA_LENGTH) {
        return false;
    }

    const Messenger *m = c->messenger;

    const uint8_t *chat_id = data;

    GC_Chat *chat = gc_get_group_by_public_key(c, chat_id);

    if (chat == nullptr || !group_can_handle_packets(chat)) {
        return false;
    }

    const uint8_t *invite_chat_pk = data + CHAT_ID_SIZE;

    const int peer_number = peer_add(chat, nullptr, invite_chat_pk);

    if (!friend_was_invited(m, chat, friend_number)) {
        return false;
    }

    GC_Connection *gconn = get_gc_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const uint32_t num_tcp_relays = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS);

    const bool copy_ip_port_result = copy_friend_ip_port_to_gconn(m, friend_number, gconn);

    if (num_tcp_relays == 0 && !copy_ip_port_result) {
        return false;
    }

    uint16_t len = GC_JOIN_DATA_LENGTH;
    uint8_t out_data[GC_JOIN_DATA_LENGTH + (GCC_MAX_TCP_SHARED_RELAYS * PACKED_NODE_SIZE_IP6)];

    memcpy(out_data, chat_id, CHAT_ID_SIZE);
    memcpy(out_data + CHAT_ID_SIZE, chat->self_public_key.enc, ENC_PUBLIC_KEY_SIZE);

    if (num_tcp_relays > 0) {
        const uint32_t tcp_relays_added = add_gc_tcp_relays(chat, gconn, tcp_relays, num_tcp_relays);

        if (tcp_relays_added == 0 && !copy_ip_port_result) {
            LOGGER_ERROR(chat->log, "Got invalid connection info from peer");
            return false;
        }

        const int nodes_len = pack_nodes(chat->log, out_data + len, sizeof(out_data) - len, tcp_relays,
                                         (uint16_t)num_tcp_relays);

        if (nodes_len <= 0 && !copy_ip_port_result) {
            return false;
        }

        len += nodes_len;
    }

    return send_gc_invite_confirmed_packet(m, chat, friend_number, out_data, len);
}

int gc_accept_invite(GC_Session *c, int32_t friend_number, const uint8_t *data, uint16_t length, const uint8_t *nick,
                     size_t nick_length, const uint8_t *passwd, uint16_t passwd_len)
{
    if (length < CHAT_ID_SIZE + ENC_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -3;
    }

    if (nick == nullptr || nick_length == 0) {
        return -4;
    }

    if (!friend_is_valid(c->messenger, friend_number)) {
        return -6;
    }

    const uint8_t *chat_id = data;
    const uint8_t *invite_chat_pk = data + CHAT_ID_SIZE;

    const int group_number = create_new_group(c, nick, nick_length, false, GI_PUBLIC);

    if (group_number == -1) {
        return -2;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (!expand_chat_id(&chat->chat_public_key, chat_id)) {
        group_delete(c, chat);
        return -2;
    }

    if (passwd != nullptr && passwd_len > 0) {
        if (!set_gc_password_local(chat, passwd, passwd_len)) {
            group_delete(c, chat);
            return -5;
        }
    }

    const int peer_id = peer_add(chat, nullptr, invite_chat_pk);

    if (peer_id < 0) {
        return -2;
    }

    chat->join_type = HJ_PRIVATE;

    if (send_gc_invite_accepted_packet(c->messenger, chat, friend_number) != 0) {
        return -7;
    }

    return group_number;
}

non_null(1, 3) nullable(5)
static bool gc_handle_announce_response_callback(Onion_Client *onion_c, uint32_t sendback_num, const uint8_t *data,
        size_t data_length, void *user_data);

GC_Session *new_dht_groupchats(Messenger *m)
{
    if (m == nullptr) {
        return nullptr;
    }

    GC_Session *c = (GC_Session *)calloc(1, sizeof(GC_Session));

    if (c == nullptr) {
        return nullptr;
    }

    c->messenger = m;
    c->announces_list = m->group_announce;

    networking_registerhandler(m->net, NET_PACKET_GC_LOSSLESS, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_LOSSY, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_HANDSHAKE, &handle_gc_udp_packet, m);
    onion_group_announce_register(m->onion_c, gc_handle_announce_response_callback, c);

    return c;
}

static void group_cleanup(const GC_Session *c, GC_Chat *chat)
{
    kill_group_friend_connection(c, chat);

    mod_list_cleanup(&chat->moderation);
    sanctions_list_cleanup(&chat->moderation);

    if (chat->tcp_conn != nullptr) {
        kill_tcp_connections(chat->tcp_conn);
    }

    gcc_cleanup(chat);

    if (chat->group != nullptr) {
        free(chat->group);
        chat->group = nullptr;
    }

    crypto_memunlock(&chat->self_secret_key, sizeof(chat->self_secret_key));
    crypto_memunlock(&chat->chat_secret_key, sizeof(chat->chat_secret_key));
    crypto_memunlock(chat->shared_state.password, sizeof(chat->shared_state.password));
}

/** Deletes chat from group chat array and cleans up. */
static void group_delete(GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr || chat == nullptr) {
        if (chat != nullptr) {
            LOGGER_ERROR(chat->log, "Null pointer");
        }

        return;
    }

    group_cleanup(c, chat);

    c->chats[chat->group_number] = empty_gc_chat;

    uint32_t i;

    for (i = c->chats_index; i > 0; --i) {
        if (c->chats[i - 1].connection_state != CS_NONE) {
            break;
        }
    }

    if (c->chats_index != i) {
        c->chats_index = i;

        if (!realloc_groupchats(c, c->chats_index)) {
            LOGGER_ERROR(c->messenger->log, "Failed to reallocate groupchats array");
        }
    }
}

int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length)
{
    chat->flag_exit = true;
    return group_can_handle_packets(chat) ? send_gc_self_exit(chat, message, length) : 0;
}

non_null()
static int kill_group(GC_Session *c, GC_Chat *chat)
{
    const int ret = gc_group_exit(c, chat, nullptr, 0);
    group_delete(c, chat);
    return ret;
}

void kill_dht_groupchats(GC_Session *c)
{
    if (c == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < c->chats_index; ++i) {
        GC_Chat *chat = &c->chats[i];

        if (chat->connection_state == CS_NONE) {
            continue;
        }

        if (kill_group(c, chat) != 0) {
            LOGGER_WARNING(c->messenger->log, "Failed to send group exit packet");
        }
    }

    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSY, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSLESS, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_HANDSHAKE, nullptr, nullptr);
    onion_group_announce_register(c->messenger->onion_c, nullptr, nullptr);

    free(c->chats);
    free(c);
}

bool gc_group_is_valid(const GC_Chat *chat)
{
    return chat->connection_state != CS_NONE && chat->shared_state.version > 0;
}

/** Return true if `group_number` designates an active group in session `c`. */
static bool group_number_valid(const GC_Session *c, int group_number)
{
    if (group_number < 0 || group_number >= c->chats_index) {
        return false;
    }

    if (c->chats == nullptr) {
        return false;
    }

    return c->chats[group_number].connection_state != CS_NONE;
}

uint32_t gc_count_groups(const GC_Session *c)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < c->chats_index; ++i) {
        const GC_Chat *chat = &c->chats[i];

        if (gc_group_is_valid(chat)) {
            ++count;
        }
    }

    return count;
}

GC_Chat *gc_get_group(const GC_Session *c, int group_number)
{
    if (!group_number_valid(c, group_number)) {
        return nullptr;
    }

    return &c->chats[group_number];
}

GC_Chat *gc_get_group_by_public_key(const GC_Session *c, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < c->chats_index; ++i) {
        GC_Chat *chat = &c->chats[i];

        if (chat->connection_state == CS_NONE) {
            continue;
        }

        if (memcmp(public_key, get_chat_id(&chat->chat_public_key), CHAT_ID_SIZE) == 0) {
            return chat;
        }
    }

    return nullptr;
}

/** Return True if chat_id exists in the session chat array */
static bool group_exists(const GC_Session *c, const uint8_t *chat_id)
{
    for (uint32_t i = 0; i < c->chats_index; ++i) {
        const GC_Chat *chat = &c->chats[i];

        if (chat->connection_state == CS_NONE) {
            continue;
        }

        if (memcmp(get_chat_id(&chat->chat_public_key), chat_id, CHAT_ID_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

/** Creates a new 32-byte session encryption keypair and puts the results in `public_key` and `secret_key`. */
static void create_gc_session_keypair(const Logger *log, const Random *rng, uint8_t *public_key, uint8_t *secret_key)
{
    if (crypto_new_keypair(rng, public_key, secret_key) != 0) {
        LOGGER_FATAL(log, "Failed to create group session keypair");
    }
}

/**
 * Creates a new 64-byte extended keypair for `chat` and puts results in `self_public_key`
 * and `self_secret_key` buffers. The first 32-bytes of the generated keys are used for
 * encryption, while the remaining 32-bytes are used for signing.
 *
 * Return false if key generation fails.
 */
non_null()
static bool create_new_chat_ext_keypair(GC_Chat *chat)
{
    crypto_memlock(&chat->self_secret_key, sizeof(chat->self_secret_key));

    if (!create_extended_keypair(&chat->self_public_key, &chat->self_secret_key, chat->rng)) {
        crypto_memunlock(&chat->self_secret_key, sizeof(chat->self_secret_key));
        return false;
    }

    return true;
}

/** @brief Handles a group announce onion response.
 *
 * Return true on success.
 */
static bool gc_handle_announce_response_callback(Onion_Client *onion_c, uint32_t sendback_num, const uint8_t *data,
        size_t data_length, void *user_data)
{
    const GC_Session *c = (GC_Session *)user_data;

    if (c == nullptr) {
        return false;
    }

    if (sendback_num == 0) {
        return false;
    }

    GC_Announce announces[GCA_MAX_SENT_ANNOUNCES];
    const uint8_t *gc_public_key = onion_friend_get_gc_public_key_num(onion_c, sendback_num - 1);
    GC_Chat *chat = gc_get_group_by_public_key(c, gc_public_key);

    if (chat == nullptr) {
        return false;
    }

    const int gc_announces_count = gca_unpack_announces_list(chat->log, data, data_length,
                                   announces, GCA_MAX_SENT_ANNOUNCES);

    if (gc_announces_count == -1) {
        return false;
    }

    const int added_peers = gc_add_peers_from_announces(chat, announces, gc_announces_count);

    return added_peers >= 0;
}

/** @brief Adds TCP relays from `announce` to the TCP relays list for `gconn`.
 *
 * Returns the number of relays successfully added.
 */
non_null()
static uint32_t add_gc_tcp_relays_from_announce(const GC_Chat *chat, GC_Connection *gconn, const GC_Announce *announce)
{
    uint32_t added_relays = 0;

    for (uint8_t j = 0; j < announce->tcp_relays_count; ++j) {
        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                   &announce->tcp_relays[j].ip_port,
                                   announce->tcp_relays[j].public_key);

        if (add_tcp_result == -1) {
            continue;
        }

        if (gcc_save_tcp_relay(chat->rng, gconn, &announce->tcp_relays[j]) == -1) {
            continue;
        }

        if (added_relays == 0) {
            memcpy(gconn->oob_relay_pk, announce->tcp_relays[j].public_key, CRYPTO_PUBLIC_KEY_SIZE);
        }

        ++added_relays;
    }

    return added_relays;
}

int gc_add_peers_from_announces(GC_Chat *chat, const GC_Announce *announces, uint8_t gc_announces_count)
{
    if (chat == nullptr || announces == nullptr) {
        return -1;
    }

    if (!is_public_chat(chat)) {
        return 0;
    }

    int added_peers = 0;

    for (uint8_t i = 0; i < gc_announces_count; ++i) {
        const GC_Announce *announce = &announces[i];

        if (!gca_is_valid_announce(announce)) {
            continue;
        }

        const bool ip_port_set = announce->ip_port_is_set;
        const IP_Port *ip_port = ip_port_set ? &announce->ip_port : nullptr;
        const int peer_number = peer_add(chat, ip_port, announce->peer_public_key);

        GC_Connection *gconn = get_gc_connection(chat, peer_number);

        if (gconn == nullptr) {
            continue;
        }

        const uint32_t added_tcp_relays = add_gc_tcp_relays_from_announce(chat, gconn, announce);

        if (!ip_port_set && added_tcp_relays == 0) {
            LOGGER_ERROR(chat->log, "Got invalid announcement: %u relays, IPP set: %d",
                         added_tcp_relays, ip_port_set);
            continue;
        }

        gconn->pending_handshake_type = HS_INVITE_REQUEST;

        if (!ip_port_set) {
            gconn->is_oob_handshake = true;
        }

        ++added_peers;
    }

    return added_peers;
}
