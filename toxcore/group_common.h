/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2022 The TokTok team.
 */

/**
 * Common groupchat data structures.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_COMMON_H
#define C_TOXCORE_TOXCORE_GROUP_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h"
#include "TCP_connection.h"
#include "attributes.h"
#include "crypto_core.h"
#include "group_moderation.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"

#define MAX_GC_PART_MESSAGE_SIZE 128
#define MAX_GC_NICK_SIZE 128
#define MAX_GC_TOPIC_SIZE 512
#define MAX_GC_GROUP_NAME_SIZE 48
#define GC_MESSAGE_PSEUDO_ID_SIZE 4
#define GROUP_MAX_MESSAGE_LENGTH  1372

/* Max size of a packet chunk. Packets larger than this must be split up.
 *
 * For an explanation on why this value was chosen, see the following link: https://archive.ph/vsCOG
 */
#define MAX_GC_PACKET_CHUNK_SIZE 500
/* Max size of an incoming packet chunk that is allowed */
#define MAX_GC_PACKET_INCOMING_CHUNK_SIZE 1372

#define MAX_GC_MESSAGE_SIZE GROUP_MAX_MESSAGE_LENGTH
#define MAX_GC_MESSAGE_RAW_SIZE (MAX_GC_MESSAGE_SIZE + GC_MESSAGE_PSEUDO_ID_SIZE)
#define MAX_GC_CUSTOM_LOSSLESS_PACKET_SIZE 1373
#define MAX_GC_CUSTOM_LOSSY_PACKET_SIZE 1373
#define MAX_GC_PASSWORD_SIZE 32
#define MAX_GC_SAVED_INVITES 10
#define MAX_GC_PEERS_DEFAULT 100
#define MAX_GC_SAVED_TIMEOUTS 12
#define GC_MAX_SAVED_PEERS 100
#define GC_SAVED_PEER_SIZE (ENC_PUBLIC_KEY_SIZE + sizeof(Node_format) + sizeof(IP_Port))

/* Max size of a complete encrypted packet including headers. */
#define MAX_GC_PACKET_SIZE (MAX_GC_PACKET_CHUNK_SIZE * 100)

/* Max number of messages to store in the send/recv arrays */
#define GCC_BUFFER_SIZE 8192

/** Self UDP status. Must correspond to return values from `ipport_self_copy()`. */
typedef enum Self_UDP_Status {
    SELF_UDP_STATUS_NONE = 0x00,
    SELF_UDP_STATUS_WAN  = 0x01,
    SELF_UDP_STATUS_LAN  = 0x02,
} Self_UDP_Status;

/** Group exit types. */
typedef enum Group_Exit_Type {
    GC_EXIT_TYPE_QUIT              = 0x00,  // Peer left the group
    GC_EXIT_TYPE_TIMEOUT           = 0x01,  // Peer connection timed out
    GC_EXIT_TYPE_DISCONNECTED      = 0x02,  // Peer diconnected from group
    GC_EXIT_TYPE_SELF_DISCONNECTED = 0x03,  // Self disconnected from group
    GC_EXIT_TYPE_KICKED            = 0x04,  // Peer was kicked from the group
    GC_EXIT_TYPE_SYNC_ERR          = 0x05,  // Peer failed to sync with the group
    GC_EXIT_TYPE_NO_CALLBACK       = 0x06,  // The peer exit callback should not be triggered
} Group_Exit_Type;

typedef struct GC_Exit_Info {
    uint8_t  part_message[MAX_GC_PART_MESSAGE_SIZE];
    uint16_t length;
    Group_Exit_Type exit_type;
} GC_Exit_Info;

typedef struct GC_PeerAddress {
    Extended_Public_Key public_key;
    IP_Port     ip_port;
} GC_PeerAddress;

typedef struct GC_Message_Array_Entry {
    uint8_t *data;
    uint16_t data_length;
    uint8_t  packet_type;
    uint64_t message_id;
    uint64_t time_added;
    uint64_t last_send_try;
} GC_Message_Array_Entry;

typedef struct GC_Connection {
    uint64_t send_message_id;   /* message_id of the next message we send to peer */

    uint16_t send_array_start;   /* send_array index of oldest item */
    GC_Message_Array_Entry *send_array;

    uint64_t received_message_id;   /* message_id of peer's last message to us */
    GC_Message_Array_Entry *recv_array;

    uint64_t    last_chunk_id;  /* The message ID of the last packet fragment we received */

    GC_PeerAddress   addr;   /* holds peer's extended real public key and ip_port */
    uint32_t    public_key_hash;   /* Jenkins one at a time hash of peer's real encryption public key */

    uint8_t     session_public_key[ENC_PUBLIC_KEY_SIZE];   /* self session public key for this peer */
    uint8_t     session_secret_key[ENC_SECRET_KEY_SIZE];   /* self session secret key for this peer */
    uint8_t     session_shared_key[CRYPTO_SHARED_KEY_SIZE];  /* made with our session sk and peer's session pk */

    int         tcp_connection_num;
    uint64_t    last_sent_tcp_relays_time;  /* the last time we attempted to send this peer our tcp relays */
    uint16_t    tcp_relay_share_index;
    uint64_t    last_received_direct_time;   /* the last time we received a direct UDP packet from this connection */
    uint64_t    last_sent_ip_time;  /* the last time we sent our ip info to this peer in a ping packet */

    Node_format connected_tcp_relays[MAX_FRIEND_TCP_CONNECTIONS];
    uint16_t    tcp_relays_count;

    uint64_t    last_received_packet_time;  /* The last time we successfully processed any packet from this peer */
    uint64_t    last_requested_packet_time;  /* The last time we requested a missing packet from this peer */
    uint64_t    last_sent_ping_time;
    uint64_t    last_sync_response;  /* the last time we sent this peer a sync response */
    uint8_t     oob_relay_pk[CRYPTO_PUBLIC_KEY_SIZE];
    bool        self_is_closer; /* true if we're "closer" to the chat_id than this peer (uses real pk's) */

    bool        confirmed;  /* true if this peer has given us their info */
    bool        handshaked;  /* true if we've successfully handshaked with this peer */
    uint16_t    handshake_attempts;
    uint64_t    last_handshake_request;
    uint64_t    last_handshake_response;
    uint8_t     pending_handshake_type;
    bool        is_pending_handshake_response;
    bool        is_oob_handshake;

    uint64_t    last_key_rotation;  /* the last time we rotated session keys for this peer */
    bool        pending_key_rotation_request;

    bool        pending_delete;  /* true if this peer has been marked for deletion */
    bool        delete_this_iteration;  /* true if this peer should be deleted this do_gc() iteration*/
    GC_Exit_Info exit_info;
} GC_Connection;

/***
 * Group roles. Roles are hierarchical in that each role has a set of privileges plus
 * all the privileges of the roles below it.
 */
typedef enum Group_Role {
    /** Group creator. All-powerful. Cannot be demoted or kicked. */
    GR_FOUNDER   = 0x00,

    /**
     * May promote or demote peers below them to any role below them.
     * May also kick peers below them and set the topic.
     */
    GR_MODERATOR = 0x01,

    /** may interact normally with the group. */
    GR_USER      = 0x02,

    /** May not interact with the group but may observe. */
    GR_OBSERVER  = 0x03,
} Group_Role;

typedef enum Group_Peer_Status {
    GS_NONE    = 0x00,
    GS_AWAY    = 0x01,
    GS_BUSY    = 0x02,
} Group_Peer_Status;

/**
 * Group voice states. The state determines which Group Roles have permission to speak.
 */
typedef enum Group_Voice_State {
    /** Every group role except Observers may speak. */
    GV_ALL       = 0x00,

    /** Only Moderators and the Founder may speak. */
    GV_MODS      = 0x01,

    /** Only the Founder may speak. */
    GV_FOUNDER   = 0x02,
} Group_Voice_State;

/** Group connection states. */
typedef enum GC_Conn_State {
    CS_NONE         = 0x00,  // Indicates a group is not initialized
    CS_DISCONNECTED = 0x01,  // Not receiving or sending any packets
    CS_CONNECTING   = 0x02,  // Attempting to establish a connection with peers in the group
    CS_CONNECTED    = 0x03,  // Has successfully received a sync response from a peer in the group
} GC_Conn_State;

/** Group privacy states. */
typedef enum Group_Privacy_State {
    GI_PUBLIC   = 0x00,  // Anyone with the chat ID may join the group
    GI_PRIVATE  = 0x01,  // Peers may only join the group via a friend invite
} Group_Privacy_State;

/** Handshake join types. */
typedef enum Group_Handshake_Join_Type {
    HJ_PUBLIC = 0x00,   // Indicates the group was joined via the DHT
    HJ_PRIVATE = 0x01,  // Indicates the group was joined via private friend invite
} Group_Handshake_Join_Type;

typedef struct GC_SavedPeerInfo {
    uint8_t     public_key[ENC_PUBLIC_KEY_SIZE];
    Node_format tcp_relay;
    IP_Port     ip_port;
} GC_SavedPeerInfo;

/** Holds info about peers who recently timed out */
typedef struct GC_TimedOutPeer {
    GC_SavedPeerInfo addr;
    uint64_t    last_seen;  // the time the peer disconnected
    uint64_t    last_reconn_try;  // the last time we tried to establish a new connection
} GC_TimedOutPeer;

typedef bitwise uint32_t GC_Peer_Id_Value;

typedef struct GC_Peer_Id {
    GC_Peer_Id_Value value;
} GC_Peer_Id;

GC_Peer_Id gc_peer_id_from_int(uint32_t value);
uint32_t gc_peer_id_to_int(GC_Peer_Id peer_id);

typedef struct GC_Peer {
    /* Below state is sent to other peers in peer info exchange */
    uint8_t       nick[MAX_GC_NICK_SIZE];
    uint16_t      nick_length;
    uint8_t       status;

    /* Below state is local only */
    Group_Role    role;
    GC_Peer_Id    peer_id;    // permanent ID (used for the public API)
    bool          ignore;

    GC_Connection gconn;
} GC_Peer;

typedef struct GC_SharedState {
    uint32_t    version;
    Extended_Public_Key founder_public_key;
    uint16_t    maxpeers;
    uint16_t    group_name_len;
    uint8_t     group_name[MAX_GC_GROUP_NAME_SIZE];
    Group_Privacy_State privacy_state;   // GI_PUBLIC (uses DHT) or GI_PRIVATE (invite only)
    uint16_t    password_length;
    uint8_t     password[MAX_GC_PASSWORD_SIZE];
    uint8_t     mod_list_hash[MOD_MODERATION_HASH_SIZE];
    uint32_t    topic_lock; // equal to GC_TOPIC_LOCK_ENABLED when lock is enabled
    Group_Voice_State voice_state;
} GC_SharedState;

typedef struct GC_TopicInfo {
    uint32_t    version;
    uint16_t    length;
    uint16_t    checksum;  // used for syncing problems. the checksum with the highest value gets priority.
    uint8_t     topic[MAX_GC_TOPIC_SIZE];
    uint8_t     public_sig_key[SIG_PUBLIC_KEY_SIZE];  // Public signature key of the topic setter
} GC_TopicInfo;

typedef struct GC_Chat {
    Mono_Time       *mono_time;
    const Logger    *log;
    const Memory    *mem;
    const Random    *rng;

    uint32_t        connected_tcp_relays;
    Self_UDP_Status self_udp_status;
    IP_Port         self_ip_port;

    Networking_Core *net;
    TCP_Connections *tcp_conn;

    uint64_t        last_checked_tcp_relays;
    Group_Handshake_Join_Type join_type;

    GC_Peer         *group;
    Moderation      moderation;

    GC_Conn_State   connection_state;

    GC_SharedState  shared_state;
    uint8_t         shared_state_sig[SIGNATURE_SIZE];  // signed by founder using the chat secret key

    GC_TopicInfo    topic_info;
    uint8_t         topic_sig[SIGNATURE_SIZE];  // signed by the peer who set the current topic
    uint16_t        topic_prev_checksum;  // checksum of the previous topic
    uint64_t        topic_time_set;

    uint16_t    peers_checksum;  // sum of the public key hash of every confirmed peer in the group
    uint16_t    roles_checksum;  // sum of every confirmed peer's role plus the first byte of their public key

    uint32_t    numpeers;
    int         group_number;

    Extended_Public_Key chat_public_key;  // the chat_id is the sig portion
    Extended_Secret_Key chat_secret_key;  // only used by the founder

    Extended_Public_Key self_public_key;
    Extended_Secret_Key self_secret_key;

    uint64_t    time_connected;
    uint64_t    last_ping_interval;
    uint64_t    last_sync_request;  // The last time we sent a sync request to any peer
    uint64_t    last_sync_response_peer_list;  // The last time we sent the peer list to any peer
    uint64_t    last_time_peers_loaded;

    /* keeps track of frequency of new inbound connections */
    uint8_t     connection_o_metre;
    uint64_t    connection_cooldown_timer;
    bool        block_handshakes;

    int32_t     saved_invites[MAX_GC_SAVED_INVITES];
    uint8_t     saved_invites_index;

    /** A list of recently seen peers in case we disconnect from a private group.
     * Peers are added once they're confirmed, and only if there are vacant
     * spots (older connections get priority). An entry is removed only when the list
     * is full, its respective peer goes offline, and an online peer who isn't yet
     * present in the list can be added.
     */
    GC_SavedPeerInfo saved_peers[GC_MAX_SAVED_PEERS];

    GC_TimedOutPeer timeout_list[MAX_GC_SAVED_TIMEOUTS];
    size_t      timeout_list_index;
    uint64_t    last_timed_out_reconn_try;  // the last time we tried to reconnect to timed out peers

    bool        update_self_announces;  // true if we should try to update our announcements
    uint64_t    last_self_announce_check;  // the last time we checked if we should update our announcements
    uint64_t    last_time_self_announce;  // the last time we announced the group
    uint8_t     announced_tcp_relay_pk[CRYPTO_PUBLIC_KEY_SIZE];  // The pk of the last TCP relay we announced

    uint8_t     m_group_public_key[CRYPTO_PUBLIC_KEY_SIZE];  // public key for group's messenger friend connection
    int         friend_connection_id;  // identifier for group's messenger friend connection

    bool        flag_exit;  // true if the group will be deleted after the next do_gc() iteration
} GC_Chat;

#ifndef MESSENGER_DEFINED
#define MESSENGER_DEFINED
typedef struct Messenger Messenger;
#endif /* MESSENGER_DEFINED */

typedef void gc_message_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, unsigned int type,
                           const uint8_t *message, size_t length, uint32_t message_id, void *user_data);
typedef void gc_private_message_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, unsigned int type,
                                   const uint8_t *message, size_t length, uint32_t message_id, void *user_data);
typedef void gc_custom_packet_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, const uint8_t *data,
                                 size_t length, void *user_data);
typedef void gc_custom_private_packet_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id,
        const uint8_t *data, size_t length, void *user_data);
typedef void gc_moderation_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id source_peer_number,
                              GC_Peer_Id target_peer_number, unsigned int mod_type, void *user_data);
typedef void gc_nick_change_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, const uint8_t *name,
                               size_t length, void *user_data);
typedef void gc_status_change_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, unsigned int status,
                                 void *user_data);
typedef void gc_topic_change_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, const uint8_t *topic,
                                size_t length, void *user_data);
typedef void gc_topic_lock_cb(const Messenger *m, uint32_t group_number, unsigned int topic_lock, void *user_data);
typedef void gc_voice_state_cb(const Messenger *m, uint32_t group_number, unsigned int voice_state, void *user_data);
typedef void gc_peer_limit_cb(const Messenger *m, uint32_t group_number, uint32_t peer_limit, void *user_data);
typedef void gc_privacy_state_cb(const Messenger *m, uint32_t group_number, unsigned int privacy_state, void *user_data);
typedef void gc_password_cb(const Messenger *m, uint32_t group_number, const uint8_t *password, size_t length,
                            void *user_data);
typedef void gc_peer_join_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, void *user_data);
typedef void gc_peer_exit_cb(const Messenger *m, uint32_t group_number, GC_Peer_Id peer_id, unsigned int exit_type,
                             const uint8_t *name, size_t name_length, const uint8_t *part_message, size_t length,
                             void *user_data);
typedef void gc_self_join_cb(const Messenger *m, uint32_t group_number, void *user_data);
typedef void gc_rejected_cb(const Messenger *m, uint32_t group_number, unsigned int fail_type, void *user_data);

typedef struct GC_Session {
    Messenger                 *messenger;
    GC_Chat                   *chats;
    struct GC_Announces_List  *announces_list;

    uint32_t     chats_index;

    gc_message_cb *message;
    gc_private_message_cb *private_message;
    gc_custom_packet_cb *custom_packet;
    gc_custom_private_packet_cb *custom_private_packet;
    gc_moderation_cb *moderation;
    gc_nick_change_cb *nick_change;
    gc_status_change_cb *status_change;
    gc_topic_change_cb *topic_change;
    gc_topic_lock_cb *topic_lock;
    gc_voice_state_cb *voice_state;
    gc_peer_limit_cb *peer_limit;
    gc_privacy_state_cb *privacy_state;
    gc_password_cb *password;
    gc_peer_join_cb *peer_join;
    gc_peer_exit_cb *peer_exit;
    gc_self_join_cb *self_join;
    gc_rejected_cb *rejected;
} GC_Session;

/** @brief Adds a new peer to group_number's peer list.
 *
 * Return peer_number on success.
 * Return -1 on failure.
 * Return -2 if a peer with public_key is already in our peerlist.
 */
non_null(1, 3) nullable(2)
int peer_add(GC_Chat *chat, const IP_Port *ipp, const uint8_t *public_key);

/** @brief Unpacks saved peers from `data` of size `length` into `chat`.
 *
 * Returns the number of unpacked peers on success.
 * Returns -1 on failure.
 */
non_null()
int unpack_gc_saved_peers(GC_Chat *chat, const uint8_t *data, uint16_t length);

/** @brief Packs all valid entries from saved peerlist into `data`.
 *
 * If `processed` is non-null it will be set to the length of the packed data
 * on success, and will be untouched on error.
 *
 * Return the number of packed saved peers on success.
 * Return -1 if buffer is too small.
 */
non_null(1, 2) nullable(4)
int pack_gc_saved_peers(const GC_Chat *chat, uint8_t *data, uint16_t length, uint16_t *processed);

#endif /* C_TOXCORE_TOXCORE_GROUP_COMMON_H */
