/* group_chats.h
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

#ifndef GROUP_CHATS_H
#define GROUP_CHATS_H

#include <stdbool.h>
#include "TCP_connection.h"

typedef struct Messenger Messenger;

#define TIME_STAMP_SIZE (sizeof(uint64_t))
#define HASH_ID_BYTES (sizeof(uint32_t))

#define MAX_GC_NICK_SIZE 128
#define MAX_GC_TOPIC_SIZE 512
#define MAX_GC_GROUP_NAME_SIZE 48
#define MAX_GC_MESSAGE_SIZE 1368
#define MAX_GC_PART_MESSAGE_SIZE 128
#define MAX_GC_PEER_ADDRS 30
#define MAX_GC_PASSWD_SIZE 32
#define MAX_GC_MODERATORS 128

#define GC_MOD_LIST_ENTRY_SIZE SIG_PUBLIC_KEY
#define GC_MODERATION_HASH_SIZE crypto_hash_sha256_BYTES
#define GC_PING_INTERVAL 10
#define GC_CONFIRMED_PEER_TIMEOUT (GC_PING_INTERVAL * 4 + 10)
#define GC_UNCONFRIMED_PEER_TIMEOUT GC_PING_INTERVAL

enum {
    GI_PUBLIC,
    GI_PRIVATE,
    GI_INVALID
} GROUP_PRIVACY_STATE;

enum {
    MV_KICK,
    MV_BAN,
    MV_OBSERVER,
    MV_USER,
    MV_MODERATOR,
    MV_INVALID
} GROUP_MODERATION_EVENT;

/* Group roles are hierarchical where each role has a set of privileges plus
 * all the privileges of the roles below it.
 *
 * - FOUNDER is all-powerful. Cannot be demoted or banned.
 * - OP may issue bans, promotions and demotions to all roles below founder.
 * - USER may talk, stream A/V, and change the group topic.
 * - OBSERVER cannot interact with the group but may observe.
 */
enum {
    GR_FOUNDER,
    GR_MODERATOR,
    GR_USER,
    GR_OBSERVER,
    GR_INVALID
} GROUP_ROLE;

enum {
    GS_NONE,
    GS_AWAY,
    GS_BUSY,
    GS_INVALID
} GROUP_STATUS;

enum {
    CS_NONE,
    CS_FAILED,
    CS_DISCONNECTED,
    CS_CONNECTING,
    CS_CONNECTED,
    CS_INVALID
} GROUP_CONNECTION_STATE;

enum {
    GJ_NICK_TAKEN,
    GJ_GROUP_FULL,
    GJ_INVALID_PASSWORD,
    GJ_INVITE_FAILED,
    GJ_INVALID
} GROUP_JOIN_REJECTED;

enum {
    GM_STATUS,
    GM_CHANGE_NICK,
    GM_CHANGE_TOPIC,
    GM_PLAIN_MESSAGE,
    GM_ACTION_MESSAGE,
    GM_PRVT_MESSAGE,
    GM_PEER_EXIT,
    GM_REMOVE_PEER,
    GM_REMOVE_BAN,
    GM_SET_MOD,
    GM_SET_OBSERVER
} GROUP_BROADCAST_TYPE;

enum {
    /* lossy packets (ID 0 is reserved) */
    GP_PING = 1,
    GP_MESSAGE_ACK = 2,
    GP_INVITE_RESPONSE_REJECT = 3,
    GP_TCP_RELAYS = 4,

    /* lossless packets */
    GP_BROADCAST = 20,
    GP_PEER_INFO_REQUEST = 21,
    GP_PEER_INFO_RESPONSE = 22,
    GP_INVITE_REQUEST = 23,
    GP_INVITE_RESPONSE = 24,
    GP_SYNC_REQUEST = 25,
    GP_SYNC_RESPONSE = 26,
    GP_SHARED_STATE = 27,
    GP_MOD_LIST = 28,
    GP_SANCTIONS_LIST = 29,
    GP_FRIEND_INVITE = 30,
    GP_HS_RESPONSE_ACK = 31,
} GROUP_PACKET_TYPE;

enum {
    HJ_PUBLIC,
    HJ_PRIVATE
} GROUP_HANDSHAKE_JOIN_TYPE;

struct GC_Sanction_Creds {
    uint32_t    version;
    uint8_t     hash[GC_MODERATION_HASH_SIZE];    /* hash of all sanctions list signatures + version */
    uint8_t     sig_pk[SIG_PUBLIC_KEY];    /* Last mod to have modified the sanctions list*/
    uint8_t     sig[SIGNATURE_SIZE];    /* signature of hash, signed by sig_pk */
};

typedef struct GC_Moderation {
    struct GC_Sanction *sanctions;
    struct GC_Sanction_Creds sanctions_creds;
    uint16_t    num_sanctions;

    uint8_t     **mod_list;    /* Array of public signature keys of all the mods */
    uint16_t    num_mods;
} GC_Moderation;

typedef struct GC_PeerAddress {
    uint8_t     public_key[EXT_PUBLIC_KEY];
    IP_Port     ip_port;
} GC_PeerAddress;

typedef struct {
    uint8_t     role;
    uint8_t     nick[MAX_GC_NICK_SIZE];
    uint16_t    nick_len;
    uint8_t     status;
} GC_GroupPeer;

typedef struct {
    uint8_t     founder_public_key[EXT_PUBLIC_KEY];
    uint32_t    maxpeers;
    uint16_t    group_name_len;
    uint8_t     group_name[MAX_GC_GROUP_NAME_SIZE];
    uint8_t     privacy_state;   /* GI_PUBLIC (uses DHT) or GI_PRIVATE (invite only) */
    uint16_t    passwd_len;
    uint8_t     passwd[MAX_GC_PASSWD_SIZE];
    uint8_t     mod_list_hash[GC_MODERATION_HASH_SIZE];
    uint32_t    version;
} GC_SharedState;

typedef struct GC_Announce GC_Announce;
typedef struct GC_Connection GC_Connection;

typedef struct GC_Chat {
    Networking_Core *net;
    TCP_Connections *tcp_conn;

    GC_GroupPeer    *group;
    GC_Connection   *gcc;
    GC_Moderation   moderation;
    GC_SharedState  shared_state;
    uint8_t     shared_state_sig[SIGNATURE_SIZE];    /* Signed by founder using the chat secret key */

    uint32_t    numpeers;
    int         groupnumber;

    uint8_t     chat_public_key[EXT_PUBLIC_KEY];    /* the chat_id is the sig portion */
    uint8_t     chat_secret_key[EXT_SECRET_KEY];    /* only used by the founder */
    uint32_t    chat_id_hash;    /* 32-bit hash of the chat_id */

    uint8_t     self_public_key[EXT_PUBLIC_KEY];
    uint8_t     self_secret_key[EXT_SECRET_KEY];
    uint32_t    self_public_key_hash;

    uint8_t     topic[MAX_GC_TOPIC_SIZE];
    uint16_t    topic_len;

    uint8_t     connection_state;
    uint64_t    last_join_attempt;
    uint8_t     get_nodes_attempts;
    uint64_t    last_get_nodes_attempt;
    uint64_t    last_sent_ping_time;
    uint64_t    announce_search_timer;
    uint8_t     join_type;   /* How we joined the group */

    /* keeps track of frequency of new inbound connections */
    uint8_t     connection_O_metre;
    uint64_t    connection_cooldown_timer;
    bool        block_handshakes;

    /* Holder for IP/keys received from announcement requests and loaded from saved groups */
    GC_PeerAddress addr_list[MAX_GC_PEER_ADDRS];
    uint16_t    num_addrs;
    uint16_t    addrs_idx;
} GC_Chat;

typedef struct GC_Session {
    Messenger *messenger;
    GC_Chat *chats;
    GC_Announce *announce;

    uint32_t num_chats;

    void (*message)(Messenger *m, uint32_t, uint32_t, unsigned int, const uint8_t *, size_t, void *);
    void *message_userdata;
    void (*private_message)(Messenger *m, uint32_t, uint32_t, const uint8_t *, size_t, void *);
    void *private_message_userdata;
    void (*moderation)(Messenger *m, uint32_t, uint32_t, uint32_t, unsigned int, void *);
    void *moderation_userdata;
    void (*nick_change)(Messenger *m, uint32_t, uint32_t, const uint8_t *, size_t, void *);
    void *nick_change_userdata;
    void (*status_change)(Messenger *m, uint32_t, uint32_t, unsigned int, void *);
    void *status_change_userdata;
    void (*topic_change)(Messenger *m, uint32_t, uint32_t, const uint8_t *,  size_t, void *);
    void *topic_change_userdata;
    void (*peer_join)(Messenger *m, uint32_t, uint32_t, void *);
    void *peer_join_userdata;
    void (*peer_exit)(Messenger *m, uint32_t, uint32_t, const uint8_t *, size_t, void *);
    void *peer_exit_userdata;
    void (*self_join)(Messenger *m, uint32_t, void *);
    void *self_join_userdata;
    void (*peerlist_update)(Messenger *m, uint32_t, void *);
    void *peerlist_update_userdata;
    void (*rejected)(Messenger *m, uint32_t, unsigned int, void *);
    void *rejected_userdata;
} GC_Session;

#define GROUP_SAVE_MAX_PEERS MAX_GC_PEER_ADDRS

struct SAVED_GROUP {
    /* Group shared state */
    uint8_t   founder_public_key[ENC_PUBLIC_KEY];
    uint16_t  maxpeers;
    uint16_t  group_name_len;
    uint8_t   group_name[MAX_GC_GROUP_NAME_SIZE];
    uint8_t   privacy_state;
    uint16_t  passwd_len;
    uint8_t   passwd[MAX_GC_PASSWD_SIZE];
    uint8_t   mod_list_hash[GC_MODERATION_HASH_SIZE];
    uint32_t  sstate_version;
    uint8_t   sstate_signature[SIGNATURE_SIZE];

    /* Other group info */
    uint8_t   chat_public_key[EXT_PUBLIC_KEY];
    uint8_t   chat_secret_key[EXT_SECRET_KEY];
    uint16_t  topic_len;
    uint8_t   topic[MAX_GC_TOPIC_SIZE];
    uint16_t  num_addrs;
    GC_PeerAddress addrs[GROUP_SAVE_MAX_PEERS];
    uint16_t  num_mods;
    uint8_t   mod_list[GC_MOD_LIST_ENTRY_SIZE * MAX_GC_MODERATORS];

    /* self info */
    uint8_t   self_public_key[EXT_PUBLIC_KEY];
    uint8_t   self_secret_key[EXT_SECRET_KEY];
    uint8_t   self_nick[MAX_GC_NICK_SIZE];
    uint16_t  self_nick_len;
    uint8_t   self_role;
    uint8_t   self_status;
};

/* Sends a plain message or an action, depending on type.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the sender has the observer role.
 * Returns -4 if the packet fails to send.
 */
int gc_send_message(GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type);

/* Sends a private message to peernumber.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the peernumber is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_private_message(GC_Chat *chat, uint32_t peernumber, const uint8_t *message, uint16_t length);

/* Toggles ignore for peernumber.
 *
 * Returns 0 on success.
 * Returns -1 if the peernumber is invalid.
 */
int gc_toggle_ignore(GC_Chat *chat, uint32_t peernumber, bool ignore);

/* Sets the group topic.
 *
 * Returns -1 if the topic is too long.
 * Returns -2 if the caller has the observer role.
 * Returns -3 if the packet fails to send.
 */
int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length);

 /* Copies topic to topicbuffer. */
void gc_get_topic(const GC_Chat *chat, uint8_t *topicbuffer);

 /* Returns topic length. */
uint16_t gc_get_topic_size(const GC_Chat *chat);

/* Copies group name to groupname. */
void gc_get_group_name(const GC_Chat *chat, uint8_t *groupname);

/* Returns group name length */
uint16_t gc_get_group_name_size(const GC_Chat *chat);

/* Returns group privacy state */
uint8_t gc_get_privacy_state(const GC_Chat *chat);

/* Returns the group peer limit. */
uint32_t gc_get_max_peers(const GC_Chat *chat);

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
int gc_set_self_nick(Messenger *m, int groupnumber, const uint8_t *nick, uint16_t length);

/* Copies your own nick to nick and returns nick length */
uint16_t gc_get_self_nick(const GC_Chat *chat, uint8_t *nick);

/* Return your own nick length */
uint16_t gc_get_self_nick_size(const GC_Chat *chat);

/* Return your own group role */
uint8_t gc_get_self_role(const GC_Chat *chat);

/* Return your own status */
uint8_t gc_get_self_status(const GC_Chat *chat);

/* Copies peernumber's nick to namebuffer.
 *
 * Returns nick length on success.
 * Returns -1 if peernumber is invalid.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peernumber, uint8_t *namebuffer);

/* Returns peernumber's nick length.
 * Returns -1 if peernumber is invalid.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peernumber);

/* Sets the caller's status to status_type
 *
 * Returns 0 on success.
 * Returns -1 if the status type is invalid.
 * Returns -2 if the packet failed to send.
 */
int gc_set_self_status(GC_Chat *chat, uint8_t status_type);

/* Returns peernumber's status.
 * Returns (uint8_t) -1 on failure.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peernumber);

/* Returns number of peers */
uint32_t gc_get_peernames(const GC_Chat *chat, uint8_t nicks[][MAX_GC_NICK_SIZE], uint16_t lengths[],
                          uint32_t num_peers);

/* Returns number of peers in chat */
uint32_t gc_get_numpeers(const GC_Chat *chat);

/* Returns peernumber's group role.
 * Returns (uint8_t) -1 on failure.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peernumber);

/* Sets the role of peernumber. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * Returns 0 on success.
 * Returns -1 if the peernumber is invalid.
 * Returns -2 if caller does not have sufficient permissions for the action.
 * Returns -3 if the role assignment is invalid.
 * Returns -4 if the role failed to be set.
 */
int gc_set_peer_role(GC_Chat *chat, uint32_t peernumber, uint8_t role);

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for the action.
 * Returns -2 if the password is too long.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *passwd, uint16_t passwd_len);

/* Sets the group privacy state and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if groupnumber is invalid.
 * Returns -2 if the privacy state is an invalid type.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the privacy state fails to set.
 * Returns -5 if the packet fails to send.
 */
int gc_founder_set_privacy_state(Messenger *m, int groupnumber, uint8_t new_privacy_state);

/* Sets the peer limit to maxpeers and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the peer limit could not be set.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_max_peers(GC_Chat *chat, int groupnumber, uint32_t maxpeers);

/* Instructs all peers to remove peernumber from their peerlist.
 * If set_ban is true peer will be added to the ban list.
 *
 * Returns 0 on success.
 * Returns -1 if the groupnumber is invalid.
 * Returns -2 if the peernumber is invalid.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the action failed.
 * Returns -5 if the packet failed to send.
 */
int gc_remove_peer(Messenger *m, int groupnumber, uint32_t peernumber, bool set_ban);

/* Instructs all peers to remove ban_id from their ban list.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the entry could not be removed.
 * Returns -3 if the packet failed to send.
 */
int gc_remove_ban(GC_Chat *chat, uint16_t ban_id);

/* Copies the chat_id to dest */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest);

void gc_callback_message(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, unsigned int,
                         const uint8_t *, size_t, void *), void *userdata);

void gc_callback_private_message(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *,
                                 size_t, void *), void *userdata);

void gc_callback_moderation(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, uint32_t, unsigned int,
                            void *), void *userdata);

void gc_callback_nick_change(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *,
                             size_t, void *), void *userdata);

void gc_callback_status_change(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, unsigned int, void *),
                               void *userdata);

void gc_callback_topic_change(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *,
                              size_t, void *), void *userdata);

void gc_callback_peer_join(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, void *), void *userdata);

void gc_callback_peer_exit(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, const uint8_t *, size_t,
                           void *), void *userdata);

void gc_callback_self_join(Messenger* m, void (*function)(Messenger *m, uint32_t, void *), void *userdata);

void gc_callback_peerlist_update(Messenger *m, void (*function)(Messenger *m, uint32_t, void *), void *userdata);

void gc_callback_rejected(Messenger *m, void (*function)(Messenger *m, uint32_t, unsigned int type, void *),
                          void *userdata);

/* This is the main loop. */
void do_gc(GC_Session* c);

/* Returns a NULL pointer if fail.
 * Make sure that DHT is initialized before calling this
 */
GC_Session* new_groupchats(Messenger* m);

/* Cleans up groupchat structures and calls gc_group_exit() for every group chat */
void kill_groupchats(GC_Session *c);

/* Loads a previously saved group and attempts to join it.
 *
 * Returns groupnumber on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, struct SAVED_GROUP *save);

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
int gc_group_add(GC_Session *c, uint8_t privacy_state, const uint8_t *group_name, uint16_t length);

/* Sends an invite request to a public group using the chat_id.
 *
 * If the group is not password protected passwd should be set to NULL and passwd_len should be 0.
 *
 * Return groupnumber on success.
 * Reutrn -1 if the group object fails to initialize.
 * Return -2 if chat_id is NULL or length is not equal to CHAT_ID_SIZE.
 * Return -3 if there is an error setting the group password.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, uint16_t length, const uint8_t *passwd, uint16_t passwd_len);

/* Resets chat saving all self state and attempts to reconnect to group */
void gc_rejoin_group(GC_Session *c, GC_Chat *chat);

/* Joins a group using the invite data received in a friend's group invite.
 *
 * Return groupnumber on success.
 * Return -1 if the invite data is malformed.
 * Return -2 if the group object fails to initialize.
 * Return -3 if there is an error setting the password.
 */
int gc_accept_invite(GC_Session *c, const uint8_t *data, uint16_t length, const uint8_t *passwd, uint16_t passwd_len);

/* Invites friendnumber to chat. Packet includes: Type, chat_id, node
 *
 * Return 0 on success.
 * Return -1 on failure to create the invite data.
 * Return -2 if the packet fails to send.
 */
int gc_invite_friend(GC_Session *c, GC_Chat *chat, int32_t friendnum);

/* Sends parting message to group and deletes group.
 *
 * Return 0 on success.
 * Return -1 if the parting message is too long.
 * Return -2 if the parting message failed to send.
 * Return -3 if the group instance failed delete.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length);

/* Count number of active groups.
 *
 * Returns the count.
 */
uint32_t gc_count_groups(const GC_Session *c);

/* Return groupnumber's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session* c, int groupnumber);

/* Deletets peernumber from group.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_peer_delete(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data, uint16_t length);

/* Updates chat_id's addr_list when we get a nodes request reply from DHT.
 * This will clear previous entries. */
void gc_update_addrs(GC_Announce *announce, const uint8_t *chat_id);

/* Packs mod_list into data.
 * data must have room for num_mods * SIG_PUBLIC_KEY bytes.
 */
void pack_gc_mod_list(const GC_Chat *chat, uint8_t *data);

/* Copies up to max_addrs peer addresses from chat into addrs.
 *
 * Returns number of addresses copied.
 */
uint16_t gc_copy_peer_addrs(const GC_Chat *chat, GC_PeerAddress *addrs, size_t max_addrs);

/* If read_id is non-zero sends a read-receipt for ack_id's packet.
 * If request_id is non-zero sends a request for the respective id's packet.
 */
int gc_send_message_ack(const GC_Chat *chat, uint32_t peernum, uint64_t read_id, uint64_t request_id);

int handle_gc_lossless_helper(Messenger *m, int groupnumber, uint32_t peernumber, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type);

#endif  /* GROUP_CHATS_H */
