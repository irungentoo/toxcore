/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Slightly better groupchats implementation.
 */
#ifndef C_TOXCORE_TOXCORE_GROUP_H
#define C_TOXCORE_TOXCORE_GROUP_H

#include "Messenger.h"

typedef enum Groupchat_Status {
    GROUPCHAT_STATUS_NONE,
    GROUPCHAT_STATUS_VALID,
    GROUPCHAT_STATUS_CONNECTED,
} Groupchat_Status;

typedef enum Groupchat_Type {
    GROUPCHAT_TYPE_TEXT,
    GROUPCHAT_TYPE_AV,
} Groupchat_Type;

#define MAX_LOSSY_COUNT 256

typedef struct Message_Info {
    uint32_t message_number;
    uint8_t  message_id;
} Message_Info;

#define MAX_LAST_MESSAGE_INFOS 8

typedef struct Group_Peer {
    uint8_t     real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t     temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
    bool        temp_pk_updated;
    bool        is_friend;

    uint64_t    last_active;

    Message_Info
    last_message_infos[MAX_LAST_MESSAGE_INFOS]; /* received messages, strictly decreasing in message_number */
    uint8_t     num_last_message_infos;

    uint8_t     nick[MAX_NAME_LENGTH];
    uint8_t     nick_len;
    bool        nick_updated;

    uint16_t peer_number;

    uint8_t  recv_lossy[MAX_LOSSY_COUNT];
    uint16_t bottom_lossy_number;
    uint16_t top_lossy_number;

    void *object;
} Group_Peer;

#define DESIRED_CLOSEST 4
#define MAX_GROUP_CONNECTIONS 16
#define GROUP_ID_LENGTH CRYPTO_SYMMETRIC_KEY_SIZE

typedef enum Groupchat_Connection_Type {
    GROUPCHAT_CONNECTION_NONE,
    GROUPCHAT_CONNECTION_CONNECTING,
    GROUPCHAT_CONNECTION_ONLINE,
} Groupchat_Connection_Type;

/** Connection is to one of the closest DESIRED_CLOSEST peers */
#define GROUPCHAT_CONNECTION_REASON_CLOSEST     (1 << 0)

/** Connection is to a peer we are introducing to the conference */
#define GROUPCHAT_CONNECTION_REASON_INTRODUCING (1 << 1)

/** Connection is to a peer who is introducing us to the conference */
#define GROUPCHAT_CONNECTION_REASON_INTRODUCER  (1 << 2)

typedef struct Groupchat_Connection {
    uint8_t type; /* `GROUPCHAT_CONNECTION_*` */
    uint8_t reasons; /* bit field with flags `GROUPCHAT_CONNECTION_REASON_*` */
    uint32_t number;
    uint16_t group_number;
} Groupchat_Connection;

typedef struct Groupchat_Closest {
    uint8_t entry;
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
} Groupchat_Closest;

typedef void peer_on_join_cb(void *object, uint32_t conference_number, uint32_t peer_number);
typedef void peer_on_leave_cb(void *object, uint32_t conference_number, void *peer_object);
typedef void group_on_delete_cb(void *object, uint32_t conference_number);

// maximum number of frozen peers to store; group_set_max_frozen() overrides.
#define MAX_FROZEN_DEFAULT 128

typedef struct Group_c {
    uint8_t status;

    bool need_send_name;
    bool title_fresh;

    Group_Peer *group;
    uint32_t numpeers;

    Group_Peer *frozen;
    uint32_t numfrozen;

    uint32_t maxfrozen;

    Groupchat_Connection connections[MAX_GROUP_CONNECTIONS];

    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    Groupchat_Closest closest_peers[DESIRED_CLOSEST];
    uint8_t changed;

    uint8_t type;
    uint8_t id[GROUP_ID_LENGTH];

    uint8_t title[MAX_NAME_LENGTH];
    uint8_t title_len;

    uint32_t message_number;
    uint16_t lossy_message_number;
    uint16_t peer_number;

    uint64_t last_sent_ping;

    uint32_t num_introducer_connections;

    void *object;

    peer_on_join_cb *peer_on_join;
    peer_on_leave_cb *peer_on_leave;
    group_on_delete_cb *group_on_delete;
} Group_c;

/** Callback for group invites.
 *
 * data of length is what needs to be passed to join_groupchat().
 */
typedef void g_conference_invite_cb(Messenger *m, uint32_t friend_number, int type, const uint8_t *cookie,
                                    size_t length, void *user_data);

/** Callback for group connection. */
typedef void g_conference_connected_cb(Messenger *m, uint32_t conference_number, void *user_data);

/** Callback for group messages. */
typedef void g_conference_message_cb(Messenger *m, uint32_t conference_number, uint32_t peer_number, int type,
                                     const uint8_t *message, size_t length, void *user_data);

/** Callback for peer nickname changes. */
typedef void peer_name_cb(Messenger *m, uint32_t conference_number, uint32_t peer_number, const uint8_t *name,
                          size_t length, void *user_data);

/** Set callback function for peer list changes. */
typedef void peer_list_changed_cb(Messenger *m, uint32_t conference_number, void *user_data);

/** Callback for title changes.
 *
 * If peer_number == -1, then author is unknown (e.g. initial joining the group).
 */
typedef void title_cb(Messenger *m, uint32_t conference_number, uint32_t peer_number, const uint8_t *title,
                      size_t length, void *user_data);

/** Callback for lossy packets.
 *
 * NOTE: Handler must return 0 if packet is to be relayed, -1 if the packet should not be relayed.
 */
typedef int lossy_packet_cb(void *object, uint32_t conference_number, uint32_t peer_number, void *peer_object,
                            const uint8_t *packet, uint16_t length);

typedef struct Group_Lossy_Handler {
    lossy_packet_cb *function;
} Group_Lossy_Handler;

typedef struct Group_Chats {
    const Mono_Time *mono_time;

    Messenger *m;
    Friend_Connections *fr_c;

    Group_c *chats;
    uint16_t num_chats;

    g_conference_invite_cb *invite_callback;
    g_conference_connected_cb *connected_callback;
    g_conference_message_cb *message_callback;
    peer_name_cb *peer_name_callback;
    peer_list_changed_cb *peer_list_changed_callback;
    title_cb *title_callback;

    Group_Lossy_Handler lossy_packethandlers[256];
} Group_Chats;

/** Set the callback for group invites. */
void g_callback_group_invite(Group_Chats *g_c, g_conference_invite_cb *function);

/** Set the callback for group connection. */
void g_callback_group_connected(Group_Chats *g_c, g_conference_connected_cb *function);

/** Set the callback for group messages. */
void g_callback_group_message(Group_Chats *g_c, g_conference_message_cb *function);


/** Set callback function for title changes. */
void g_callback_group_title(Group_Chats *g_c, title_cb *function);

/** Set callback function for peer nickname changes.
 *
 * It gets called every time a peer changes their nickname.
 */
void g_callback_peer_name(Group_Chats *g_c, peer_name_cb *function);

/** Set callback function for peer list changes.
 *
 * It gets called every time the name list changes(new peer, deleted peer)
 */
void g_callback_peer_list_changed(Group_Chats *g_c, peer_list_changed_cb *function);

/** Creates a new groupchat and puts it in the chats array.
 *
 * type is one of `GROUPCHAT_TYPE_*`
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Group_Chats *g_c, uint8_t type);

/** Delete a groupchat from the chats array, informing the group first as
 * appropriate.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 */
int del_groupchat(Group_Chats *g_c, uint32_t groupnumber, bool leave_permanently);

/** Copy the public key of (frozen, if frozen is true) peernumber who is in
 * groupnumber to pk. pk must be CRYPTO_PUBLIC_KEY_SIZE long.
 *
 * return 0 on success
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peer_pubkey(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, uint8_t *pk, bool frozen);

/**
 * Return the size of (frozen, if frozen is true) peernumber's name.
 *
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peername_size(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, bool frozen);

/** Copy the name of (frozen, if frozen is true) peernumber who is in
 * groupnumber to name. name must be at least MAX_NAME_LENGTH long.
 *
 * return length of name if success
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_peername(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, uint8_t *name, bool frozen);

/** Copy last active timestamp of frozen peernumber who is in groupnumber to
 * last_active.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 */
int group_frozen_last_active(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber,
                             uint64_t *last_active);

/** Set maximum number of frozen peers.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 */
int group_set_max_frozen(const Group_Chats *g_c, uint32_t groupnumber, uint32_t maxfrozen);

/** invite friendnumber to groupnumber.
 *
 * return 0 on success.
 * return -1 if groupnumber is invalid.
 * return -2 if invite packet failed to send.
 * return -3 if we are not connected to the group chat.
 */
int invite_friend(const Group_Chats *g_c, uint32_t friendnumber, uint32_t groupnumber);

/** Join a group (we need to have been invited first.)
 *
 * expected_type is the groupchat type we expect the chat we are joining to
 * have.
 *
 * return group number on success.
 * return -1 if data length is invalid.
 * return -2 if group is not the expected type.
 * return -3 if friendnumber is invalid.
 * return -4 if client is already in this group.
 * return -5 if group instance failed to initialize.
 * return -6 if join packet fails to send.
 */
int join_groupchat(Group_Chats *g_c, uint32_t friendnumber, uint8_t expected_type, const uint8_t *data,
                   uint16_t length);

/** send a group message
 * return 0 on success
 * see: send_message_group() for error codes.
 */
int group_message_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *message, uint16_t length);

/** send a group action
 * return 0 on success
 * see: send_message_group() for error codes.
 */
int group_action_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *action, uint16_t length);

/** set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 if groupnumber is invalid.
 * return -2 if title is too long or empty.
 * return -3 if packet fails to send.
 */
int group_title_send(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *title, uint8_t title_len);


/** return the group's title size.
 * return -1 of groupnumber is invalid.
 * return -2 if title is too long or empty.
 */
int group_title_get_size(const Group_Chats *g_c, uint32_t groupnumber);

/** Get group title from groupnumber and put it in title.
 * Title needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 * return length of copied title if success.
 * return -1 if groupnumber is invalid.
 * return -2 if title is too long or empty.
 */
int group_title_get(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *title);

/** Return the number of (frozen, if frozen is true) peers in the group chat on
 * success.
 * return -1 if groupnumber is invalid.
 */
int group_number_peers(const Group_Chats *g_c, uint32_t groupnumber, bool frozen);

/** return 1 if the peernumber corresponds to ours.
 * return 0 if the peernumber is not ours.
 * return -1 if groupnumber is invalid.
 * return -2 if peernumber is invalid.
 * return -3 if we are not connected to the group chat.
 */
int group_peernumber_is_ours(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber);

/** Set handlers for custom lossy packets. */
void group_lossy_packet_registerhandler(Group_Chats *g_c, uint8_t byte, lossy_packet_cb *function);

/** High level function to send custom lossy packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_group_lossy_packet(const Group_Chats *g_c, uint32_t groupnumber, const uint8_t *data, uint16_t length);

/** Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist.
 */
uint32_t count_chatlist(const Group_Chats *g_c);

/** Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(const Group_Chats *g_c, uint32_t *out_list, uint32_t list_size);

/** return the type of groupchat (GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
int group_get_type(const Group_Chats *g_c, uint32_t groupnumber);

/** Copies the unique id of `group_chat[groupnumber]` into `id`.
 *
 * return false on failure.
 * return true on success.
 */
bool conference_get_id(const Group_Chats *g_c, uint32_t groupnumber, uint8_t *id);

int32_t conference_by_id(const Group_Chats *g_c, const uint8_t *id);

/** Send current name (set in messenger) to all online groups.
 */
void send_name_all_groups(const Group_Chats *g_c);

/** Set the object that is tied to the group chat.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_set_object(const Group_Chats *g_c, uint32_t groupnumber, void *object);

/** Set the object that is tied to the group peer.
 *
 * return 0 on success.
 * return -1 on failure
 */
int group_peer_set_object(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber, void *object);

/** Return the object tied to the group chat previously set by group_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_get_object(const Group_Chats *g_c, uint32_t groupnumber);

/** Return the object tied to the group chat peer previously set by group_peer_set_object.
 *
 * return NULL on failure.
 * return object on success.
 */
void *group_peer_get_object(const Group_Chats *g_c, uint32_t groupnumber, uint32_t peernumber);

/** Set a function to be called when a new peer joins a group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_new(const Group_Chats *g_c, uint32_t groupnumber, peer_on_join_cb *function);

/** Set a function to be called when a peer leaves a group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_peer_delete(const Group_Chats *g_c, uint32_t groupnumber, peer_on_leave_cb *function);

/** Set a function to be called when the group chat is deleted.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int callback_groupchat_delete(const Group_Chats *g_c, uint32_t groupnumber, group_on_delete_cb *function);

/** Return size of the conferences data (for saving). */
uint32_t conferences_size(const Group_Chats *g_c);

/** Save the conferences in data (must be allocated memory of size at least conferences_size()) */
uint8_t *conferences_save(const Group_Chats *g_c, uint8_t *data);

/**
 * Load a state section.
 *
 * @param data Data to load
 * @param length Length of data
 * @param type Type of section (`STATE_TYPE_*`)
 * @param status Result of loading section is stored here if the section is handled.
 * @return true iff section handled.
 */
bool conferences_load_state_section(Group_Chats *g_c, const uint8_t *data, uint32_t length, uint16_t type,
                                    State_Load_Status *status);

/** Create new groupchat instance. */
Group_Chats *new_groupchats(const Mono_Time *mono_time, Messenger *m);

/** main groupchats loop. */
void do_groupchats(Group_Chats *g_c, void *userdata);

/** Free everything related with group chats. */
void kill_groupchats(Group_Chats *g_c);

#endif
