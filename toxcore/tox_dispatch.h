/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_DISPATCH_H
#define C_TOXCORE_TOXCORE_TOX_DISPATCH_H

#include "tox.h"
#include "tox_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The events dispatch table.
 *
 * This holds all the callbacks registered with `tox_events_callback_*`
 * functions below.
 */
typedef struct Tox_Dispatch Tox_Dispatch;

typedef enum Tox_Err_Dispatch_New {
    /**
     * The function returned successfully.
     */
    TOX_ERR_DISPATCH_NEW_OK,

    /**
     * The function failed to allocate memory for the dispatch table.
     */
    TOX_ERR_DISPATCH_NEW_MALLOC,
} Tox_Err_Dispatch_New;

/**
 * @brief Creates a new empty event dispatch table.
 */
Tox_Dispatch *tox_dispatch_new(Tox_Err_Dispatch_New *error);

/**
 * @brief Deallocate an event dispatch table.
 */
void tox_dispatch_free(Tox_Dispatch *dispatch);

/**
 * @brief Invoke registered callbacks for each of the events.
 *
 * @param dispatch The events dispatch table.
 * @param events The events object received from @ref tox_events_iterate.
 * @param user_data User data pointer to pass down to the callbacks.
 */
void tox_dispatch_invoke(const Tox_Dispatch *dispatch, const Tox_Events *events, void *user_data);

typedef void tox_events_conference_connected_cb(
    const Tox_Event_Conference_Connected *event, void *user_data);
typedef void tox_events_conference_invite_cb(
    const Tox_Event_Conference_Invite *event, void *user_data);
typedef void tox_events_conference_message_cb(
    const Tox_Event_Conference_Message *event, void *user_data);
typedef void tox_events_conference_peer_list_changed_cb(
    const Tox_Event_Conference_Peer_List_Changed *event, void *user_data);
typedef void tox_events_conference_peer_name_cb(
    const Tox_Event_Conference_Peer_Name *event, void *user_data);
typedef void tox_events_conference_title_cb(
    const Tox_Event_Conference_Title *event, void *user_data);
typedef void tox_events_file_chunk_request_cb(
    const Tox_Event_File_Chunk_Request *event, void *user_data);
typedef void tox_events_file_recv_cb(
    const Tox_Event_File_Recv *event, void *user_data);
typedef void tox_events_file_recv_chunk_cb(
    const Tox_Event_File_Recv_Chunk *event, void *user_data);
typedef void tox_events_file_recv_control_cb(
    const Tox_Event_File_Recv_Control *event, void *user_data);
typedef void tox_events_friend_connection_status_cb(
    const Tox_Event_Friend_Connection_Status *event, void *user_data);
typedef void tox_events_friend_lossless_packet_cb(
    const Tox_Event_Friend_Lossless_Packet *event, void *user_data);
typedef void tox_events_friend_lossy_packet_cb(
    const Tox_Event_Friend_Lossy_Packet *event, void *user_data);
typedef void tox_events_friend_message_cb(
    const Tox_Event_Friend_Message *event, void *user_data);
typedef void tox_events_friend_name_cb(
    const Tox_Event_Friend_Name *event, void *user_data);
typedef void tox_events_friend_read_receipt_cb(
    const Tox_Event_Friend_Read_Receipt *event, void *user_data);
typedef void tox_events_friend_request_cb(
    const Tox_Event_Friend_Request *event, void *user_data);
typedef void tox_events_friend_status_cb(
    const Tox_Event_Friend_Status *event, void *user_data);
typedef void tox_events_friend_status_message_cb(
    const Tox_Event_Friend_Status_Message *event, void *user_data);
typedef void tox_events_friend_typing_cb(
    const Tox_Event_Friend_Typing *event, void *user_data);
typedef void tox_events_self_connection_status_cb(
    const Tox_Event_Self_Connection_Status *event, void *user_data);
typedef void tox_events_group_peer_name_cb(
    const Tox_Event_Group_Peer_Name *event, void *user_data);
typedef void tox_events_group_peer_status_cb(
    const Tox_Event_Group_Peer_Status *event, void *user_data);
typedef void tox_events_group_topic_cb(
    const Tox_Event_Group_Topic *event, void *user_data);
typedef void tox_events_group_privacy_state_cb(
    const Tox_Event_Group_Privacy_State *event, void *user_data);
typedef void tox_events_group_voice_state_cb(
    const Tox_Event_Group_Voice_State *event, void *user_data);
typedef void tox_events_group_topic_lock_cb(
    const Tox_Event_Group_Topic_Lock *event, void *user_data);
typedef void tox_events_group_peer_limit_cb(
    const Tox_Event_Group_Peer_Limit *event, void *user_data);
typedef void tox_events_group_password_cb(
    const Tox_Event_Group_Password *event, void *user_data);
typedef void tox_events_group_message_cb(
    const Tox_Event_Group_Message *event, void *user_data);
typedef void tox_events_group_private_message_cb(
    const Tox_Event_Group_Private_Message *event, void *user_data);
typedef void tox_events_group_custom_packet_cb(
    const Tox_Event_Group_Custom_Packet *event, void *user_data);
typedef void tox_events_group_custom_private_packet_cb(
    const Tox_Event_Group_Custom_Private_Packet *event, void *user_data);
typedef void tox_events_group_invite_cb(
    const Tox_Event_Group_Invite *event, void *user_data);
typedef void tox_events_group_peer_join_cb(
    const Tox_Event_Group_Peer_Join *event, void *user_data);
typedef void tox_events_group_peer_exit_cb(
    const Tox_Event_Group_Peer_Exit *event, void *user_data);
typedef void tox_events_group_self_join_cb(
    const Tox_Event_Group_Self_Join *event, void *user_data);
typedef void tox_events_group_join_fail_cb(
    const Tox_Event_Group_Join_Fail *event, void *user_data);
typedef void tox_events_group_moderation_cb(
    const Tox_Event_Group_Moderation *event, void *user_data);
typedef void tox_events_dht_get_nodes_response_cb(
    const Tox_Event_Dht_Get_Nodes_Response *event, void *user_data);

void tox_events_callback_conference_connected(
    Tox_Dispatch *dispatch, tox_events_conference_connected_cb *callback);
void tox_events_callback_conference_invite(
    Tox_Dispatch *dispatch, tox_events_conference_invite_cb *callback);
void tox_events_callback_conference_message(
    Tox_Dispatch *dispatch, tox_events_conference_message_cb *callback);
void tox_events_callback_conference_peer_list_changed(
    Tox_Dispatch *dispatch, tox_events_conference_peer_list_changed_cb *callback);
void tox_events_callback_conference_peer_name(
    Tox_Dispatch *dispatch, tox_events_conference_peer_name_cb *callback);
void tox_events_callback_conference_title(
    Tox_Dispatch *dispatch, tox_events_conference_title_cb *callback);
void tox_events_callback_file_chunk_request(
    Tox_Dispatch *dispatch, tox_events_file_chunk_request_cb *callback);
void tox_events_callback_file_recv(
    Tox_Dispatch *dispatch, tox_events_file_recv_cb *callback);
void tox_events_callback_file_recv_chunk(
    Tox_Dispatch *dispatch, tox_events_file_recv_chunk_cb *callback);
void tox_events_callback_file_recv_control(
    Tox_Dispatch *dispatch, tox_events_file_recv_control_cb *callback);
void tox_events_callback_friend_connection_status(
    Tox_Dispatch *dispatch, tox_events_friend_connection_status_cb *callback);
void tox_events_callback_friend_lossless_packet(
    Tox_Dispatch *dispatch, tox_events_friend_lossless_packet_cb *callback);
void tox_events_callback_friend_lossy_packet(
    Tox_Dispatch *dispatch, tox_events_friend_lossy_packet_cb *callback);
void tox_events_callback_friend_message(
    Tox_Dispatch *dispatch, tox_events_friend_message_cb *callback);
void tox_events_callback_friend_name(
    Tox_Dispatch *dispatch, tox_events_friend_name_cb *callback);
void tox_events_callback_friend_read_receipt(
    Tox_Dispatch *dispatch, tox_events_friend_read_receipt_cb *callback);
void tox_events_callback_friend_request(
    Tox_Dispatch *dispatch, tox_events_friend_request_cb *callback);
void tox_events_callback_friend_status(
    Tox_Dispatch *dispatch, tox_events_friend_status_cb *callback);
void tox_events_callback_friend_status_message(
    Tox_Dispatch *dispatch, tox_events_friend_status_message_cb *callback);
void tox_events_callback_friend_typing(
    Tox_Dispatch *dispatch, tox_events_friend_typing_cb *callback);
void tox_events_callback_self_connection_status(
    Tox_Dispatch *dispatch, tox_events_self_connection_status_cb *callback);
void tox_events_callback_group_peer_name(
    Tox_Dispatch *dispatch, tox_events_group_peer_name_cb *callback);
void tox_events_callback_group_peer_status(
    Tox_Dispatch *dispatch, tox_events_group_peer_status_cb *callback);
void tox_events_callback_group_topic(
    Tox_Dispatch *dispatch, tox_events_group_topic_cb *callback);
void tox_events_callback_group_privacy_state(
    Tox_Dispatch *dispatch, tox_events_group_privacy_state_cb *callback);
void tox_events_callback_group_voice_state(
    Tox_Dispatch *dispatch, tox_events_group_voice_state_cb *callback);
void tox_events_callback_group_topic_lock(
    Tox_Dispatch *dispatch, tox_events_group_topic_lock_cb *callback);
void tox_events_callback_group_peer_limit(
    Tox_Dispatch *dispatch, tox_events_group_peer_limit_cb *callback);
void tox_events_callback_group_password(
    Tox_Dispatch *dispatch, tox_events_group_password_cb *callback);
void tox_events_callback_group_message(
    Tox_Dispatch *dispatch, tox_events_group_message_cb *callback);
void tox_events_callback_group_private_message(
    Tox_Dispatch *dispatch, tox_events_group_private_message_cb *callback);
void tox_events_callback_group_custom_packet(
    Tox_Dispatch *dispatch, tox_events_group_custom_packet_cb *callback);
void tox_events_callback_group_custom_private_packet(
    Tox_Dispatch *dispatch, tox_events_group_custom_private_packet_cb *callback);
void tox_events_callback_group_invite(
    Tox_Dispatch *dispatch, tox_events_group_invite_cb *callback);
void tox_events_callback_group_peer_join(
    Tox_Dispatch *dispatch, tox_events_group_peer_join_cb *callback);
void tox_events_callback_group_peer_exit(
    Tox_Dispatch *dispatch, tox_events_group_peer_exit_cb *callback);
void tox_events_callback_group_self_join(
    Tox_Dispatch *dispatch, tox_events_group_self_join_cb *callback);
void tox_events_callback_group_join_fail(
    Tox_Dispatch *dispatch, tox_events_group_join_fail_cb *callback);
void tox_events_callback_group_moderation(
    Tox_Dispatch *dispatch, tox_events_group_moderation_cb *callback);
void tox_events_callback_dht_get_nodes_response(
    Tox_Dispatch *dispatch, tox_events_dht_get_nodes_response_cb *callback);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_DISPATCH_H */
