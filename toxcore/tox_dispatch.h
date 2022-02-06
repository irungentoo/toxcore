/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_DISPATCH_H
#define C_TOXCORE_TOXCORE_TOX_DISPATCH_H

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
 * @param tox The tox object to pass down to the callbacks.
 * @param user_data User data pointer to pass down to the callbacks.
 */
void tox_dispatch_invoke(const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data);

typedef void tox_events_conference_connected_cb(
    Tox *tox, const Tox_Event_Conference_Connected *event, void *user_data);
typedef void tox_events_conference_invite_cb(
    Tox *tox, const Tox_Event_Conference_Invite *event, void *user_data);
typedef void tox_events_conference_message_cb(
    Tox *tox, const Tox_Event_Conference_Message *event, void *user_data);
typedef void tox_events_conference_peer_list_changed_cb(
    Tox *tox, const Tox_Event_Conference_Peer_List_Changed *event, void *user_data);
typedef void tox_events_conference_peer_name_cb(
    Tox *tox, const Tox_Event_Conference_Peer_Name *event, void *user_data);
typedef void tox_events_conference_title_cb(
    Tox *tox, const Tox_Event_Conference_Title *event, void *user_data);
typedef void tox_events_file_chunk_request_cb(
    Tox *tox, const Tox_Event_File_Chunk_Request *event, void *user_data);
typedef void tox_events_file_recv_cb(
    Tox *tox, const Tox_Event_File_Recv *event, void *user_data);
typedef void tox_events_file_recv_chunk_cb(
    Tox *tox, const Tox_Event_File_Recv_Chunk *event, void *user_data);
typedef void tox_events_file_recv_control_cb(
    Tox *tox, const Tox_Event_File_Recv_Control *event, void *user_data);
typedef void tox_events_friend_connection_status_cb(
    Tox *tox, const Tox_Event_Friend_Connection_Status *event, void *user_data);
typedef void tox_events_friend_lossless_packet_cb(
    Tox *tox, const Tox_Event_Friend_Lossless_Packet *event, void *user_data);
typedef void tox_events_friend_lossy_packet_cb(
    Tox *tox, const Tox_Event_Friend_Lossy_Packet *event, void *user_data);
typedef void tox_events_friend_message_cb(
    Tox *tox, const Tox_Event_Friend_Message *event, void *user_data);
typedef void tox_events_friend_name_cb(
    Tox *tox, const Tox_Event_Friend_Name *event, void *user_data);
typedef void tox_events_friend_read_receipt_cb(
    Tox *tox, const Tox_Event_Friend_Read_Receipt *event, void *user_data);
typedef void tox_events_friend_request_cb(
    Tox *tox, const Tox_Event_Friend_Request *event, void *user_data);
typedef void tox_events_friend_status_cb(
    Tox *tox, const Tox_Event_Friend_Status *event, void *user_data);
typedef void tox_events_friend_status_message_cb(
    Tox *tox, const Tox_Event_Friend_Status_Message *event, void *user_data);
typedef void tox_events_friend_typing_cb(
    Tox *tox, const Tox_Event_Friend_Typing *event, void *user_data);
typedef void tox_events_self_connection_status_cb(
    Tox *tox, const Tox_Event_Self_Connection_Status *event, void *user_data);

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

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_DISPATCH_H
