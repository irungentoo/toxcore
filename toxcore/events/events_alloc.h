/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H
#define C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../tox_events.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_Events {
    Tox_Event_Conference_Connected *conference_connected;
    uint32_t conference_connected_size;
    uint32_t conference_connected_capacity;

    Tox_Event_Conference_Invite *conference_invite;
    uint32_t conference_invite_size;
    uint32_t conference_invite_capacity;

    Tox_Event_Conference_Message *conference_message;
    uint32_t conference_message_size;
    uint32_t conference_message_capacity;

    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed;
    uint32_t conference_peer_list_changed_size;
    uint32_t conference_peer_list_changed_capacity;

    Tox_Event_Conference_Peer_Name *conference_peer_name;
    uint32_t conference_peer_name_size;
    uint32_t conference_peer_name_capacity;

    Tox_Event_Conference_Title *conference_title;
    uint32_t conference_title_size;
    uint32_t conference_title_capacity;

    Tox_Event_File_Chunk_Request *file_chunk_request;
    uint32_t file_chunk_request_size;
    uint32_t file_chunk_request_capacity;

    Tox_Event_File_Recv *file_recv;
    uint32_t file_recv_size;
    uint32_t file_recv_capacity;

    Tox_Event_File_Recv_Chunk *file_recv_chunk;
    uint32_t file_recv_chunk_size;
    uint32_t file_recv_chunk_capacity;

    Tox_Event_File_Recv_Control *file_recv_control;
    uint32_t file_recv_control_size;
    uint32_t file_recv_control_capacity;

    Tox_Event_Friend_Connection_Status *friend_connection_status;
    uint32_t friend_connection_status_size;
    uint32_t friend_connection_status_capacity;

    Tox_Event_Friend_Lossless_Packet *friend_lossless_packet;
    uint32_t friend_lossless_packet_size;
    uint32_t friend_lossless_packet_capacity;

    Tox_Event_Friend_Lossy_Packet *friend_lossy_packet;
    uint32_t friend_lossy_packet_size;
    uint32_t friend_lossy_packet_capacity;

    Tox_Event_Friend_Message *friend_message;
    uint32_t friend_message_size;
    uint32_t friend_message_capacity;

    Tox_Event_Friend_Name *friend_name;
    uint32_t friend_name_size;
    uint32_t friend_name_capacity;

    Tox_Event_Friend_Read_Receipt *friend_read_receipt;
    uint32_t friend_read_receipt_size;
    uint32_t friend_read_receipt_capacity;

    Tox_Event_Friend_Request *friend_request;
    uint32_t friend_request_size;
    uint32_t friend_request_capacity;

    Tox_Event_Friend_Status *friend_status;
    uint32_t friend_status_size;
    uint32_t friend_status_capacity;

    Tox_Event_Friend_Status_Message *friend_status_message;
    uint32_t friend_status_message_size;
    uint32_t friend_status_message_capacity;

    Tox_Event_Friend_Typing *friend_typing;
    uint32_t friend_typing_size;
    uint32_t friend_typing_capacity;

    Tox_Event_Self_Connection_Status *self_connection_status;
    uint32_t self_connection_status_size;
    uint32_t self_connection_status_capacity;
};

typedef struct Tox_Events_State {
    Tox_Err_Events_Iterate error;
    Tox_Events *events;
} Tox_Events_State;

tox_conference_connected_cb tox_events_handle_conference_connected;
tox_conference_invite_cb tox_events_handle_conference_invite;
tox_conference_message_cb tox_events_handle_conference_message;
tox_conference_peer_list_changed_cb tox_events_handle_conference_peer_list_changed;
tox_conference_peer_name_cb tox_events_handle_conference_peer_name;
tox_conference_title_cb tox_events_handle_conference_title;
tox_file_chunk_request_cb tox_events_handle_file_chunk_request;
tox_file_recv_cb tox_events_handle_file_recv;
tox_file_recv_chunk_cb tox_events_handle_file_recv_chunk;
tox_file_recv_control_cb tox_events_handle_file_recv_control;
tox_friend_connection_status_cb tox_events_handle_friend_connection_status;
tox_friend_lossless_packet_cb tox_events_handle_friend_lossless_packet;
tox_friend_lossy_packet_cb tox_events_handle_friend_lossy_packet;
tox_friend_message_cb tox_events_handle_friend_message;
tox_friend_name_cb tox_events_handle_friend_name;
tox_friend_read_receipt_cb tox_events_handle_friend_read_receipt;
tox_friend_request_cb tox_events_handle_friend_request;
tox_friend_status_cb tox_events_handle_friend_status;
tox_friend_status_message_cb tox_events_handle_friend_status_message;
tox_friend_typing_cb tox_events_handle_friend_typing;
tox_self_connection_status_cb tox_events_handle_self_connection_status;

// non_null()
typedef void tox_events_clear_cb(Tox_Events *events);

tox_events_clear_cb tox_events_clear_conference_connected;
tox_events_clear_cb tox_events_clear_conference_invite;
tox_events_clear_cb tox_events_clear_conference_message;
tox_events_clear_cb tox_events_clear_conference_peer_list_changed;
tox_events_clear_cb tox_events_clear_conference_peer_name;
tox_events_clear_cb tox_events_clear_conference_title;
tox_events_clear_cb tox_events_clear_file_chunk_request;
tox_events_clear_cb tox_events_clear_file_recv_chunk;
tox_events_clear_cb tox_events_clear_file_recv_control;
tox_events_clear_cb tox_events_clear_file_recv;
tox_events_clear_cb tox_events_clear_friend_connection_status;
tox_events_clear_cb tox_events_clear_friend_lossless_packet;
tox_events_clear_cb tox_events_clear_friend_lossy_packet;
tox_events_clear_cb tox_events_clear_friend_message;
tox_events_clear_cb tox_events_clear_friend_name;
tox_events_clear_cb tox_events_clear_friend_read_receipt;
tox_events_clear_cb tox_events_clear_friend_request;
tox_events_clear_cb tox_events_clear_friend_status_message;
tox_events_clear_cb tox_events_clear_friend_status;
tox_events_clear_cb tox_events_clear_friend_typing;
tox_events_clear_cb tox_events_clear_self_connection_status;

// non_null()
typedef bool tox_events_pack_cb(const Tox_Events *events, Bin_Pack *bp);

tox_events_pack_cb tox_events_pack_conference_connected;
tox_events_pack_cb tox_events_pack_conference_invite;
tox_events_pack_cb tox_events_pack_conference_message;
tox_events_pack_cb tox_events_pack_conference_peer_list_changed;
tox_events_pack_cb tox_events_pack_conference_peer_name;
tox_events_pack_cb tox_events_pack_conference_title;
tox_events_pack_cb tox_events_pack_file_chunk_request;
tox_events_pack_cb tox_events_pack_file_recv_chunk;
tox_events_pack_cb tox_events_pack_file_recv_control;
tox_events_pack_cb tox_events_pack_file_recv;
tox_events_pack_cb tox_events_pack_friend_connection_status;
tox_events_pack_cb tox_events_pack_friend_lossless_packet;
tox_events_pack_cb tox_events_pack_friend_lossy_packet;
tox_events_pack_cb tox_events_pack_friend_message;
tox_events_pack_cb tox_events_pack_friend_name;
tox_events_pack_cb tox_events_pack_friend_read_receipt;
tox_events_pack_cb tox_events_pack_friend_request;
tox_events_pack_cb tox_events_pack_friend_status_message;
tox_events_pack_cb tox_events_pack_friend_status;
tox_events_pack_cb tox_events_pack_friend_typing;
tox_events_pack_cb tox_events_pack_self_connection_status;

tox_events_pack_cb tox_events_pack;

// non_null()
typedef bool tox_events_unpack_cb(Tox_Events *events, Bin_Unpack *bu);

tox_events_unpack_cb tox_events_unpack_conference_connected;
tox_events_unpack_cb tox_events_unpack_conference_invite;
tox_events_unpack_cb tox_events_unpack_conference_message;
tox_events_unpack_cb tox_events_unpack_conference_peer_list_changed;
tox_events_unpack_cb tox_events_unpack_conference_peer_name;
tox_events_unpack_cb tox_events_unpack_conference_title;
tox_events_unpack_cb tox_events_unpack_file_chunk_request;
tox_events_unpack_cb tox_events_unpack_file_recv_chunk;
tox_events_unpack_cb tox_events_unpack_file_recv_control;
tox_events_unpack_cb tox_events_unpack_file_recv;
tox_events_unpack_cb tox_events_unpack_friend_connection_status;
tox_events_unpack_cb tox_events_unpack_friend_lossless_packet;
tox_events_unpack_cb tox_events_unpack_friend_lossy_packet;
tox_events_unpack_cb tox_events_unpack_friend_message;
tox_events_unpack_cb tox_events_unpack_friend_name;
tox_events_unpack_cb tox_events_unpack_friend_read_receipt;
tox_events_unpack_cb tox_events_unpack_friend_request;
tox_events_unpack_cb tox_events_unpack_friend_status_message;
tox_events_unpack_cb tox_events_unpack_friend_status;
tox_events_unpack_cb tox_events_unpack_friend_typing;
tox_events_unpack_cb tox_events_unpack_self_connection_status;

tox_events_unpack_cb tox_events_unpack;

non_null()
Tox_Events_State *tox_events_alloc(void *user_data);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H
