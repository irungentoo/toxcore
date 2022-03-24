/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENTS_H
#define C_TOXCORE_TOXCORE_TOX_EVENTS_H

#include "tox.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Event_Conference_Connected Tox_Event_Conference_Connected;
uint32_t tox_event_conference_connected_get_conference_number(
    const Tox_Event_Conference_Connected *conference_connected);

typedef struct Tox_Event_Conference_Invite Tox_Event_Conference_Invite;
const uint8_t *tox_event_conference_invite_get_cookie(
    const Tox_Event_Conference_Invite *conference_invite);
uint32_t tox_event_conference_invite_get_cookie_length(
    const Tox_Event_Conference_Invite *conference_invite);
Tox_Conference_Type tox_event_conference_invite_get_type(
    const Tox_Event_Conference_Invite *conference_invite);
uint32_t tox_event_conference_invite_get_friend_number(
    const Tox_Event_Conference_Invite *conference_invite);

typedef struct Tox_Event_Conference_Message Tox_Event_Conference_Message;
const uint8_t *tox_event_conference_message_get_message(
    const Tox_Event_Conference_Message *conference_message);
uint32_t tox_event_conference_message_get_message_length(
    const Tox_Event_Conference_Message *conference_message);
Tox_Message_Type tox_event_conference_message_get_type(
    const Tox_Event_Conference_Message *conference_message);
uint32_t tox_event_conference_message_get_conference_number(
    const Tox_Event_Conference_Message *conference_message);
uint32_t tox_event_conference_message_get_peer_number(
    const Tox_Event_Conference_Message *conference_message);

typedef struct Tox_Event_Conference_Peer_List_Changed Tox_Event_Conference_Peer_List_Changed;
uint32_t tox_event_conference_peer_list_changed_get_conference_number(
    const Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed);

typedef struct Tox_Event_Conference_Peer_Name Tox_Event_Conference_Peer_Name;
const uint8_t *tox_event_conference_peer_name_get_name(
    const Tox_Event_Conference_Peer_Name *conference_peer_name);
uint32_t tox_event_conference_peer_name_get_name_length(
    const Tox_Event_Conference_Peer_Name *conference_peer_name);
uint32_t tox_event_conference_peer_name_get_conference_number(
    const Tox_Event_Conference_Peer_Name *conference_peer_name);
uint32_t tox_event_conference_peer_name_get_peer_number(
    const Tox_Event_Conference_Peer_Name *conference_peer_name);

typedef struct Tox_Event_Conference_Title Tox_Event_Conference_Title;
const uint8_t *tox_event_conference_title_get_title(
    const Tox_Event_Conference_Title *conference_title);
uint32_t tox_event_conference_title_get_title_length(
    const Tox_Event_Conference_Title *conference_title);
uint32_t tox_event_conference_title_get_conference_number(
    const Tox_Event_Conference_Title *conference_title);
uint32_t tox_event_conference_title_get_peer_number(
    const Tox_Event_Conference_Title *conference_title);

typedef struct Tox_Event_File_Chunk_Request Tox_Event_File_Chunk_Request;
uint16_t tox_event_file_chunk_request_get_length(
    const Tox_Event_File_Chunk_Request *file_chunk_request);
uint32_t tox_event_file_chunk_request_get_file_number(
    const Tox_Event_File_Chunk_Request *file_chunk_request);
uint32_t tox_event_file_chunk_request_get_friend_number(
    const Tox_Event_File_Chunk_Request *file_chunk_request);
uint64_t tox_event_file_chunk_request_get_position(
    const Tox_Event_File_Chunk_Request *file_chunk_request);

typedef struct Tox_Event_File_Recv Tox_Event_File_Recv;
const uint8_t *tox_event_file_recv_get_filename(
    const Tox_Event_File_Recv *file_recv);
uint32_t tox_event_file_recv_get_filename_length(
    const Tox_Event_File_Recv *file_recv);
uint32_t tox_event_file_recv_get_file_number(
    const Tox_Event_File_Recv *file_recv);
uint64_t tox_event_file_recv_get_file_size(
    const Tox_Event_File_Recv *file_recv);
uint32_t tox_event_file_recv_get_friend_number(
    const Tox_Event_File_Recv *file_recv);
uint32_t tox_event_file_recv_get_kind(
    const Tox_Event_File_Recv *file_recv);

typedef struct Tox_Event_File_Recv_Chunk Tox_Event_File_Recv_Chunk;
const uint8_t *tox_event_file_recv_chunk_get_data(
    const Tox_Event_File_Recv_Chunk *file_recv_chunk);
uint32_t tox_event_file_recv_chunk_get_length(
    const Tox_Event_File_Recv_Chunk *file_recv_chunk);
uint32_t tox_event_file_recv_chunk_get_file_number(
    const Tox_Event_File_Recv_Chunk *file_recv_chunk);
uint32_t tox_event_file_recv_chunk_get_friend_number(
    const Tox_Event_File_Recv_Chunk *file_recv_chunk);
uint64_t tox_event_file_recv_chunk_get_position(
    const Tox_Event_File_Recv_Chunk *file_recv_chunk);

typedef struct Tox_Event_File_Recv_Control Tox_Event_File_Recv_Control;
Tox_File_Control tox_event_file_recv_control_get_control(
    const Tox_Event_File_Recv_Control *file_recv_control);
uint32_t tox_event_file_recv_control_get_file_number(
    const Tox_Event_File_Recv_Control *file_recv_control);
uint32_t tox_event_file_recv_control_get_friend_number(
    const Tox_Event_File_Recv_Control *file_recv_control);

typedef struct Tox_Event_Friend_Connection_Status Tox_Event_Friend_Connection_Status;
Tox_Connection tox_event_friend_connection_status_get_connection_status(
    const Tox_Event_Friend_Connection_Status *friend_connection_status);
uint32_t tox_event_friend_connection_status_get_friend_number(
    const Tox_Event_Friend_Connection_Status *friend_connection_status);

typedef struct Tox_Event_Friend_Lossless_Packet Tox_Event_Friend_Lossless_Packet;
const uint8_t *tox_event_friend_lossless_packet_get_data(
    const Tox_Event_Friend_Lossless_Packet *friend_lossless_packet);
uint32_t tox_event_friend_lossless_packet_get_data_length(
    const Tox_Event_Friend_Lossless_Packet *friend_lossless_packet);
uint32_t tox_event_friend_lossless_packet_get_friend_number(
    const Tox_Event_Friend_Lossless_Packet *friend_lossless_packet);

typedef struct Tox_Event_Friend_Lossy_Packet Tox_Event_Friend_Lossy_Packet;
const uint8_t *tox_event_friend_lossy_packet_get_data(
    const Tox_Event_Friend_Lossy_Packet *friend_lossy_packet);
uint32_t tox_event_friend_lossy_packet_get_data_length(
    const Tox_Event_Friend_Lossy_Packet *friend_lossy_packet);
uint32_t tox_event_friend_lossy_packet_get_friend_number(
    const Tox_Event_Friend_Lossy_Packet *friend_lossy_packet);

typedef struct Tox_Event_Friend_Message Tox_Event_Friend_Message;
uint32_t tox_event_friend_message_get_friend_number(
    const Tox_Event_Friend_Message *friend_message);
Tox_Message_Type tox_event_friend_message_get_type(
    const Tox_Event_Friend_Message *friend_message);
uint32_t tox_event_friend_message_get_message_length(
    const Tox_Event_Friend_Message *friend_message);
const uint8_t *tox_event_friend_message_get_message(
    const Tox_Event_Friend_Message *friend_message);

typedef struct Tox_Event_Friend_Name Tox_Event_Friend_Name;
const uint8_t *tox_event_friend_name_get_name(
    const Tox_Event_Friend_Name *friend_name);
uint32_t tox_event_friend_name_get_name_length(
    const Tox_Event_Friend_Name *friend_name);
uint32_t tox_event_friend_name_get_friend_number(
    const Tox_Event_Friend_Name *friend_name);

typedef struct Tox_Event_Friend_Read_Receipt Tox_Event_Friend_Read_Receipt;
uint32_t tox_event_friend_read_receipt_get_friend_number(
    const Tox_Event_Friend_Read_Receipt *friend_read_receipt);
uint32_t tox_event_friend_read_receipt_get_message_id(
    const Tox_Event_Friend_Read_Receipt *friend_read_receipt);

typedef struct Tox_Event_Friend_Request Tox_Event_Friend_Request;
const uint8_t *tox_event_friend_request_get_message(
    const Tox_Event_Friend_Request *friend_request);
const uint8_t *tox_event_friend_request_get_public_key(
    const Tox_Event_Friend_Request *friend_request);
uint32_t tox_event_friend_request_get_message_length(
    const Tox_Event_Friend_Request *friend_request);

typedef struct Tox_Event_Friend_Status Tox_Event_Friend_Status;
Tox_User_Status tox_event_friend_status_get_status(
    const Tox_Event_Friend_Status *friend_status);
uint32_t tox_event_friend_status_get_friend_number(
    const Tox_Event_Friend_Status *friend_status);

typedef struct Tox_Event_Friend_Status_Message Tox_Event_Friend_Status_Message;
const uint8_t *tox_event_friend_status_message_get_message(
    const Tox_Event_Friend_Status_Message *friend_status_message);
uint32_t tox_event_friend_status_message_get_message_length(
    const Tox_Event_Friend_Status_Message *friend_status_message);
uint32_t tox_event_friend_status_message_get_friend_number(
    const Tox_Event_Friend_Status_Message *friend_status_message);

typedef struct Tox_Event_Friend_Typing Tox_Event_Friend_Typing;
bool tox_event_friend_typing_get_typing(
    const Tox_Event_Friend_Typing *friend_typing);
uint32_t tox_event_friend_typing_get_friend_number(
    const Tox_Event_Friend_Typing *friend_typing);

typedef struct Tox_Event_Self_Connection_Status Tox_Event_Self_Connection_Status;
Tox_Connection tox_event_self_connection_status_get_connection_status(
    const Tox_Event_Self_Connection_Status *self_connection_status);


typedef enum Tox_Event {
    TOX_EVENT_SELF_CONNECTION_STATUS        = 0,

    TOX_EVENT_FRIEND_REQUEST                = 1,
    TOX_EVENT_FRIEND_CONNECTION_STATUS      = 2,
    TOX_EVENT_FRIEND_LOSSY_PACKET           = 3,
    TOX_EVENT_FRIEND_LOSSLESS_PACKET        = 4,

    TOX_EVENT_FRIEND_NAME                   = 5,
    TOX_EVENT_FRIEND_STATUS                 = 6,
    TOX_EVENT_FRIEND_STATUS_MESSAGE         = 7,

    TOX_EVENT_FRIEND_MESSAGE                = 8,
    TOX_EVENT_FRIEND_READ_RECEIPT           = 9,
    TOX_EVENT_FRIEND_TYPING                 = 10,

    TOX_EVENT_FILE_CHUNK_REQUEST            = 11,
    TOX_EVENT_FILE_RECV                     = 12,
    TOX_EVENT_FILE_RECV_CHUNK               = 13,
    TOX_EVENT_FILE_RECV_CONTROL             = 14,

    TOX_EVENT_CONFERENCE_INVITE             = 15,
    TOX_EVENT_CONFERENCE_CONNECTED          = 16,
    TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED  = 17,
    TOX_EVENT_CONFERENCE_PEER_NAME          = 18,
    TOX_EVENT_CONFERENCE_TITLE              = 19,

    TOX_EVENT_CONFERENCE_MESSAGE            = 20,
} Tox_Event;

/**
 * Container object for all Tox core events.
 *
 * This is an immutable object once created.
 */
typedef struct Tox_Events Tox_Events;

uint32_t tox_events_get_conference_connected_size(const Tox_Events *events);
uint32_t tox_events_get_conference_invite_size(const Tox_Events *events);
uint32_t tox_events_get_conference_message_size(const Tox_Events *events);
uint32_t tox_events_get_conference_peer_list_changed_size(const Tox_Events *events);
uint32_t tox_events_get_conference_peer_name_size(const Tox_Events *events);
uint32_t tox_events_get_conference_title_size(const Tox_Events *events);
uint32_t tox_events_get_file_chunk_request_size(const Tox_Events *events);
uint32_t tox_events_get_file_recv_chunk_size(const Tox_Events *events);
uint32_t tox_events_get_file_recv_control_size(const Tox_Events *events);
uint32_t tox_events_get_file_recv_size(const Tox_Events *events);
uint32_t tox_events_get_friend_connection_status_size(const Tox_Events *events);
uint32_t tox_events_get_friend_lossless_packet_size(const Tox_Events *events);
uint32_t tox_events_get_friend_lossy_packet_size(const Tox_Events *events);
uint32_t tox_events_get_friend_message_size(const Tox_Events *events);
uint32_t tox_events_get_friend_name_size(const Tox_Events *events);
uint32_t tox_events_get_friend_read_receipt_size(const Tox_Events *events);
uint32_t tox_events_get_friend_request_size(const Tox_Events *events);
uint32_t tox_events_get_friend_status_message_size(const Tox_Events *events);
uint32_t tox_events_get_friend_status_size(const Tox_Events *events);
uint32_t tox_events_get_friend_typing_size(const Tox_Events *events);
uint32_t tox_events_get_self_connection_status_size(const Tox_Events *events);

const Tox_Event_Conference_Connected *tox_events_get_conference_connected(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Conference_Invite *tox_events_get_conference_invite(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Conference_Message *tox_events_get_conference_message(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Conference_Peer_List_Changed *tox_events_get_conference_peer_list_changed(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Conference_Peer_Name *tox_events_get_conference_peer_name(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Conference_Title *tox_events_get_conference_title(
    const Tox_Events *events, uint32_t index);
const Tox_Event_File_Chunk_Request *tox_events_get_file_chunk_request(
    const Tox_Events *events, uint32_t index);
const Tox_Event_File_Recv_Chunk *tox_events_get_file_recv_chunk(
    const Tox_Events *events, uint32_t index);
const Tox_Event_File_Recv_Control *tox_events_get_file_recv_control(
    const Tox_Events *events, uint32_t index);
const Tox_Event_File_Recv *tox_events_get_file_recv(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Connection_Status *tox_events_get_friend_connection_status(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Lossless_Packet *tox_events_get_friend_lossless_packet(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Lossy_Packet *tox_events_get_friend_lossy_packet(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Message *tox_events_get_friend_message(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Name *tox_events_get_friend_name(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Read_Receipt *tox_events_get_friend_read_receipt(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Request *tox_events_get_friend_request(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Status_Message *tox_events_get_friend_status_message(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Status *tox_events_get_friend_status(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Friend_Typing *tox_events_get_friend_typing(
    const Tox_Events *events, uint32_t index);
const Tox_Event_Self_Connection_Status *tox_events_get_self_connection_status(
    const Tox_Events *events, uint32_t index);

/**
 * Initialise the events recording system.
 *
 * All callbacks will be set to handlers inside the events recording system.
 * After this function returns, no user-defined event handlers will be
 * invoked. If the client sets their own handlers after calling this function,
 * the events associated with that handler will not be recorded.
 */
void tox_events_init(Tox *tox);

typedef enum Tox_Err_Events_Iterate {
    /**
     * The function returned successfully.
     */
    TOX_ERR_EVENTS_ITERATE_OK,

    /**
     * The function failed to allocate enough memory to store the events.
     *
     * Some events may still be stored if the return value is NULL. The events
     * object will always be valid (or NULL) but if this error code is set,
     * the function may have missed some events.
     */
    TOX_ERR_EVENTS_ITERATE_MALLOC,
} Tox_Err_Events_Iterate;

/**
 * Run a single `tox_iterate` iteration and record all the events.
 *
 * If allocation of the top level events object fails, this returns NULL.
 * Otherwise it returns an object with the recorded events in it. If an
 * allocation fails while recording events, some events may be dropped.
 *
 * If @p fail_hard is `true`, any failure will result in NULL, so all recorded
 * events will be dropped.
 *
 * The result must be freed using `tox_events_free`.
 *
 * @param tox The Tox instance to iterate on.
 * @param fail_hard Drop all events when any allocation fails.
 * @param error An error code. Will be set to OK on success.
 *
 * @return the recorded events structure.
 */
Tox_Events *tox_events_iterate(Tox *tox, bool fail_hard, Tox_Err_Events_Iterate *error);

/**
 * Frees all memory associated with the events structure.
 *
 * All pointers into this object and its sub-objects, including byte buffers,
 * will be invalid once this function returns.
 */
void tox_events_free(Tox_Events *events);

uint32_t tox_events_bytes_size(const Tox_Events *events);
void tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes);

Tox_Events *tox_events_load(const uint8_t *bytes, uint32_t bytes_size);

bool tox_events_equal(const Tox_Events *a, const Tox_Events *b);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_EVENTS_H
