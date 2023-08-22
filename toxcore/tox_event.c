/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_event.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bin_unpack.h"
#include "ccompat.h"
#include "events/events_alloc.h"
#include "tox.h"

const char *tox_event_type_to_string(Tox_Event_Type type)
{
    switch (type) {
        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return "TOX_EVENT_SELF_CONNECTION_STATUS";

        case TOX_EVENT_FRIEND_REQUEST:
            return "TOX_EVENT_FRIEND_REQUEST";

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return "TOX_EVENT_FRIEND_CONNECTION_STATUS";

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return "TOX_EVENT_FRIEND_LOSSY_PACKET";

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return "TOX_EVENT_FRIEND_LOSSLESS_PACKET";

        case TOX_EVENT_FRIEND_NAME:
            return "TOX_EVENT_FRIEND_NAME";

        case TOX_EVENT_FRIEND_STATUS:
            return "TOX_EVENT_FRIEND_STATUS";

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return "TOX_EVENT_FRIEND_STATUS_MESSAGE";

        case TOX_EVENT_FRIEND_MESSAGE:
            return "TOX_EVENT_FRIEND_MESSAGE";

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return "TOX_EVENT_FRIEND_READ_RECEIPT";

        case TOX_EVENT_FRIEND_TYPING:
            return "TOX_EVENT_FRIEND_TYPING";

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return "TOX_EVENT_FILE_CHUNK_REQUEST";

        case TOX_EVENT_FILE_RECV:
            return "TOX_EVENT_FILE_RECV";

        case TOX_EVENT_FILE_RECV_CHUNK:
            return "TOX_EVENT_FILE_RECV_CHUNK";

        case TOX_EVENT_FILE_RECV_CONTROL:
            return "TOX_EVENT_FILE_RECV_CONTROL";

        case TOX_EVENT_CONFERENCE_INVITE:
            return "TOX_EVENT_CONFERENCE_INVITE";

        case TOX_EVENT_CONFERENCE_CONNECTED:
            return "TOX_EVENT_CONFERENCE_CONNECTED";

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return "TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED";

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return "TOX_EVENT_CONFERENCE_PEER_NAME";

        case TOX_EVENT_CONFERENCE_TITLE:
            return "TOX_EVENT_CONFERENCE_TITLE";

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return "TOX_EVENT_CONFERENCE_MESSAGE";

        case TOX_EVENT_INVALID:
            return "TOX_EVENT_INVALID";
    }

    return "<invalid Tox_Event_Type>";
}

Tox_Event_Type tox_event_get_type(const Tox_Event *event)
{
    assert(event != nullptr);
    return event->type;
}

bool tox_event_construct(Tox_Event *event, Tox_Event_Type type, const Memory *mem)
{
    event->type = type;
    event->data.value = nullptr;

    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            event->data.conference_connected = tox_event_conference_connected_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            event->data.conference_invite = tox_event_conference_invite_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            event->data.conference_message = tox_event_conference_message_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            event->data.conference_peer_list_changed = tox_event_conference_peer_list_changed_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            event->data.conference_peer_name = tox_event_conference_peer_name_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            event->data.conference_title = tox_event_conference_title_new(mem);
            break;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            event->data.file_chunk_request = tox_event_file_chunk_request_new(mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            event->data.file_recv_chunk = tox_event_file_recv_chunk_new(mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            event->data.file_recv_control = tox_event_file_recv_control_new(mem);
            break;
        }

        case TOX_EVENT_FILE_RECV: {
            event->data.file_recv = tox_event_file_recv_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            event->data.friend_connection_status = tox_event_friend_connection_status_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            event->data.friend_lossless_packet = tox_event_friend_lossless_packet_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            event->data.friend_lossy_packet = tox_event_friend_lossy_packet_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            event->data.friend_message = tox_event_friend_message_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_NAME: {
            event->data.friend_name = tox_event_friend_name_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            event->data.friend_read_receipt = tox_event_friend_read_receipt_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            event->data.friend_request = tox_event_friend_request_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            event->data.friend_status = tox_event_friend_status_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            event->data.friend_status_message = tox_event_friend_status_message_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            event->data.friend_typing = tox_event_friend_typing_new(mem);
            break;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            event->data.self_connection_status = tox_event_self_connection_status_new(mem);
            break;
        }

        case TOX_EVENT_INVALID:
            return false;
    }

    return event->data.value != nullptr;
}

void tox_event_destruct(Tox_Event *event, const Memory *mem)
{
    if (event == nullptr) {
        return;
    }

    switch (event->type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            tox_event_conference_connected_free(event->data.conference_connected, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            tox_event_conference_invite_free(event->data.conference_invite, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            tox_event_conference_message_free(event->data.conference_message, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            tox_event_conference_peer_list_changed_free(event->data.conference_peer_list_changed, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            tox_event_conference_peer_name_free(event->data.conference_peer_name, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            tox_event_conference_title_free(event->data.conference_title, mem);
            break;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            tox_event_file_chunk_request_free(event->data.file_chunk_request, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            tox_event_file_recv_chunk_free(event->data.file_recv_chunk, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            tox_event_file_recv_control_free(event->data.file_recv_control, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV: {
            tox_event_file_recv_free(event->data.file_recv, mem);
            break;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            tox_event_friend_connection_status_free(event->data.friend_connection_status, mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            tox_event_friend_lossless_packet_free(event->data.friend_lossless_packet, mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            tox_event_friend_lossy_packet_free(event->data.friend_lossy_packet, mem);
            break;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            tox_event_friend_message_free(event->data.friend_message, mem);
            break;
        }

        case TOX_EVENT_FRIEND_NAME: {
            tox_event_friend_name_free(event->data.friend_name, mem);
            break;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            tox_event_friend_read_receipt_free(event->data.friend_read_receipt, mem);
            break;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            tox_event_friend_request_free(event->data.friend_request, mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            tox_event_friend_status_free(event->data.friend_status, mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            tox_event_friend_status_message_free(event->data.friend_status_message, mem);
            break;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            tox_event_friend_typing_free(event->data.friend_typing, mem);
            break;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            tox_event_self_connection_status_free(event->data.self_connection_status, mem);
            break;
        }

        case TOX_EVENT_INVALID: {
            break;
        }
    }

    event->data.value = nullptr;
}

bool tox_event_pack(const Tox_Event *event, Bin_Pack *bp)
{
    assert(event->type != TOX_EVENT_INVALID);

    switch (event->type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_event_conference_connected_pack(event->data.conference_connected, bp);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_event_conference_invite_pack(event->data.conference_invite, bp);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_event_conference_message_pack(event->data.conference_message, bp);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_event_conference_peer_list_changed_pack(event->data.conference_peer_list_changed, bp);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_event_conference_peer_name_pack(event->data.conference_peer_name, bp);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_event_conference_title_pack(event->data.conference_title, bp);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_event_file_chunk_request_pack(event->data.file_chunk_request, bp);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_event_file_recv_chunk_pack(event->data.file_recv_chunk, bp);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_event_file_recv_control_pack(event->data.file_recv_control, bp);

        case TOX_EVENT_FILE_RECV:
            return tox_event_file_recv_pack(event->data.file_recv, bp);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_event_friend_connection_status_pack(event->data.friend_connection_status, bp);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_event_friend_lossless_packet_pack(event->data.friend_lossless_packet, bp);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_event_friend_lossy_packet_pack(event->data.friend_lossy_packet, bp);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_event_friend_message_pack(event->data.friend_message, bp);

        case TOX_EVENT_FRIEND_NAME:
            return tox_event_friend_name_pack(event->data.friend_name, bp);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_event_friend_read_receipt_pack(event->data.friend_read_receipt, bp);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_event_friend_request_pack(event->data.friend_request, bp);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_event_friend_status_pack(event->data.friend_status, bp);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_event_friend_status_message_pack(event->data.friend_status_message, bp);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_event_friend_typing_pack(event->data.friend_typing, bp);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_event_self_connection_status_pack(event->data.self_connection_status, bp);

        case TOX_EVENT_INVALID:
            return false;
    }

    return false;
}

non_null()
static bool tox_event_type_from_int(uint32_t value, Tox_Event_Type *out)
{
    switch (value) {
        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            *out = TOX_EVENT_SELF_CONNECTION_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            *out = TOX_EVENT_FRIEND_REQUEST;
            return true;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            *out = TOX_EVENT_FRIEND_CONNECTION_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            *out = TOX_EVENT_FRIEND_LOSSY_PACKET;
            return true;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            *out = TOX_EVENT_FRIEND_LOSSLESS_PACKET;
            return true;
        }

        case TOX_EVENT_FRIEND_NAME: {
            *out = TOX_EVENT_FRIEND_NAME;
            return true;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            *out = TOX_EVENT_FRIEND_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            *out = TOX_EVENT_FRIEND_STATUS_MESSAGE;
            return true;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            *out = TOX_EVENT_FRIEND_MESSAGE;
            return true;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            *out = TOX_EVENT_FRIEND_READ_RECEIPT;
            return true;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            *out = TOX_EVENT_FRIEND_TYPING;
            return true;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            *out = TOX_EVENT_FILE_CHUNK_REQUEST;
            return true;
        }

        case TOX_EVENT_FILE_RECV: {
            *out = TOX_EVENT_FILE_RECV;
            return true;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            *out = TOX_EVENT_FILE_RECV_CHUNK;
            return true;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            *out = TOX_EVENT_FILE_RECV_CONTROL;
            return true;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            *out = TOX_EVENT_CONFERENCE_INVITE;
            return true;
        }

        case TOX_EVENT_CONFERENCE_CONNECTED: {
            *out = TOX_EVENT_CONFERENCE_CONNECTED;
            return true;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            *out = TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED;
            return true;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            *out = TOX_EVENT_CONFERENCE_PEER_NAME;
            return true;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            *out = TOX_EVENT_CONFERENCE_TITLE;
            return true;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            *out = TOX_EVENT_CONFERENCE_MESSAGE;
            return true;
        }

        case TOX_EVENT_INVALID: {
            *out = TOX_EVENT_INVALID;
            return true;
        }

        default: {
            *out = TOX_EVENT_INVALID;
            return false;
        }
    }
}

non_null()
static bool tox_event_type_unpack(Bin_Unpack *bu, Tox_Event_Type *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_event_type_from_int(u32, val);
}

bool tox_event_unpack_into(Tox_Event *event, Bin_Unpack *bu, const Memory *mem)
{
    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    if (size != 2) {
        return false;
    }

    Tox_Event_Type type;
    if (!tox_event_type_unpack(bu, &type)) {
        return false;
    }

    event->type = type;

    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_event_conference_connected_unpack(&event->data.conference_connected, bu, mem);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_event_conference_invite_unpack(&event->data.conference_invite, bu, mem);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_event_conference_message_unpack(&event->data.conference_message, bu, mem);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_event_conference_peer_list_changed_unpack(&event->data.conference_peer_list_changed, bu, mem);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_event_conference_peer_name_unpack(&event->data.conference_peer_name, bu, mem);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_event_conference_title_unpack(&event->data.conference_title, bu, mem);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_event_file_chunk_request_unpack(&event->data.file_chunk_request, bu, mem);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_event_file_recv_chunk_unpack(&event->data.file_recv_chunk, bu, mem);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_event_file_recv_control_unpack(&event->data.file_recv_control, bu, mem);

        case TOX_EVENT_FILE_RECV:
            return tox_event_file_recv_unpack(&event->data.file_recv, bu, mem);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_event_friend_connection_status_unpack(&event->data.friend_connection_status, bu, mem);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_event_friend_lossless_packet_unpack(&event->data.friend_lossless_packet, bu, mem);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_event_friend_lossy_packet_unpack(&event->data.friend_lossy_packet, bu, mem);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_event_friend_message_unpack(&event->data.friend_message, bu, mem);

        case TOX_EVENT_FRIEND_NAME:
            return tox_event_friend_name_unpack(&event->data.friend_name, bu, mem);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_event_friend_read_receipt_unpack(&event->data.friend_read_receipt, bu, mem);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_event_friend_request_unpack(&event->data.friend_request, bu, mem);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_event_friend_status_message_unpack(&event->data.friend_status_message, bu, mem);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_event_friend_status_unpack(&event->data.friend_status, bu, mem);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_event_friend_typing_unpack(&event->data.friend_typing, bu, mem);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_event_self_connection_status_unpack(&event->data.self_connection_status, bu, mem);

        case TOX_EVENT_INVALID:
            return false;
    }

    return false;
}
