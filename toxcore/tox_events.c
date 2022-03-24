/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_events.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bin_unpack.h"
#include "ccompat.h"
#include "events/events_alloc.h"
#include "tox.h"


/*****************************************************
 *
 * :: Set up event handlers.
 *
 *****************************************************/


void tox_events_init(Tox *tox)
{
    tox_callback_conference_connected(tox, tox_events_handle_conference_connected);
    tox_callback_conference_invite(tox, tox_events_handle_conference_invite);
    tox_callback_conference_message(tox, tox_events_handle_conference_message);
    tox_callback_conference_peer_list_changed(tox, tox_events_handle_conference_peer_list_changed);
    tox_callback_conference_peer_name(tox, tox_events_handle_conference_peer_name);
    tox_callback_conference_title(tox, tox_events_handle_conference_title);
    tox_callback_file_chunk_request(tox, tox_events_handle_file_chunk_request);
    tox_callback_file_recv_chunk(tox, tox_events_handle_file_recv_chunk);
    tox_callback_file_recv_control(tox, tox_events_handle_file_recv_control);
    tox_callback_file_recv(tox, tox_events_handle_file_recv);
    tox_callback_friend_connection_status(tox, tox_events_handle_friend_connection_status);
    tox_callback_friend_lossless_packet(tox, tox_events_handle_friend_lossless_packet);
    tox_callback_friend_lossy_packet(tox, tox_events_handle_friend_lossy_packet);
    tox_callback_friend_message(tox, tox_events_handle_friend_message);
    tox_callback_friend_name(tox, tox_events_handle_friend_name);
    tox_callback_friend_read_receipt(tox, tox_events_handle_friend_read_receipt);
    tox_callback_friend_request(tox, tox_events_handle_friend_request);
    tox_callback_friend_status_message(tox, tox_events_handle_friend_status_message);
    tox_callback_friend_status(tox, tox_events_handle_friend_status);
    tox_callback_friend_typing(tox, tox_events_handle_friend_typing);
    tox_callback_self_connection_status(tox, tox_events_handle_self_connection_status);
}

Tox_Events *tox_events_iterate(Tox *tox, bool fail_hard, Tox_Err_Events_Iterate *error)
{
    Tox_Events_State state = {TOX_ERR_EVENTS_ITERATE_OK};
    tox_iterate(tox, &state);

    if (error != nullptr) {
        *error = state.error;
    }

    if (fail_hard && state.error != TOX_ERR_EVENTS_ITERATE_OK) {
        tox_events_free(state.events);
        return nullptr;
    }

    return state.events;
}

bool tox_events_pack(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t count = tox_events_get_conference_connected_size(events)
                           + tox_events_get_conference_invite_size(events)
                           + tox_events_get_conference_message_size(events)
                           + tox_events_get_conference_peer_list_changed_size(events)
                           + tox_events_get_conference_peer_name_size(events)
                           + tox_events_get_conference_title_size(events)
                           + tox_events_get_file_chunk_request_size(events)
                           + tox_events_get_file_recv_chunk_size(events)
                           + tox_events_get_file_recv_control_size(events)
                           + tox_events_get_file_recv_size(events)
                           + tox_events_get_friend_connection_status_size(events)
                           + tox_events_get_friend_lossless_packet_size(events)
                           + tox_events_get_friend_lossy_packet_size(events)
                           + tox_events_get_friend_message_size(events)
                           + tox_events_get_friend_name_size(events)
                           + tox_events_get_friend_read_receipt_size(events)
                           + tox_events_get_friend_request_size(events)
                           + tox_events_get_friend_status_message_size(events)
                           + tox_events_get_friend_status_size(events)
                           + tox_events_get_friend_typing_size(events)
                           + tox_events_get_self_connection_status_size(events);

    return bin_pack_array(bp, count)
           && tox_events_pack_conference_connected(events, bp)
           && tox_events_pack_conference_invite(events, bp)
           && tox_events_pack_conference_message(events, bp)
           && tox_events_pack_conference_peer_list_changed(events, bp)
           && tox_events_pack_conference_peer_name(events, bp)
           && tox_events_pack_conference_title(events, bp)
           && tox_events_pack_file_chunk_request(events, bp)
           && tox_events_pack_file_recv_chunk(events, bp)
           && tox_events_pack_file_recv_control(events, bp)
           && tox_events_pack_file_recv(events, bp)
           && tox_events_pack_friend_connection_status(events, bp)
           && tox_events_pack_friend_lossless_packet(events, bp)
           && tox_events_pack_friend_lossy_packet(events, bp)
           && tox_events_pack_friend_message(events, bp)
           && tox_events_pack_friend_name(events, bp)
           && tox_events_pack_friend_read_receipt(events, bp)
           && tox_events_pack_friend_request(events, bp)
           && tox_events_pack_friend_status_message(events, bp)
           && tox_events_pack_friend_status(events, bp)
           && tox_events_pack_friend_typing(events, bp)
           && tox_events_pack_self_connection_status(events, bp);
}

non_null()
static bool tox_event_unpack(Tox_Events *events, Bin_Unpack *bu)
{
    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    if (size != 2) {
        return false;
    }

    uint8_t type;
    if (!bin_unpack_u08(bu, &type)) {
        return false;
    }

    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_events_unpack_conference_connected(events, bu);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_events_unpack_conference_invite(events, bu);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_events_unpack_conference_message(events, bu);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_events_unpack_conference_peer_list_changed(events, bu);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_events_unpack_conference_peer_name(events, bu);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_events_unpack_conference_title(events, bu);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_events_unpack_file_chunk_request(events, bu);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_events_unpack_file_recv_chunk(events, bu);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_events_unpack_file_recv_control(events, bu);

        case TOX_EVENT_FILE_RECV:
            return tox_events_unpack_file_recv(events, bu);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_events_unpack_friend_connection_status(events, bu);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_events_unpack_friend_lossless_packet(events, bu);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_events_unpack_friend_lossy_packet(events, bu);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_events_unpack_friend_message(events, bu);

        case TOX_EVENT_FRIEND_NAME:
            return tox_events_unpack_friend_name(events, bu);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_events_unpack_friend_read_receipt(events, bu);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_events_unpack_friend_request(events, bu);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_events_unpack_friend_status_message(events, bu);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_events_unpack_friend_status(events, bu);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_events_unpack_friend_typing(events, bu);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_events_unpack_self_connection_status(events, bu);

        default:
            return false;
    }

    return true;
}

bool tox_events_unpack(Tox_Events *events, Bin_Unpack *bu)
{
    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_unpack(events, bu)) {
            return false;
        }
    }

    return true;
}

non_null(1) nullable(2)
static bool tox_events_bin_pack_handler(Bin_Pack *bp, const void *obj)
{
    return tox_events_pack((const Tox_Events *)obj, bp);
}

uint32_t tox_events_bytes_size(const Tox_Events *events)
{
    return bin_pack_obj_size(tox_events_bin_pack_handler, events);
}

void tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes)
{
    bin_pack_obj(tox_events_bin_pack_handler, events, bytes, UINT32_MAX);
}

Tox_Events *tox_events_load(const uint8_t *bytes, uint32_t bytes_size)
{
    Bin_Unpack *bu = bin_unpack_new(bytes, bytes_size);

    if (bu == nullptr) {
        return nullptr;
    }

    Tox_Events *events = (Tox_Events *)calloc(1, sizeof(Tox_Events));

    if (events == nullptr) {
        bin_unpack_free(bu);
        return nullptr;
    }

    *events = (Tox_Events) {
        nullptr
    };

    if (!tox_events_unpack(events, bu)) {
        tox_events_free(events);
        bin_unpack_free(bu);
        return nullptr;
    }

    bin_unpack_free(bu);
    return events;
}

bool tox_events_equal(const Tox_Events *a, const Tox_Events *b)
{
    const uint32_t a_size = tox_events_bytes_size(a);
    const uint32_t b_size = tox_events_bytes_size(b);

    if (a_size != b_size) {
        return false;
    }

    uint8_t *a_bytes = (uint8_t *)malloc(a_size);
    uint8_t *b_bytes = (uint8_t *)malloc(b_size);

    if (a_bytes == nullptr || b_bytes == nullptr) {
        free(b_bytes);
        free(a_bytes);
        return false;
    }

    tox_events_get_bytes(a, a_bytes);
    tox_events_get_bytes(b, b_bytes);

    const bool ret = memcmp(a_bytes, b_bytes, a_size) == 0;

    free(b_bytes);
    free(a_bytes);

    return ret;
}
