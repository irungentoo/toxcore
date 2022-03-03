/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_dispatch.h"

#include <stdlib.h>

#include "ccompat.h"

struct Tox_Dispatch {
    tox_events_conference_connected_cb *conference_connected_callback;
    tox_events_conference_invite_cb *conference_invite_callback;
    tox_events_conference_message_cb *conference_message_callback;
    tox_events_conference_peer_list_changed_cb *conference_peer_list_changed_callback;
    tox_events_conference_peer_name_cb *conference_peer_name_callback;
    tox_events_conference_title_cb *conference_title_callback;
    tox_events_file_chunk_request_cb *file_chunk_request_callback;
    tox_events_file_recv_cb *file_recv_callback;
    tox_events_file_recv_chunk_cb *file_recv_chunk_callback;
    tox_events_file_recv_control_cb *file_recv_control_callback;
    tox_events_friend_connection_status_cb *friend_connection_status_callback;
    tox_events_friend_lossless_packet_cb *friend_lossless_packet_callback;
    tox_events_friend_lossy_packet_cb *friend_lossy_packet_callback;
    tox_events_friend_message_cb *friend_message_callback;
    tox_events_friend_name_cb *friend_name_callback;
    tox_events_friend_read_receipt_cb *friend_read_receipt_callback;
    tox_events_friend_request_cb *friend_request_callback;
    tox_events_friend_status_cb *friend_status_callback;
    tox_events_friend_status_message_cb *friend_status_message_callback;
    tox_events_friend_typing_cb *friend_typing_callback;
    tox_events_self_connection_status_cb *self_connection_status_callback;
};

Tox_Dispatch *tox_dispatch_new(Tox_Err_Dispatch_New *error)
{
    Tox_Dispatch *dispatch = (Tox_Dispatch *)calloc(1, sizeof(Tox_Dispatch));

    if (dispatch == nullptr) {
        if (error != nullptr) {
            *error = TOX_ERR_DISPATCH_NEW_MALLOC;
        }

        return nullptr;
    }

    *dispatch = (Tox_Dispatch) {
        nullptr
    };
    if (error != nullptr) {
        *error = TOX_ERR_DISPATCH_NEW_OK;
    }
    return dispatch;
}

void tox_dispatch_free(Tox_Dispatch *dispatch)
{
    free(dispatch);
}

void tox_events_callback_conference_connected(
    Tox_Dispatch *dispatch, tox_events_conference_connected_cb *callback)
{
    dispatch->conference_connected_callback = callback;
}
void tox_events_callback_conference_invite(
    Tox_Dispatch *dispatch, tox_events_conference_invite_cb *callback)
{
    dispatch->conference_invite_callback = callback;
}
void tox_events_callback_conference_message(
    Tox_Dispatch *dispatch, tox_events_conference_message_cb *callback)
{
    dispatch->conference_message_callback = callback;
}
void tox_events_callback_conference_peer_list_changed(
    Tox_Dispatch *dispatch, tox_events_conference_peer_list_changed_cb *callback)
{
    dispatch->conference_peer_list_changed_callback = callback;
}
void tox_events_callback_conference_peer_name(
    Tox_Dispatch *dispatch, tox_events_conference_peer_name_cb *callback)
{
    dispatch->conference_peer_name_callback = callback;
}
void tox_events_callback_conference_title(
    Tox_Dispatch *dispatch, tox_events_conference_title_cb *callback)
{
    dispatch->conference_title_callback = callback;
}
void tox_events_callback_file_chunk_request(
    Tox_Dispatch *dispatch, tox_events_file_chunk_request_cb *callback)
{
    dispatch->file_chunk_request_callback = callback;
}
void tox_events_callback_file_recv(
    Tox_Dispatch *dispatch, tox_events_file_recv_cb *callback)
{
    dispatch->file_recv_callback = callback;
}
void tox_events_callback_file_recv_chunk(
    Tox_Dispatch *dispatch, tox_events_file_recv_chunk_cb *callback)
{
    dispatch->file_recv_chunk_callback = callback;
}
void tox_events_callback_file_recv_control(
    Tox_Dispatch *dispatch, tox_events_file_recv_control_cb *callback)
{
    dispatch->file_recv_control_callback = callback;
}
void tox_events_callback_friend_connection_status(
    Tox_Dispatch *dispatch, tox_events_friend_connection_status_cb *callback)
{
    dispatch->friend_connection_status_callback = callback;
}
void tox_events_callback_friend_lossless_packet(
    Tox_Dispatch *dispatch, tox_events_friend_lossless_packet_cb *callback)
{
    dispatch->friend_lossless_packet_callback = callback;
}
void tox_events_callback_friend_lossy_packet(
    Tox_Dispatch *dispatch, tox_events_friend_lossy_packet_cb *callback)
{
    dispatch->friend_lossy_packet_callback = callback;
}
void tox_events_callback_friend_message(
    Tox_Dispatch *dispatch, tox_events_friend_message_cb *callback)
{
    dispatch->friend_message_callback = callback;
}
void tox_events_callback_friend_name(
    Tox_Dispatch *dispatch, tox_events_friend_name_cb *callback)
{
    dispatch->friend_name_callback = callback;
}
void tox_events_callback_friend_read_receipt(
    Tox_Dispatch *dispatch, tox_events_friend_read_receipt_cb *callback)
{
    dispatch->friend_read_receipt_callback = callback;
}
void tox_events_callback_friend_request(
    Tox_Dispatch *dispatch, tox_events_friend_request_cb *callback)
{
    dispatch->friend_request_callback = callback;
}
void tox_events_callback_friend_status(
    Tox_Dispatch *dispatch, tox_events_friend_status_cb *callback)
{
    dispatch->friend_status_callback = callback;
}
void tox_events_callback_friend_status_message(
    Tox_Dispatch *dispatch, tox_events_friend_status_message_cb *callback)
{
    dispatch->friend_status_message_callback = callback;
}
void tox_events_callback_friend_typing(
    Tox_Dispatch *dispatch, tox_events_friend_typing_cb *callback)
{
    dispatch->friend_typing_callback = callback;
}
void tox_events_callback_self_connection_status(
    Tox_Dispatch *dispatch, tox_events_self_connection_status_cb *callback)
{
    dispatch->self_connection_status_callback = callback;
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_conference_connected(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_conference_connected_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->conference_connected_callback != nullptr) {
            dispatch->conference_connected_callback(
                tox, tox_events_get_conference_connected(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_conference_invite(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_conference_invite_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->conference_invite_callback != nullptr) {
            dispatch->conference_invite_callback(
                tox, tox_events_get_conference_invite(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_conference_message(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_conference_message_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->conference_message_callback != nullptr) {
            dispatch->conference_message_callback(
                tox, tox_events_get_conference_message(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_conference_peer_list_changed(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_conference_peer_list_changed_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->conference_peer_list_changed_callback != nullptr) {
            dispatch->conference_peer_list_changed_callback(
                tox, tox_events_get_conference_peer_list_changed(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_conference_peer_name(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_conference_peer_name_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->conference_peer_name_callback != nullptr) {
            dispatch->conference_peer_name_callback(
                tox, tox_events_get_conference_peer_name(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_conference_title(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_conference_title_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->conference_title_callback != nullptr) {
            dispatch->conference_title_callback(
                tox, tox_events_get_conference_title(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_file_chunk_request(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_file_chunk_request_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->file_chunk_request_callback != nullptr) {
            dispatch->file_chunk_request_callback(
                tox, tox_events_get_file_chunk_request(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_file_recv(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_file_recv_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->file_recv_callback != nullptr) {
            dispatch->file_recv_callback(
                tox, tox_events_get_file_recv(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_file_recv_chunk(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_file_recv_chunk_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->file_recv_chunk_callback != nullptr) {
            dispatch->file_recv_chunk_callback(
                tox, tox_events_get_file_recv_chunk(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_file_recv_control(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_file_recv_control_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->file_recv_control_callback != nullptr) {
            dispatch->file_recv_control_callback(
                tox, tox_events_get_file_recv_control(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_connection_status(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_connection_status_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_connection_status_callback != nullptr) {
            dispatch->friend_connection_status_callback(
                tox, tox_events_get_friend_connection_status(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_lossless_packet(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_lossless_packet_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_lossless_packet_callback != nullptr) {
            dispatch->friend_lossless_packet_callback(
                tox, tox_events_get_friend_lossless_packet(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_lossy_packet(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_lossy_packet_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_lossy_packet_callback != nullptr) {
            dispatch->friend_lossy_packet_callback(
                tox, tox_events_get_friend_lossy_packet(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_message(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_message_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_message_callback != nullptr) {
            dispatch->friend_message_callback(
                tox, tox_events_get_friend_message(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_name(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_name_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_name_callback != nullptr) {
            dispatch->friend_name_callback(
                tox, tox_events_get_friend_name(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_read_receipt(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_read_receipt_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_read_receipt_callback != nullptr) {
            dispatch->friend_read_receipt_callback(
                tox, tox_events_get_friend_read_receipt(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_request(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_request_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_request_callback != nullptr) {
            dispatch->friend_request_callback(
                tox, tox_events_get_friend_request(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_status(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_status_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_status_callback != nullptr) {
            dispatch->friend_status_callback(
                tox, tox_events_get_friend_status(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_status_message(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_status_message_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_status_message_callback != nullptr) {
            dispatch->friend_status_message_callback(
                tox, tox_events_get_friend_status_message(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_friend_typing(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_friend_typing_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->friend_typing_callback != nullptr) {
            dispatch->friend_typing_callback(
                tox, tox_events_get_friend_typing(events, i), user_data);
        }
    }
}

non_null(1, 3) nullable(2, 4)
static void tox_dispatch_invoke_self_connection_status(
    const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    const uint32_t size = tox_events_get_self_connection_status_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (dispatch->self_connection_status_callback != nullptr) {
            dispatch->self_connection_status_callback(
                tox, tox_events_get_self_connection_status(events, i), user_data);
        }
    }
}

void tox_dispatch_invoke(const Tox_Dispatch *dispatch, const Tox_Events *events, Tox *tox, void *user_data)
{
    tox_dispatch_invoke_conference_connected(dispatch, events, tox, user_data);
    tox_dispatch_invoke_conference_invite(dispatch, events, tox, user_data);
    tox_dispatch_invoke_conference_message(dispatch, events, tox, user_data);
    tox_dispatch_invoke_conference_peer_list_changed(dispatch, events, tox, user_data);
    tox_dispatch_invoke_conference_peer_name(dispatch, events, tox, user_data);
    tox_dispatch_invoke_conference_title(dispatch, events, tox, user_data);
    tox_dispatch_invoke_file_chunk_request(dispatch, events, tox, user_data);
    tox_dispatch_invoke_file_recv(dispatch, events, tox, user_data);
    tox_dispatch_invoke_file_recv_chunk(dispatch, events, tox, user_data);
    tox_dispatch_invoke_file_recv_control(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_connection_status(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_lossless_packet(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_lossy_packet(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_message(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_name(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_read_receipt(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_request(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_status(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_status_message(dispatch, events, tox, user_data);
    tox_dispatch_invoke_friend_typing(dispatch, events, tox, user_data);
    tox_dispatch_invoke_self_connection_status(dispatch, events, tox, user_data);
}
