/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_dispatch.h"

#include <stdlib.h>

#include "attributes.h"
#include "ccompat.h"
#include "events/events_alloc.h" // IWYU pragma: keep
#include "tox.h"
#include "tox_event.h"
#include "tox_events.h"

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
    tox_events_group_peer_name_cb *group_peer_name_callback;
    tox_events_group_peer_status_cb *group_peer_status_callback;
    tox_events_group_topic_cb *group_topic_callback;
    tox_events_group_privacy_state_cb *group_privacy_state_callback;
    tox_events_group_voice_state_cb *group_voice_state_callback;
    tox_events_group_topic_lock_cb *group_topic_lock_callback;
    tox_events_group_peer_limit_cb *group_peer_limit_callback;
    tox_events_group_password_cb *group_password_callback;
    tox_events_group_message_cb *group_message_callback;
    tox_events_group_private_message_cb *group_private_message_callback;
    tox_events_group_custom_packet_cb *group_custom_packet_callback;
    tox_events_group_custom_private_packet_cb *group_custom_private_packet_callback;
    tox_events_group_invite_cb *group_invite_callback;
    tox_events_group_peer_join_cb *group_peer_join_callback;
    tox_events_group_peer_exit_cb *group_peer_exit_callback;
    tox_events_group_self_join_cb *group_self_join_callback;
    tox_events_group_join_fail_cb *group_join_fail_callback;
    tox_events_group_moderation_cb *group_moderation_callback;
    tox_events_dht_get_nodes_response_cb *dht_get_nodes_response_callback;
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
void tox_events_callback_group_peer_name(
    Tox_Dispatch *dispatch, tox_events_group_peer_name_cb *callback)
{
    dispatch->group_peer_name_callback = callback;
}
void tox_events_callback_group_peer_status(
    Tox_Dispatch *dispatch, tox_events_group_peer_status_cb *callback)
{
    dispatch->group_peer_status_callback = callback;
}
void tox_events_callback_group_topic(
    Tox_Dispatch *dispatch, tox_events_group_topic_cb *callback)
{
    dispatch->group_topic_callback = callback;
}
void tox_events_callback_group_privacy_state(
    Tox_Dispatch *dispatch, tox_events_group_privacy_state_cb *callback)
{
    dispatch->group_privacy_state_callback = callback;
}
void tox_events_callback_group_voice_state(
    Tox_Dispatch *dispatch, tox_events_group_voice_state_cb *callback)
{
    dispatch->group_voice_state_callback = callback;
}
void tox_events_callback_group_topic_lock(
    Tox_Dispatch *dispatch, tox_events_group_topic_lock_cb *callback)
{
    dispatch->group_topic_lock_callback = callback;
}
void tox_events_callback_group_peer_limit(
    Tox_Dispatch *dispatch, tox_events_group_peer_limit_cb *callback)
{
    dispatch->group_peer_limit_callback = callback;
}
void tox_events_callback_group_password(
    Tox_Dispatch *dispatch, tox_events_group_password_cb *callback)
{
    dispatch->group_password_callback = callback;
}
void tox_events_callback_group_message(
    Tox_Dispatch *dispatch, tox_events_group_message_cb *callback)
{
    dispatch->group_message_callback = callback;
}
void tox_events_callback_group_private_message(
    Tox_Dispatch *dispatch, tox_events_group_private_message_cb *callback)
{
    dispatch->group_private_message_callback = callback;
}
void tox_events_callback_group_custom_packet(
    Tox_Dispatch *dispatch, tox_events_group_custom_packet_cb *callback)
{
    dispatch->group_custom_packet_callback = callback;
}
void tox_events_callback_group_custom_private_packet(
    Tox_Dispatch *dispatch, tox_events_group_custom_private_packet_cb *callback)
{
    dispatch->group_custom_private_packet_callback = callback;
}
void tox_events_callback_group_invite(
    Tox_Dispatch *dispatch, tox_events_group_invite_cb *callback)
{
    dispatch->group_invite_callback = callback;
}
void tox_events_callback_group_peer_join(
    Tox_Dispatch *dispatch, tox_events_group_peer_join_cb *callback)
{
    dispatch->group_peer_join_callback = callback;
}
void tox_events_callback_group_peer_exit(
    Tox_Dispatch *dispatch, tox_events_group_peer_exit_cb *callback)
{
    dispatch->group_peer_exit_callback = callback;
}
void tox_events_callback_group_self_join(
    Tox_Dispatch *dispatch, tox_events_group_self_join_cb *callback)
{
    dispatch->group_self_join_callback = callback;
}
void tox_events_callback_group_join_fail(
    Tox_Dispatch *dispatch, tox_events_group_join_fail_cb *callback)
{
    dispatch->group_join_fail_callback = callback;
}
void tox_events_callback_group_moderation(
    Tox_Dispatch *dispatch, tox_events_group_moderation_cb *callback)
{
    dispatch->group_moderation_callback = callback;
}
void tox_events_callback_dht_get_nodes_response(
    Tox_Dispatch *dispatch, tox_events_dht_get_nodes_response_cb *callback)
{
    dispatch->dht_get_nodes_response_callback = callback;
}

non_null(1, 2) nullable(3)
static void tox_dispatch_invoke_event(const Tox_Dispatch *dispatch, const Tox_Event *event, void *user_data)
{
    switch (event->type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            if (dispatch->conference_connected_callback != nullptr) {
                dispatch->conference_connected_callback(event->data.conference_connected, user_data);
            }

            break;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            if (dispatch->conference_invite_callback != nullptr) {
                dispatch->conference_invite_callback(event->data.conference_invite, user_data);
            }

            break;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            if (dispatch->conference_message_callback != nullptr) {
                dispatch->conference_message_callback(event->data.conference_message, user_data);
            }

            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            if (dispatch->conference_peer_list_changed_callback != nullptr) {
                dispatch->conference_peer_list_changed_callback(event->data.conference_peer_list_changed, user_data);
            }

            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            if (dispatch->conference_peer_name_callback != nullptr) {
                dispatch->conference_peer_name_callback(event->data.conference_peer_name, user_data);
            }

            break;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            if (dispatch->conference_title_callback != nullptr) {
                dispatch->conference_title_callback(event->data.conference_title, user_data);
            }

            break;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            if (dispatch->file_chunk_request_callback != nullptr) {
                dispatch->file_chunk_request_callback(event->data.file_chunk_request, user_data);
            }

            break;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            if (dispatch->file_recv_chunk_callback != nullptr) {
                dispatch->file_recv_chunk_callback(event->data.file_recv_chunk, user_data);
            }

            break;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            if (dispatch->file_recv_control_callback != nullptr) {
                dispatch->file_recv_control_callback(event->data.file_recv_control, user_data);
            }

            break;
        }

        case TOX_EVENT_FILE_RECV: {
            if (dispatch->file_recv_callback != nullptr) {
                dispatch->file_recv_callback(event->data.file_recv, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            if (dispatch->friend_connection_status_callback != nullptr) {
                dispatch->friend_connection_status_callback(event->data.friend_connection_status, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            if (dispatch->friend_lossless_packet_callback != nullptr) {
                dispatch->friend_lossless_packet_callback(event->data.friend_lossless_packet, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            if (dispatch->friend_lossy_packet_callback != nullptr) {
                dispatch->friend_lossy_packet_callback(event->data.friend_lossy_packet, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            if (dispatch->friend_message_callback != nullptr) {
                dispatch->friend_message_callback(event->data.friend_message, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_NAME: {
            if (dispatch->friend_name_callback != nullptr) {
                dispatch->friend_name_callback(event->data.friend_name, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            if (dispatch->friend_read_receipt_callback != nullptr) {
                dispatch->friend_read_receipt_callback(event->data.friend_read_receipt, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            if (dispatch->friend_request_callback != nullptr) {
                dispatch->friend_request_callback(event->data.friend_request, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            if (dispatch->friend_status_callback != nullptr) {
                dispatch->friend_status_callback(event->data.friend_status, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            if (dispatch->friend_status_message_callback != nullptr) {
                dispatch->friend_status_message_callback(event->data.friend_status_message, user_data);
            }

            break;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            if (dispatch->friend_typing_callback != nullptr) {
                dispatch->friend_typing_callback(event->data.friend_typing, user_data);
            }

            break;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            if (dispatch->self_connection_status_callback != nullptr) {
                dispatch->self_connection_status_callback(event->data.self_connection_status, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            if (dispatch->group_peer_name_callback != nullptr) {
                dispatch->group_peer_name_callback(event->data.group_peer_name, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            if (dispatch->group_peer_status_callback != nullptr) {
                dispatch->group_peer_status_callback(event->data.group_peer_status, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            if (dispatch->group_topic_callback != nullptr) {
                dispatch->group_topic_callback(event->data.group_topic, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            if (dispatch->group_privacy_state_callback != nullptr) {
                dispatch->group_privacy_state_callback(event->data.group_privacy_state, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            if (dispatch->group_voice_state_callback != nullptr) {
                dispatch->group_voice_state_callback(event->data.group_voice_state, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            if (dispatch->group_topic_lock_callback != nullptr) {
                dispatch->group_topic_lock_callback(event->data.group_topic_lock, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            if (dispatch->group_peer_limit_callback != nullptr) {
                dispatch->group_peer_limit_callback(event->data.group_peer_limit, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            if (dispatch->group_password_callback != nullptr) {
                dispatch->group_password_callback(event->data.group_password, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            if (dispatch->group_message_callback != nullptr) {
                dispatch->group_message_callback(event->data.group_message, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            if (dispatch->group_private_message_callback != nullptr) {
                dispatch->group_private_message_callback(event->data.group_private_message, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            if (dispatch->group_custom_packet_callback != nullptr) {
                dispatch->group_custom_packet_callback(event->data.group_custom_packet, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            if (dispatch->group_custom_private_packet_callback != nullptr) {
                dispatch->group_custom_private_packet_callback(event->data.group_custom_private_packet, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_INVITE: {
            if (dispatch->group_invite_callback != nullptr) {
                dispatch->group_invite_callback(event->data.group_invite, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            if (dispatch->group_peer_join_callback != nullptr) {
                dispatch->group_peer_join_callback(event->data.group_peer_join, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            if (dispatch->group_peer_exit_callback != nullptr) {
                dispatch->group_peer_exit_callback(event->data.group_peer_exit, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            if (dispatch->group_self_join_callback != nullptr) {
                dispatch->group_self_join_callback(event->data.group_self_join, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            if (dispatch->group_join_fail_callback != nullptr) {
                dispatch->group_join_fail_callback(event->data.group_join_fail, user_data);
            }

            break;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            if (dispatch->group_moderation_callback != nullptr) {
                dispatch->group_moderation_callback(event->data.group_moderation, user_data);
            }

            break;
        }

        case TOX_EVENT_DHT_GET_NODES_RESPONSE: {
            if (dispatch->dht_get_nodes_response_callback != nullptr) {
                dispatch->dht_get_nodes_response_callback(event->data.dht_get_nodes_response, user_data);
            }

            break;
        }

        case TOX_EVENT_INVALID: {
            break;
        }
    }
}

void tox_dispatch_invoke(const Tox_Dispatch *dispatch, const Tox_Events *events, void *user_data)
{
    const uint32_t size = tox_events_get_size(events);
    for (uint32_t i = 0; i < size; ++i) {
        const Tox_Event *event = &events->events[i];
        tox_dispatch_invoke_event(dispatch, event, user_data);
    }
}
