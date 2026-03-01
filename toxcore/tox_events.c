/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#include "tox_events.h"

#include <assert.h>
#include <string.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "events/events_alloc.h"
#include "logger.h"
#include "mem.h"
#include "tox.h"
#include "tox_event.h"
#include "tox_private.h"
#include "tox_struct.h" // IWYU pragma: keep

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
    tox_callback_group_peer_name(tox, tox_events_handle_group_peer_name);
    tox_callback_group_peer_status(tox, tox_events_handle_group_peer_status);
    tox_callback_group_topic(tox, tox_events_handle_group_topic);
    tox_callback_group_privacy_state(tox, tox_events_handle_group_privacy_state);
    tox_callback_group_voice_state(tox, tox_events_handle_group_voice_state);
    tox_callback_group_topic_lock(tox, tox_events_handle_group_topic_lock);
    tox_callback_group_peer_limit(tox, tox_events_handle_group_peer_limit);
    tox_callback_group_password(tox, tox_events_handle_group_password);
    tox_callback_group_message(tox, tox_events_handle_group_message);
    tox_callback_group_private_message(tox, tox_events_handle_group_private_message);
    tox_callback_group_custom_packet(tox, tox_events_handle_group_custom_packet);
    tox_callback_group_custom_private_packet(tox, tox_events_handle_group_custom_private_packet);
    tox_callback_group_invite(tox, tox_events_handle_group_invite);
    tox_callback_group_peer_join(tox, tox_events_handle_group_peer_join);
    tox_callback_group_peer_exit(tox, tox_events_handle_group_peer_exit);
    tox_callback_group_self_join(tox, tox_events_handle_group_self_join);
    tox_callback_group_join_fail(tox, tox_events_handle_group_join_fail);
    tox_callback_group_moderation(tox, tox_events_handle_group_moderation);
    tox_callback_dht_nodes_response(tox, tox_events_handle_dht_nodes_response);
}

uint32_t tox_events_get_size(const Tox_Events *events)
{
    return events == nullptr ? 0 : events->events_size;
}

static const Tox_Event *_Nullable tox_events_get_events(const Tox_Events *_Nullable events)
{
    return events == nullptr ? nullptr : events->events;
}

const Tox_Event *tox_events_get(const Tox_Events *events, uint32_t index)
{
    if (index >= tox_events_get_size(events)) {
        return nullptr;
    }

    return &events->events[index];
}

Tox_Events *tox_events_iterate(Tox *tox, const Tox_Iterate_Options *options, Tox_Err_Events_Iterate *error)
{
    const Tox_System *sys = tox_get_system(tox);
    Tox_Events_State state = {TOX_ERR_EVENTS_ITERATE_OK, sys->mem, nullptr};

    tox_iterate_with_options(tox, options, &state);

    if (error != nullptr) {
        *error = state.error;
    }

    const bool fail_hard = tox_iterate_options_get_fail_hard(options);

    if (fail_hard && state.error != TOX_ERR_EVENTS_ITERATE_OK) {
        tox_events_free(state.events);
        return nullptr;
    }

    return state.events;
}

static bool tox_event_pack_handler(const void *_Nonnull arr, uint32_t index, const Logger *_Nonnull logger, Bin_Pack *_Nonnull bp)
{
    const Tox_Event *events = (const Tox_Event *)arr;
    assert(events != nullptr);
    return tox_event_pack(&events[index], bp);
}

static bool tox_events_pack_handler(const void *_Nullable obj, const Logger *_Nullable logger, Bin_Pack *_Nonnull bp)
{
    const Tox_Events *events = (const Tox_Events *)obj;
    return bin_pack_obj_array(bp, tox_event_pack_handler, tox_events_get_events(events), tox_events_get_size(events), logger);
}

uint32_t tox_events_bytes_size(const Tox_Events *events)
{
    return bin_pack_obj_size(tox_events_pack_handler, events, nullptr);
}

bool tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes)
{
    return bin_pack_obj(tox_events_pack_handler, events, nullptr, bytes, UINT32_MAX);
}

static bool tox_events_unpack_handler(void *_Nonnull obj, Bin_Unpack *_Nonnull bu)
{
    Tox_Events *events = (Tox_Events *)obj;

    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    for (uint32_t i = 0; i < size; ++i) {
        Tox_Event event = {TOX_EVENT_INVALID};
        if (!tox_event_unpack_into(&event, bu, events->mem)) {
            tox_event_destruct(&event, events->mem);
            return false;
        }

        if (!tox_events_add(events, &event)) {
            tox_event_destruct(&event, events->mem);
            return false;
        }
    }

    // Invariant: if all adds worked, the events size must be the input array size.
    assert(tox_events_get_size(events) == size);
    return true;
}

Tox_Events *tox_events_load(const Tox_System *sys, const uint8_t *bytes, uint32_t bytes_size)
{
    Tox_Events *events = (Tox_Events *)mem_alloc(sys->mem, sizeof(Tox_Events));

    if (events == nullptr) {
        return nullptr;
    }

    *events = (Tox_Events) {
        nullptr
    };
    events->mem = sys->mem;

    if (!bin_unpack_obj(sys->mem, tox_events_unpack_handler, events, bytes, bytes_size)) {
        tox_events_free(events);
        return nullptr;
    }

    return events;
}

void tox_events_dispatch(Tox *tox, Tox_Events *events, void *user_data)
{
    if (events == nullptr) {
        return;
    }

    const uint32_t size = tox_events_get_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        const Tox_Event *event = tox_events_get(events, i);
        const Tox_Event_Type type = tox_event_get_type(event);

        switch (type) {
            case TOX_EVENT_SELF_CONNECTION_STATUS: {
                tox_events_handle_self_connection_status_dispatch(tox, event->data.self_connection_status, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_REQUEST: {
                tox_events_handle_friend_request_dispatch(tox, event->data.friend_request, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
                tox_events_handle_friend_connection_status_dispatch(tox, event->data.friend_connection_status, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_LOSSY_PACKET: {
                tox_events_handle_friend_lossy_packet_dispatch(tox, event->data.friend_lossy_packet, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
                tox_events_handle_friend_lossless_packet_dispatch(tox, event->data.friend_lossless_packet, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_NAME: {
                tox_events_handle_friend_name_dispatch(tox, event->data.friend_name, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_STATUS: {
                tox_events_handle_friend_status_dispatch(tox, event->data.friend_status, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
                tox_events_handle_friend_status_message_dispatch(tox, event->data.friend_status_message, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_MESSAGE: {
                tox_events_handle_friend_message_dispatch(tox, event->data.friend_message, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_READ_RECEIPT: {
                tox_events_handle_friend_read_receipt_dispatch(tox, event->data.friend_read_receipt, user_data);
                break;
            }

            case TOX_EVENT_FRIEND_TYPING: {
                tox_events_handle_friend_typing_dispatch(tox, event->data.friend_typing, user_data);
                break;
            }

            case TOX_EVENT_FILE_CHUNK_REQUEST: {
                tox_events_handle_file_chunk_request_dispatch(tox, event->data.file_chunk_request, user_data);
                break;
            }

            case TOX_EVENT_FILE_RECV: {
                tox_events_handle_file_recv_dispatch(tox, event->data.file_recv, user_data);
                break;
            }

            case TOX_EVENT_FILE_RECV_CHUNK: {
                tox_events_handle_file_recv_chunk_dispatch(tox, event->data.file_recv_chunk, user_data);
                break;
            }

            case TOX_EVENT_FILE_RECV_CONTROL: {
                tox_events_handle_file_recv_control_dispatch(tox, event->data.file_recv_control, user_data);
                break;
            }

            case TOX_EVENT_CONFERENCE_INVITE: {
                tox_events_handle_conference_invite_dispatch(tox, event->data.conference_invite, user_data);
                break;
            }

            case TOX_EVENT_CONFERENCE_CONNECTED: {
                tox_events_handle_conference_connected_dispatch(tox, event->data.conference_connected, user_data);
                break;
            }

            case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
                tox_events_handle_conference_peer_list_changed_dispatch(tox, event->data.conference_peer_list_changed, user_data);
                break;
            }

            case TOX_EVENT_CONFERENCE_PEER_NAME: {
                tox_events_handle_conference_peer_name_dispatch(tox, event->data.conference_peer_name, user_data);
                break;
            }

            case TOX_EVENT_CONFERENCE_TITLE: {
                tox_events_handle_conference_title_dispatch(tox, event->data.conference_title, user_data);
                break;
            }

            case TOX_EVENT_CONFERENCE_MESSAGE: {
                tox_events_handle_conference_message_dispatch(tox, event->data.conference_message, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PEER_NAME: {
                tox_events_handle_group_peer_name_dispatch(tox, event->data.group_peer_name, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PEER_STATUS: {
                tox_events_handle_group_peer_status_dispatch(tox, event->data.group_peer_status, user_data);
                break;
            }

            case TOX_EVENT_GROUP_TOPIC: {
                tox_events_handle_group_topic_dispatch(tox, event->data.group_topic, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PRIVACY_STATE: {
                tox_events_handle_group_privacy_state_dispatch(tox, event->data.group_privacy_state, user_data);
                break;
            }

            case TOX_EVENT_GROUP_VOICE_STATE: {
                tox_events_handle_group_voice_state_dispatch(tox, event->data.group_voice_state, user_data);
                break;
            }

            case TOX_EVENT_GROUP_TOPIC_LOCK: {
                tox_events_handle_group_topic_lock_dispatch(tox, event->data.group_topic_lock, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PEER_LIMIT: {
                tox_events_handle_group_peer_limit_dispatch(tox, event->data.group_peer_limit, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PASSWORD: {
                tox_events_handle_group_password_dispatch(tox, event->data.group_password, user_data);
                break;
            }

            case TOX_EVENT_GROUP_MESSAGE: {
                tox_events_handle_group_message_dispatch(tox, event->data.group_message, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
                tox_events_handle_group_private_message_dispatch(tox, event->data.group_private_message, user_data);
                break;
            }

            case TOX_EVENT_GROUP_CUSTOM_PACKET: {
                tox_events_handle_group_custom_packet_dispatch(tox, event->data.group_custom_packet, user_data);
                break;
            }

            case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
                tox_events_handle_group_custom_private_packet_dispatch(tox, event->data.group_custom_private_packet, user_data);
                break;
            }

            case TOX_EVENT_GROUP_INVITE: {
                tox_events_handle_group_invite_dispatch(tox, event->data.group_invite, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PEER_JOIN: {
                tox_events_handle_group_peer_join_dispatch(tox, event->data.group_peer_join, user_data);
                break;
            }

            case TOX_EVENT_GROUP_PEER_EXIT: {
                tox_events_handle_group_peer_exit_dispatch(tox, event->data.group_peer_exit, user_data);
                break;
            }

            case TOX_EVENT_GROUP_SELF_JOIN: {
                tox_events_handle_group_self_join_dispatch(tox, event->data.group_self_join, user_data);
                break;
            }

            case TOX_EVENT_GROUP_JOIN_FAIL: {
                tox_events_handle_group_join_fail_dispatch(tox, event->data.group_join_fail, user_data);
                break;
            }

            case TOX_EVENT_GROUP_MODERATION: {
                tox_events_handle_group_moderation_dispatch(tox, event->data.group_moderation, user_data);
                break;
            }

            case TOX_EVENT_DHT_NODES_RESPONSE: {
                tox_events_handle_dht_nodes_response_dispatch(tox, event->data.dht_nodes_response, user_data);
                break;
            }

            case TOX_EVENT_INVALID:
                break;
        }
    }
}

bool tox_events_equal(const Tox_System *sys, const Tox_Events *a, const Tox_Events *b)
{
    assert(sys != nullptr);
    assert(sys->mem != nullptr);

    const uint32_t a_size = tox_events_bytes_size(a);
    const uint32_t b_size = tox_events_bytes_size(b);

    if (a_size != b_size) {
        return false;
    }

    uint8_t *a_bytes = (uint8_t *)mem_balloc(sys->mem, a_size);
    uint8_t *b_bytes = (uint8_t *)mem_balloc(sys->mem, b_size);

    if (a_bytes == nullptr || b_bytes == nullptr) {
        mem_delete(sys->mem, b_bytes);
        mem_delete(sys->mem, a_bytes);
        return false;
    }

    tox_events_get_bytes(a, a_bytes);
    tox_events_get_bytes(b, b_bytes);

    const bool ret = memcmp(a_bytes, b_bytes, a_size) == 0;

    mem_delete(sys->mem, b_bytes);
    mem_delete(sys->mem, a_bytes);

    return ret;
}
