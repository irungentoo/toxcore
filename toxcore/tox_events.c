/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_events.h"

#include <assert.h>
#include <string.h>

#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "events/events_alloc.h"
#include "logger.h"
#include "mem.h"
#include "tox.h"
#include "tox_event.h"
#include "tox_private.h"
#include "tox_struct.h"


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
}

uint32_t tox_events_get_size(const Tox_Events *events)
{
    return events == nullptr ? 0 : events->events_size;
}

const Tox_Event *tox_events_get(const Tox_Events *events, uint32_t index)
{
    if (index >= tox_events_get_size(events)) {
        return nullptr;
    }

    return &events->events[index];
}

Tox_Events *tox_events_iterate(Tox *tox, bool fail_hard, Tox_Err_Events_Iterate *error)
{
    const Tox_System *sys = tox_get_system(tox);
    Tox_Events_State state = {TOX_ERR_EVENTS_ITERATE_OK, sys->mem};
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
    const uint32_t size = tox_events_get_size(events);
    if (!bin_pack_array(bp, size)) {
        return false;
    }

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_pack(&events->events[i], bp)) {
            return false;
        }
    }

    return true;
}

bool tox_events_unpack(Tox_Events *events, Bin_Unpack *bu, const Memory *mem)
{
    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    for (uint32_t i = 0; i < size; ++i) {
        Tox_Event event = {TOX_EVENT_INVALID};
        if (!tox_event_unpack_into(&event, bu, mem)) {
            tox_event_destruct(&event, mem);
            return false;
        }

        if (!tox_events_add(events, &event)) {
            tox_event_destruct(&event, mem);
            return false;
        }
    }

    // Invariant: if all adds worked, the events size must be the input array size.
    assert(tox_events_get_size(events) == size);
    return true;
}

non_null(1) nullable(2, 3)
static bool tox_events_bin_pack_handler(Bin_Pack *bp, const Logger *logger, const void *obj)
{
    const Tox_Events *events = (const Tox_Events *)obj;
    return tox_events_pack(events, bp);
}

uint32_t tox_events_bytes_size(const Tox_Events *events)
{
    return bin_pack_obj_size(tox_events_bin_pack_handler, nullptr, events);
}

bool tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes)
{
    return bin_pack_obj(tox_events_bin_pack_handler, nullptr, events, bytes, UINT32_MAX);
}

Tox_Events *tox_events_load(const Tox_System *sys, const uint8_t *bytes, uint32_t bytes_size)
{
    Bin_Unpack *bu = bin_unpack_new(bytes, bytes_size);

    if (bu == nullptr) {
        return nullptr;
    }

    Tox_Events *events = (Tox_Events *)mem_alloc(sys->mem, sizeof(Tox_Events));

    if (events == nullptr) {
        bin_unpack_free(bu);
        return nullptr;
    }

    *events = (Tox_Events) {
        nullptr
    };
    events->mem = sys->mem;

    if (!tox_events_unpack(events, bu, sys->mem)) {
        tox_events_free(events);
        bin_unpack_free(bu);
        return nullptr;
    }

    bin_unpack_free(bu);
    return events;
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
