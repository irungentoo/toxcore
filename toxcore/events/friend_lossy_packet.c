/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <string.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_event.h"
#include "../tox_events.h"
#include "../tox_struct.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Friend_Lossy_Packet {
    uint32_t friend_number;
    uint8_t *_Nullable data;
    uint32_t data_length;
};

static void tox_event_friend_lossy_packet_set_friend_number(Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet, uint32_t friend_number)
{
    assert(friend_lossy_packet != nullptr);
    friend_lossy_packet->friend_number = friend_number;
}
uint32_t tox_event_friend_lossy_packet_get_friend_number(const Tox_Event_Friend_Lossy_Packet *friend_lossy_packet)
{
    assert(friend_lossy_packet != nullptr);
    return friend_lossy_packet->friend_number;
}

static bool tox_event_friend_lossy_packet_set_data(Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet,
        const Memory *_Nonnull mem, const uint8_t *_Nullable data, uint32_t data_length)
{
    assert(friend_lossy_packet != nullptr);
    if (friend_lossy_packet->data != nullptr) {
        mem_delete(mem, friend_lossy_packet->data);
        friend_lossy_packet->data = nullptr;
        friend_lossy_packet->data_length = 0;
    }

    if (data == nullptr) {
        assert(data_length == 0);
        return true;
    }

    if (data_length == 0) {
        friend_lossy_packet->data = nullptr;
        friend_lossy_packet->data_length = 0;
        return true;
    }

    uint8_t *data_copy = (uint8_t *)mem_balloc(mem, data_length);

    if (data_copy == nullptr) {
        return false;
    }

    memcpy(data_copy, data, data_length);
    friend_lossy_packet->data = data_copy;
    friend_lossy_packet->data_length = data_length;
    return true;
}
uint32_t tox_event_friend_lossy_packet_get_data_length(const Tox_Event_Friend_Lossy_Packet *friend_lossy_packet)
{
    assert(friend_lossy_packet != nullptr);
    return friend_lossy_packet->data_length;
}
const uint8_t *tox_event_friend_lossy_packet_get_data(const Tox_Event_Friend_Lossy_Packet *friend_lossy_packet)
{
    assert(friend_lossy_packet != nullptr);
    return friend_lossy_packet->data;
}

static void tox_event_friend_lossy_packet_construct(Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet)
{
    *friend_lossy_packet = (Tox_Event_Friend_Lossy_Packet) {
        0
    };
}
static void tox_event_friend_lossy_packet_destruct(Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet, const Memory *_Nonnull mem)
{
    mem_delete(mem, friend_lossy_packet->data);
}

bool tox_event_friend_lossy_packet_pack(
    const Tox_Event_Friend_Lossy_Packet *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->data, event->data_length);
}

static bool tox_event_friend_lossy_packet_unpack_into(Tox_Event_Friend_Lossy_Packet *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->data, &event->data_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Lossy_Packet *tox_event_get_friend_lossy_packet(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_LOSSY_PACKET ? event->data.friend_lossy_packet : nullptr;
}

Tox_Event_Friend_Lossy_Packet *tox_event_friend_lossy_packet_new(const Memory *mem)
{
    Tox_Event_Friend_Lossy_Packet *const friend_lossy_packet =
        (Tox_Event_Friend_Lossy_Packet *)mem_alloc(mem, sizeof(Tox_Event_Friend_Lossy_Packet));

    if (friend_lossy_packet == nullptr) {
        return nullptr;
    }

    tox_event_friend_lossy_packet_construct(friend_lossy_packet);
    return friend_lossy_packet;
}

void tox_event_friend_lossy_packet_free(Tox_Event_Friend_Lossy_Packet *friend_lossy_packet, const Memory *mem)
{
    if (friend_lossy_packet != nullptr) {
        tox_event_friend_lossy_packet_destruct(friend_lossy_packet, mem);
    }
    mem_delete(mem, friend_lossy_packet);
}

static Tox_Event_Friend_Lossy_Packet *_Nullable tox_events_add_friend_lossy_packet(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Friend_Lossy_Packet *const friend_lossy_packet = tox_event_friend_lossy_packet_new(mem);

    if (friend_lossy_packet == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_LOSSY_PACKET;
    event.data.friend_lossy_packet = friend_lossy_packet;

    if (!tox_events_add(events, &event)) {
        tox_event_friend_lossy_packet_free(friend_lossy_packet, mem);
        return nullptr;
    }
    return friend_lossy_packet;
}

bool tox_event_friend_lossy_packet_unpack(
    Tox_Event_Friend_Lossy_Packet **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_lossy_packet_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_lossy_packet_unpack_into(*event, bu);
}

static Tox_Event_Friend_Lossy_Packet *_Nullable tox_event_friend_lossy_packet_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Lossy_Packet *friend_lossy_packet = tox_events_add_friend_lossy_packet(state->events, state->mem);

    if (friend_lossy_packet == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_lossy_packet;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_lossy_packet(
    Tox *_Nonnull tox,
    uint32_t friend_number,
    const uint8_t *_Nullable data, size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Friend_Lossy_Packet *friend_lossy_packet = tox_event_friend_lossy_packet_alloc(state);

    if (friend_lossy_packet == nullptr) {
        return;
    }

    tox_event_friend_lossy_packet_set_friend_number(friend_lossy_packet, friend_number);
    if (!tox_event_friend_lossy_packet_set_data(friend_lossy_packet, state->mem, data, length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_friend_lossy_packet_dispatch(Tox *tox, const Tox_Event_Friend_Lossy_Packet *event, void *user_data)
{
    if (event->data_length == 0 || tox->friend_lossy_packet_callback_per_pktid[event->data[0]] == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->friend_lossy_packet_callback_per_pktid[event->data[0]](tox, event->friend_number, event->data, event->data_length, user_data);
    tox_lock(tox);
}
