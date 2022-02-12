/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Lossless_Packet {
    uint32_t friend_number;
    uint8_t *data;
    size_t data_length;
};

non_null()
static void tox_event_friend_lossless_packet_construct(Tox_Event_Friend_Lossless_Packet *friend_lossless_packet)
{
    *friend_lossless_packet = (Tox_Event_Friend_Lossless_Packet) {
        0
    };
}
non_null()
static void tox_event_friend_lossless_packet_destruct(Tox_Event_Friend_Lossless_Packet *friend_lossless_packet)
{
    free(friend_lossless_packet->data);
}

non_null()
static void tox_event_friend_lossless_packet_set_friend_number(Tox_Event_Friend_Lossless_Packet *friend_lossless_packet,
        uint32_t friend_number)
{
    assert(friend_lossless_packet != nullptr);
    friend_lossless_packet->friend_number = friend_number;
}
uint32_t tox_event_friend_lossless_packet_get_friend_number(const Tox_Event_Friend_Lossless_Packet
        *friend_lossless_packet)
{
    assert(friend_lossless_packet != nullptr);
    return friend_lossless_packet->friend_number;
}

non_null()
static bool tox_event_friend_lossless_packet_set_data(Tox_Event_Friend_Lossless_Packet *friend_lossless_packet,
        const uint8_t *data, size_t data_length)
{
    assert(friend_lossless_packet != nullptr);

    if (friend_lossless_packet->data != nullptr) {
        free(friend_lossless_packet->data);
        friend_lossless_packet->data = nullptr;
        friend_lossless_packet->data_length = 0;
    }

    friend_lossless_packet->data = (uint8_t *)malloc(data_length);

    if (friend_lossless_packet->data == nullptr) {
        return false;
    }

    memcpy(friend_lossless_packet->data, data, data_length);
    friend_lossless_packet->data_length = data_length;
    return true;
}
size_t tox_event_friend_lossless_packet_get_data_length(const Tox_Event_Friend_Lossless_Packet *friend_lossless_packet)
{
    assert(friend_lossless_packet != nullptr);
    return friend_lossless_packet->data_length;
}
const uint8_t *tox_event_friend_lossless_packet_get_data(const Tox_Event_Friend_Lossless_Packet *friend_lossless_packet)
{
    assert(friend_lossless_packet != nullptr);
    return friend_lossless_packet->data;
}

non_null()
static void tox_event_friend_lossless_packet_pack(
    const Tox_Event_Friend_Lossless_Packet *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    bin_pack_array(mp, 2);
    bin_pack_u32(mp, TOX_EVENT_FRIEND_LOSSLESS_PACKET);
    bin_pack_array(mp, 2);
    bin_pack_u32(mp, event->friend_number);
    bin_pack_bytes(mp, event->data, event->data_length);
}

non_null()
static bool tox_event_friend_lossless_packet_unpack(
    Tox_Event_Friend_Lossless_Packet *event, const msgpack_object *obj)
{
    assert(event != nullptr);

    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 2) {
        return false;
    }

    return bin_unpack_u32(&event->friend_number, &obj->via.array.ptr[0])
           && bin_unpack_bytes(&event->data, &event->data_length, &obj->via.array.ptr[1]);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Friend_Lossless_Packet *tox_events_add_friend_lossless_packet(Tox_Events *events)
{
    if (events->friend_lossless_packet_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->friend_lossless_packet_size == events->friend_lossless_packet_capacity) {
        const uint32_t new_friend_lossless_packet_capacity = events->friend_lossless_packet_capacity * 2 + 1;
        Tox_Event_Friend_Lossless_Packet *new_friend_lossless_packet = (Tox_Event_Friend_Lossless_Packet *)realloc(
                    events->friend_lossless_packet, new_friend_lossless_packet_capacity * sizeof(Tox_Event_Friend_Lossless_Packet));

        if (new_friend_lossless_packet == nullptr) {
            return nullptr;
        }

        events->friend_lossless_packet = new_friend_lossless_packet;
        events->friend_lossless_packet_capacity = new_friend_lossless_packet_capacity;
    }

    Tox_Event_Friend_Lossless_Packet *const friend_lossless_packet =
        &events->friend_lossless_packet[events->friend_lossless_packet_size];
    tox_event_friend_lossless_packet_construct(friend_lossless_packet);
    ++events->friend_lossless_packet_size;
    return friend_lossless_packet;
}

void tox_events_clear_friend_lossless_packet(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->friend_lossless_packet_size; ++i) {
        tox_event_friend_lossless_packet_destruct(&events->friend_lossless_packet[i]);
    }

    free(events->friend_lossless_packet);
    events->friend_lossless_packet = nullptr;
    events->friend_lossless_packet_size = 0;
    events->friend_lossless_packet_capacity = 0;
}

uint32_t tox_events_get_friend_lossless_packet_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->friend_lossless_packet_size;
}

const Tox_Event_Friend_Lossless_Packet *tox_events_get_friend_lossless_packet(const Tox_Events *events, uint32_t index)
{
    assert(index < events->friend_lossless_packet_size);
    assert(events->friend_lossless_packet != nullptr);
    return &events->friend_lossless_packet[index];
}

void tox_events_pack_friend_lossless_packet(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_friend_lossless_packet_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_friend_lossless_packet_pack(tox_events_get_friend_lossless_packet(events, i), mp);
    }
}

bool tox_events_unpack_friend_lossless_packet(Tox_Events *events, const msgpack_object *obj)
{
    Tox_Event_Friend_Lossless_Packet *event = tox_events_add_friend_lossless_packet(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_friend_lossless_packet_unpack(event, obj);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_Friend_Lossless_Packet *friend_lossless_packet = tox_events_add_friend_lossless_packet(state->events);

    if (friend_lossless_packet == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_friend_lossless_packet_set_friend_number(friend_lossless_packet, friend_number);
    tox_event_friend_lossless_packet_set_data(friend_lossless_packet, data, length);
}
