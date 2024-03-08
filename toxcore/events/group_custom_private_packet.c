/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_events.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Group_Custom_Private_Packet {
    uint32_t group_number;
    uint32_t peer_id;
    uint8_t *data;
    uint32_t data_length;
};

non_null()
static void tox_event_group_custom_private_packet_set_group_number(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet,
        uint32_t group_number)
{
    assert(group_custom_private_packet != nullptr);
    group_custom_private_packet->group_number = group_number;
}
uint32_t tox_event_group_custom_private_packet_get_group_number(const Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet)
{
    assert(group_custom_private_packet != nullptr);
    return group_custom_private_packet->group_number;
}

non_null()
static void tox_event_group_custom_private_packet_set_peer_id(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet,
        uint32_t peer_id)
{
    assert(group_custom_private_packet != nullptr);
    group_custom_private_packet->peer_id = peer_id;
}
uint32_t tox_event_group_custom_private_packet_get_peer_id(const Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet)
{
    assert(group_custom_private_packet != nullptr);
    return group_custom_private_packet->peer_id;
}

non_null(1) nullable(2)
static bool tox_event_group_custom_private_packet_set_data(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet,
        const uint8_t *data, uint32_t data_length)
{
    assert(group_custom_private_packet != nullptr);

    if (group_custom_private_packet->data != nullptr) {
        free(group_custom_private_packet->data);
        group_custom_private_packet->data = nullptr;
        group_custom_private_packet->data_length = 0;
    }

    if (data == nullptr) {
        assert(data_length == 0);
        return true;
    }

    uint8_t *data_copy = (uint8_t *)malloc(data_length);

    if (data_copy == nullptr) {
        return false;
    }

    memcpy(data_copy, data, data_length);
    group_custom_private_packet->data = data_copy;
    group_custom_private_packet->data_length = data_length;
    return true;
}
uint32_t tox_event_group_custom_private_packet_get_data_length(const Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet)
{
    assert(group_custom_private_packet != nullptr);
    return group_custom_private_packet->data_length;
}
const uint8_t *tox_event_group_custom_private_packet_get_data(const Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet)
{
    assert(group_custom_private_packet != nullptr);
    return group_custom_private_packet->data;
}

non_null()
static void tox_event_group_custom_private_packet_construct(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet)
{
    *group_custom_private_packet = (Tox_Event_Group_Custom_Private_Packet) {
        0
    };
}
non_null()
static void tox_event_group_custom_private_packet_destruct(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet, const Memory *mem)
{
    free(group_custom_private_packet->data);
}

bool tox_event_group_custom_private_packet_pack(
    const Tox_Event_Group_Custom_Private_Packet *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_bin(bp, event->data, event->data_length);
}

non_null()
static bool tox_event_group_custom_private_packet_unpack_into(
    Tox_Event_Group_Custom_Private_Packet *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && bin_unpack_bin(bu, &event->data, &event->data_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Custom_Private_Packet *tox_event_get_group_custom_private_packet(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET ? event->data.group_custom_private_packet : nullptr;
}

Tox_Event_Group_Custom_Private_Packet *tox_event_group_custom_private_packet_new(const Memory *mem)
{
    Tox_Event_Group_Custom_Private_Packet *const group_custom_private_packet =
        (Tox_Event_Group_Custom_Private_Packet *)mem_alloc(mem, sizeof(Tox_Event_Group_Custom_Private_Packet));

    if (group_custom_private_packet == nullptr) {
        return nullptr;
    }

    tox_event_group_custom_private_packet_construct(group_custom_private_packet);
    return group_custom_private_packet;
}

void tox_event_group_custom_private_packet_free(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet, const Memory *mem)
{
    if (group_custom_private_packet != nullptr) {
        tox_event_group_custom_private_packet_destruct(group_custom_private_packet, mem);
    }
    mem_delete(mem, group_custom_private_packet);
}

non_null()
static Tox_Event_Group_Custom_Private_Packet *tox_events_add_group_custom_private_packet(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Custom_Private_Packet *const group_custom_private_packet = tox_event_group_custom_private_packet_new(mem);

    if (group_custom_private_packet == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET;
    event.data.group_custom_private_packet = group_custom_private_packet;

    tox_events_add(events, &event);
    return group_custom_private_packet;
}

bool tox_event_group_custom_private_packet_unpack(
    Tox_Event_Group_Custom_Private_Packet **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_custom_private_packet_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_custom_private_packet_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Custom_Private_Packet *tox_event_group_custom_private_packet_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet = tox_events_add_group_custom_private_packet(state->events, state->mem);

    if (group_custom_private_packet == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_custom_private_packet;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_custom_private_packet(
    Tox *tox, uint32_t group_number, uint32_t peer_id, const uint8_t *data, size_t data_length,
    void *user_data)
{
    Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet = tox_event_group_custom_private_packet_alloc(user_data);

    if (group_custom_private_packet == nullptr) {
        return;
    }

    tox_event_group_custom_private_packet_set_group_number(group_custom_private_packet, group_number);
    tox_event_group_custom_private_packet_set_peer_id(group_custom_private_packet, peer_id);
    tox_event_group_custom_private_packet_set_data(group_custom_private_packet, data, data_length);
}
