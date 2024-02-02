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

struct Tox_Event_Conference_Peer_Name {
    uint32_t conference_number;
    uint32_t peer_number;
    uint8_t *name;
    uint32_t name_length;
};

non_null()
static void tox_event_conference_peer_name_set_conference_number(Tox_Event_Conference_Peer_Name *conference_peer_name,
        uint32_t conference_number)
{
    assert(conference_peer_name != nullptr);
    conference_peer_name->conference_number = conference_number;
}
uint32_t tox_event_conference_peer_name_get_conference_number(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->conference_number;
}

non_null()
static void tox_event_conference_peer_name_set_peer_number(Tox_Event_Conference_Peer_Name *conference_peer_name,
        uint32_t peer_number)
{
    assert(conference_peer_name != nullptr);
    conference_peer_name->peer_number = peer_number;
}
uint32_t tox_event_conference_peer_name_get_peer_number(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->peer_number;
}

non_null(1) nullable(2)
static bool tox_event_conference_peer_name_set_name(Tox_Event_Conference_Peer_Name *conference_peer_name,
        const uint8_t *name, uint32_t name_length)
{
    assert(conference_peer_name != nullptr);

    if (conference_peer_name->name != nullptr) {
        free(conference_peer_name->name);
        conference_peer_name->name = nullptr;
        conference_peer_name->name_length = 0;
    }

    if (name == nullptr) {
        assert(name_length == 0);
        return true;
    }

    uint8_t *name_copy = (uint8_t *)malloc(name_length);

    if (name_copy == nullptr) {
        return false;
    }

    memcpy(name_copy, name, name_length);
    conference_peer_name->name = name_copy;
    conference_peer_name->name_length = name_length;
    return true;
}
uint32_t tox_event_conference_peer_name_get_name_length(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->name_length;
}
const uint8_t *tox_event_conference_peer_name_get_name(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->name;
}

non_null()
static void tox_event_conference_peer_name_construct(Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    *conference_peer_name = (Tox_Event_Conference_Peer_Name) {
        0
    };
}
non_null()
static void tox_event_conference_peer_name_destruct(Tox_Event_Conference_Peer_Name *conference_peer_name, const Memory *mem)
{
    free(conference_peer_name->name);
}

bool tox_event_conference_peer_name_pack(
    const Tox_Event_Conference_Peer_Name *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_bin(bp, event->name, event->name_length);
}

non_null()
static bool tox_event_conference_peer_name_unpack_into(
    Tox_Event_Conference_Peer_Name *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Conference_Peer_Name *tox_event_get_conference_peer_name(const Tox_Event *event)
{
    return event->type == TOX_EVENT_CONFERENCE_PEER_NAME ? event->data.conference_peer_name : nullptr;
}

Tox_Event_Conference_Peer_Name *tox_event_conference_peer_name_new(const Memory *mem)
{
    Tox_Event_Conference_Peer_Name *const conference_peer_name =
        (Tox_Event_Conference_Peer_Name *)mem_alloc(mem, sizeof(Tox_Event_Conference_Peer_Name));

    if (conference_peer_name == nullptr) {
        return nullptr;
    }

    tox_event_conference_peer_name_construct(conference_peer_name);
    return conference_peer_name;
}

void tox_event_conference_peer_name_free(Tox_Event_Conference_Peer_Name *conference_peer_name, const Memory *mem)
{
    if (conference_peer_name != nullptr) {
        tox_event_conference_peer_name_destruct(conference_peer_name, mem);
    }
    mem_delete(mem, conference_peer_name);
}

non_null()
static Tox_Event_Conference_Peer_Name *tox_events_add_conference_peer_name(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Conference_Peer_Name *const conference_peer_name = tox_event_conference_peer_name_new(mem);

    if (conference_peer_name == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_PEER_NAME;
    event.data.conference_peer_name = conference_peer_name;

    tox_events_add(events, &event);
    return conference_peer_name;
}

bool tox_event_conference_peer_name_unpack(
    Tox_Event_Conference_Peer_Name **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_conference_peer_name_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_conference_peer_name_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Conference_Peer_Name *tox_event_conference_peer_name_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Conference_Peer_Name *conference_peer_name = tox_events_add_conference_peer_name(state->events, state->mem);

    if (conference_peer_name == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return conference_peer_name;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_peer_name(
    Tox *tox, uint32_t conference_number, uint32_t peer_number, const uint8_t *name, size_t length,
    void *user_data)
{
    Tox_Event_Conference_Peer_Name *conference_peer_name = tox_event_conference_peer_name_alloc(user_data);

    if (conference_peer_name == nullptr) {
        return;
    }

    tox_event_conference_peer_name_set_conference_number(conference_peer_name, conference_number);
    tox_event_conference_peer_name_set_peer_number(conference_peer_name, peer_number);
    tox_event_conference_peer_name_set_name(conference_peer_name, name, length);
}
