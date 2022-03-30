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


struct Tox_Event_Conference_Peer_Name {
    uint32_t conference_number;
    uint32_t peer_number;
    uint8_t *name;
    uint32_t name_length;
};

non_null()
static void tox_event_conference_peer_name_construct(Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    *conference_peer_name = (Tox_Event_Conference_Peer_Name) {
        0
    };
}
non_null()
static void tox_event_conference_peer_name_destruct(Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    free(conference_peer_name->name);
}

non_null()
static void tox_event_conference_peer_name_set_conference_number(Tox_Event_Conference_Peer_Name *conference_peer_name,
        uint32_t conference_number)
{
    assert(conference_peer_name != nullptr);
    conference_peer_name->conference_number = conference_number;
}
uint32_t tox_event_conference_peer_name_get_conference_number(const Tox_Event_Conference_Peer_Name
        *conference_peer_name)
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

non_null()
static bool tox_event_conference_peer_name_set_name(Tox_Event_Conference_Peer_Name *conference_peer_name,
        const uint8_t *name, uint32_t name_length)
{
    assert(conference_peer_name != nullptr);

    if (conference_peer_name->name != nullptr) {
        free(conference_peer_name->name);
        conference_peer_name->name = nullptr;
        conference_peer_name->name_length = 0;
    }

    conference_peer_name->name = (uint8_t *)malloc(name_length);

    if (conference_peer_name->name == nullptr) {
        return false;
    }

    memcpy(conference_peer_name->name, name, name_length);
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
static bool tox_event_conference_peer_name_pack(
    const Tox_Event_Conference_Peer_Name *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_PEER_NAME)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_bin(bp, event->name, event->name_length);
}

non_null()
static bool tox_event_conference_peer_name_unpack(
    Tox_Event_Conference_Peer_Name *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Conference_Peer_Name *tox_events_add_conference_peer_name(Tox_Events *events)
{
    if (events->conference_peer_name_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->conference_peer_name_size == events->conference_peer_name_capacity) {
        const uint32_t new_conference_peer_name_capacity = events->conference_peer_name_capacity * 2 + 1;
        Tox_Event_Conference_Peer_Name *new_conference_peer_name = (Tox_Event_Conference_Peer_Name *)realloc(
                    events->conference_peer_name, new_conference_peer_name_capacity * sizeof(Tox_Event_Conference_Peer_Name));

        if (new_conference_peer_name == nullptr) {
            return nullptr;
        }

        events->conference_peer_name = new_conference_peer_name;
        events->conference_peer_name_capacity = new_conference_peer_name_capacity;
    }

    Tox_Event_Conference_Peer_Name *const conference_peer_name =
        &events->conference_peer_name[events->conference_peer_name_size];
    tox_event_conference_peer_name_construct(conference_peer_name);
    ++events->conference_peer_name_size;
    return conference_peer_name;
}

void tox_events_clear_conference_peer_name(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->conference_peer_name_size; ++i) {
        tox_event_conference_peer_name_destruct(&events->conference_peer_name[i]);
    }

    free(events->conference_peer_name);
    events->conference_peer_name = nullptr;
    events->conference_peer_name_size = 0;
    events->conference_peer_name_capacity = 0;
}

uint32_t tox_events_get_conference_peer_name_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->conference_peer_name_size;
}

const Tox_Event_Conference_Peer_Name *tox_events_get_conference_peer_name(const Tox_Events *events, uint32_t index)
{
    assert(index < events->conference_peer_name_size);
    assert(events->conference_peer_name != nullptr);
    return &events->conference_peer_name[index];
}

bool tox_events_pack_conference_peer_name(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_conference_peer_name_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_conference_peer_name_pack(tox_events_get_conference_peer_name(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_conference_peer_name(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Conference_Peer_Name *event = tox_events_add_conference_peer_name(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_conference_peer_name_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_peer_name(Tox *tox, uint32_t conference_number, uint32_t peer_number,
        const uint8_t *name, size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Conference_Peer_Name *conference_peer_name = tox_events_add_conference_peer_name(state->events);

    if (conference_peer_name == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_conference_peer_name_set_conference_number(conference_peer_name, conference_number);
    tox_event_conference_peer_name_set_peer_number(conference_peer_name, peer_number);
    tox_event_conference_peer_name_set_name(conference_peer_name, name, length);
}
