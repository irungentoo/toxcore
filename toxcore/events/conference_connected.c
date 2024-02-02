/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>

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

struct Tox_Event_Conference_Connected {
    uint32_t conference_number;
};

non_null()
static void tox_event_conference_connected_set_conference_number(Tox_Event_Conference_Connected *conference_connected,
        uint32_t conference_number)
{
    assert(conference_connected != nullptr);
    conference_connected->conference_number = conference_number;
}
uint32_t tox_event_conference_connected_get_conference_number(const Tox_Event_Conference_Connected *conference_connected)
{
    assert(conference_connected != nullptr);
    return conference_connected->conference_number;
}

non_null()
static void tox_event_conference_connected_construct(Tox_Event_Conference_Connected *conference_connected)
{
    *conference_connected = (Tox_Event_Conference_Connected) {
        0
    };
}
non_null()
static void tox_event_conference_connected_destruct(Tox_Event_Conference_Connected *conference_connected, const Memory *mem)
{
    return;
}

bool tox_event_conference_connected_pack(
    const Tox_Event_Conference_Connected *event, Bin_Pack *bp)
{
    return bin_pack_u32(bp, event->conference_number);
}

non_null()
static bool tox_event_conference_connected_unpack_into(
    Tox_Event_Conference_Connected *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    return bin_unpack_u32(bu, &event->conference_number);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Conference_Connected *tox_event_get_conference_connected(const Tox_Event *event)
{
    return event->type == TOX_EVENT_CONFERENCE_CONNECTED ? event->data.conference_connected : nullptr;
}

Tox_Event_Conference_Connected *tox_event_conference_connected_new(const Memory *mem)
{
    Tox_Event_Conference_Connected *const conference_connected =
        (Tox_Event_Conference_Connected *)mem_alloc(mem, sizeof(Tox_Event_Conference_Connected));

    if (conference_connected == nullptr) {
        return nullptr;
    }

    tox_event_conference_connected_construct(conference_connected);
    return conference_connected;
}

void tox_event_conference_connected_free(Tox_Event_Conference_Connected *conference_connected, const Memory *mem)
{
    if (conference_connected != nullptr) {
        tox_event_conference_connected_destruct(conference_connected, mem);
    }
    mem_delete(mem, conference_connected);
}

non_null()
static Tox_Event_Conference_Connected *tox_events_add_conference_connected(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Conference_Connected *const conference_connected = tox_event_conference_connected_new(mem);

    if (conference_connected == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_CONNECTED;
    event.data.conference_connected = conference_connected;

    tox_events_add(events, &event);
    return conference_connected;
}

bool tox_event_conference_connected_unpack(
    Tox_Event_Conference_Connected **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_conference_connected_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_conference_connected_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Conference_Connected *tox_event_conference_connected_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Conference_Connected *conference_connected = tox_events_add_conference_connected(state->events, state->mem);

    if (conference_connected == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return conference_connected;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_connected(
    Tox *tox, uint32_t conference_number,
    void *user_data)
{
    Tox_Event_Conference_Connected *conference_connected = tox_event_conference_connected_alloc(user_data);

    if (conference_connected == nullptr) {
        return;
    }

    tox_event_conference_connected_set_conference_number(conference_connected, conference_number);
}
