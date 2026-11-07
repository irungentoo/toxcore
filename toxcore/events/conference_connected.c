/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>

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

struct Tox_Event_Conference_Connected {
    uint32_t conference_number;
};

static void tox_event_conference_connected_set_conference_number(Tox_Event_Conference_Connected *_Nonnull conference_connected, uint32_t conference_number)
{
    assert(conference_connected != nullptr);
    conference_connected->conference_number = conference_number;
}
uint32_t tox_event_conference_connected_get_conference_number(const Tox_Event_Conference_Connected *conference_connected)
{
    assert(conference_connected != nullptr);
    return conference_connected->conference_number;
}

static void tox_event_conference_connected_construct(Tox_Event_Conference_Connected *_Nonnull conference_connected)
{
    *conference_connected = (Tox_Event_Conference_Connected) {
        0
    };
}
static void tox_event_conference_connected_destruct(Tox_Event_Conference_Connected *_Nonnull conference_connected, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_conference_connected_pack(
    const Tox_Event_Conference_Connected *event, Bin_Pack *bp)
{
    return bin_pack_u32(bp, event->conference_number);
}

static bool tox_event_conference_connected_unpack_into(Tox_Event_Conference_Connected *_Nonnull event, Bin_Unpack *_Nonnull bu)
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

static void tox_events_add_conference_connected(Tox_Events_State *_Nonnull state, Tox_Event_Conference_Connected *_Nonnull conference_connected)
{
    if (state->events == nullptr) {
        tox_event_conference_connected_free(conference_connected, state->mem);
        return;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_CONNECTED;
    event.data.conference_connected = conference_connected;

    if (!tox_events_add(state->events, &event)) {
        tox_event_conference_connected_free(conference_connected, state->mem);
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
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

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_connected(
    uint32_t conference_number,
    Tox_Events_State *state)
{
    Tox_Event_Conference_Connected *conference_connected = tox_event_conference_connected_new(state->mem);

    if (conference_connected == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_conference_connected_set_conference_number(conference_connected, conference_number);

    tox_events_add_conference_connected(tox_events_alloc(state), conference_connected);
}

void tox_events_handle_conference_connected_dispatch(Tox *tox, const Tox_Event_Conference_Connected *event, void *user_data)
{
    if (tox->conference_connected_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->conference_connected_callback(tox, event->conference_number, user_data);
    tox_lock(tox);
}
