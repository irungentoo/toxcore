/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../ccompat.h"
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

static void tox_event_conference_connected_construct(Tox_Event_Conference_Connected *conference_connected)
{
    *conference_connected = (Tox_Event_Conference_Connected) {
        0
    };
}
static void tox_event_conference_connected_destruct(Tox_Event_Conference_Connected *conference_connected)
{
    return;
}

static void tox_event_conference_connected_set_conference_number(Tox_Event_Conference_Connected *conference_connected,
        uint32_t conference_number)
{
    assert(conference_connected != nullptr);
    conference_connected->conference_number = conference_number;
}
uint32_t tox_event_conference_connected_get_conference_number(const Tox_Event_Conference_Connected
        *conference_connected)
{
    assert(conference_connected != nullptr);
    return conference_connected->conference_number;
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


static Tox_Event_Conference_Connected *tox_events_add_conference_connected(Tox_Events *events)
{
    if (events->conference_connected_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->conference_connected_size == events->conference_connected_capacity) {
        const uint32_t new_conference_connected_capacity = events->conference_connected_capacity * 2 + 1;
        Tox_Event_Conference_Connected *new_conference_connected = (Tox_Event_Conference_Connected *)realloc(
                    events->conference_connected, new_conference_connected_capacity * sizeof(Tox_Event_Conference_Connected));

        if (new_conference_connected == nullptr) {
            return nullptr;
        }

        events->conference_connected = new_conference_connected;
        events->conference_connected_capacity = new_conference_connected_capacity;
    }

    Tox_Event_Conference_Connected *const conference_connected =
        &events->conference_connected[events->conference_connected_size];
    tox_event_conference_connected_construct(conference_connected);
    ++events->conference_connected_size;
    return conference_connected;
}

void tox_events_clear_conference_connected(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->conference_connected_size; ++i) {
        tox_event_conference_connected_destruct(&events->conference_connected[i]);
    }

    free(events->conference_connected);
    events->conference_connected = nullptr;
    events->conference_connected_size = 0;
    events->conference_connected_capacity = 0;
}

uint32_t tox_events_get_conference_connected_size(const Tox_Events *events)
{
    return events->conference_connected_size;
}

const Tox_Event_Conference_Connected *tox_events_get_conference_connected(const Tox_Events *events, uint32_t index)
{
    assert(index < events->conference_connected_size);
    assert(events->conference_connected != nullptr);
    return &events->conference_connected[index];
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_connected(Tox *tox, uint32_t conference_number, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_Conference_Connected *conference_connected = tox_events_add_conference_connected(state->events);

    if (conference_connected == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_conference_connected_set_conference_number(conference_connected, conference_number);
}
