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


struct Tox_Event_Conference_Title {
    uint32_t conference_number;
    uint32_t peer_number;
    uint8_t *title;
    uint32_t title_length;
};

non_null()
static void tox_event_conference_title_construct(Tox_Event_Conference_Title *conference_title)
{
    *conference_title = (Tox_Event_Conference_Title) {
        0
    };
}
non_null()
static void tox_event_conference_title_destruct(Tox_Event_Conference_Title *conference_title)
{
    free(conference_title->title);
}

non_null()
static void tox_event_conference_title_set_conference_number(Tox_Event_Conference_Title *conference_title,
        uint32_t conference_number)
{
    assert(conference_title != nullptr);
    conference_title->conference_number = conference_number;
}
uint32_t tox_event_conference_title_get_conference_number(const Tox_Event_Conference_Title *conference_title)
{
    assert(conference_title != nullptr);
    return conference_title->conference_number;
}

non_null()
static void tox_event_conference_title_set_peer_number(Tox_Event_Conference_Title *conference_title,
        uint32_t peer_number)
{
    assert(conference_title != nullptr);
    conference_title->peer_number = peer_number;
}
uint32_t tox_event_conference_title_get_peer_number(const Tox_Event_Conference_Title *conference_title)
{
    assert(conference_title != nullptr);
    return conference_title->peer_number;
}

non_null()
static bool tox_event_conference_title_set_title(Tox_Event_Conference_Title *conference_title, const uint8_t *title,
        uint32_t title_length)
{
    assert(conference_title != nullptr);

    if (conference_title->title != nullptr) {
        free(conference_title->title);
        conference_title->title = nullptr;
        conference_title->title_length = 0;
    }

    conference_title->title = (uint8_t *)malloc(title_length);

    if (conference_title->title == nullptr) {
        return false;
    }

    memcpy(conference_title->title, title, title_length);
    conference_title->title_length = title_length;
    return true;
}
uint32_t tox_event_conference_title_get_title_length(const Tox_Event_Conference_Title *conference_title)
{
    assert(conference_title != nullptr);
    return conference_title->title_length;
}
const uint8_t *tox_event_conference_title_get_title(const Tox_Event_Conference_Title *conference_title)
{
    assert(conference_title != nullptr);
    return conference_title->title;
}

non_null()
static bool tox_event_conference_title_pack(
    const Tox_Event_Conference_Title *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_TITLE)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_bin(bp, event->title, event->title_length);
}

non_null()
static bool tox_event_conference_title_unpack(
    Tox_Event_Conference_Title *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && bin_unpack_bin(bu, &event->title, &event->title_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Conference_Title *tox_events_add_conference_title(Tox_Events *events)
{
    if (events->conference_title_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->conference_title_size == events->conference_title_capacity) {
        const uint32_t new_conference_title_capacity = events->conference_title_capacity * 2 + 1;
        Tox_Event_Conference_Title *new_conference_title = (Tox_Event_Conference_Title *)realloc(
                    events->conference_title, new_conference_title_capacity * sizeof(Tox_Event_Conference_Title));

        if (new_conference_title == nullptr) {
            return nullptr;
        }

        events->conference_title = new_conference_title;
        events->conference_title_capacity = new_conference_title_capacity;
    }

    Tox_Event_Conference_Title *const conference_title = &events->conference_title[events->conference_title_size];
    tox_event_conference_title_construct(conference_title);
    ++events->conference_title_size;
    return conference_title;
}

void tox_events_clear_conference_title(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->conference_title_size; ++i) {
        tox_event_conference_title_destruct(&events->conference_title[i]);
    }

    free(events->conference_title);
    events->conference_title = nullptr;
    events->conference_title_size = 0;
    events->conference_title_capacity = 0;
}

uint32_t tox_events_get_conference_title_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->conference_title_size;
}

const Tox_Event_Conference_Title *tox_events_get_conference_title(const Tox_Events *events, uint32_t index)
{
    assert(index < events->conference_title_size);
    assert(events->conference_title != nullptr);
    return &events->conference_title[index];
}

bool tox_events_pack_conference_title(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_conference_title_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_conference_title_pack(tox_events_get_conference_title(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_conference_title(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Conference_Title *event = tox_events_add_conference_title(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_conference_title_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_title(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        const uint8_t *title, size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Conference_Title *conference_title = tox_events_add_conference_title(state->events);

    if (conference_title == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_conference_title_set_conference_number(conference_title, conference_number);
    tox_event_conference_title_set_peer_number(conference_title, peer_number);
    tox_event_conference_title_set_title(conference_title, title, length);
}
