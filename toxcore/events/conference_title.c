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

struct Tox_Event_Conference_Title {
    uint32_t conference_number;
    uint32_t peer_number;
    uint8_t *title;
    uint32_t title_length;
};

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

non_null(1) nullable(2)
static bool tox_event_conference_title_set_title(Tox_Event_Conference_Title *conference_title,
        const uint8_t *title, uint32_t title_length)
{
    assert(conference_title != nullptr);

    if (conference_title->title != nullptr) {
        free(conference_title->title);
        conference_title->title = nullptr;
        conference_title->title_length = 0;
    }

    if (title == nullptr) {
        assert(title_length == 0);
        return true;
    }

    uint8_t *title_copy = (uint8_t *)malloc(title_length);

    if (title_copy == nullptr) {
        return false;
    }

    memcpy(title_copy, title, title_length);
    conference_title->title = title_copy;
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
static void tox_event_conference_title_construct(Tox_Event_Conference_Title *conference_title)
{
    *conference_title = (Tox_Event_Conference_Title) {
        0
    };
}
non_null()
static void tox_event_conference_title_destruct(Tox_Event_Conference_Title *conference_title, const Memory *mem)
{
    free(conference_title->title);
}

bool tox_event_conference_title_pack(
    const Tox_Event_Conference_Title *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_bin(bp, event->title, event->title_length);
}

non_null()
static bool tox_event_conference_title_unpack_into(
    Tox_Event_Conference_Title *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && bin_unpack_bin(bu, &event->title, &event->title_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Conference_Title *tox_event_get_conference_title(const Tox_Event *event)
{
    return event->type == TOX_EVENT_CONFERENCE_TITLE ? event->data.conference_title : nullptr;
}

Tox_Event_Conference_Title *tox_event_conference_title_new(const Memory *mem)
{
    Tox_Event_Conference_Title *const conference_title =
        (Tox_Event_Conference_Title *)mem_alloc(mem, sizeof(Tox_Event_Conference_Title));

    if (conference_title == nullptr) {
        return nullptr;
    }

    tox_event_conference_title_construct(conference_title);
    return conference_title;
}

void tox_event_conference_title_free(Tox_Event_Conference_Title *conference_title, const Memory *mem)
{
    if (conference_title != nullptr) {
        tox_event_conference_title_destruct(conference_title, mem);
    }
    mem_delete(mem, conference_title);
}

non_null()
static Tox_Event_Conference_Title *tox_events_add_conference_title(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Conference_Title *const conference_title = tox_event_conference_title_new(mem);

    if (conference_title == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_TITLE;
    event.data.conference_title = conference_title;

    tox_events_add(events, &event);
    return conference_title;
}

bool tox_event_conference_title_unpack(
    Tox_Event_Conference_Title **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_conference_title_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_conference_title_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Conference_Title *tox_event_conference_title_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Conference_Title *conference_title = tox_events_add_conference_title(state->events, state->mem);

    if (conference_title == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return conference_title;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_title(
    Tox *tox, uint32_t conference_number, uint32_t peer_number, const uint8_t *title, size_t length,
    void *user_data)
{
    Tox_Event_Conference_Title *conference_title = tox_event_conference_title_alloc(user_data);

    if (conference_title == nullptr) {
        return;
    }

    tox_event_conference_title_set_conference_number(conference_title, conference_number);
    tox_event_conference_title_set_peer_number(conference_title, peer_number);
    tox_event_conference_title_set_title(conference_title, title, length);
}
