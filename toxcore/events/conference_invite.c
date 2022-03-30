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
#include "../tox_unpack.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Conference_Invite {
    uint32_t friend_number;
    Tox_Conference_Type type;
    uint8_t *cookie;
    uint32_t cookie_length;
};

non_null()
static void tox_event_conference_invite_construct(Tox_Event_Conference_Invite *conference_invite)
{
    *conference_invite = (Tox_Event_Conference_Invite) {
        0
    };
}
non_null()
static void tox_event_conference_invite_destruct(Tox_Event_Conference_Invite *conference_invite)
{
    free(conference_invite->cookie);
}

non_null()
static void tox_event_conference_invite_set_friend_number(Tox_Event_Conference_Invite *conference_invite,
        uint32_t friend_number)
{
    assert(conference_invite != nullptr);
    conference_invite->friend_number = friend_number;
}
uint32_t tox_event_conference_invite_get_friend_number(const Tox_Event_Conference_Invite *conference_invite)
{
    assert(conference_invite != nullptr);
    return conference_invite->friend_number;
}

non_null()
static void tox_event_conference_invite_set_type(Tox_Event_Conference_Invite *conference_invite,
        Tox_Conference_Type type)
{
    assert(conference_invite != nullptr);
    conference_invite->type = type;
}
Tox_Conference_Type tox_event_conference_invite_get_type(const Tox_Event_Conference_Invite *conference_invite)
{
    assert(conference_invite != nullptr);
    return conference_invite->type;
}

non_null()
static bool tox_event_conference_invite_set_cookie(Tox_Event_Conference_Invite *conference_invite,
        const uint8_t *cookie, uint32_t cookie_length)
{
    assert(conference_invite != nullptr);

    if (conference_invite->cookie != nullptr) {
        free(conference_invite->cookie);
        conference_invite->cookie = nullptr;
        conference_invite->cookie_length = 0;
    }

    conference_invite->cookie = (uint8_t *)malloc(cookie_length);

    if (conference_invite->cookie == nullptr) {
        return false;
    }

    memcpy(conference_invite->cookie, cookie, cookie_length);
    conference_invite->cookie_length = cookie_length;
    return true;
}
uint32_t tox_event_conference_invite_get_cookie_length(const Tox_Event_Conference_Invite *conference_invite)
{
    assert(conference_invite != nullptr);
    return conference_invite->cookie_length;
}
const uint8_t *tox_event_conference_invite_get_cookie(const Tox_Event_Conference_Invite *conference_invite)
{
    assert(conference_invite != nullptr);
    return conference_invite->cookie;
}

non_null()
static bool tox_event_conference_invite_pack(
    const Tox_Event_Conference_Invite *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_INVITE)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->type)
           && bin_pack_bin(bp, event->cookie, event->cookie_length);
}

non_null()
static bool tox_event_conference_invite_unpack(
    Tox_Event_Conference_Invite *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_unpack_conference_type(bu, &event->type)
           && bin_unpack_bin(bu, &event->cookie, &event->cookie_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Conference_Invite *tox_events_add_conference_invite(Tox_Events *events)
{
    if (events->conference_invite_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->conference_invite_size == events->conference_invite_capacity) {
        const uint32_t new_conference_invite_capacity = events->conference_invite_capacity * 2 + 1;
        Tox_Event_Conference_Invite *new_conference_invite = (Tox_Event_Conference_Invite *)realloc(
                    events->conference_invite, new_conference_invite_capacity * sizeof(Tox_Event_Conference_Invite));

        if (new_conference_invite == nullptr) {
            return nullptr;
        }

        events->conference_invite = new_conference_invite;
        events->conference_invite_capacity = new_conference_invite_capacity;
    }

    Tox_Event_Conference_Invite *const conference_invite = &events->conference_invite[events->conference_invite_size];
    tox_event_conference_invite_construct(conference_invite);
    ++events->conference_invite_size;
    return conference_invite;
}

void tox_events_clear_conference_invite(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->conference_invite_size; ++i) {
        tox_event_conference_invite_destruct(&events->conference_invite[i]);
    }

    free(events->conference_invite);
    events->conference_invite = nullptr;
    events->conference_invite_size = 0;
    events->conference_invite_capacity = 0;
}

uint32_t tox_events_get_conference_invite_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->conference_invite_size;
}

const Tox_Event_Conference_Invite *tox_events_get_conference_invite(const Tox_Events *events, uint32_t index)
{
    assert(index < events->conference_invite_size);
    assert(events->conference_invite != nullptr);
    return &events->conference_invite[index];
}

bool tox_events_pack_conference_invite(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_conference_invite_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_conference_invite_pack(tox_events_get_conference_invite(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_conference_invite(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Conference_Invite *event = tox_events_add_conference_invite(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_conference_invite_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_invite(Tox *tox, uint32_t friend_number, Tox_Conference_Type type,
        const uint8_t *cookie, size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Conference_Invite *conference_invite = tox_events_add_conference_invite(state->events);

    if (conference_invite == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_conference_invite_set_friend_number(conference_invite, friend_number);
    tox_event_conference_invite_set_type(conference_invite, type);
    tox_event_conference_invite_set_cookie(conference_invite, cookie, length);
}
