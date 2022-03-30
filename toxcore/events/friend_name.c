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


struct Tox_Event_Friend_Name {
    uint32_t friend_number;
    uint8_t *name;
    uint32_t name_length;
};

non_null()
static void tox_event_friend_name_construct(Tox_Event_Friend_Name *friend_name)
{
    *friend_name = (Tox_Event_Friend_Name) {
        0
    };
}
non_null()
static void tox_event_friend_name_destruct(Tox_Event_Friend_Name *friend_name)
{
    free(friend_name->name);
}

non_null()
static void tox_event_friend_name_set_friend_number(Tox_Event_Friend_Name *friend_name,
        uint32_t friend_number)
{
    assert(friend_name != nullptr);
    friend_name->friend_number = friend_number;
}
uint32_t tox_event_friend_name_get_friend_number(const Tox_Event_Friend_Name *friend_name)
{
    assert(friend_name != nullptr);
    return friend_name->friend_number;
}

non_null()
static bool tox_event_friend_name_set_name(Tox_Event_Friend_Name *friend_name, const uint8_t *name,
        uint32_t name_length)
{
    assert(friend_name != nullptr);

    if (friend_name->name != nullptr) {
        free(friend_name->name);
        friend_name->name = nullptr;
        friend_name->name_length = 0;
    }

    friend_name->name = (uint8_t *)malloc(name_length);

    if (friend_name->name == nullptr) {
        return false;
    }

    memcpy(friend_name->name, name, name_length);
    friend_name->name_length = name_length;
    return true;
}
uint32_t tox_event_friend_name_get_name_length(const Tox_Event_Friend_Name *friend_name)
{
    assert(friend_name != nullptr);
    return friend_name->name_length;
}
const uint8_t *tox_event_friend_name_get_name(const Tox_Event_Friend_Name *friend_name)
{
    assert(friend_name != nullptr);
    return friend_name->name;
}

non_null()
static bool tox_event_friend_name_pack(
    const Tox_Event_Friend_Name *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_NAME)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->name, event->name_length);
}

non_null()
static bool tox_event_friend_name_unpack(
    Tox_Event_Friend_Name *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Friend_Name *tox_events_add_friend_name(Tox_Events *events)
{
    if (events->friend_name_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->friend_name_size == events->friend_name_capacity) {
        const uint32_t new_friend_name_capacity = events->friend_name_capacity * 2 + 1;
        Tox_Event_Friend_Name *new_friend_name = (Tox_Event_Friend_Name *)realloc(
                    events->friend_name, new_friend_name_capacity * sizeof(Tox_Event_Friend_Name));

        if (new_friend_name == nullptr) {
            return nullptr;
        }

        events->friend_name = new_friend_name;
        events->friend_name_capacity = new_friend_name_capacity;
    }

    Tox_Event_Friend_Name *const friend_name = &events->friend_name[events->friend_name_size];
    tox_event_friend_name_construct(friend_name);
    ++events->friend_name_size;
    return friend_name;
}

void tox_events_clear_friend_name(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->friend_name_size; ++i) {
        tox_event_friend_name_destruct(&events->friend_name[i]);
    }

    free(events->friend_name);
    events->friend_name = nullptr;
    events->friend_name_size = 0;
    events->friend_name_capacity = 0;
}

uint32_t tox_events_get_friend_name_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->friend_name_size;
}

const Tox_Event_Friend_Name *tox_events_get_friend_name(const Tox_Events *events, uint32_t index)
{
    assert(index < events->friend_name_size);
    assert(events->friend_name != nullptr);
    return &events->friend_name[index];
}

bool tox_events_pack_friend_name(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_friend_name_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_friend_name_pack(tox_events_get_friend_name(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_friend_name(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Friend_Name *event = tox_events_add_friend_name(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_friend_name_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_name(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length,
                                   void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Friend_Name *friend_name = tox_events_add_friend_name(state->events);

    if (friend_name == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_friend_name_set_friend_number(friend_name, friend_number);
    tox_event_friend_name_set_name(friend_name, name, length);
}
