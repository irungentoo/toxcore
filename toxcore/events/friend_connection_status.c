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


struct Tox_Event_Friend_Connection_Status {
    uint32_t friend_number;
    Tox_Connection connection_status;
};

non_null()
static void tox_event_friend_connection_status_construct(Tox_Event_Friend_Connection_Status *friend_connection_status)
{
    *friend_connection_status = (Tox_Event_Friend_Connection_Status) {
        0
    };
}
non_null()
static void tox_event_friend_connection_status_destruct(Tox_Event_Friend_Connection_Status *friend_connection_status)
{
    return;
}

non_null()
static void tox_event_friend_connection_status_set_friend_number(Tox_Event_Friend_Connection_Status
        *friend_connection_status, uint32_t friend_number)
{
    assert(friend_connection_status != nullptr);
    friend_connection_status->friend_number = friend_number;
}
uint32_t tox_event_friend_connection_status_get_friend_number(const Tox_Event_Friend_Connection_Status
        *friend_connection_status)
{
    assert(friend_connection_status != nullptr);
    return friend_connection_status->friend_number;
}

non_null()
static void tox_event_friend_connection_status_set_connection_status(Tox_Event_Friend_Connection_Status
        *friend_connection_status, Tox_Connection connection_status)
{
    assert(friend_connection_status != nullptr);
    friend_connection_status->connection_status = connection_status;
}
Tox_Connection tox_event_friend_connection_status_get_connection_status(const Tox_Event_Friend_Connection_Status
        *friend_connection_status)
{
    assert(friend_connection_status != nullptr);
    return friend_connection_status->connection_status;
}

non_null()
static bool tox_event_friend_connection_status_pack(
    const Tox_Event_Friend_Connection_Status *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_CONNECTION_STATUS)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->connection_status);
}

non_null()
static bool tox_event_friend_connection_status_unpack(
    Tox_Event_Friend_Connection_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_unpack_connection(bu, &event->connection_status);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Friend_Connection_Status *tox_events_add_friend_connection_status(Tox_Events *events)
{
    if (events->friend_connection_status_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->friend_connection_status_size == events->friend_connection_status_capacity) {
        const uint32_t new_friend_connection_status_capacity = events->friend_connection_status_capacity * 2 + 1;
        Tox_Event_Friend_Connection_Status *new_friend_connection_status = (Tox_Event_Friend_Connection_Status *)realloc(
                    events->friend_connection_status, new_friend_connection_status_capacity * sizeof(Tox_Event_Friend_Connection_Status));

        if (new_friend_connection_status == nullptr) {
            return nullptr;
        }

        events->friend_connection_status = new_friend_connection_status;
        events->friend_connection_status_capacity = new_friend_connection_status_capacity;
    }

    Tox_Event_Friend_Connection_Status *const friend_connection_status =
        &events->friend_connection_status[events->friend_connection_status_size];
    tox_event_friend_connection_status_construct(friend_connection_status);
    ++events->friend_connection_status_size;
    return friend_connection_status;
}

void tox_events_clear_friend_connection_status(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->friend_connection_status_size; ++i) {
        tox_event_friend_connection_status_destruct(&events->friend_connection_status[i]);
    }

    free(events->friend_connection_status);
    events->friend_connection_status = nullptr;
    events->friend_connection_status_size = 0;
    events->friend_connection_status_capacity = 0;
}

uint32_t tox_events_get_friend_connection_status_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->friend_connection_status_size;
}

const Tox_Event_Friend_Connection_Status *tox_events_get_friend_connection_status(const Tox_Events *events,
        uint32_t index)
{
    assert(index < events->friend_connection_status_size);
    assert(events->friend_connection_status != nullptr);
    return &events->friend_connection_status[index];
}

bool tox_events_pack_friend_connection_status(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_friend_connection_status_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_friend_connection_status_pack(tox_events_get_friend_connection_status(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_friend_connection_status(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Friend_Connection_Status *event = tox_events_add_friend_connection_status(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_friend_connection_status_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_connection_status(Tox *tox, uint32_t friend_number, Tox_Connection connection_status,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Friend_Connection_Status *friend_connection_status = tox_events_add_friend_connection_status(state->events);

    if (friend_connection_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_friend_connection_status_set_friend_number(friend_connection_status, friend_number);
    tox_event_friend_connection_status_set_connection_status(friend_connection_status, connection_status);
}
