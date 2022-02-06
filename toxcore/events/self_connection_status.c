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


struct Tox_Event_Self_Connection_Status {
    Tox_Connection connection_status;
};

static void tox_event_self_connection_status_pack(const Tox_Event_Self_Connection_Status *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    msgpack_pack_array(mp, 1);
    msgpack_pack_uint32(mp, event->connection_status);
}

static void tox_event_self_connection_status_construct(Tox_Event_Self_Connection_Status *self_connection_status)
{
    *self_connection_status = (Tox_Event_Self_Connection_Status) {
        TOX_CONNECTION_NONE
    };
}
static void tox_event_self_connection_status_destruct(Tox_Event_Self_Connection_Status *self_connection_status)
{
    return;
}

static void tox_event_self_connection_status_set_connection_status(Tox_Event_Self_Connection_Status
        *self_connection_status, Tox_Connection connection_status)
{
    assert(self_connection_status != nullptr);
    self_connection_status->connection_status = connection_status;
}
Tox_Connection tox_event_self_connection_status_get_connection_status(const Tox_Event_Self_Connection_Status
        *self_connection_status)
{
    assert(self_connection_status != nullptr);
    return self_connection_status->connection_status;
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


static Tox_Event_Self_Connection_Status *tox_events_add_self_connection_status(Tox_Events *events)
{
    if (events->self_connection_status_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->self_connection_status_size == events->self_connection_status_capacity) {
        const uint32_t new_self_connection_status_capacity = events->self_connection_status_capacity * 2 + 1;
        Tox_Event_Self_Connection_Status *new_self_connection_status = (Tox_Event_Self_Connection_Status *)realloc(
                    events->self_connection_status, new_self_connection_status_capacity * sizeof(Tox_Event_Self_Connection_Status));

        if (new_self_connection_status == nullptr) {
            return nullptr;
        }

        events->self_connection_status = new_self_connection_status;
        events->self_connection_status_capacity = new_self_connection_status_capacity;
    }

    Tox_Event_Self_Connection_Status *const self_connection_status =
        &events->self_connection_status[events->self_connection_status_size];
    tox_event_self_connection_status_construct(self_connection_status);
    ++events->self_connection_status_size;
    return self_connection_status;
}

void tox_events_clear_self_connection_status(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->self_connection_status_size; ++i) {
        tox_event_self_connection_status_destruct(&events->self_connection_status[i]);
    }

    free(events->self_connection_status);
    events->self_connection_status = nullptr;
    events->self_connection_status_size = 0;
    events->self_connection_status_capacity = 0;
}

uint32_t tox_events_get_self_connection_status_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->self_connection_status_size;
}

const Tox_Event_Self_Connection_Status *tox_events_get_self_connection_status(const Tox_Events *events, uint32_t index)
{
    assert(index < events->self_connection_status_size);
    assert(events->self_connection_status != nullptr);
    return &events->self_connection_status[index];
}

void tox_events_pack_self_connection_status(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_self_connection_status_size(events);

    msgpack_pack_array(mp, size);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_self_connection_status_pack(tox_events_get_self_connection_status(events, i), mp);
    }
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_self_connection_status(Tox *tox, Tox_Connection connection_status, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_Self_Connection_Status *self_connection_status = tox_events_add_self_connection_status(state->events);

    if (self_connection_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_self_connection_status_set_connection_status(self_connection_status, connection_status);
}
