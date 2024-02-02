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
#include "../tox_pack.h"
#include "../tox_unpack.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Self_Connection_Status {
    Tox_Connection connection_status;
};

non_null()
static void tox_event_self_connection_status_set_connection_status(Tox_Event_Self_Connection_Status *self_connection_status,
        Tox_Connection connection_status)
{
    assert(self_connection_status != nullptr);
    self_connection_status->connection_status = connection_status;
}
Tox_Connection tox_event_self_connection_status_get_connection_status(const Tox_Event_Self_Connection_Status *self_connection_status)
{
    assert(self_connection_status != nullptr);
    return self_connection_status->connection_status;
}

non_null()
static void tox_event_self_connection_status_construct(Tox_Event_Self_Connection_Status *self_connection_status)
{
    *self_connection_status = (Tox_Event_Self_Connection_Status) {
        TOX_CONNECTION_NONE
    };
}
non_null()
static void tox_event_self_connection_status_destruct(Tox_Event_Self_Connection_Status *self_connection_status, const Memory *mem)
{
    return;
}

bool tox_event_self_connection_status_pack(
    const Tox_Event_Self_Connection_Status *event, Bin_Pack *bp)
{
    return tox_connection_pack(event->connection_status, bp);
}

non_null()
static bool tox_event_self_connection_status_unpack_into(
    Tox_Event_Self_Connection_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    return tox_connection_unpack(&event->connection_status, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Self_Connection_Status *tox_event_get_self_connection_status(const Tox_Event *event)
{
    return event->type == TOX_EVENT_SELF_CONNECTION_STATUS ? event->data.self_connection_status : nullptr;
}

Tox_Event_Self_Connection_Status *tox_event_self_connection_status_new(const Memory *mem)
{
    Tox_Event_Self_Connection_Status *const self_connection_status =
        (Tox_Event_Self_Connection_Status *)mem_alloc(mem, sizeof(Tox_Event_Self_Connection_Status));

    if (self_connection_status == nullptr) {
        return nullptr;
    }

    tox_event_self_connection_status_construct(self_connection_status);
    return self_connection_status;
}

void tox_event_self_connection_status_free(Tox_Event_Self_Connection_Status *self_connection_status, const Memory *mem)
{
    if (self_connection_status != nullptr) {
        tox_event_self_connection_status_destruct(self_connection_status, mem);
    }
    mem_delete(mem, self_connection_status);
}

non_null()
static Tox_Event_Self_Connection_Status *tox_events_add_self_connection_status(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Self_Connection_Status *const self_connection_status = tox_event_self_connection_status_new(mem);

    if (self_connection_status == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_SELF_CONNECTION_STATUS;
    event.data.self_connection_status = self_connection_status;

    tox_events_add(events, &event);
    return self_connection_status;
}

bool tox_event_self_connection_status_unpack(
    Tox_Event_Self_Connection_Status **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_self_connection_status_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_self_connection_status_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Self_Connection_Status *tox_event_self_connection_status_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Self_Connection_Status *self_connection_status = tox_events_add_self_connection_status(state->events, state->mem);

    if (self_connection_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return self_connection_status;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_self_connection_status(
    Tox *tox, Tox_Connection connection_status,
    void *user_data)
{
    Tox_Event_Self_Connection_Status *self_connection_status = tox_event_self_connection_status_alloc(user_data);

    if (self_connection_status == nullptr) {
        return;
    }

    tox_event_self_connection_status_set_connection_status(self_connection_status, connection_status);
}
