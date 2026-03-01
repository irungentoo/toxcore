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
#include "../tox_pack.h"
#include "../tox_struct.h"
#include "../tox_unpack.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Self_Connection_Status {
    Tox_Connection connection_status;
};

static void tox_event_self_connection_status_set_connection_status(Tox_Event_Self_Connection_Status *_Nonnull self_connection_status, Tox_Connection connection_status)
{
    assert(self_connection_status != nullptr);
    self_connection_status->connection_status = connection_status;
}
Tox_Connection tox_event_self_connection_status_get_connection_status(const Tox_Event_Self_Connection_Status *self_connection_status)
{
    assert(self_connection_status != nullptr);
    return self_connection_status->connection_status;
}

static void tox_event_self_connection_status_construct(Tox_Event_Self_Connection_Status *_Nonnull self_connection_status)
{
    *self_connection_status = (Tox_Event_Self_Connection_Status) {
        TOX_CONNECTION_NONE
    };
}
static void tox_event_self_connection_status_destruct(Tox_Event_Self_Connection_Status *_Nonnull self_connection_status, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_self_connection_status_pack(
    const Tox_Event_Self_Connection_Status *event, Bin_Pack *bp)
{
    return tox_connection_pack(event->connection_status, bp);
}

static bool tox_event_self_connection_status_unpack_into(Tox_Event_Self_Connection_Status *_Nonnull event, Bin_Unpack *_Nonnull bu)
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

static Tox_Event_Self_Connection_Status *_Nullable tox_events_add_self_connection_status(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Self_Connection_Status *const self_connection_status = tox_event_self_connection_status_new(mem);

    if (self_connection_status == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_SELF_CONNECTION_STATUS;
    event.data.self_connection_status = self_connection_status;

    if (!tox_events_add(events, &event)) {
        tox_event_self_connection_status_free(self_connection_status, mem);
        return nullptr;
    }
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

static Tox_Event_Self_Connection_Status *_Nullable tox_event_self_connection_status_alloc(Tox_Events_State *_Nonnull state)
{
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
    Tox *_Nonnull tox,
    Tox_Connection connection_status,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Self_Connection_Status *self_connection_status = tox_event_self_connection_status_alloc(state);

    if (self_connection_status == nullptr) {
        return;
    }

    tox_event_self_connection_status_set_connection_status(self_connection_status, connection_status);
}

void tox_events_handle_self_connection_status_dispatch(Tox *tox, const Tox_Event_Self_Connection_Status *event, void *user_data)
{
    if (tox->self_connection_status_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->self_connection_status_callback(tox, event->connection_status, user_data);
    tox_lock(tox);
}
