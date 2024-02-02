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

struct Tox_Event_Friend_Connection_Status {
    uint32_t friend_number;
    Tox_Connection connection_status;
};

non_null()
static void tox_event_friend_connection_status_set_friend_number(Tox_Event_Friend_Connection_Status *friend_connection_status,
        uint32_t friend_number)
{
    assert(friend_connection_status != nullptr);
    friend_connection_status->friend_number = friend_number;
}
uint32_t tox_event_friend_connection_status_get_friend_number(const Tox_Event_Friend_Connection_Status *friend_connection_status)
{
    assert(friend_connection_status != nullptr);
    return friend_connection_status->friend_number;
}

non_null()
static void tox_event_friend_connection_status_set_connection_status(Tox_Event_Friend_Connection_Status *friend_connection_status,
        Tox_Connection connection_status)
{
    assert(friend_connection_status != nullptr);
    friend_connection_status->connection_status = connection_status;
}
Tox_Connection tox_event_friend_connection_status_get_connection_status(const Tox_Event_Friend_Connection_Status *friend_connection_status)
{
    assert(friend_connection_status != nullptr);
    return friend_connection_status->connection_status;
}

non_null()
static void tox_event_friend_connection_status_construct(Tox_Event_Friend_Connection_Status *friend_connection_status)
{
    *friend_connection_status = (Tox_Event_Friend_Connection_Status) {
        0
    };
}
non_null()
static void tox_event_friend_connection_status_destruct(Tox_Event_Friend_Connection_Status *friend_connection_status, const Memory *mem)
{
    return;
}

bool tox_event_friend_connection_status_pack(
    const Tox_Event_Friend_Connection_Status *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && tox_connection_pack(event->connection_status, bp);
}

non_null()
static bool tox_event_friend_connection_status_unpack_into(
    Tox_Event_Friend_Connection_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_connection_unpack(&event->connection_status, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Connection_Status *tox_event_get_friend_connection_status(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_CONNECTION_STATUS ? event->data.friend_connection_status : nullptr;
}

Tox_Event_Friend_Connection_Status *tox_event_friend_connection_status_new(const Memory *mem)
{
    Tox_Event_Friend_Connection_Status *const friend_connection_status =
        (Tox_Event_Friend_Connection_Status *)mem_alloc(mem, sizeof(Tox_Event_Friend_Connection_Status));

    if (friend_connection_status == nullptr) {
        return nullptr;
    }

    tox_event_friend_connection_status_construct(friend_connection_status);
    return friend_connection_status;
}

void tox_event_friend_connection_status_free(Tox_Event_Friend_Connection_Status *friend_connection_status, const Memory *mem)
{
    if (friend_connection_status != nullptr) {
        tox_event_friend_connection_status_destruct(friend_connection_status, mem);
    }
    mem_delete(mem, friend_connection_status);
}

non_null()
static Tox_Event_Friend_Connection_Status *tox_events_add_friend_connection_status(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Friend_Connection_Status *const friend_connection_status = tox_event_friend_connection_status_new(mem);

    if (friend_connection_status == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_CONNECTION_STATUS;
    event.data.friend_connection_status = friend_connection_status;

    tox_events_add(events, &event);
    return friend_connection_status;
}

bool tox_event_friend_connection_status_unpack(
    Tox_Event_Friend_Connection_Status **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_connection_status_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_connection_status_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Friend_Connection_Status *tox_event_friend_connection_status_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Connection_Status *friend_connection_status = tox_events_add_friend_connection_status(state->events, state->mem);

    if (friend_connection_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_connection_status;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_connection_status(
    Tox *tox, uint32_t friend_number, Tox_Connection connection_status,
    void *user_data)
{
    Tox_Event_Friend_Connection_Status *friend_connection_status = tox_event_friend_connection_status_alloc(user_data);

    if (friend_connection_status == nullptr) {
        return;
    }

    tox_event_friend_connection_status_set_friend_number(friend_connection_status, friend_number);
    tox_event_friend_connection_status_set_connection_status(friend_connection_status, connection_status);
}
