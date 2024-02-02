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

struct Tox_Event_Friend_Status {
    uint32_t friend_number;
    Tox_User_Status status;
};

non_null()
static void tox_event_friend_status_set_friend_number(Tox_Event_Friend_Status *friend_status,
        uint32_t friend_number)
{
    assert(friend_status != nullptr);
    friend_status->friend_number = friend_number;
}
uint32_t tox_event_friend_status_get_friend_number(const Tox_Event_Friend_Status *friend_status)
{
    assert(friend_status != nullptr);
    return friend_status->friend_number;
}

non_null()
static void tox_event_friend_status_set_status(Tox_Event_Friend_Status *friend_status,
        Tox_User_Status status)
{
    assert(friend_status != nullptr);
    friend_status->status = status;
}
Tox_User_Status tox_event_friend_status_get_status(const Tox_Event_Friend_Status *friend_status)
{
    assert(friend_status != nullptr);
    return friend_status->status;
}

non_null()
static void tox_event_friend_status_construct(Tox_Event_Friend_Status *friend_status)
{
    *friend_status = (Tox_Event_Friend_Status) {
        0
    };
}
non_null()
static void tox_event_friend_status_destruct(Tox_Event_Friend_Status *friend_status, const Memory *mem)
{
    return;
}

bool tox_event_friend_status_pack(
    const Tox_Event_Friend_Status *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && tox_user_status_pack(event->status, bp);
}

non_null()
static bool tox_event_friend_status_unpack_into(
    Tox_Event_Friend_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_user_status_unpack(&event->status, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Status *tox_event_get_friend_status(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_STATUS ? event->data.friend_status : nullptr;
}

Tox_Event_Friend_Status *tox_event_friend_status_new(const Memory *mem)
{
    Tox_Event_Friend_Status *const friend_status =
        (Tox_Event_Friend_Status *)mem_alloc(mem, sizeof(Tox_Event_Friend_Status));

    if (friend_status == nullptr) {
        return nullptr;
    }

    tox_event_friend_status_construct(friend_status);
    return friend_status;
}

void tox_event_friend_status_free(Tox_Event_Friend_Status *friend_status, const Memory *mem)
{
    if (friend_status != nullptr) {
        tox_event_friend_status_destruct(friend_status, mem);
    }
    mem_delete(mem, friend_status);
}

non_null()
static Tox_Event_Friend_Status *tox_events_add_friend_status(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Friend_Status *const friend_status = tox_event_friend_status_new(mem);

    if (friend_status == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_STATUS;
    event.data.friend_status = friend_status;

    tox_events_add(events, &event);
    return friend_status;
}

bool tox_event_friend_status_unpack(
    Tox_Event_Friend_Status **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_status_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_status_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Friend_Status *tox_event_friend_status_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Status *friend_status = tox_events_add_friend_status(state->events, state->mem);

    if (friend_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_status;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_status(
    Tox *tox, uint32_t friend_number, Tox_User_Status status,
    void *user_data)
{
    Tox_Event_Friend_Status *friend_status = tox_event_friend_status_alloc(user_data);

    if (friend_status == nullptr) {
        return;
    }

    tox_event_friend_status_set_friend_number(friend_status, friend_number);
    tox_event_friend_status_set_status(friend_status, status);
}
