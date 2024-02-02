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

struct Tox_Event_Group_Peer_Status {
    uint32_t group_number;
    uint32_t peer_id;
    Tox_User_Status status;
};

non_null()
static void tox_event_group_peer_status_set_group_number(Tox_Event_Group_Peer_Status *group_peer_status,
        uint32_t group_number)
{
    assert(group_peer_status != nullptr);
    group_peer_status->group_number = group_number;
}
uint32_t tox_event_group_peer_status_get_group_number(const Tox_Event_Group_Peer_Status *group_peer_status)
{
    assert(group_peer_status != nullptr);
    return group_peer_status->group_number;
}

non_null()
static void tox_event_group_peer_status_set_peer_id(Tox_Event_Group_Peer_Status *group_peer_status,
        uint32_t peer_id)
{
    assert(group_peer_status != nullptr);
    group_peer_status->peer_id = peer_id;
}
uint32_t tox_event_group_peer_status_get_peer_id(const Tox_Event_Group_Peer_Status *group_peer_status)
{
    assert(group_peer_status != nullptr);
    return group_peer_status->peer_id;
}

non_null()
static void tox_event_group_peer_status_set_status(Tox_Event_Group_Peer_Status *group_peer_status,
        Tox_User_Status status)
{
    assert(group_peer_status != nullptr);
    group_peer_status->status = status;
}
Tox_User_Status tox_event_group_peer_status_get_status(const Tox_Event_Group_Peer_Status *group_peer_status)
{
    assert(group_peer_status != nullptr);
    return group_peer_status->status;
}

non_null()
static void tox_event_group_peer_status_construct(Tox_Event_Group_Peer_Status *group_peer_status)
{
    *group_peer_status = (Tox_Event_Group_Peer_Status) {
        0
    };
}
non_null()
static void tox_event_group_peer_status_destruct(Tox_Event_Group_Peer_Status *group_peer_status, const Memory *mem)
{
    return;
}

bool tox_event_group_peer_status_pack(
    const Tox_Event_Group_Peer_Status *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && tox_user_status_pack(event->status, bp);
}

non_null()
static bool tox_event_group_peer_status_unpack_into(
    Tox_Event_Group_Peer_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && tox_user_status_unpack(&event->status, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Peer_Status *tox_event_get_group_peer_status(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_PEER_STATUS ? event->data.group_peer_status : nullptr;
}

Tox_Event_Group_Peer_Status *tox_event_group_peer_status_new(const Memory *mem)
{
    Tox_Event_Group_Peer_Status *const group_peer_status =
        (Tox_Event_Group_Peer_Status *)mem_alloc(mem, sizeof(Tox_Event_Group_Peer_Status));

    if (group_peer_status == nullptr) {
        return nullptr;
    }

    tox_event_group_peer_status_construct(group_peer_status);
    return group_peer_status;
}

void tox_event_group_peer_status_free(Tox_Event_Group_Peer_Status *group_peer_status, const Memory *mem)
{
    if (group_peer_status != nullptr) {
        tox_event_group_peer_status_destruct(group_peer_status, mem);
    }
    mem_delete(mem, group_peer_status);
}

non_null()
static Tox_Event_Group_Peer_Status *tox_events_add_group_peer_status(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Peer_Status *const group_peer_status = tox_event_group_peer_status_new(mem);

    if (group_peer_status == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_PEER_STATUS;
    event.data.group_peer_status = group_peer_status;

    tox_events_add(events, &event);
    return group_peer_status;
}

bool tox_event_group_peer_status_unpack(
    Tox_Event_Group_Peer_Status **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_peer_status_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_peer_status_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Peer_Status *tox_event_group_peer_status_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Peer_Status *group_peer_status = tox_events_add_group_peer_status(state->events, state->mem);

    if (group_peer_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_peer_status;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_peer_status(
    Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_User_Status status,
    void *user_data)
{
    Tox_Event_Group_Peer_Status *group_peer_status = tox_event_group_peer_status_alloc(user_data);

    if (group_peer_status == nullptr) {
        return;
    }

    tox_event_group_peer_status_set_group_number(group_peer_status, group_number);
    tox_event_group_peer_status_set_peer_id(group_peer_status, peer_id);
    tox_event_group_peer_status_set_status(group_peer_status, status);
}
