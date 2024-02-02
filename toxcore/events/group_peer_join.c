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

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Group_Peer_Join {
    uint32_t group_number;
    uint32_t peer_id;
};

non_null()
static void tox_event_group_peer_join_set_group_number(Tox_Event_Group_Peer_Join *group_peer_join,
        uint32_t group_number)
{
    assert(group_peer_join != nullptr);
    group_peer_join->group_number = group_number;
}
uint32_t tox_event_group_peer_join_get_group_number(const Tox_Event_Group_Peer_Join *group_peer_join)
{
    assert(group_peer_join != nullptr);
    return group_peer_join->group_number;
}

non_null()
static void tox_event_group_peer_join_set_peer_id(Tox_Event_Group_Peer_Join *group_peer_join,
        uint32_t peer_id)
{
    assert(group_peer_join != nullptr);
    group_peer_join->peer_id = peer_id;
}
uint32_t tox_event_group_peer_join_get_peer_id(const Tox_Event_Group_Peer_Join *group_peer_join)
{
    assert(group_peer_join != nullptr);
    return group_peer_join->peer_id;
}

non_null()
static void tox_event_group_peer_join_construct(Tox_Event_Group_Peer_Join *group_peer_join)
{
    *group_peer_join = (Tox_Event_Group_Peer_Join) {
        0
    };
}
non_null()
static void tox_event_group_peer_join_destruct(Tox_Event_Group_Peer_Join *group_peer_join, const Memory *mem)
{
    return;
}

bool tox_event_group_peer_join_pack(
    const Tox_Event_Group_Peer_Join *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id);
}

non_null()
static bool tox_event_group_peer_join_unpack_into(
    Tox_Event_Group_Peer_Join *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Peer_Join *tox_event_get_group_peer_join(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_PEER_JOIN ? event->data.group_peer_join : nullptr;
}

Tox_Event_Group_Peer_Join *tox_event_group_peer_join_new(const Memory *mem)
{
    Tox_Event_Group_Peer_Join *const group_peer_join =
        (Tox_Event_Group_Peer_Join *)mem_alloc(mem, sizeof(Tox_Event_Group_Peer_Join));

    if (group_peer_join == nullptr) {
        return nullptr;
    }

    tox_event_group_peer_join_construct(group_peer_join);
    return group_peer_join;
}

void tox_event_group_peer_join_free(Tox_Event_Group_Peer_Join *group_peer_join, const Memory *mem)
{
    if (group_peer_join != nullptr) {
        tox_event_group_peer_join_destruct(group_peer_join, mem);
    }
    mem_delete(mem, group_peer_join);
}

non_null()
static Tox_Event_Group_Peer_Join *tox_events_add_group_peer_join(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Peer_Join *const group_peer_join = tox_event_group_peer_join_new(mem);

    if (group_peer_join == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_PEER_JOIN;
    event.data.group_peer_join = group_peer_join;

    tox_events_add(events, &event);
    return group_peer_join;
}

bool tox_event_group_peer_join_unpack(
    Tox_Event_Group_Peer_Join **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_peer_join_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_peer_join_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Peer_Join *tox_event_group_peer_join_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Peer_Join *group_peer_join = tox_events_add_group_peer_join(state->events, state->mem);

    if (group_peer_join == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_peer_join;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_peer_join(
    Tox *tox, uint32_t group_number, uint32_t peer_id,
    void *user_data)
{
    Tox_Event_Group_Peer_Join *group_peer_join = tox_event_group_peer_join_alloc(user_data);

    if (group_peer_join == nullptr) {
        return;
    }

    tox_event_group_peer_join_set_group_number(group_peer_join, group_number);
    tox_event_group_peer_join_set_peer_id(group_peer_join, peer_id);
}
