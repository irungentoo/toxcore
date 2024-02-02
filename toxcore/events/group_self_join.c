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

struct Tox_Event_Group_Self_Join {
    uint32_t group_number;
};

non_null()
static void tox_event_group_self_join_set_group_number(Tox_Event_Group_Self_Join *group_self_join,
        uint32_t group_number)
{
    assert(group_self_join != nullptr);
    group_self_join->group_number = group_number;
}
uint32_t tox_event_group_self_join_get_group_number(const Tox_Event_Group_Self_Join *group_self_join)
{
    assert(group_self_join != nullptr);
    return group_self_join->group_number;
}

non_null()
static void tox_event_group_self_join_construct(Tox_Event_Group_Self_Join *group_self_join)
{
    *group_self_join = (Tox_Event_Group_Self_Join) {
        0
    };
}
non_null()
static void tox_event_group_self_join_destruct(Tox_Event_Group_Self_Join *group_self_join, const Memory *mem)
{
    return;
}

bool tox_event_group_self_join_pack(
    const Tox_Event_Group_Self_Join *event, Bin_Pack *bp)
{
    return bin_pack_u32(bp, event->group_number);
}

non_null()
static bool tox_event_group_self_join_unpack_into(
    Tox_Event_Group_Self_Join *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    return bin_unpack_u32(bu, &event->group_number);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Self_Join *tox_event_get_group_self_join(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_SELF_JOIN ? event->data.group_self_join : nullptr;
}

Tox_Event_Group_Self_Join *tox_event_group_self_join_new(const Memory *mem)
{
    Tox_Event_Group_Self_Join *const group_self_join =
        (Tox_Event_Group_Self_Join *)mem_alloc(mem, sizeof(Tox_Event_Group_Self_Join));

    if (group_self_join == nullptr) {
        return nullptr;
    }

    tox_event_group_self_join_construct(group_self_join);
    return group_self_join;
}

void tox_event_group_self_join_free(Tox_Event_Group_Self_Join *group_self_join, const Memory *mem)
{
    if (group_self_join != nullptr) {
        tox_event_group_self_join_destruct(group_self_join, mem);
    }
    mem_delete(mem, group_self_join);
}

non_null()
static Tox_Event_Group_Self_Join *tox_events_add_group_self_join(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Self_Join *const group_self_join = tox_event_group_self_join_new(mem);

    if (group_self_join == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_SELF_JOIN;
    event.data.group_self_join = group_self_join;

    tox_events_add(events, &event);
    return group_self_join;
}

bool tox_event_group_self_join_unpack(
    Tox_Event_Group_Self_Join **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_self_join_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_self_join_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Self_Join *tox_event_group_self_join_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Self_Join *group_self_join = tox_events_add_group_self_join(state->events, state->mem);

    if (group_self_join == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_self_join;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_self_join(
    Tox *tox, uint32_t group_number,
    void *user_data)
{
    Tox_Event_Group_Self_Join *group_self_join = tox_event_group_self_join_alloc(user_data);

    if (group_self_join == nullptr) {
        return;
    }

    tox_event_group_self_join_set_group_number(group_self_join, group_number);
}
