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

struct Tox_Event_Group_Join_Fail {
    uint32_t group_number;
    Tox_Group_Join_Fail fail_type;
};

non_null()
static void tox_event_group_join_fail_set_group_number(Tox_Event_Group_Join_Fail *group_join_fail,
        uint32_t group_number)
{
    assert(group_join_fail != nullptr);
    group_join_fail->group_number = group_number;
}
uint32_t tox_event_group_join_fail_get_group_number(const Tox_Event_Group_Join_Fail *group_join_fail)
{
    assert(group_join_fail != nullptr);
    return group_join_fail->group_number;
}

non_null()
static void tox_event_group_join_fail_set_fail_type(Tox_Event_Group_Join_Fail *group_join_fail,
        Tox_Group_Join_Fail fail_type)
{
    assert(group_join_fail != nullptr);
    group_join_fail->fail_type = fail_type;
}
Tox_Group_Join_Fail tox_event_group_join_fail_get_fail_type(const Tox_Event_Group_Join_Fail *group_join_fail)
{
    assert(group_join_fail != nullptr);
    return group_join_fail->fail_type;
}

non_null()
static void tox_event_group_join_fail_construct(Tox_Event_Group_Join_Fail *group_join_fail)
{
    *group_join_fail = (Tox_Event_Group_Join_Fail) {
        0
    };
}
non_null()
static void tox_event_group_join_fail_destruct(Tox_Event_Group_Join_Fail *group_join_fail, const Memory *mem)
{
    return;
}

bool tox_event_group_join_fail_pack(
    const Tox_Event_Group_Join_Fail *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && tox_group_join_fail_pack(event->fail_type, bp);
}

non_null()
static bool tox_event_group_join_fail_unpack_into(
    Tox_Event_Group_Join_Fail *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && tox_group_join_fail_unpack(&event->fail_type, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Join_Fail *tox_event_get_group_join_fail(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_JOIN_FAIL ? event->data.group_join_fail : nullptr;
}

Tox_Event_Group_Join_Fail *tox_event_group_join_fail_new(const Memory *mem)
{
    Tox_Event_Group_Join_Fail *const group_join_fail =
        (Tox_Event_Group_Join_Fail *)mem_alloc(mem, sizeof(Tox_Event_Group_Join_Fail));

    if (group_join_fail == nullptr) {
        return nullptr;
    }

    tox_event_group_join_fail_construct(group_join_fail);
    return group_join_fail;
}

void tox_event_group_join_fail_free(Tox_Event_Group_Join_Fail *group_join_fail, const Memory *mem)
{
    if (group_join_fail != nullptr) {
        tox_event_group_join_fail_destruct(group_join_fail, mem);
    }
    mem_delete(mem, group_join_fail);
}

non_null()
static Tox_Event_Group_Join_Fail *tox_events_add_group_join_fail(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Join_Fail *const group_join_fail = tox_event_group_join_fail_new(mem);

    if (group_join_fail == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_JOIN_FAIL;
    event.data.group_join_fail = group_join_fail;

    tox_events_add(events, &event);
    return group_join_fail;
}

bool tox_event_group_join_fail_unpack(
    Tox_Event_Group_Join_Fail **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_join_fail_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_join_fail_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Join_Fail *tox_event_group_join_fail_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Join_Fail *group_join_fail = tox_events_add_group_join_fail(state->events, state->mem);

    if (group_join_fail == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_join_fail;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_join_fail(
    Tox *tox, uint32_t group_number, Tox_Group_Join_Fail fail_type,
    void *user_data)
{
    Tox_Event_Group_Join_Fail *group_join_fail = tox_event_group_join_fail_alloc(user_data);

    if (group_join_fail == nullptr) {
        return;
    }

    tox_event_group_join_fail_set_group_number(group_join_fail, group_number);
    tox_event_group_join_fail_set_fail_type(group_join_fail, fail_type);
}
