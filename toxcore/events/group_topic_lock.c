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

struct Tox_Event_Group_Topic_Lock {
    uint32_t group_number;
    Tox_Group_Topic_Lock topic_lock;
};

non_null()
static void tox_event_group_topic_lock_set_group_number(Tox_Event_Group_Topic_Lock *group_topic_lock,
        uint32_t group_number)
{
    assert(group_topic_lock != nullptr);
    group_topic_lock->group_number = group_number;
}
uint32_t tox_event_group_topic_lock_get_group_number(const Tox_Event_Group_Topic_Lock *group_topic_lock)
{
    assert(group_topic_lock != nullptr);
    return group_topic_lock->group_number;
}

non_null()
static void tox_event_group_topic_lock_set_topic_lock(Tox_Event_Group_Topic_Lock *group_topic_lock,
        Tox_Group_Topic_Lock topic_lock)
{
    assert(group_topic_lock != nullptr);
    group_topic_lock->topic_lock = topic_lock;
}
Tox_Group_Topic_Lock tox_event_group_topic_lock_get_topic_lock(const Tox_Event_Group_Topic_Lock *group_topic_lock)
{
    assert(group_topic_lock != nullptr);
    return group_topic_lock->topic_lock;
}

non_null()
static void tox_event_group_topic_lock_construct(Tox_Event_Group_Topic_Lock *group_topic_lock)
{
    *group_topic_lock = (Tox_Event_Group_Topic_Lock) {
        0
    };
}
non_null()
static void tox_event_group_topic_lock_destruct(Tox_Event_Group_Topic_Lock *group_topic_lock, const Memory *mem)
{
    return;
}

bool tox_event_group_topic_lock_pack(
    const Tox_Event_Group_Topic_Lock *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && tox_group_topic_lock_pack(event->topic_lock, bp);
}

non_null()
static bool tox_event_group_topic_lock_unpack_into(
    Tox_Event_Group_Topic_Lock *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && tox_group_topic_lock_unpack(&event->topic_lock, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Topic_Lock *tox_event_get_group_topic_lock(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_TOPIC_LOCK ? event->data.group_topic_lock : nullptr;
}

Tox_Event_Group_Topic_Lock *tox_event_group_topic_lock_new(const Memory *mem)
{
    Tox_Event_Group_Topic_Lock *const group_topic_lock =
        (Tox_Event_Group_Topic_Lock *)mem_alloc(mem, sizeof(Tox_Event_Group_Topic_Lock));

    if (group_topic_lock == nullptr) {
        return nullptr;
    }

    tox_event_group_topic_lock_construct(group_topic_lock);
    return group_topic_lock;
}

void tox_event_group_topic_lock_free(Tox_Event_Group_Topic_Lock *group_topic_lock, const Memory *mem)
{
    if (group_topic_lock != nullptr) {
        tox_event_group_topic_lock_destruct(group_topic_lock, mem);
    }
    mem_delete(mem, group_topic_lock);
}

non_null()
static Tox_Event_Group_Topic_Lock *tox_events_add_group_topic_lock(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Topic_Lock *const group_topic_lock = tox_event_group_topic_lock_new(mem);

    if (group_topic_lock == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_TOPIC_LOCK;
    event.data.group_topic_lock = group_topic_lock;

    tox_events_add(events, &event);
    return group_topic_lock;
}

bool tox_event_group_topic_lock_unpack(
    Tox_Event_Group_Topic_Lock **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_topic_lock_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_topic_lock_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Topic_Lock *tox_event_group_topic_lock_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Topic_Lock *group_topic_lock = tox_events_add_group_topic_lock(state->events, state->mem);

    if (group_topic_lock == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_topic_lock;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_topic_lock(
    Tox *tox, uint32_t group_number, Tox_Group_Topic_Lock topic_lock,
    void *user_data)
{
    Tox_Event_Group_Topic_Lock *group_topic_lock = tox_event_group_topic_lock_alloc(user_data);

    if (group_topic_lock == nullptr) {
        return;
    }

    tox_event_group_topic_lock_set_group_number(group_topic_lock, group_number);
    tox_event_group_topic_lock_set_topic_lock(group_topic_lock, topic_lock);
}
