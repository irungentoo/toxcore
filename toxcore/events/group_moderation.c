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

struct Tox_Event_Group_Moderation {
    uint32_t group_number;
    uint32_t source_peer_id;
    uint32_t target_peer_id;
    Tox_Group_Mod_Event mod_type;
};

non_null()
static void tox_event_group_moderation_set_group_number(Tox_Event_Group_Moderation *group_moderation,
        uint32_t group_number)
{
    assert(group_moderation != nullptr);
    group_moderation->group_number = group_number;
}
uint32_t tox_event_group_moderation_get_group_number(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->group_number;
}

non_null()
static void tox_event_group_moderation_set_source_peer_id(Tox_Event_Group_Moderation *group_moderation,
        uint32_t source_peer_id)
{
    assert(group_moderation != nullptr);
    group_moderation->source_peer_id = source_peer_id;
}
uint32_t tox_event_group_moderation_get_source_peer_id(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->source_peer_id;
}

non_null()
static void tox_event_group_moderation_set_target_peer_id(Tox_Event_Group_Moderation *group_moderation,
        uint32_t target_peer_id)
{
    assert(group_moderation != nullptr);
    group_moderation->target_peer_id = target_peer_id;
}
uint32_t tox_event_group_moderation_get_target_peer_id(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->target_peer_id;
}

non_null()
static void tox_event_group_moderation_set_mod_type(Tox_Event_Group_Moderation *group_moderation,
        Tox_Group_Mod_Event mod_type)
{
    assert(group_moderation != nullptr);
    group_moderation->mod_type = mod_type;
}
Tox_Group_Mod_Event tox_event_group_moderation_get_mod_type(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->mod_type;
}

non_null()
static void tox_event_group_moderation_construct(Tox_Event_Group_Moderation *group_moderation)
{
    *group_moderation = (Tox_Event_Group_Moderation) {
        0
    };
}
non_null()
static void tox_event_group_moderation_destruct(Tox_Event_Group_Moderation *group_moderation, const Memory *mem)
{
    return;
}

bool tox_event_group_moderation_pack(
    const Tox_Event_Group_Moderation *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->source_peer_id)
           && bin_pack_u32(bp, event->target_peer_id)
           && tox_group_mod_event_pack(event->mod_type, bp);
}

non_null()
static bool tox_event_group_moderation_unpack_into(
    Tox_Event_Group_Moderation *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->source_peer_id)
           && bin_unpack_u32(bu, &event->target_peer_id)
           && tox_group_mod_event_unpack(&event->mod_type, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Moderation *tox_event_get_group_moderation(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_MODERATION ? event->data.group_moderation : nullptr;
}

Tox_Event_Group_Moderation *tox_event_group_moderation_new(const Memory *mem)
{
    Tox_Event_Group_Moderation *const group_moderation =
        (Tox_Event_Group_Moderation *)mem_alloc(mem, sizeof(Tox_Event_Group_Moderation));

    if (group_moderation == nullptr) {
        return nullptr;
    }

    tox_event_group_moderation_construct(group_moderation);
    return group_moderation;
}

void tox_event_group_moderation_free(Tox_Event_Group_Moderation *group_moderation, const Memory *mem)
{
    if (group_moderation != nullptr) {
        tox_event_group_moderation_destruct(group_moderation, mem);
    }
    mem_delete(mem, group_moderation);
}

non_null()
static Tox_Event_Group_Moderation *tox_events_add_group_moderation(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Moderation *const group_moderation = tox_event_group_moderation_new(mem);

    if (group_moderation == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_MODERATION;
    event.data.group_moderation = group_moderation;

    tox_events_add(events, &event);
    return group_moderation;
}

bool tox_event_group_moderation_unpack(
    Tox_Event_Group_Moderation **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_moderation_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_moderation_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Moderation *tox_event_group_moderation_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Moderation *group_moderation = tox_events_add_group_moderation(state->events, state->mem);

    if (group_moderation == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_moderation;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_moderation(
    Tox *tox, uint32_t group_number, uint32_t source_peer_id, uint32_t target_peer_id, Tox_Group_Mod_Event mod_type,
    void *user_data)
{
    Tox_Event_Group_Moderation *group_moderation = tox_event_group_moderation_alloc(user_data);

    if (group_moderation == nullptr) {
        return;
    }

    tox_event_group_moderation_set_group_number(group_moderation, group_number);
    tox_event_group_moderation_set_source_peer_id(group_moderation, source_peer_id);
    tox_event_group_moderation_set_target_peer_id(group_moderation, target_peer_id);
    tox_event_group_moderation_set_mod_type(group_moderation, mod_type);
}
