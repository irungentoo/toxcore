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

struct Tox_Event_Group_Voice_State {
    uint32_t group_number;
    Tox_Group_Voice_State voice_state;
};

static void tox_event_group_voice_state_set_group_number(Tox_Event_Group_Voice_State *_Nonnull group_voice_state, uint32_t group_number)
{
    assert(group_voice_state != nullptr);
    group_voice_state->group_number = group_number;
}
uint32_t tox_event_group_voice_state_get_group_number(const Tox_Event_Group_Voice_State *group_voice_state)
{
    assert(group_voice_state != nullptr);
    return group_voice_state->group_number;
}

static void tox_event_group_voice_state_set_voice_state(Tox_Event_Group_Voice_State *_Nonnull group_voice_state, Tox_Group_Voice_State voice_state)
{
    assert(group_voice_state != nullptr);
    group_voice_state->voice_state = voice_state;
}
Tox_Group_Voice_State tox_event_group_voice_state_get_voice_state(const Tox_Event_Group_Voice_State *group_voice_state)
{
    assert(group_voice_state != nullptr);
    return group_voice_state->voice_state;
}

static void tox_event_group_voice_state_construct(Tox_Event_Group_Voice_State *_Nonnull group_voice_state)
{
    *group_voice_state = (Tox_Event_Group_Voice_State) {
        0
    };
}
static void tox_event_group_voice_state_destruct(Tox_Event_Group_Voice_State *_Nonnull group_voice_state, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_group_voice_state_pack(
    const Tox_Event_Group_Voice_State *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && tox_group_voice_state_pack(event->voice_state, bp);
}

static bool tox_event_group_voice_state_unpack_into(Tox_Event_Group_Voice_State *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && tox_group_voice_state_unpack(&event->voice_state, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Voice_State *tox_event_get_group_voice_state(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_VOICE_STATE ? event->data.group_voice_state : nullptr;
}

Tox_Event_Group_Voice_State *tox_event_group_voice_state_new(const Memory *mem)
{
    Tox_Event_Group_Voice_State *const group_voice_state =
        (Tox_Event_Group_Voice_State *)mem_alloc(mem, sizeof(Tox_Event_Group_Voice_State));

    if (group_voice_state == nullptr) {
        return nullptr;
    }

    tox_event_group_voice_state_construct(group_voice_state);
    return group_voice_state;
}

void tox_event_group_voice_state_free(Tox_Event_Group_Voice_State *group_voice_state, const Memory *mem)
{
    if (group_voice_state != nullptr) {
        tox_event_group_voice_state_destruct(group_voice_state, mem);
    }
    mem_delete(mem, group_voice_state);
}

static Tox_Event_Group_Voice_State *_Nullable tox_events_add_group_voice_state(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Group_Voice_State *const group_voice_state = tox_event_group_voice_state_new(mem);

    if (group_voice_state == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_VOICE_STATE;
    event.data.group_voice_state = group_voice_state;

    if (!tox_events_add(events, &event)) {
        tox_event_group_voice_state_free(group_voice_state, mem);
        return nullptr;
    }
    return group_voice_state;
}

bool tox_event_group_voice_state_unpack(
    Tox_Event_Group_Voice_State **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_voice_state_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_voice_state_unpack_into(*event, bu);
}

static Tox_Event_Group_Voice_State *_Nullable tox_event_group_voice_state_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Voice_State *group_voice_state = tox_events_add_group_voice_state(state->events, state->mem);

    if (group_voice_state == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_voice_state;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_voice_state(
    Tox *_Nonnull tox,
    uint32_t group_number,
    Tox_Group_Voice_State voice_state,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Group_Voice_State *group_voice_state = tox_event_group_voice_state_alloc(state);

    if (group_voice_state == nullptr) {
        return;
    }

    tox_event_group_voice_state_set_group_number(group_voice_state, group_number);
    tox_event_group_voice_state_set_voice_state(group_voice_state, voice_state);
}

void tox_events_handle_group_voice_state_dispatch(Tox *tox, const Tox_Event_Group_Voice_State *event, void *user_data)
{
    if (tox->group_voice_state_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->group_voice_state_callback(tox, event->group_number, event->voice_state, user_data);
    tox_lock(tox);
}
