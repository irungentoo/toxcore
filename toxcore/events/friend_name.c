/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <string.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_event.h"
#include "../tox_events.h"
#include "../tox_struct.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Friend_Name {
    uint32_t friend_number;
    uint8_t *_Nullable name;
    uint32_t name_length;
};

static void tox_event_friend_name_set_friend_number(Tox_Event_Friend_Name *_Nonnull friend_name, uint32_t friend_number)
{
    assert(friend_name != nullptr);
    friend_name->friend_number = friend_number;
}
uint32_t tox_event_friend_name_get_friend_number(const Tox_Event_Friend_Name *friend_name)
{
    assert(friend_name != nullptr);
    return friend_name->friend_number;
}

static bool tox_event_friend_name_set_name(Tox_Event_Friend_Name *_Nonnull friend_name,
        const Memory *_Nonnull mem, const uint8_t *_Nullable name, uint32_t name_length)
{
    assert(friend_name != nullptr);
    if (friend_name->name != nullptr) {
        mem_delete(mem, friend_name->name);
        friend_name->name = nullptr;
        friend_name->name_length = 0;
    }

    if (name == nullptr) {
        assert(name_length == 0);
        return true;
    }

    if (name_length == 0) {
        friend_name->name = nullptr;
        friend_name->name_length = 0;
        return true;
    }

    uint8_t *name_copy = (uint8_t *)mem_balloc(mem, name_length);

    if (name_copy == nullptr) {
        return false;
    }

    memcpy(name_copy, name, name_length);
    friend_name->name = name_copy;
    friend_name->name_length = name_length;
    return true;
}
uint32_t tox_event_friend_name_get_name_length(const Tox_Event_Friend_Name *friend_name)
{
    assert(friend_name != nullptr);
    return friend_name->name_length;
}
const uint8_t *tox_event_friend_name_get_name(const Tox_Event_Friend_Name *friend_name)
{
    assert(friend_name != nullptr);
    return friend_name->name;
}

static void tox_event_friend_name_construct(Tox_Event_Friend_Name *_Nonnull friend_name)
{
    *friend_name = (Tox_Event_Friend_Name) {
        0
    };
}
static void tox_event_friend_name_destruct(Tox_Event_Friend_Name *_Nonnull friend_name, const Memory *_Nonnull mem)
{
    mem_delete(mem, friend_name->name);
}

bool tox_event_friend_name_pack(
    const Tox_Event_Friend_Name *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->name, event->name_length);
}

static bool tox_event_friend_name_unpack_into(Tox_Event_Friend_Name *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Name *tox_event_get_friend_name(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_NAME ? event->data.friend_name : nullptr;
}

Tox_Event_Friend_Name *tox_event_friend_name_new(const Memory *mem)
{
    Tox_Event_Friend_Name *const friend_name =
        (Tox_Event_Friend_Name *)mem_alloc(mem, sizeof(Tox_Event_Friend_Name));

    if (friend_name == nullptr) {
        return nullptr;
    }

    tox_event_friend_name_construct(friend_name);
    return friend_name;
}

void tox_event_friend_name_free(Tox_Event_Friend_Name *friend_name, const Memory *mem)
{
    if (friend_name != nullptr) {
        tox_event_friend_name_destruct(friend_name, mem);
    }
    mem_delete(mem, friend_name);
}

static Tox_Event_Friend_Name *_Nullable tox_events_add_friend_name(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Friend_Name *const friend_name = tox_event_friend_name_new(mem);

    if (friend_name == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_NAME;
    event.data.friend_name = friend_name;

    if (!tox_events_add(events, &event)) {
        tox_event_friend_name_free(friend_name, mem);
        return nullptr;
    }
    return friend_name;
}

bool tox_event_friend_name_unpack(
    Tox_Event_Friend_Name **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_name_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_name_unpack_into(*event, bu);
}

static Tox_Event_Friend_Name *_Nullable tox_event_friend_name_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Name *friend_name = tox_events_add_friend_name(state->events, state->mem);

    if (friend_name == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_name;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_name(
    Tox *_Nonnull tox,
    uint32_t friend_number,
    const uint8_t *_Nullable name, size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Friend_Name *friend_name = tox_event_friend_name_alloc(state);

    if (friend_name == nullptr) {
        return;
    }

    tox_event_friend_name_set_friend_number(friend_name, friend_number);
    if (!tox_event_friend_name_set_name(friend_name, state->mem, name, length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_friend_name_dispatch(Tox *tox, const Tox_Event_Friend_Name *event, void *user_data)
{
    if (tox->friend_name_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->friend_name_callback(tox, event->friend_number, event->name, event->name_length, user_data);
    tox_lock(tox);
}
