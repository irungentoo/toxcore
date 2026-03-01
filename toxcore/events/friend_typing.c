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
#include "../tox_struct.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Friend_Typing {
    uint32_t friend_number;
    bool typing;
};

static void tox_event_friend_typing_set_friend_number(Tox_Event_Friend_Typing *_Nonnull friend_typing, uint32_t friend_number)
{
    assert(friend_typing != nullptr);
    friend_typing->friend_number = friend_number;
}
uint32_t tox_event_friend_typing_get_friend_number(const Tox_Event_Friend_Typing *friend_typing)
{
    assert(friend_typing != nullptr);
    return friend_typing->friend_number;
}

static void tox_event_friend_typing_set_typing(Tox_Event_Friend_Typing *_Nonnull friend_typing, bool typing)
{
    assert(friend_typing != nullptr);
    friend_typing->typing = typing;
}
bool tox_event_friend_typing_get_typing(const Tox_Event_Friend_Typing *friend_typing)
{
    assert(friend_typing != nullptr);
    return friend_typing->typing;
}

static void tox_event_friend_typing_construct(Tox_Event_Friend_Typing *_Nonnull friend_typing)
{
    *friend_typing = (Tox_Event_Friend_Typing) {
        0
    };
}
static void tox_event_friend_typing_destruct(Tox_Event_Friend_Typing *_Nonnull friend_typing, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_friend_typing_pack(
    const Tox_Event_Friend_Typing *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bool(bp, event->typing);
}

static bool tox_event_friend_typing_unpack_into(Tox_Event_Friend_Typing *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bool(bu, &event->typing);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Typing *tox_event_get_friend_typing(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_TYPING ? event->data.friend_typing : nullptr;
}

Tox_Event_Friend_Typing *tox_event_friend_typing_new(const Memory *mem)
{
    Tox_Event_Friend_Typing *const friend_typing =
        (Tox_Event_Friend_Typing *)mem_alloc(mem, sizeof(Tox_Event_Friend_Typing));

    if (friend_typing == nullptr) {
        return nullptr;
    }

    tox_event_friend_typing_construct(friend_typing);
    return friend_typing;
}

void tox_event_friend_typing_free(Tox_Event_Friend_Typing *friend_typing, const Memory *mem)
{
    if (friend_typing != nullptr) {
        tox_event_friend_typing_destruct(friend_typing, mem);
    }
    mem_delete(mem, friend_typing);
}

static Tox_Event_Friend_Typing *_Nullable tox_events_add_friend_typing(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Friend_Typing *const friend_typing = tox_event_friend_typing_new(mem);

    if (friend_typing == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_TYPING;
    event.data.friend_typing = friend_typing;

    if (!tox_events_add(events, &event)) {
        tox_event_friend_typing_free(friend_typing, mem);
        return nullptr;
    }
    return friend_typing;
}

bool tox_event_friend_typing_unpack(
    Tox_Event_Friend_Typing **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_typing_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_typing_unpack_into(*event, bu);
}

static Tox_Event_Friend_Typing *_Nullable tox_event_friend_typing_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Typing *friend_typing = tox_events_add_friend_typing(state->events, state->mem);

    if (friend_typing == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_typing;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_typing(
    Tox *_Nonnull tox,
    uint32_t friend_number,
    bool typing,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Friend_Typing *friend_typing = tox_event_friend_typing_alloc(state);

    if (friend_typing == nullptr) {
        return;
    }

    tox_event_friend_typing_set_friend_number(friend_typing, friend_number);
    tox_event_friend_typing_set_typing(friend_typing, typing);
}

void tox_events_handle_friend_typing_dispatch(Tox *tox, const Tox_Event_Friend_Typing *event, void *user_data)
{
    if (tox->friend_typing_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->friend_typing_callback(tox, event->friend_number, event->typing, user_data);
    tox_lock(tox);
}
