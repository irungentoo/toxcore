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

struct Tox_Event_Group_Peer_Limit {
    uint32_t group_number;
    uint32_t peer_limit;
};

static void tox_event_group_peer_limit_set_group_number(Tox_Event_Group_Peer_Limit *_Nonnull group_peer_limit, uint32_t group_number)
{
    assert(group_peer_limit != nullptr);
    group_peer_limit->group_number = group_number;
}
uint32_t tox_event_group_peer_limit_get_group_number(const Tox_Event_Group_Peer_Limit *group_peer_limit)
{
    assert(group_peer_limit != nullptr);
    return group_peer_limit->group_number;
}

static void tox_event_group_peer_limit_set_peer_limit(Tox_Event_Group_Peer_Limit *_Nonnull group_peer_limit, uint32_t peer_limit)
{
    assert(group_peer_limit != nullptr);
    group_peer_limit->peer_limit = peer_limit;
}
uint32_t tox_event_group_peer_limit_get_peer_limit(const Tox_Event_Group_Peer_Limit *group_peer_limit)
{
    assert(group_peer_limit != nullptr);
    return group_peer_limit->peer_limit;
}

static void tox_event_group_peer_limit_construct(Tox_Event_Group_Peer_Limit *_Nonnull group_peer_limit)
{
    *group_peer_limit = (Tox_Event_Group_Peer_Limit) {
        0
    };
}
static void tox_event_group_peer_limit_destruct(Tox_Event_Group_Peer_Limit *_Nonnull group_peer_limit, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_group_peer_limit_pack(
    const Tox_Event_Group_Peer_Limit *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_limit);
}

static bool tox_event_group_peer_limit_unpack_into(Tox_Event_Group_Peer_Limit *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_limit);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Peer_Limit *tox_event_get_group_peer_limit(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_PEER_LIMIT ? event->data.group_peer_limit : nullptr;
}

Tox_Event_Group_Peer_Limit *tox_event_group_peer_limit_new(const Memory *mem)
{
    Tox_Event_Group_Peer_Limit *const group_peer_limit =
        (Tox_Event_Group_Peer_Limit *)mem_alloc(mem, sizeof(Tox_Event_Group_Peer_Limit));

    if (group_peer_limit == nullptr) {
        return nullptr;
    }

    tox_event_group_peer_limit_construct(group_peer_limit);
    return group_peer_limit;
}

void tox_event_group_peer_limit_free(Tox_Event_Group_Peer_Limit *group_peer_limit, const Memory *mem)
{
    if (group_peer_limit != nullptr) {
        tox_event_group_peer_limit_destruct(group_peer_limit, mem);
    }
    mem_delete(mem, group_peer_limit);
}

static Tox_Event_Group_Peer_Limit *_Nullable tox_events_add_group_peer_limit(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Group_Peer_Limit *const group_peer_limit = tox_event_group_peer_limit_new(mem);

    if (group_peer_limit == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_PEER_LIMIT;
    event.data.group_peer_limit = group_peer_limit;

    if (!tox_events_add(events, &event)) {
        tox_event_group_peer_limit_free(group_peer_limit, mem);
        return nullptr;
    }
    return group_peer_limit;
}

bool tox_event_group_peer_limit_unpack(
    Tox_Event_Group_Peer_Limit **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_peer_limit_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_peer_limit_unpack_into(*event, bu);
}

static Tox_Event_Group_Peer_Limit *_Nullable tox_event_group_peer_limit_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Peer_Limit *group_peer_limit = tox_events_add_group_peer_limit(state->events, state->mem);

    if (group_peer_limit == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_peer_limit;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_peer_limit(
    Tox *_Nonnull tox,
    uint32_t group_number,
    uint32_t peer_limit,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Group_Peer_Limit *group_peer_limit = tox_event_group_peer_limit_alloc(state);

    if (group_peer_limit == nullptr) {
        return;
    }

    tox_event_group_peer_limit_set_group_number(group_peer_limit, group_number);
    tox_event_group_peer_limit_set_peer_limit(group_peer_limit, peer_limit);
}

void tox_events_handle_group_peer_limit_dispatch(Tox *tox, const Tox_Event_Group_Peer_Limit *event, void *user_data)
{
    if (tox->group_peer_limit_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->group_peer_limit_callback(tox, event->group_number, event->peer_limit, user_data);
    tox_lock(tox);
}
