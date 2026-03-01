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

struct Tox_Event_Conference_Peer_Name {
    uint32_t conference_number;
    uint32_t peer_number;
    uint8_t *_Nullable name;
    uint32_t name_length;
};

static void tox_event_conference_peer_name_set_conference_number(Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name, uint32_t conference_number)
{
    assert(conference_peer_name != nullptr);
    conference_peer_name->conference_number = conference_number;
}
uint32_t tox_event_conference_peer_name_get_conference_number(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->conference_number;
}

static void tox_event_conference_peer_name_set_peer_number(Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name, uint32_t peer_number)
{
    assert(conference_peer_name != nullptr);
    conference_peer_name->peer_number = peer_number;
}
uint32_t tox_event_conference_peer_name_get_peer_number(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->peer_number;
}

static bool tox_event_conference_peer_name_set_name(Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name,
        const Memory *_Nonnull mem, const uint8_t *_Nullable name, uint32_t name_length)
{
    assert(conference_peer_name != nullptr);
    if (conference_peer_name->name != nullptr) {
        mem_delete(mem, conference_peer_name->name);
        conference_peer_name->name = nullptr;
        conference_peer_name->name_length = 0;
    }

    if (name == nullptr) {
        assert(name_length == 0);
        return true;
    }

    if (name_length == 0) {
        conference_peer_name->name = nullptr;
        conference_peer_name->name_length = 0;
        return true;
    }

    uint8_t *name_copy = (uint8_t *)mem_balloc(mem, name_length);

    if (name_copy == nullptr) {
        return false;
    }

    memcpy(name_copy, name, name_length);
    conference_peer_name->name = name_copy;
    conference_peer_name->name_length = name_length;
    return true;
}
uint32_t tox_event_conference_peer_name_get_name_length(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->name_length;
}
const uint8_t *tox_event_conference_peer_name_get_name(const Tox_Event_Conference_Peer_Name *conference_peer_name)
{
    assert(conference_peer_name != nullptr);
    return conference_peer_name->name;
}

static void tox_event_conference_peer_name_construct(Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name)
{
    *conference_peer_name = (Tox_Event_Conference_Peer_Name) {
        0
    };
}
static void tox_event_conference_peer_name_destruct(Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name, const Memory *_Nonnull mem)
{
    mem_delete(mem, conference_peer_name->name);
}

bool tox_event_conference_peer_name_pack(
    const Tox_Event_Conference_Peer_Name *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_bin(bp, event->name, event->name_length);
}

static bool tox_event_conference_peer_name_unpack_into(Tox_Event_Conference_Peer_Name *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Conference_Peer_Name *tox_event_get_conference_peer_name(const Tox_Event *event)
{
    return event->type == TOX_EVENT_CONFERENCE_PEER_NAME ? event->data.conference_peer_name : nullptr;
}

Tox_Event_Conference_Peer_Name *tox_event_conference_peer_name_new(const Memory *mem)
{
    Tox_Event_Conference_Peer_Name *const conference_peer_name =
        (Tox_Event_Conference_Peer_Name *)mem_alloc(mem, sizeof(Tox_Event_Conference_Peer_Name));

    if (conference_peer_name == nullptr) {
        return nullptr;
    }

    tox_event_conference_peer_name_construct(conference_peer_name);
    return conference_peer_name;
}

void tox_event_conference_peer_name_free(Tox_Event_Conference_Peer_Name *conference_peer_name, const Memory *mem)
{
    if (conference_peer_name != nullptr) {
        tox_event_conference_peer_name_destruct(conference_peer_name, mem);
    }
    mem_delete(mem, conference_peer_name);
}

static Tox_Event_Conference_Peer_Name *_Nullable tox_events_add_conference_peer_name(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Conference_Peer_Name *const conference_peer_name = tox_event_conference_peer_name_new(mem);

    if (conference_peer_name == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_PEER_NAME;
    event.data.conference_peer_name = conference_peer_name;

    if (!tox_events_add(events, &event)) {
        tox_event_conference_peer_name_free(conference_peer_name, mem);
        return nullptr;
    }
    return conference_peer_name;
}

bool tox_event_conference_peer_name_unpack(
    Tox_Event_Conference_Peer_Name **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_conference_peer_name_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_conference_peer_name_unpack_into(*event, bu);
}

static Tox_Event_Conference_Peer_Name *_Nullable tox_event_conference_peer_name_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Conference_Peer_Name *conference_peer_name = tox_events_add_conference_peer_name(state->events, state->mem);

    if (conference_peer_name == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return conference_peer_name;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_peer_name(
    Tox *_Nonnull tox,
    uint32_t conference_number,
    uint32_t peer_number,
    const uint8_t *_Nullable name, size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Conference_Peer_Name *conference_peer_name = tox_event_conference_peer_name_alloc(state);

    if (conference_peer_name == nullptr) {
        return;
    }

    tox_event_conference_peer_name_set_conference_number(conference_peer_name, conference_number);
    tox_event_conference_peer_name_set_peer_number(conference_peer_name, peer_number);
    if (!tox_event_conference_peer_name_set_name(conference_peer_name, state->mem, name, length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_conference_peer_name_dispatch(Tox *tox, const Tox_Event_Conference_Peer_Name *event, void *user_data)
{
    if (tox->conference_peer_name_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->conference_peer_name_callback(tox, event->conference_number, event->peer_number, event->name, event->name_length, user_data);
    tox_lock(tox);
}
