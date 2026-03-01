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

struct Tox_Event_Conference_Peer_List_Changed {
    uint32_t conference_number;
};

static void tox_event_conference_peer_list_changed_set_conference_number(Tox_Event_Conference_Peer_List_Changed *_Nonnull conference_peer_list_changed, uint32_t conference_number)
{
    assert(conference_peer_list_changed != nullptr);
    conference_peer_list_changed->conference_number = conference_number;
}
uint32_t tox_event_conference_peer_list_changed_get_conference_number(const Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed)
{
    assert(conference_peer_list_changed != nullptr);
    return conference_peer_list_changed->conference_number;
}

static void tox_event_conference_peer_list_changed_construct(Tox_Event_Conference_Peer_List_Changed *_Nonnull conference_peer_list_changed)
{
    *conference_peer_list_changed = (Tox_Event_Conference_Peer_List_Changed) {
        0
    };
}
static void tox_event_conference_peer_list_changed_destruct(Tox_Event_Conference_Peer_List_Changed *_Nonnull conference_peer_list_changed, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_conference_peer_list_changed_pack(
    const Tox_Event_Conference_Peer_List_Changed *event, Bin_Pack *bp)
{
    return bin_pack_u32(bp, event->conference_number);
}

static bool tox_event_conference_peer_list_changed_unpack_into(Tox_Event_Conference_Peer_List_Changed *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    return bin_unpack_u32(bu, &event->conference_number);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Conference_Peer_List_Changed *tox_event_get_conference_peer_list_changed(const Tox_Event *event)
{
    return event->type == TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED ? event->data.conference_peer_list_changed : nullptr;
}

Tox_Event_Conference_Peer_List_Changed *tox_event_conference_peer_list_changed_new(const Memory *mem)
{
    Tox_Event_Conference_Peer_List_Changed *const conference_peer_list_changed =
        (Tox_Event_Conference_Peer_List_Changed *)mem_alloc(mem, sizeof(Tox_Event_Conference_Peer_List_Changed));

    if (conference_peer_list_changed == nullptr) {
        return nullptr;
    }

    tox_event_conference_peer_list_changed_construct(conference_peer_list_changed);
    return conference_peer_list_changed;
}

void tox_event_conference_peer_list_changed_free(Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed, const Memory *mem)
{
    if (conference_peer_list_changed != nullptr) {
        tox_event_conference_peer_list_changed_destruct(conference_peer_list_changed, mem);
    }
    mem_delete(mem, conference_peer_list_changed);
}

static Tox_Event_Conference_Peer_List_Changed *_Nullable tox_events_add_conference_peer_list_changed(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Conference_Peer_List_Changed *const conference_peer_list_changed = tox_event_conference_peer_list_changed_new(mem);

    if (conference_peer_list_changed == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED;
    event.data.conference_peer_list_changed = conference_peer_list_changed;

    if (!tox_events_add(events, &event)) {
        tox_event_conference_peer_list_changed_free(conference_peer_list_changed, mem);
        return nullptr;
    }
    return conference_peer_list_changed;
}

bool tox_event_conference_peer_list_changed_unpack(
    Tox_Event_Conference_Peer_List_Changed **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_conference_peer_list_changed_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_conference_peer_list_changed_unpack_into(*event, bu);
}

static Tox_Event_Conference_Peer_List_Changed *_Nullable tox_event_conference_peer_list_changed_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed = tox_events_add_conference_peer_list_changed(state->events, state->mem);

    if (conference_peer_list_changed == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return conference_peer_list_changed;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_peer_list_changed(
    Tox *_Nonnull tox,
    uint32_t conference_number,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed = tox_event_conference_peer_list_changed_alloc(state);

    if (conference_peer_list_changed == nullptr) {
        return;
    }

    tox_event_conference_peer_list_changed_set_conference_number(conference_peer_list_changed, conference_number);
}

void tox_events_handle_conference_peer_list_changed_dispatch(Tox *tox, const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    if (tox->conference_peer_list_changed_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->conference_peer_list_changed_callback(tox, event->conference_number, user_data);
    tox_lock(tox);
}
