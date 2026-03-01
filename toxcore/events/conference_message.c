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
#include "../tox_pack.h"
#include "../tox_struct.h"
#include "../tox_unpack.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Conference_Message {
    uint32_t conference_number;
    uint32_t peer_number;
    Tox_Message_Type type;
    uint8_t *_Nullable message;
    uint32_t message_length;
};

static void tox_event_conference_message_set_conference_number(Tox_Event_Conference_Message *_Nonnull conference_message, uint32_t conference_number)
{
    assert(conference_message != nullptr);
    conference_message->conference_number = conference_number;
}
uint32_t tox_event_conference_message_get_conference_number(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->conference_number;
}

static void tox_event_conference_message_set_peer_number(Tox_Event_Conference_Message *_Nonnull conference_message, uint32_t peer_number)
{
    assert(conference_message != nullptr);
    conference_message->peer_number = peer_number;
}
uint32_t tox_event_conference_message_get_peer_number(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->peer_number;
}

static void tox_event_conference_message_set_type(Tox_Event_Conference_Message *_Nonnull conference_message, Tox_Message_Type type)
{
    assert(conference_message != nullptr);
    conference_message->type = type;
}
Tox_Message_Type tox_event_conference_message_get_type(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->type;
}

static bool tox_event_conference_message_set_message(Tox_Event_Conference_Message *_Nonnull conference_message,
        const Memory *_Nonnull mem, const uint8_t *_Nullable message, uint32_t message_length)
{
    assert(conference_message != nullptr);
    if (conference_message->message != nullptr) {
        mem_delete(mem, conference_message->message);
        conference_message->message = nullptr;
        conference_message->message_length = 0;
    }

    if (message == nullptr) {
        assert(message_length == 0);
        return true;
    }

    if (message_length == 0) {
        conference_message->message = nullptr;
        conference_message->message_length = 0;
        return true;
    }

    uint8_t *message_copy = (uint8_t *)mem_balloc(mem, message_length);

    if (message_copy == nullptr) {
        return false;
    }

    memcpy(message_copy, message, message_length);
    conference_message->message = message_copy;
    conference_message->message_length = message_length;
    return true;
}
uint32_t tox_event_conference_message_get_message_length(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->message_length;
}
const uint8_t *tox_event_conference_message_get_message(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->message;
}

static void tox_event_conference_message_construct(Tox_Event_Conference_Message *_Nonnull conference_message)
{
    *conference_message = (Tox_Event_Conference_Message) {
        0
    };
}
static void tox_event_conference_message_destruct(Tox_Event_Conference_Message *_Nonnull conference_message, const Memory *_Nonnull mem)
{
    mem_delete(mem, conference_message->message);
}

bool tox_event_conference_message_pack(
    const Tox_Event_Conference_Message *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && tox_message_type_pack(event->type, bp)
           && bin_pack_bin(bp, event->message, event->message_length);
}

static bool tox_event_conference_message_unpack_into(Tox_Event_Conference_Message *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && tox_message_type_unpack(&event->type, bu)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Conference_Message *tox_event_get_conference_message(const Tox_Event *event)
{
    return event->type == TOX_EVENT_CONFERENCE_MESSAGE ? event->data.conference_message : nullptr;
}

Tox_Event_Conference_Message *tox_event_conference_message_new(const Memory *mem)
{
    Tox_Event_Conference_Message *const conference_message =
        (Tox_Event_Conference_Message *)mem_alloc(mem, sizeof(Tox_Event_Conference_Message));

    if (conference_message == nullptr) {
        return nullptr;
    }

    tox_event_conference_message_construct(conference_message);
    return conference_message;
}

void tox_event_conference_message_free(Tox_Event_Conference_Message *conference_message, const Memory *mem)
{
    if (conference_message != nullptr) {
        tox_event_conference_message_destruct(conference_message, mem);
    }
    mem_delete(mem, conference_message);
}

static Tox_Event_Conference_Message *_Nullable tox_events_add_conference_message(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Conference_Message *const conference_message = tox_event_conference_message_new(mem);

    if (conference_message == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_CONFERENCE_MESSAGE;
    event.data.conference_message = conference_message;

    if (!tox_events_add(events, &event)) {
        tox_event_conference_message_free(conference_message, mem);
        return nullptr;
    }
    return conference_message;
}

bool tox_event_conference_message_unpack(
    Tox_Event_Conference_Message **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_conference_message_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_conference_message_unpack_into(*event, bu);
}

static Tox_Event_Conference_Message *_Nullable tox_event_conference_message_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Conference_Message *conference_message = tox_events_add_conference_message(state->events, state->mem);

    if (conference_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return conference_message;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_message(
    Tox *_Nonnull tox,
    uint32_t conference_number,
    uint32_t peer_number,
    Tox_Message_Type type,
    const uint8_t *_Nullable message, size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Conference_Message *conference_message = tox_event_conference_message_alloc(state);

    if (conference_message == nullptr) {
        return;
    }

    tox_event_conference_message_set_conference_number(conference_message, conference_number);
    tox_event_conference_message_set_peer_number(conference_message, peer_number);
    tox_event_conference_message_set_type(conference_message, type);
    if (!tox_event_conference_message_set_message(conference_message, state->mem, message, length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_conference_message_dispatch(Tox *tox, const Tox_Event_Conference_Message *event, void *user_data)
{
    if (tox->conference_message_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->conference_message_callback(tox, event->conference_number, event->peer_number, event->type, event->message, event->message_length, user_data);
    tox_lock(tox);
}
