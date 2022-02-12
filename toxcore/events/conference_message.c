/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"
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
    uint8_t *message;
    size_t message_length;
};

non_null()
static void tox_event_conference_message_construct(Tox_Event_Conference_Message *conference_message)
{
    *conference_message = (Tox_Event_Conference_Message) {
        0
    };
}
non_null()
static void tox_event_conference_message_destruct(Tox_Event_Conference_Message *conference_message)
{
    free(conference_message->message);
}

non_null()
static void tox_event_conference_message_set_conference_number(Tox_Event_Conference_Message *conference_message,
        uint32_t conference_number)
{
    assert(conference_message != nullptr);
    conference_message->conference_number = conference_number;
}
uint32_t tox_event_conference_message_get_conference_number(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->conference_number;
}

non_null()
static void tox_event_conference_message_set_peer_number(Tox_Event_Conference_Message *conference_message,
        uint32_t peer_number)
{
    assert(conference_message != nullptr);
    conference_message->peer_number = peer_number;
}
uint32_t tox_event_conference_message_get_peer_number(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->peer_number;
}

non_null()
static void tox_event_conference_message_set_type(Tox_Event_Conference_Message *conference_message,
        Tox_Message_Type type)
{
    assert(conference_message != nullptr);
    conference_message->type = type;
}
Tox_Message_Type tox_event_conference_message_get_type(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->type;
}

non_null()
static bool tox_event_conference_message_set_message(Tox_Event_Conference_Message *conference_message,
        const uint8_t *message, size_t message_length)
{
    assert(conference_message != nullptr);

    if (conference_message->message != nullptr) {
        free(conference_message->message);
        conference_message->message = nullptr;
        conference_message->message_length = 0;
    }

    conference_message->message = (uint8_t *)malloc(message_length);

    if (conference_message->message == nullptr) {
        return false;
    }

    memcpy(conference_message->message, message, message_length);
    conference_message->message_length = message_length;
    return true;
}
size_t tox_event_conference_message_get_message_length(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->message_length;
}
const uint8_t *tox_event_conference_message_get_message(const Tox_Event_Conference_Message *conference_message)
{
    assert(conference_message != nullptr);
    return conference_message->message;
}

non_null()
static void tox_event_conference_message_pack(
    const Tox_Event_Conference_Message *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    bin_pack_array(mp, 2);
    bin_pack_u32(mp, TOX_EVENT_CONFERENCE_MESSAGE);
    bin_pack_array(mp, 4);
    bin_pack_u32(mp, event->conference_number);
    bin_pack_u32(mp, event->peer_number);
    bin_pack_u32(mp, event->type);
    bin_pack_bytes(mp, event->message, event->message_length);
}

non_null()
static bool tox_event_conference_message_unpack(
    Tox_Event_Conference_Message *event, const msgpack_object *obj)
{
    assert(event != nullptr);

    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 4) {
        return false;
    }

    return bin_unpack_u32(&event->conference_number, &obj->via.array.ptr[0])
           && bin_unpack_u32(&event->peer_number, &obj->via.array.ptr[1])
           && tox_unpack_message_type(&event->type, &obj->via.array.ptr[2])
           && bin_unpack_bytes(&event->message, &event->message_length, &obj->via.array.ptr[3]);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Conference_Message *tox_events_add_conference_message(Tox_Events *events)
{
    if (events->conference_message_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->conference_message_size == events->conference_message_capacity) {
        const uint32_t new_conference_message_capacity = events->conference_message_capacity * 2 + 1;
        Tox_Event_Conference_Message *new_conference_message = (Tox_Event_Conference_Message *)realloc(
                    events->conference_message, new_conference_message_capacity * sizeof(Tox_Event_Conference_Message));

        if (new_conference_message == nullptr) {
            return nullptr;
        }

        events->conference_message = new_conference_message;
        events->conference_message_capacity = new_conference_message_capacity;
    }

    Tox_Event_Conference_Message *const conference_message = &events->conference_message[events->conference_message_size];
    tox_event_conference_message_construct(conference_message);
    ++events->conference_message_size;
    return conference_message;
}

void tox_events_clear_conference_message(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->conference_message_size; ++i) {
        tox_event_conference_message_destruct(&events->conference_message[i]);
    }

    free(events->conference_message);
    events->conference_message = nullptr;
    events->conference_message_size = 0;
    events->conference_message_capacity = 0;
}

uint32_t tox_events_get_conference_message_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->conference_message_size;
}

const Tox_Event_Conference_Message *tox_events_get_conference_message(const Tox_Events *events, uint32_t index)
{
    assert(index < events->conference_message_size);
    assert(events->conference_message != nullptr);
    return &events->conference_message[index];
}

void tox_events_pack_conference_message(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_conference_message_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_conference_message_pack(tox_events_get_conference_message(events, i), mp);
    }
}

bool tox_events_unpack_conference_message(Tox_Events *events, const msgpack_object *obj)
{
    Tox_Event_Conference_Message *event = tox_events_add_conference_message(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_conference_message_unpack(event, obj);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
        Tox_Message_Type type, const uint8_t *message, size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_Conference_Message *conference_message = tox_events_add_conference_message(state->events);

    if (conference_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_conference_message_set_conference_number(conference_message, conference_number);
    tox_event_conference_message_set_peer_number(conference_message, peer_number);
    tox_event_conference_message_set_type(conference_message, type);
    tox_event_conference_message_set_message(conference_message, message, length);
}
