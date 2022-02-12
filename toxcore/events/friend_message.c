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


struct Tox_Event_Friend_Message {
    uint32_t friend_number;
    Tox_Message_Type type;
    uint8_t *message;
    size_t message_length;
};

non_null()
static void tox_event_friend_message_construct(Tox_Event_Friend_Message *friend_message)
{
    *friend_message = (Tox_Event_Friend_Message) {
        0
    };
}
non_null()
static void tox_event_friend_message_destruct(Tox_Event_Friend_Message *friend_message)
{
    free(friend_message->message);
}

non_null()
static void tox_event_friend_message_set_friend_number(Tox_Event_Friend_Message *friend_message,
        uint32_t friend_number)
{
    assert(friend_message != nullptr);
    friend_message->friend_number = friend_number;
}
uint32_t tox_event_friend_message_get_friend_number(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->friend_number;
}

non_null()
static void tox_event_friend_message_set_type(Tox_Event_Friend_Message *friend_message, Tox_Message_Type type)
{
    assert(friend_message != nullptr);
    friend_message->type = type;
}
Tox_Message_Type tox_event_friend_message_get_type(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->type;
}

non_null()
static bool tox_event_friend_message_set_message(Tox_Event_Friend_Message *friend_message, const uint8_t *message,
        size_t message_length)
{
    assert(friend_message != nullptr);

    if (friend_message->message != nullptr) {
        free(friend_message->message);
        friend_message->message = nullptr;
        friend_message->message_length = 0;
    }

    friend_message->message = (uint8_t *)malloc(message_length);

    if (friend_message->message == nullptr) {
        return false;
    }

    memcpy(friend_message->message, message, message_length);
    friend_message->message_length = message_length;
    return true;
}
size_t tox_event_friend_message_get_message_length(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->message_length;
}
const uint8_t *tox_event_friend_message_get_message(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->message;
}

non_null()
static void tox_event_friend_message_pack(
    const Tox_Event_Friend_Message *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    bin_pack_array(mp, 2);
    bin_pack_u32(mp, TOX_EVENT_FRIEND_MESSAGE);
    bin_pack_array(mp, 3);
    bin_pack_u32(mp, event->friend_number);
    bin_pack_u32(mp, event->type);
    bin_pack_bytes(mp, event->message, event->message_length);
}

non_null()
static bool tox_event_friend_message_unpack(
    Tox_Event_Friend_Message *event, const msgpack_object *obj)
{
    assert(event != nullptr);

    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 3) {
        return false;
    }

    return bin_unpack_u32(&event->friend_number, &obj->via.array.ptr[0])
           && tox_unpack_message_type(&event->type, &obj->via.array.ptr[1])
           && bin_unpack_bytes(&event->message, &event->message_length, &obj->via.array.ptr[2]);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Friend_Message *tox_events_add_friend_message(Tox_Events *events)
{
    if (events->friend_message_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->friend_message_size == events->friend_message_capacity) {
        const uint32_t new_friend_message_capacity = events->friend_message_capacity * 2 + 1;
        Tox_Event_Friend_Message *new_friend_message = (Tox_Event_Friend_Message *)realloc(
                    events->friend_message, new_friend_message_capacity * sizeof(Tox_Event_Friend_Message));

        if (new_friend_message == nullptr) {
            return nullptr;
        }

        events->friend_message = new_friend_message;
        events->friend_message_capacity = new_friend_message_capacity;
    }

    Tox_Event_Friend_Message *const friend_message = &events->friend_message[events->friend_message_size];
    tox_event_friend_message_construct(friend_message);
    ++events->friend_message_size;
    return friend_message;
}

void tox_events_clear_friend_message(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->friend_message_size; ++i) {
        tox_event_friend_message_destruct(&events->friend_message[i]);
    }

    free(events->friend_message);
    events->friend_message = nullptr;
    events->friend_message_size = 0;
    events->friend_message_capacity = 0;
}

uint32_t tox_events_get_friend_message_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->friend_message_size;
}

const Tox_Event_Friend_Message *tox_events_get_friend_message(const Tox_Events *events, uint32_t index)
{
    assert(index < events->friend_message_size);
    assert(events->friend_message != nullptr);
    return &events->friend_message[index];
}

void tox_events_pack_friend_message(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_friend_message_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_friend_message_pack(tox_events_get_friend_message(events, i), mp);
    }
}

bool tox_events_unpack_friend_message(Tox_Events *events, const msgpack_object *obj)
{
    Tox_Event_Friend_Message *event = tox_events_add_friend_message(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_friend_message_unpack(event, obj);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_message(Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message,
                                      size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_Friend_Message *friend_message = tox_events_add_friend_message(state->events);

    if (friend_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_friend_message_set_friend_number(friend_message, friend_number);
    tox_event_friend_message_set_type(friend_message, type);
    tox_event_friend_message_set_message(friend_message, message, length);
}
