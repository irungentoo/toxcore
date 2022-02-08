/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_unpack.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Status_Message {
    uint32_t friend_number;
    uint8_t *status_message;
    size_t status_message_length;
};

non_null()
static void tox_event_friend_status_message_construct(Tox_Event_Friend_Status_Message *friend_status_message)
{
    *friend_status_message = (Tox_Event_Friend_Status_Message) {
        0
    };
}
non_null()
static void tox_event_friend_status_message_destruct(Tox_Event_Friend_Status_Message *friend_status_message)
{
    free(friend_status_message->status_message);
}

non_null()
static void tox_event_friend_status_message_set_friend_number(Tox_Event_Friend_Status_Message *friend_status_message,
        uint32_t friend_number)
{
    assert(friend_status_message != nullptr);
    friend_status_message->friend_number = friend_number;
}
uint32_t tox_event_friend_status_message_get_friend_number(const Tox_Event_Friend_Status_Message *friend_status_message)
{
    assert(friend_status_message != nullptr);
    return friend_status_message->friend_number;
}

non_null()
static bool tox_event_friend_status_message_set_status_message(Tox_Event_Friend_Status_Message *friend_status_message,
        const uint8_t *status_message, size_t status_message_length)
{
    assert(friend_status_message != nullptr);

    if (friend_status_message->status_message != nullptr) {
        free(friend_status_message->status_message);
        friend_status_message->status_message = nullptr;
        friend_status_message->status_message_length = 0;
    }

    friend_status_message->status_message = (uint8_t *)malloc(status_message_length);

    if (friend_status_message->status_message == nullptr) {
        return false;
    }

    memcpy(friend_status_message->status_message, status_message, status_message_length);
    friend_status_message->status_message_length = status_message_length;
    return true;
}
size_t tox_event_friend_status_message_get_status_message_length(const Tox_Event_Friend_Status_Message
        *friend_status_message)
{
    assert(friend_status_message != nullptr);
    return friend_status_message->status_message_length;
}
const uint8_t *tox_event_friend_status_message_get_status_message(const Tox_Event_Friend_Status_Message
        *friend_status_message)
{
    assert(friend_status_message != nullptr);
    return friend_status_message->status_message;
}

non_null()
static void tox_event_friend_status_message_pack(
    const Tox_Event_Friend_Status_Message *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    msgpack_pack_array(mp, 2);
    msgpack_pack_uint32(mp, event->friend_number);
    msgpack_pack_bin(mp, event->status_message_length);
    msgpack_pack_bin_body(mp, event->status_message, event->status_message_length);
}

non_null()
static bool tox_event_friend_status_message_unpack(
    Tox_Event_Friend_Status_Message *event, const msgpack_object *obj)
{
    assert(event != nullptr);

    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 2) {
        return false;
    }

    return tox_unpack_u32(&event->friend_number, &obj->via.array.ptr[0])
           && tox_unpack_bin(&event->status_message, &event->status_message_length, &obj->via.array.ptr[1]);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Friend_Status_Message *tox_events_add_friend_status_message(Tox_Events *events)
{
    if (events->friend_status_message_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->friend_status_message_size == events->friend_status_message_capacity) {
        const uint32_t new_friend_status_message_capacity = events->friend_status_message_capacity * 2 + 1;
        Tox_Event_Friend_Status_Message *new_friend_status_message = (Tox_Event_Friend_Status_Message *)realloc(
                    events->friend_status_message, new_friend_status_message_capacity * sizeof(Tox_Event_Friend_Status_Message));

        if (new_friend_status_message == nullptr) {
            return nullptr;
        }

        events->friend_status_message = new_friend_status_message;
        events->friend_status_message_capacity = new_friend_status_message_capacity;
    }

    Tox_Event_Friend_Status_Message *const friend_status_message =
        &events->friend_status_message[events->friend_status_message_size];
    tox_event_friend_status_message_construct(friend_status_message);
    ++events->friend_status_message_size;
    return friend_status_message;
}

void tox_events_clear_friend_status_message(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->friend_status_message_size; ++i) {
        tox_event_friend_status_message_destruct(&events->friend_status_message[i]);
    }

    free(events->friend_status_message);
    events->friend_status_message = nullptr;
    events->friend_status_message_size = 0;
    events->friend_status_message_capacity = 0;
}

uint32_t tox_events_get_friend_status_message_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->friend_status_message_size;
}

const Tox_Event_Friend_Status_Message *tox_events_get_friend_status_message(const Tox_Events *events, uint32_t index)
{
    assert(index < events->friend_status_message_size);
    assert(events->friend_status_message != nullptr);
    return &events->friend_status_message[index];
}

void tox_events_pack_friend_status_message(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_friend_status_message_size(events);

    msgpack_pack_array(mp, size);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_friend_status_message_pack(tox_events_get_friend_status_message(events, i), mp);
    }
}

bool tox_events_unpack_friend_status_message(Tox_Events *events, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY) {
        return false;
    }

    for (uint32_t i = 0; i < obj->via.array.size; ++i) {
        Tox_Event_Friend_Status_Message *event = tox_events_add_friend_status_message(events);

        if (event == nullptr) {
            return false;
        }

        if (!tox_event_friend_status_message_unpack(event, &obj->via.array.ptr[i])) {
            return false;
        }
    }

    return true;
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_status_message(Tox *tox, uint32_t friend_number, const uint8_t *status_message,
        size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_Friend_Status_Message *friend_status_message = tox_events_add_friend_status_message(state->events);

    if (friend_status_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_friend_status_message_set_friend_number(friend_status_message, friend_number);
    tox_event_friend_status_message_set_status_message(friend_status_message, status_message, length);
}
