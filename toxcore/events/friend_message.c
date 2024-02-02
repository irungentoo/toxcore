/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_pack.h"
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
    uint32_t message_length;
};

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
static void tox_event_friend_message_set_type(Tox_Event_Friend_Message *friend_message,
        Tox_Message_Type type)
{
    assert(friend_message != nullptr);
    friend_message->type = type;
}
Tox_Message_Type tox_event_friend_message_get_type(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->type;
}

non_null(1) nullable(2)
static bool tox_event_friend_message_set_message(Tox_Event_Friend_Message *friend_message,
        const uint8_t *message, uint32_t message_length)
{
    assert(friend_message != nullptr);

    if (friend_message->message != nullptr) {
        free(friend_message->message);
        friend_message->message = nullptr;
        friend_message->message_length = 0;
    }

    if (message == nullptr) {
        assert(message_length == 0);
        return true;
    }

    uint8_t *message_copy = (uint8_t *)malloc(message_length);

    if (message_copy == nullptr) {
        return false;
    }

    memcpy(message_copy, message, message_length);
    friend_message->message = message_copy;
    friend_message->message_length = message_length;
    return true;
}
uint32_t tox_event_friend_message_get_message_length(const Tox_Event_Friend_Message *friend_message)
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
static void tox_event_friend_message_construct(Tox_Event_Friend_Message *friend_message)
{
    *friend_message = (Tox_Event_Friend_Message) {
        0
    };
}
non_null()
static void tox_event_friend_message_destruct(Tox_Event_Friend_Message *friend_message, const Memory *mem)
{
    free(friend_message->message);
}

bool tox_event_friend_message_pack(
    const Tox_Event_Friend_Message *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && tox_message_type_pack(event->type, bp)
           && bin_pack_bin(bp, event->message, event->message_length);
}

non_null()
static bool tox_event_friend_message_unpack_into(
    Tox_Event_Friend_Message *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_message_type_unpack(&event->type, bu)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Message *tox_event_get_friend_message(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_MESSAGE ? event->data.friend_message : nullptr;
}

Tox_Event_Friend_Message *tox_event_friend_message_new(const Memory *mem)
{
    Tox_Event_Friend_Message *const friend_message =
        (Tox_Event_Friend_Message *)mem_alloc(mem, sizeof(Tox_Event_Friend_Message));

    if (friend_message == nullptr) {
        return nullptr;
    }

    tox_event_friend_message_construct(friend_message);
    return friend_message;
}

void tox_event_friend_message_free(Tox_Event_Friend_Message *friend_message, const Memory *mem)
{
    if (friend_message != nullptr) {
        tox_event_friend_message_destruct(friend_message, mem);
    }
    mem_delete(mem, friend_message);
}

non_null()
static Tox_Event_Friend_Message *tox_events_add_friend_message(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Friend_Message *const friend_message = tox_event_friend_message_new(mem);

    if (friend_message == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_MESSAGE;
    event.data.friend_message = friend_message;

    tox_events_add(events, &event);
    return friend_message;
}

bool tox_event_friend_message_unpack(
    Tox_Event_Friend_Message **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_message_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_message_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Friend_Message *tox_event_friend_message_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Message *friend_message = tox_events_add_friend_message(state->events, state->mem);

    if (friend_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_message;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_message(
    Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message, size_t length,
    void *user_data)
{
    Tox_Event_Friend_Message *friend_message = tox_event_friend_message_alloc(user_data);

    if (friend_message == nullptr) {
        return;
    }

    tox_event_friend_message_set_friend_number(friend_message, friend_number);
    tox_event_friend_message_set_type(friend_message, type);
    tox_event_friend_message_set_message(friend_message, message, length);
}
