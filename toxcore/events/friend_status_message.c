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

struct Tox_Event_Friend_Status_Message {
    uint32_t friend_number;
    uint8_t *_Nullable message;
    uint32_t message_length;
};

static void tox_event_friend_status_message_set_friend_number(Tox_Event_Friend_Status_Message *_Nonnull friend_status_message, uint32_t friend_number)
{
    assert(friend_status_message != nullptr);
    friend_status_message->friend_number = friend_number;
}
uint32_t tox_event_friend_status_message_get_friend_number(const Tox_Event_Friend_Status_Message *friend_status_message)
{
    assert(friend_status_message != nullptr);
    return friend_status_message->friend_number;
}

static bool tox_event_friend_status_message_set_message(Tox_Event_Friend_Status_Message *_Nonnull friend_status_message,
        const Memory *_Nonnull mem, const uint8_t *_Nullable message, uint32_t message_length)
{
    assert(friend_status_message != nullptr);
    if (friend_status_message->message != nullptr) {
        mem_delete(mem, friend_status_message->message);
        friend_status_message->message = nullptr;
        friend_status_message->message_length = 0;
    }

    if (message == nullptr) {
        assert(message_length == 0);
        return true;
    }

    if (message_length == 0) {
        friend_status_message->message = nullptr;
        friend_status_message->message_length = 0;
        return true;
    }

    uint8_t *message_copy = (uint8_t *)mem_balloc(mem, message_length);

    if (message_copy == nullptr) {
        return false;
    }

    memcpy(message_copy, message, message_length);
    friend_status_message->message = message_copy;
    friend_status_message->message_length = message_length;
    return true;
}
uint32_t tox_event_friend_status_message_get_message_length(const Tox_Event_Friend_Status_Message *friend_status_message)
{
    assert(friend_status_message != nullptr);
    return friend_status_message->message_length;
}
const uint8_t *tox_event_friend_status_message_get_message(const Tox_Event_Friend_Status_Message *friend_status_message)
{
    assert(friend_status_message != nullptr);
    return friend_status_message->message;
}

static void tox_event_friend_status_message_construct(Tox_Event_Friend_Status_Message *_Nonnull friend_status_message)
{
    *friend_status_message = (Tox_Event_Friend_Status_Message) {
        0
    };
}
static void tox_event_friend_status_message_destruct(Tox_Event_Friend_Status_Message *_Nonnull friend_status_message, const Memory *_Nonnull mem)
{
    mem_delete(mem, friend_status_message->message);
}

bool tox_event_friend_status_message_pack(
    const Tox_Event_Friend_Status_Message *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->message, event->message_length);
}

static bool tox_event_friend_status_message_unpack_into(Tox_Event_Friend_Status_Message *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Status_Message *tox_event_get_friend_status_message(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_STATUS_MESSAGE ? event->data.friend_status_message : nullptr;
}

Tox_Event_Friend_Status_Message *tox_event_friend_status_message_new(const Memory *mem)
{
    Tox_Event_Friend_Status_Message *const friend_status_message =
        (Tox_Event_Friend_Status_Message *)mem_alloc(mem, sizeof(Tox_Event_Friend_Status_Message));

    if (friend_status_message == nullptr) {
        return nullptr;
    }

    tox_event_friend_status_message_construct(friend_status_message);
    return friend_status_message;
}

void tox_event_friend_status_message_free(Tox_Event_Friend_Status_Message *friend_status_message, const Memory *mem)
{
    if (friend_status_message != nullptr) {
        tox_event_friend_status_message_destruct(friend_status_message, mem);
    }
    mem_delete(mem, friend_status_message);
}

static Tox_Event_Friend_Status_Message *_Nullable tox_events_add_friend_status_message(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Friend_Status_Message *const friend_status_message = tox_event_friend_status_message_new(mem);

    if (friend_status_message == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_STATUS_MESSAGE;
    event.data.friend_status_message = friend_status_message;

    if (!tox_events_add(events, &event)) {
        tox_event_friend_status_message_free(friend_status_message, mem);
        return nullptr;
    }
    return friend_status_message;
}

bool tox_event_friend_status_message_unpack(
    Tox_Event_Friend_Status_Message **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_status_message_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_status_message_unpack_into(*event, bu);
}

static Tox_Event_Friend_Status_Message *_Nullable tox_event_friend_status_message_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Status_Message *friend_status_message = tox_events_add_friend_status_message(state->events, state->mem);

    if (friend_status_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_status_message;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_status_message(
    Tox *_Nonnull tox,
    uint32_t friend_number,
    const uint8_t *_Nullable message, size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Friend_Status_Message *friend_status_message = tox_event_friend_status_message_alloc(state);

    if (friend_status_message == nullptr) {
        return;
    }

    tox_event_friend_status_message_set_friend_number(friend_status_message, friend_number);
    if (!tox_event_friend_status_message_set_message(friend_status_message, state->mem, message, length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_friend_status_message_dispatch(Tox *tox, const Tox_Event_Friend_Status_Message *event, void *user_data)
{
    if (tox->friend_status_message_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->friend_status_message_callback(tox, event->friend_number, event->message, event->message_length, user_data);
    tox_lock(tox);
}
