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

struct Tox_Event_Friend_Request {
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    uint8_t *_Nullable message;
    uint32_t message_length;
};

static bool tox_event_friend_request_set_public_key(Tox_Event_Friend_Request *_Nonnull friend_request, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE])
{
    assert(friend_request != nullptr);
    memcpy(friend_request->public_key, public_key, TOX_PUBLIC_KEY_SIZE);
    return true;
}
const uint8_t *tox_event_friend_request_get_public_key(const Tox_Event_Friend_Request *friend_request)
{
    assert(friend_request != nullptr);
    return friend_request->public_key;
}

static bool tox_event_friend_request_set_message(Tox_Event_Friend_Request *_Nonnull friend_request,
        const Memory *_Nonnull mem, const uint8_t *_Nullable message, uint32_t message_length)
{
    assert(friend_request != nullptr);
    if (friend_request->message != nullptr) {
        mem_delete(mem, friend_request->message);
        friend_request->message = nullptr;
        friend_request->message_length = 0;
    }

    if (message == nullptr) {
        assert(message_length == 0);
        return true;
    }

    if (message_length == 0) {
        friend_request->message = nullptr;
        friend_request->message_length = 0;
        return true;
    }

    uint8_t *message_copy = (uint8_t *)mem_balloc(mem, message_length);

    if (message_copy == nullptr) {
        return false;
    }

    memcpy(message_copy, message, message_length);
    friend_request->message = message_copy;
    friend_request->message_length = message_length;
    return true;
}
uint32_t tox_event_friend_request_get_message_length(const Tox_Event_Friend_Request *friend_request)
{
    assert(friend_request != nullptr);
    return friend_request->message_length;
}
const uint8_t *tox_event_friend_request_get_message(const Tox_Event_Friend_Request *friend_request)
{
    assert(friend_request != nullptr);
    return friend_request->message;
}

static void tox_event_friend_request_construct(Tox_Event_Friend_Request *_Nonnull friend_request)
{
    *friend_request = (Tox_Event_Friend_Request) {
        {
            0
        }
    };
}
static void tox_event_friend_request_destruct(Tox_Event_Friend_Request *_Nonnull friend_request, const Memory *_Nonnull mem)
{
    mem_delete(mem, friend_request->message);
}

bool tox_event_friend_request_pack(
    const Tox_Event_Friend_Request *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_bin(bp, event->public_key, TOX_PUBLIC_KEY_SIZE)
           && bin_pack_bin(bp, event->message, event->message_length);
}

static bool tox_event_friend_request_unpack_into(Tox_Event_Friend_Request *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_bin_fixed(bu, event->public_key, TOX_PUBLIC_KEY_SIZE)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Request *tox_event_get_friend_request(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_REQUEST ? event->data.friend_request : nullptr;
}

Tox_Event_Friend_Request *tox_event_friend_request_new(const Memory *mem)
{
    Tox_Event_Friend_Request *const friend_request =
        (Tox_Event_Friend_Request *)mem_alloc(mem, sizeof(Tox_Event_Friend_Request));

    if (friend_request == nullptr) {
        return nullptr;
    }

    tox_event_friend_request_construct(friend_request);
    return friend_request;
}

void tox_event_friend_request_free(Tox_Event_Friend_Request *friend_request, const Memory *mem)
{
    if (friend_request != nullptr) {
        tox_event_friend_request_destruct(friend_request, mem);
    }
    mem_delete(mem, friend_request);
}

static Tox_Event_Friend_Request *_Nullable tox_events_add_friend_request(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Friend_Request *const friend_request = tox_event_friend_request_new(mem);

    if (friend_request == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_REQUEST;
    event.data.friend_request = friend_request;

    if (!tox_events_add(events, &event)) {
        tox_event_friend_request_free(friend_request, mem);
        return nullptr;
    }
    return friend_request;
}

bool tox_event_friend_request_unpack(
    Tox_Event_Friend_Request **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_request_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_request_unpack_into(*event, bu);
}

static Tox_Event_Friend_Request *_Nullable tox_event_friend_request_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Request *friend_request = tox_events_add_friend_request(state->events, state->mem);

    if (friend_request == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_request;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_request(
    Tox *_Nonnull tox,
    const uint8_t *_Nonnull public_key,
    const uint8_t *_Nullable message, size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Friend_Request *friend_request = tox_event_friend_request_alloc(state);

    if (friend_request == nullptr) {
        return;
    }

    tox_event_friend_request_set_public_key(friend_request, public_key);
    if (!tox_event_friend_request_set_message(friend_request, state->mem, message, length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_friend_request_dispatch(Tox *tox, const Tox_Event_Friend_Request *event, void *user_data)
{
    if (tox->friend_request_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->friend_request_callback(tox, event->public_key, event->message, event->message_length, user_data);
    tox_lock(tox);
}
