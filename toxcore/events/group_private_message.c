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

struct Tox_Event_Group_Private_Message {
    uint32_t group_number;
    uint32_t peer_id;
    Tox_Message_Type message_type;
    uint8_t *message;
    uint32_t message_length;
    uint32_t message_id;
};

non_null()
static void tox_event_group_private_message_set_group_number(Tox_Event_Group_Private_Message *group_private_message,
        uint32_t group_number)
{
    assert(group_private_message != nullptr);
    group_private_message->group_number = group_number;
}
uint32_t tox_event_group_private_message_get_group_number(const Tox_Event_Group_Private_Message *group_private_message)
{
    assert(group_private_message != nullptr);
    return group_private_message->group_number;
}

non_null()
static void tox_event_group_private_message_set_peer_id(Tox_Event_Group_Private_Message *group_private_message,
        uint32_t peer_id)
{
    assert(group_private_message != nullptr);
    group_private_message->peer_id = peer_id;
}
uint32_t tox_event_group_private_message_get_peer_id(const Tox_Event_Group_Private_Message *group_private_message)
{
    assert(group_private_message != nullptr);
    return group_private_message->peer_id;
}

non_null()
static void tox_event_group_private_message_set_message_type(Tox_Event_Group_Private_Message *group_private_message,
        Tox_Message_Type message_type)
{
    assert(group_private_message != nullptr);
    group_private_message->message_type = message_type;
}
Tox_Message_Type tox_event_group_private_message_get_message_type(const Tox_Event_Group_Private_Message *group_private_message)
{
    assert(group_private_message != nullptr);
    return group_private_message->message_type;
}

non_null(1) nullable(2)
static bool tox_event_group_private_message_set_message(Tox_Event_Group_Private_Message *group_private_message,
        const uint8_t *message, uint32_t message_length)
{
    assert(group_private_message != nullptr);

    if (group_private_message->message != nullptr) {
        free(group_private_message->message);
        group_private_message->message = nullptr;
        group_private_message->message_length = 0;
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
    group_private_message->message = message_copy;
    group_private_message->message_length = message_length;
    return true;
}
uint32_t tox_event_group_private_message_get_message_length(const Tox_Event_Group_Private_Message *group_private_message)
{
    assert(group_private_message != nullptr);
    return group_private_message->message_length;
}
const uint8_t *tox_event_group_private_message_get_message(const Tox_Event_Group_Private_Message *group_private_message)
{
    assert(group_private_message != nullptr);
    return group_private_message->message;
}

non_null()
static void tox_event_group_private_message_set_message_id(Tox_Event_Group_Private_Message *group_private_message,
        uint32_t message_id)
{
    assert(group_private_message != nullptr);
    group_private_message->message_id = message_id;
}
uint32_t tox_event_group_private_message_get_message_id(const Tox_Event_Group_Private_Message *group_private_message)
{
    assert(group_private_message != nullptr);
    return group_private_message->message_id;
}

non_null()
static void tox_event_group_private_message_construct(Tox_Event_Group_Private_Message *group_private_message)
{
    *group_private_message = (Tox_Event_Group_Private_Message) {
        0
    };
}
non_null()
static void tox_event_group_private_message_destruct(Tox_Event_Group_Private_Message *group_private_message, const Memory *mem)
{
    free(group_private_message->message);
}

bool tox_event_group_private_message_pack(
    const Tox_Event_Group_Private_Message *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 5)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && tox_message_type_pack(event->message_type, bp)
           && bin_pack_bin(bp, event->message, event->message_length)
           && bin_pack_u32(bp, event->message_id);
}

non_null()
static bool tox_event_group_private_message_unpack_into(
    Tox_Event_Group_Private_Message *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 5, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && tox_message_type_unpack(&event->message_type, bu)
           && bin_unpack_bin(bu, &event->message, &event->message_length)
           && bin_unpack_u32(bu, &event->message_id);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Private_Message *tox_event_get_group_private_message(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_PRIVATE_MESSAGE ? event->data.group_private_message : nullptr;
}

Tox_Event_Group_Private_Message *tox_event_group_private_message_new(const Memory *mem)
{
    Tox_Event_Group_Private_Message *const group_private_message =
        (Tox_Event_Group_Private_Message *)mem_alloc(mem, sizeof(Tox_Event_Group_Private_Message));

    if (group_private_message == nullptr) {
        return nullptr;
    }

    tox_event_group_private_message_construct(group_private_message);
    return group_private_message;
}

void tox_event_group_private_message_free(Tox_Event_Group_Private_Message *group_private_message, const Memory *mem)
{
    if (group_private_message != nullptr) {
        tox_event_group_private_message_destruct(group_private_message, mem);
    }
    mem_delete(mem, group_private_message);
}

non_null()
static Tox_Event_Group_Private_Message *tox_events_add_group_private_message(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Private_Message *const group_private_message = tox_event_group_private_message_new(mem);

    if (group_private_message == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_PRIVATE_MESSAGE;
    event.data.group_private_message = group_private_message;

    tox_events_add(events, &event);
    return group_private_message;
}

bool tox_event_group_private_message_unpack(
    Tox_Event_Group_Private_Message **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_private_message_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_private_message_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Private_Message *tox_event_group_private_message_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Private_Message *group_private_message = tox_events_add_group_private_message(state->events, state->mem);

    if (group_private_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_private_message;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_private_message(
    Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_Message_Type message_type, const uint8_t *message, size_t message_length, uint32_t message_id,
    void *user_data)
{
    Tox_Event_Group_Private_Message *group_private_message = tox_event_group_private_message_alloc(user_data);

    if (group_private_message == nullptr) {
        return;
    }

    tox_event_group_private_message_set_group_number(group_private_message, group_number);
    tox_event_group_private_message_set_peer_id(group_private_message, peer_id);
    tox_event_group_private_message_set_message_type(group_private_message, message_type);
    tox_event_group_private_message_set_message(group_private_message, message, message_length);
    tox_event_group_private_message_set_message_id(group_private_message, message_id);
}
