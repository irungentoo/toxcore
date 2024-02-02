/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_events.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Friend_Read_Receipt {
    uint32_t friend_number;
    uint32_t message_id;
};

non_null()
static void tox_event_friend_read_receipt_set_friend_number(Tox_Event_Friend_Read_Receipt *friend_read_receipt,
        uint32_t friend_number)
{
    assert(friend_read_receipt != nullptr);
    friend_read_receipt->friend_number = friend_number;
}
uint32_t tox_event_friend_read_receipt_get_friend_number(const Tox_Event_Friend_Read_Receipt *friend_read_receipt)
{
    assert(friend_read_receipt != nullptr);
    return friend_read_receipt->friend_number;
}

non_null()
static void tox_event_friend_read_receipt_set_message_id(Tox_Event_Friend_Read_Receipt *friend_read_receipt,
        uint32_t message_id)
{
    assert(friend_read_receipt != nullptr);
    friend_read_receipt->message_id = message_id;
}
uint32_t tox_event_friend_read_receipt_get_message_id(const Tox_Event_Friend_Read_Receipt *friend_read_receipt)
{
    assert(friend_read_receipt != nullptr);
    return friend_read_receipt->message_id;
}

non_null()
static void tox_event_friend_read_receipt_construct(Tox_Event_Friend_Read_Receipt *friend_read_receipt)
{
    *friend_read_receipt = (Tox_Event_Friend_Read_Receipt) {
        0
    };
}
non_null()
static void tox_event_friend_read_receipt_destruct(Tox_Event_Friend_Read_Receipt *friend_read_receipt, const Memory *mem)
{
    return;
}

bool tox_event_friend_read_receipt_pack(
    const Tox_Event_Friend_Read_Receipt *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->message_id);
}

non_null()
static bool tox_event_friend_read_receipt_unpack_into(
    Tox_Event_Friend_Read_Receipt *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->message_id);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Friend_Read_Receipt *tox_event_get_friend_read_receipt(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FRIEND_READ_RECEIPT ? event->data.friend_read_receipt : nullptr;
}

Tox_Event_Friend_Read_Receipt *tox_event_friend_read_receipt_new(const Memory *mem)
{
    Tox_Event_Friend_Read_Receipt *const friend_read_receipt =
        (Tox_Event_Friend_Read_Receipt *)mem_alloc(mem, sizeof(Tox_Event_Friend_Read_Receipt));

    if (friend_read_receipt == nullptr) {
        return nullptr;
    }

    tox_event_friend_read_receipt_construct(friend_read_receipt);
    return friend_read_receipt;
}

void tox_event_friend_read_receipt_free(Tox_Event_Friend_Read_Receipt *friend_read_receipt, const Memory *mem)
{
    if (friend_read_receipt != nullptr) {
        tox_event_friend_read_receipt_destruct(friend_read_receipt, mem);
    }
    mem_delete(mem, friend_read_receipt);
}

non_null()
static Tox_Event_Friend_Read_Receipt *tox_events_add_friend_read_receipt(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Friend_Read_Receipt *const friend_read_receipt = tox_event_friend_read_receipt_new(mem);

    if (friend_read_receipt == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FRIEND_READ_RECEIPT;
    event.data.friend_read_receipt = friend_read_receipt;

    tox_events_add(events, &event);
    return friend_read_receipt;
}

bool tox_event_friend_read_receipt_unpack(
    Tox_Event_Friend_Read_Receipt **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_friend_read_receipt_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_friend_read_receipt_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Friend_Read_Receipt *tox_event_friend_read_receipt_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Friend_Read_Receipt *friend_read_receipt = tox_events_add_friend_read_receipt(state->events, state->mem);

    if (friend_read_receipt == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return friend_read_receipt;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_friend_read_receipt(
    Tox *tox, uint32_t friend_number, uint32_t message_id,
    void *user_data)
{
    Tox_Event_Friend_Read_Receipt *friend_read_receipt = tox_event_friend_read_receipt_alloc(user_data);

    if (friend_read_receipt == nullptr) {
        return;
    }

    tox_event_friend_read_receipt_set_friend_number(friend_read_receipt, friend_number);
    tox_event_friend_read_receipt_set_message_id(friend_read_receipt, message_id);
}
