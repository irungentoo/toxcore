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

struct Tox_Event_Group_Password {
    uint32_t group_number;
    uint8_t *_Nullable password;
    uint32_t password_length;
};

static void tox_event_group_password_set_group_number(Tox_Event_Group_Password *_Nonnull group_password, uint32_t group_number)
{
    assert(group_password != nullptr);
    group_password->group_number = group_number;
}
uint32_t tox_event_group_password_get_group_number(const Tox_Event_Group_Password *group_password)
{
    assert(group_password != nullptr);
    return group_password->group_number;
}

static bool tox_event_group_password_set_password(Tox_Event_Group_Password *_Nonnull group_password,
        const Memory *_Nonnull mem, const uint8_t *_Nullable password, uint32_t password_length)
{
    assert(group_password != nullptr);
    if (group_password->password != nullptr) {
        mem_delete(mem, group_password->password);
        group_password->password = nullptr;
        group_password->password_length = 0;
    }

    if (password == nullptr) {
        assert(password_length == 0);
        return true;
    }

    if (password_length == 0) {
        group_password->password = nullptr;
        group_password->password_length = 0;
        return true;
    }

    uint8_t *password_copy = (uint8_t *)mem_balloc(mem, password_length);

    if (password_copy == nullptr) {
        return false;
    }

    memcpy(password_copy, password, password_length);
    group_password->password = password_copy;
    group_password->password_length = password_length;
    return true;
}
uint32_t tox_event_group_password_get_password_length(const Tox_Event_Group_Password *group_password)
{
    assert(group_password != nullptr);
    return group_password->password_length;
}
const uint8_t *tox_event_group_password_get_password(const Tox_Event_Group_Password *group_password)
{
    assert(group_password != nullptr);
    return group_password->password;
}

static void tox_event_group_password_construct(Tox_Event_Group_Password *_Nonnull group_password)
{
    *group_password = (Tox_Event_Group_Password) {
        0
    };
}
static void tox_event_group_password_destruct(Tox_Event_Group_Password *_Nonnull group_password, const Memory *_Nonnull mem)
{
    mem_delete(mem, group_password->password);
}

bool tox_event_group_password_pack(
    const Tox_Event_Group_Password *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_bin(bp, event->password, event->password_length);
}

static bool tox_event_group_password_unpack_into(Tox_Event_Group_Password *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_bin(bu, &event->password, &event->password_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Password *tox_event_get_group_password(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_PASSWORD ? event->data.group_password : nullptr;
}

Tox_Event_Group_Password *tox_event_group_password_new(const Memory *mem)
{
    Tox_Event_Group_Password *const group_password =
        (Tox_Event_Group_Password *)mem_alloc(mem, sizeof(Tox_Event_Group_Password));

    if (group_password == nullptr) {
        return nullptr;
    }

    tox_event_group_password_construct(group_password);
    return group_password;
}

void tox_event_group_password_free(Tox_Event_Group_Password *group_password, const Memory *mem)
{
    if (group_password != nullptr) {
        tox_event_group_password_destruct(group_password, mem);
    }
    mem_delete(mem, group_password);
}

static Tox_Event_Group_Password *_Nullable tox_events_add_group_password(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Group_Password *const group_password = tox_event_group_password_new(mem);

    if (group_password == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_PASSWORD;
    event.data.group_password = group_password;

    if (!tox_events_add(events, &event)) {
        tox_event_group_password_free(group_password, mem);
        return nullptr;
    }
    return group_password;
}

bool tox_event_group_password_unpack(
    Tox_Event_Group_Password **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_password_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_password_unpack_into(*event, bu);
}

static Tox_Event_Group_Password *_Nullable tox_event_group_password_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Password *group_password = tox_events_add_group_password(state->events, state->mem);

    if (group_password == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_password;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_password(
    Tox *_Nonnull tox,
    uint32_t group_number,
    const uint8_t *_Nullable password, size_t password_length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Group_Password *group_password = tox_event_group_password_alloc(state);

    if (group_password == nullptr) {
        return;
    }

    tox_event_group_password_set_group_number(group_password, group_number);
    if (!tox_event_group_password_set_password(group_password, state->mem, password, password_length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_group_password_dispatch(Tox *tox, const Tox_Event_Group_Password *event, void *user_data)
{
    if (tox->group_password_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->group_password_callback(tox, event->group_number, event->password, event->password_length, user_data);
    tox_lock(tox);
}
