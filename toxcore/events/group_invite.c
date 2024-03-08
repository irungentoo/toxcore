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

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Group_Invite {
    uint32_t friend_number;
    uint8_t *invite_data;
    uint32_t invite_data_length;
    uint8_t *group_name;
    uint32_t group_name_length;
};

non_null()
static void tox_event_group_invite_set_friend_number(Tox_Event_Group_Invite *group_invite,
        uint32_t friend_number)
{
    assert(group_invite != nullptr);
    group_invite->friend_number = friend_number;
}
uint32_t tox_event_group_invite_get_friend_number(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->friend_number;
}

non_null(1) nullable(2)
static bool tox_event_group_invite_set_invite_data(Tox_Event_Group_Invite *group_invite,
        const uint8_t *invite_data, uint32_t invite_data_length)
{
    assert(group_invite != nullptr);

    if (group_invite->invite_data != nullptr) {
        free(group_invite->invite_data);
        group_invite->invite_data = nullptr;
        group_invite->invite_data_length = 0;
    }

    if (invite_data == nullptr) {
        assert(invite_data_length == 0);
        return true;
    }

    uint8_t *invite_data_copy = (uint8_t *)malloc(invite_data_length);

    if (invite_data_copy == nullptr) {
        return false;
    }

    memcpy(invite_data_copy, invite_data, invite_data_length);
    group_invite->invite_data = invite_data_copy;
    group_invite->invite_data_length = invite_data_length;
    return true;
}
uint32_t tox_event_group_invite_get_invite_data_length(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->invite_data_length;
}
const uint8_t *tox_event_group_invite_get_invite_data(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->invite_data;
}

non_null(1) nullable(2)
static bool tox_event_group_invite_set_group_name(Tox_Event_Group_Invite *group_invite,
        const uint8_t *group_name, uint32_t group_name_length)
{
    assert(group_invite != nullptr);

    if (group_invite->group_name != nullptr) {
        free(group_invite->group_name);
        group_invite->group_name = nullptr;
        group_invite->group_name_length = 0;
    }

    if (group_name == nullptr) {
        assert(group_name_length == 0);
        return true;
    }

    uint8_t *group_name_copy = (uint8_t *)malloc(group_name_length);

    if (group_name_copy == nullptr) {
        return false;
    }

    memcpy(group_name_copy, group_name, group_name_length);
    group_invite->group_name = group_name_copy;
    group_invite->group_name_length = group_name_length;
    return true;
}
uint32_t tox_event_group_invite_get_group_name_length(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->group_name_length;
}
const uint8_t *tox_event_group_invite_get_group_name(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->group_name;
}

non_null()
static void tox_event_group_invite_construct(Tox_Event_Group_Invite *group_invite)
{
    *group_invite = (Tox_Event_Group_Invite) {
        0
    };
}
non_null()
static void tox_event_group_invite_destruct(Tox_Event_Group_Invite *group_invite, const Memory *mem)
{
    free(group_invite->invite_data);
    free(group_invite->group_name);
}

bool tox_event_group_invite_pack(
    const Tox_Event_Group_Invite *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->invite_data, event->invite_data_length)
           && bin_pack_bin(bp, event->group_name, event->group_name_length);
}

non_null()
static bool tox_event_group_invite_unpack_into(
    Tox_Event_Group_Invite *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->invite_data, &event->invite_data_length)
           && bin_unpack_bin(bu, &event->group_name, &event->group_name_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Invite *tox_event_get_group_invite(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_INVITE ? event->data.group_invite : nullptr;
}

Tox_Event_Group_Invite *tox_event_group_invite_new(const Memory *mem)
{
    Tox_Event_Group_Invite *const group_invite =
        (Tox_Event_Group_Invite *)mem_alloc(mem, sizeof(Tox_Event_Group_Invite));

    if (group_invite == nullptr) {
        return nullptr;
    }

    tox_event_group_invite_construct(group_invite);
    return group_invite;
}

void tox_event_group_invite_free(Tox_Event_Group_Invite *group_invite, const Memory *mem)
{
    if (group_invite != nullptr) {
        tox_event_group_invite_destruct(group_invite, mem);
    }
    mem_delete(mem, group_invite);
}

non_null()
static Tox_Event_Group_Invite *tox_events_add_group_invite(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Invite *const group_invite = tox_event_group_invite_new(mem);

    if (group_invite == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_INVITE;
    event.data.group_invite = group_invite;

    tox_events_add(events, &event);
    return group_invite;
}

bool tox_event_group_invite_unpack(
    Tox_Event_Group_Invite **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_invite_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_invite_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Group_Invite *tox_event_group_invite_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Invite *group_invite = tox_events_add_group_invite(state->events, state->mem);

    if (group_invite == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_invite;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_invite(
    Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t invite_data_length, const uint8_t *group_name, size_t group_name_length,
    void *user_data)
{
    Tox_Event_Group_Invite *group_invite = tox_event_group_invite_alloc(user_data);

    if (group_invite == nullptr) {
        return;
    }

    tox_event_group_invite_set_friend_number(group_invite, friend_number);
    tox_event_group_invite_set_invite_data(group_invite, invite_data, invite_data_length);
    tox_event_group_invite_set_group_name(group_invite, group_name, group_name_length);
}
