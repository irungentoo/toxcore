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
#include "../tox_pack.h"
#include "../tox_unpack.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_File_Recv_Control {
    uint32_t friend_number;
    uint32_t file_number;
    Tox_File_Control control;
};

non_null()
static void tox_event_file_recv_control_set_friend_number(Tox_Event_File_Recv_Control *file_recv_control,
        uint32_t friend_number)
{
    assert(file_recv_control != nullptr);
    file_recv_control->friend_number = friend_number;
}
uint32_t tox_event_file_recv_control_get_friend_number(const Tox_Event_File_Recv_Control *file_recv_control)
{
    assert(file_recv_control != nullptr);
    return file_recv_control->friend_number;
}

non_null()
static void tox_event_file_recv_control_set_file_number(Tox_Event_File_Recv_Control *file_recv_control,
        uint32_t file_number)
{
    assert(file_recv_control != nullptr);
    file_recv_control->file_number = file_number;
}
uint32_t tox_event_file_recv_control_get_file_number(const Tox_Event_File_Recv_Control *file_recv_control)
{
    assert(file_recv_control != nullptr);
    return file_recv_control->file_number;
}

non_null()
static void tox_event_file_recv_control_set_control(Tox_Event_File_Recv_Control *file_recv_control,
        Tox_File_Control control)
{
    assert(file_recv_control != nullptr);
    file_recv_control->control = control;
}
Tox_File_Control tox_event_file_recv_control_get_control(const Tox_Event_File_Recv_Control *file_recv_control)
{
    assert(file_recv_control != nullptr);
    return file_recv_control->control;
}

non_null()
static void tox_event_file_recv_control_construct(Tox_Event_File_Recv_Control *file_recv_control)
{
    *file_recv_control = (Tox_Event_File_Recv_Control) {
        0
    };
}
non_null()
static void tox_event_file_recv_control_destruct(Tox_Event_File_Recv_Control *file_recv_control, const Memory *mem)
{
    return;
}

bool tox_event_file_recv_control_pack(
    const Tox_Event_File_Recv_Control *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && tox_file_control_pack(event->control, bp);
}

non_null()
static bool tox_event_file_recv_control_unpack_into(
    Tox_Event_File_Recv_Control *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && tox_file_control_unpack(&event->control, bu);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_File_Recv_Control *tox_event_get_file_recv_control(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FILE_RECV_CONTROL ? event->data.file_recv_control : nullptr;
}

Tox_Event_File_Recv_Control *tox_event_file_recv_control_new(const Memory *mem)
{
    Tox_Event_File_Recv_Control *const file_recv_control =
        (Tox_Event_File_Recv_Control *)mem_alloc(mem, sizeof(Tox_Event_File_Recv_Control));

    if (file_recv_control == nullptr) {
        return nullptr;
    }

    tox_event_file_recv_control_construct(file_recv_control);
    return file_recv_control;
}

void tox_event_file_recv_control_free(Tox_Event_File_Recv_Control *file_recv_control, const Memory *mem)
{
    if (file_recv_control != nullptr) {
        tox_event_file_recv_control_destruct(file_recv_control, mem);
    }
    mem_delete(mem, file_recv_control);
}

non_null()
static Tox_Event_File_Recv_Control *tox_events_add_file_recv_control(Tox_Events *events, const Memory *mem)
{
    Tox_Event_File_Recv_Control *const file_recv_control = tox_event_file_recv_control_new(mem);

    if (file_recv_control == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FILE_RECV_CONTROL;
    event.data.file_recv_control = file_recv_control;

    tox_events_add(events, &event);
    return file_recv_control;
}

bool tox_event_file_recv_control_unpack(
    Tox_Event_File_Recv_Control **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_file_recv_control_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_file_recv_control_unpack_into(*event, bu);
}

non_null()
static Tox_Event_File_Recv_Control *tox_event_file_recv_control_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_File_Recv_Control *file_recv_control = tox_events_add_file_recv_control(state->events, state->mem);

    if (file_recv_control == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return file_recv_control;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_file_recv_control(
    Tox *tox, uint32_t friend_number, uint32_t file_number, Tox_File_Control control,
    void *user_data)
{
    Tox_Event_File_Recv_Control *file_recv_control = tox_event_file_recv_control_alloc(user_data);

    if (file_recv_control == nullptr) {
        return;
    }

    tox_event_file_recv_control_set_friend_number(file_recv_control, friend_number);
    tox_event_file_recv_control_set_file_number(file_recv_control, file_number);
    tox_event_file_recv_control_set_control(file_recv_control, control);
}
