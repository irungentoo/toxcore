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


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_File_Recv {
    uint32_t friend_number;
    uint32_t file_number;
    uint32_t kind;
    uint64_t file_size;
    uint8_t *filename;
    uint32_t filename_length;
};

non_null()
static void tox_event_file_recv_construct(Tox_Event_File_Recv *file_recv)
{
    *file_recv = (Tox_Event_File_Recv) {
        0
    };
}
non_null()
static void tox_event_file_recv_destruct(Tox_Event_File_Recv *file_recv)
{
    free(file_recv->filename);
}

non_null()
static void tox_event_file_recv_set_friend_number(Tox_Event_File_Recv *file_recv,
        uint32_t friend_number)
{
    assert(file_recv != nullptr);
    file_recv->friend_number = friend_number;
}
uint32_t tox_event_file_recv_get_friend_number(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->friend_number;
}

non_null()
static void tox_event_file_recv_set_file_number(Tox_Event_File_Recv *file_recv,
        uint32_t file_number)
{
    assert(file_recv != nullptr);
    file_recv->file_number = file_number;
}
uint32_t tox_event_file_recv_get_file_number(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->file_number;
}

non_null()
static void tox_event_file_recv_set_kind(Tox_Event_File_Recv *file_recv,
        uint32_t kind)
{
    assert(file_recv != nullptr);
    file_recv->kind = kind;
}
uint32_t tox_event_file_recv_get_kind(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->kind;
}

non_null()
static void tox_event_file_recv_set_file_size(Tox_Event_File_Recv *file_recv,
        uint64_t file_size)
{
    assert(file_recv != nullptr);
    file_recv->file_size = file_size;
}
uint64_t tox_event_file_recv_get_file_size(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->file_size;
}

non_null()
static bool tox_event_file_recv_set_filename(Tox_Event_File_Recv *file_recv, const uint8_t *filename,
        uint32_t filename_length)
{
    assert(file_recv != nullptr);

    if (file_recv->filename != nullptr) {
        free(file_recv->filename);
        file_recv->filename = nullptr;
        file_recv->filename_length = 0;
    }

    file_recv->filename = (uint8_t *)malloc(filename_length);

    if (file_recv->filename == nullptr) {
        return false;
    }

    memcpy(file_recv->filename, filename, filename_length);
    file_recv->filename_length = filename_length;
    return true;
}
uint32_t tox_event_file_recv_get_filename_length(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->filename_length;
}
const uint8_t *tox_event_file_recv_get_filename(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->filename;
}

non_null()
static bool tox_event_file_recv_pack(
    const Tox_Event_File_Recv *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FILE_RECV)
           && bin_pack_array(bp, 5)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u32(bp, event->kind)
           && bin_pack_u64(bp, event->file_size)
           && bin_pack_bin(bp, event->filename, event->filename_length);
}

non_null()
static bool tox_event_file_recv_unpack(
    Tox_Event_File_Recv *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 5)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u32(bu, &event->kind)
           && bin_unpack_u64(bu, &event->file_size)
           && bin_unpack_bin(bu, &event->filename, &event->filename_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_File_Recv *tox_events_add_file_recv(Tox_Events *events)
{
    if (events->file_recv_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->file_recv_size == events->file_recv_capacity) {
        const uint32_t new_file_recv_capacity = events->file_recv_capacity * 2 + 1;
        Tox_Event_File_Recv *new_file_recv = (Tox_Event_File_Recv *)realloc(
                events->file_recv, new_file_recv_capacity * sizeof(Tox_Event_File_Recv));

        if (new_file_recv == nullptr) {
            return nullptr;
        }

        events->file_recv = new_file_recv;
        events->file_recv_capacity = new_file_recv_capacity;
    }

    Tox_Event_File_Recv *const file_recv = &events->file_recv[events->file_recv_size];
    tox_event_file_recv_construct(file_recv);
    ++events->file_recv_size;
    return file_recv;
}

void tox_events_clear_file_recv(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->file_recv_size; ++i) {
        tox_event_file_recv_destruct(&events->file_recv[i]);
    }

    free(events->file_recv);
    events->file_recv = nullptr;
    events->file_recv_size = 0;
    events->file_recv_capacity = 0;
}

uint32_t tox_events_get_file_recv_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->file_recv_size;
}

const Tox_Event_File_Recv *tox_events_get_file_recv(const Tox_Events *events, uint32_t index)
{
    assert(index < events->file_recv_size);
    assert(events->file_recv != nullptr);
    return &events->file_recv[index];
}

bool tox_events_pack_file_recv(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_file_recv_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_file_recv_pack(tox_events_get_file_recv(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_file_recv(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_File_Recv *event = tox_events_add_file_recv(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_file_recv_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind,
                                 uint64_t file_size, const uint8_t *filename, size_t filename_length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_File_Recv *file_recv = tox_events_add_file_recv(state->events);

    if (file_recv == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_file_recv_set_friend_number(file_recv, friend_number);
    tox_event_file_recv_set_file_number(file_recv, file_number);
    tox_event_file_recv_set_kind(file_recv, kind);
    tox_event_file_recv_set_file_size(file_recv, file_size);
    tox_event_file_recv_set_filename(file_recv, filename, filename_length);
}
