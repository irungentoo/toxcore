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


struct Tox_Event_File_Chunk_Request {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    uint16_t length;
};

non_null()
static void tox_event_file_chunk_request_construct(Tox_Event_File_Chunk_Request *file_chunk_request)
{
    *file_chunk_request = (Tox_Event_File_Chunk_Request) {
        0
    };
}
non_null()
static void tox_event_file_chunk_request_destruct(Tox_Event_File_Chunk_Request *file_chunk_request)
{
    return;
}

non_null()
static void tox_event_file_chunk_request_set_friend_number(Tox_Event_File_Chunk_Request *file_chunk_request,
        uint32_t friend_number)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->friend_number = friend_number;
}
uint32_t tox_event_file_chunk_request_get_friend_number(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->friend_number;
}

non_null()
static void tox_event_file_chunk_request_set_file_number(Tox_Event_File_Chunk_Request *file_chunk_request,
        uint32_t file_number)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->file_number = file_number;
}
uint32_t tox_event_file_chunk_request_get_file_number(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->file_number;
}

non_null()
static void tox_event_file_chunk_request_set_position(Tox_Event_File_Chunk_Request *file_chunk_request,
        uint64_t position)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->position = position;
}
uint64_t tox_event_file_chunk_request_get_position(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->position;
}

non_null()
static void tox_event_file_chunk_request_set_length(Tox_Event_File_Chunk_Request *file_chunk_request, uint16_t length)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->length = length;
}
uint16_t tox_event_file_chunk_request_get_length(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->length;
}

non_null()
static bool tox_event_file_chunk_request_pack(
    const Tox_Event_File_Chunk_Request *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FILE_CHUNK_REQUEST)
           && bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u64(bp, event->position)
           && bin_pack_u16(bp, event->length);
}

non_null()
static bool tox_event_file_chunk_request_unpack(
    Tox_Event_File_Chunk_Request *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u64(bu, &event->position)
           && bin_unpack_u16(bu, &event->length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_File_Chunk_Request *tox_events_add_file_chunk_request(Tox_Events *events)
{
    if (events->file_chunk_request_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->file_chunk_request_size == events->file_chunk_request_capacity) {
        const uint32_t new_file_chunk_request_capacity = events->file_chunk_request_capacity * 2 + 1;
        Tox_Event_File_Chunk_Request *new_file_chunk_request = (Tox_Event_File_Chunk_Request *)realloc(
                    events->file_chunk_request, new_file_chunk_request_capacity * sizeof(Tox_Event_File_Chunk_Request));

        if (new_file_chunk_request == nullptr) {
            return nullptr;
        }

        events->file_chunk_request = new_file_chunk_request;
        events->file_chunk_request_capacity = new_file_chunk_request_capacity;
    }

    Tox_Event_File_Chunk_Request *const file_chunk_request = &events->file_chunk_request[events->file_chunk_request_size];
    tox_event_file_chunk_request_construct(file_chunk_request);
    ++events->file_chunk_request_size;
    return file_chunk_request;
}

void tox_events_clear_file_chunk_request(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->file_chunk_request_size; ++i) {
        tox_event_file_chunk_request_destruct(&events->file_chunk_request[i]);
    }

    free(events->file_chunk_request);
    events->file_chunk_request = nullptr;
    events->file_chunk_request_size = 0;
    events->file_chunk_request_capacity = 0;
}

uint32_t tox_events_get_file_chunk_request_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->file_chunk_request_size;
}

const Tox_Event_File_Chunk_Request *tox_events_get_file_chunk_request(const Tox_Events *events, uint32_t index)
{
    assert(index < events->file_chunk_request_size);
    assert(events->file_chunk_request != nullptr);
    return &events->file_chunk_request[index];
}

bool tox_events_pack_file_chunk_request(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_file_chunk_request_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_file_chunk_request_pack(tox_events_get_file_chunk_request(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_file_chunk_request(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_File_Chunk_Request *event = tox_events_add_file_chunk_request(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_file_chunk_request_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
        size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_File_Chunk_Request *file_chunk_request = tox_events_add_file_chunk_request(state->events);

    if (file_chunk_request == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_file_chunk_request_set_friend_number(file_chunk_request, friend_number);
    tox_event_file_chunk_request_set_file_number(file_chunk_request, file_number);
    tox_event_file_chunk_request_set_position(file_chunk_request, position);
    tox_event_file_chunk_request_set_length(file_chunk_request, length);
}
