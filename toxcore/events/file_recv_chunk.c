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


struct Tox_Event_File_Recv_Chunk {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    uint8_t *data;
    size_t data_length;
};

non_null()
static void tox_event_file_recv_chunk_construct(Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    *file_recv_chunk = (Tox_Event_File_Recv_Chunk) {
        0
    };
}
non_null()
static void tox_event_file_recv_chunk_destruct(Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    free(file_recv_chunk->data);
}

non_null()
static void tox_event_file_recv_chunk_set_friend_number(Tox_Event_File_Recv_Chunk *file_recv_chunk,
        uint32_t friend_number)
{
    assert(file_recv_chunk != nullptr);
    file_recv_chunk->friend_number = friend_number;
}
uint32_t tox_event_file_recv_chunk_get_friend_number(const Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    assert(file_recv_chunk != nullptr);
    return file_recv_chunk->friend_number;
}

non_null()
static void tox_event_file_recv_chunk_set_file_number(Tox_Event_File_Recv_Chunk *file_recv_chunk,
        uint32_t file_number)
{
    assert(file_recv_chunk != nullptr);
    file_recv_chunk->file_number = file_number;
}
uint32_t tox_event_file_recv_chunk_get_file_number(const Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    assert(file_recv_chunk != nullptr);
    return file_recv_chunk->file_number;
}

non_null()
static void tox_event_file_recv_chunk_set_position(Tox_Event_File_Recv_Chunk *file_recv_chunk,
        uint64_t position)
{
    assert(file_recv_chunk != nullptr);
    file_recv_chunk->position = position;
}
uint64_t tox_event_file_recv_chunk_get_position(const Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    assert(file_recv_chunk != nullptr);
    return file_recv_chunk->position;
}

non_null()
static bool tox_event_file_recv_chunk_set_data(Tox_Event_File_Recv_Chunk *file_recv_chunk, const uint8_t *data,
        size_t data_length)
{
    assert(file_recv_chunk != nullptr);

    if (file_recv_chunk->data != nullptr) {
        free(file_recv_chunk->data);
        file_recv_chunk->data = nullptr;
        file_recv_chunk->data_length = 0;
    }

    file_recv_chunk->data = (uint8_t *)malloc(data_length);

    if (file_recv_chunk->data == nullptr) {
        return false;
    }

    memcpy(file_recv_chunk->data, data, data_length);
    file_recv_chunk->data_length = data_length;
    return true;
}
size_t tox_event_file_recv_chunk_get_length(const Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    assert(file_recv_chunk != nullptr);
    return file_recv_chunk->data_length;
}
const uint8_t *tox_event_file_recv_chunk_get_data(const Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    assert(file_recv_chunk != nullptr);
    return file_recv_chunk->data;
}

non_null()
static void tox_event_file_recv_chunk_pack(
    const Tox_Event_File_Recv_Chunk *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    bin_pack_array(mp, 2);
    bin_pack_u32(mp, TOX_EVENT_FILE_RECV_CHUNK);
    bin_pack_array(mp, 4);
    bin_pack_u32(mp, event->friend_number);
    bin_pack_u32(mp, event->file_number);
    bin_pack_u64(mp, event->position);
    bin_pack_bytes(mp, event->data, event->data_length);
}

non_null()
static bool tox_event_file_recv_chunk_unpack(
    Tox_Event_File_Recv_Chunk *event, const msgpack_object *obj)
{
    assert(event != nullptr);

    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 4) {
        return false;
    }

    return bin_unpack_u32(&event->friend_number, &obj->via.array.ptr[0])
           && bin_unpack_u32(&event->file_number, &obj->via.array.ptr[1])
           && bin_unpack_u64(&event->position, &obj->via.array.ptr[2])
           && bin_unpack_bytes(&event->data, &event->data_length, &obj->via.array.ptr[3]);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_File_Recv_Chunk *tox_events_add_file_recv_chunk(Tox_Events *events)
{
    if (events->file_recv_chunk_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->file_recv_chunk_size == events->file_recv_chunk_capacity) {
        const uint32_t new_file_recv_chunk_capacity = events->file_recv_chunk_capacity * 2 + 1;
        Tox_Event_File_Recv_Chunk *new_file_recv_chunk = (Tox_Event_File_Recv_Chunk *)realloc(
                    events->file_recv_chunk, new_file_recv_chunk_capacity * sizeof(Tox_Event_File_Recv_Chunk));

        if (new_file_recv_chunk == nullptr) {
            return nullptr;
        }

        events->file_recv_chunk = new_file_recv_chunk;
        events->file_recv_chunk_capacity = new_file_recv_chunk_capacity;
    }

    Tox_Event_File_Recv_Chunk *const file_recv_chunk = &events->file_recv_chunk[events->file_recv_chunk_size];
    tox_event_file_recv_chunk_construct(file_recv_chunk);
    ++events->file_recv_chunk_size;
    return file_recv_chunk;
}

void tox_events_clear_file_recv_chunk(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->file_recv_chunk_size; ++i) {
        tox_event_file_recv_chunk_destruct(&events->file_recv_chunk[i]);
    }

    free(events->file_recv_chunk);
    events->file_recv_chunk = nullptr;
    events->file_recv_chunk_size = 0;
    events->file_recv_chunk_capacity = 0;
}

uint32_t tox_events_get_file_recv_chunk_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->file_recv_chunk_size;
}

const Tox_Event_File_Recv_Chunk *tox_events_get_file_recv_chunk(const Tox_Events *events, uint32_t index)
{
    assert(index < events->file_recv_chunk_size);
    assert(events->file_recv_chunk != nullptr);
    return &events->file_recv_chunk[index];
}

void tox_events_pack_file_recv_chunk(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_file_recv_chunk_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_file_recv_chunk_pack(tox_events_get_file_recv_chunk(events, i), mp);
    }
}

bool tox_events_unpack_file_recv_chunk(Tox_Events *events, const msgpack_object *obj)
{
    Tox_Event_File_Recv_Chunk *event = tox_events_add_file_recv_chunk(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_file_recv_chunk_unpack(event, obj);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                       const uint8_t *data, size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_File_Recv_Chunk *file_recv_chunk = tox_events_add_file_recv_chunk(state->events);

    if (file_recv_chunk == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_file_recv_chunk_set_friend_number(file_recv_chunk, friend_number);
    tox_event_file_recv_chunk_set_file_number(file_recv_chunk, file_number);
    tox_event_file_recv_chunk_set_position(file_recv_chunk, position);
    tox_event_file_recv_chunk_set_data(file_recv_chunk, data, length);
}
