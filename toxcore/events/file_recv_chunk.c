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

struct Tox_Event_File_Recv_Chunk {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    uint8_t *data;
    uint32_t data_length;
};

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

non_null(1) nullable(2)
static bool tox_event_file_recv_chunk_set_data(Tox_Event_File_Recv_Chunk *file_recv_chunk,
        const uint8_t *data, uint32_t data_length)
{
    assert(file_recv_chunk != nullptr);

    if (file_recv_chunk->data != nullptr) {
        free(file_recv_chunk->data);
        file_recv_chunk->data = nullptr;
        file_recv_chunk->data_length = 0;
    }

    if (data == nullptr) {
        assert(data_length == 0);
        return true;
    }

    uint8_t *data_copy = (uint8_t *)malloc(data_length);

    if (data_copy == nullptr) {
        return false;
    }

    memcpy(data_copy, data, data_length);
    file_recv_chunk->data = data_copy;
    file_recv_chunk->data_length = data_length;
    return true;
}
uint32_t tox_event_file_recv_chunk_get_data_length(const Tox_Event_File_Recv_Chunk *file_recv_chunk)
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
static void tox_event_file_recv_chunk_construct(Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    *file_recv_chunk = (Tox_Event_File_Recv_Chunk) {
        0
    };
}
non_null()
static void tox_event_file_recv_chunk_destruct(Tox_Event_File_Recv_Chunk *file_recv_chunk, const Memory *mem)
{
    free(file_recv_chunk->data);
}

bool tox_event_file_recv_chunk_pack(
    const Tox_Event_File_Recv_Chunk *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u64(bp, event->position)
           && bin_pack_bin(bp, event->data, event->data_length);
}

non_null()
static bool tox_event_file_recv_chunk_unpack_into(
    Tox_Event_File_Recv_Chunk *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u64(bu, &event->position)
           && bin_unpack_bin(bu, &event->data, &event->data_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_File_Recv_Chunk *tox_event_get_file_recv_chunk(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FILE_RECV_CHUNK ? event->data.file_recv_chunk : nullptr;
}

Tox_Event_File_Recv_Chunk *tox_event_file_recv_chunk_new(const Memory *mem)
{
    Tox_Event_File_Recv_Chunk *const file_recv_chunk =
        (Tox_Event_File_Recv_Chunk *)mem_alloc(mem, sizeof(Tox_Event_File_Recv_Chunk));

    if (file_recv_chunk == nullptr) {
        return nullptr;
    }

    tox_event_file_recv_chunk_construct(file_recv_chunk);
    return file_recv_chunk;
}

void tox_event_file_recv_chunk_free(Tox_Event_File_Recv_Chunk *file_recv_chunk, const Memory *mem)
{
    if (file_recv_chunk != nullptr) {
        tox_event_file_recv_chunk_destruct(file_recv_chunk, mem);
    }
    mem_delete(mem, file_recv_chunk);
}

non_null()
static Tox_Event_File_Recv_Chunk *tox_events_add_file_recv_chunk(Tox_Events *events, const Memory *mem)
{
    Tox_Event_File_Recv_Chunk *const file_recv_chunk = tox_event_file_recv_chunk_new(mem);

    if (file_recv_chunk == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FILE_RECV_CHUNK;
    event.data.file_recv_chunk = file_recv_chunk;

    tox_events_add(events, &event);
    return file_recv_chunk;
}

bool tox_event_file_recv_chunk_unpack(
    Tox_Event_File_Recv_Chunk **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_file_recv_chunk_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_file_recv_chunk_unpack_into(*event, bu);
}

non_null()
static Tox_Event_File_Recv_Chunk *tox_event_file_recv_chunk_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_File_Recv_Chunk *file_recv_chunk = tox_events_add_file_recv_chunk(state->events, state->mem);

    if (file_recv_chunk == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return file_recv_chunk;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_file_recv_chunk(
    Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data, size_t length,
    void *user_data)
{
    Tox_Event_File_Recv_Chunk *file_recv_chunk = tox_event_file_recv_chunk_alloc(user_data);

    if (file_recv_chunk == nullptr) {
        return;
    }

    tox_event_file_recv_chunk_set_friend_number(file_recv_chunk, friend_number);
    tox_event_file_recv_chunk_set_file_number(file_recv_chunk, file_number);
    tox_event_file_recv_chunk_set_position(file_recv_chunk, position);
    tox_event_file_recv_chunk_set_data(file_recv_chunk, data, length);
}
