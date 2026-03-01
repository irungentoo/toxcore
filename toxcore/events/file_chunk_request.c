/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>

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

struct Tox_Event_File_Chunk_Request {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    uint16_t length;
};

static void tox_event_file_chunk_request_set_friend_number(Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request, uint32_t friend_number)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->friend_number = friend_number;
}
uint32_t tox_event_file_chunk_request_get_friend_number(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->friend_number;
}

static void tox_event_file_chunk_request_set_file_number(Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request, uint32_t file_number)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->file_number = file_number;
}
uint32_t tox_event_file_chunk_request_get_file_number(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->file_number;
}

static void tox_event_file_chunk_request_set_position(Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request, uint64_t position)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->position = position;
}
uint64_t tox_event_file_chunk_request_get_position(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->position;
}

static void tox_event_file_chunk_request_set_length(Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request, uint16_t length)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->length = length;
}
uint16_t tox_event_file_chunk_request_get_length(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->length;
}

static void tox_event_file_chunk_request_construct(Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request)
{
    *file_chunk_request = (Tox_Event_File_Chunk_Request) {
        0
    };
}
static void tox_event_file_chunk_request_destruct(Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request, const Memory *_Nonnull mem)
{
    return;
}

bool tox_event_file_chunk_request_pack(
    const Tox_Event_File_Chunk_Request *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u64(bp, event->position)
           && bin_pack_u16(bp, event->length);
}

static bool tox_event_file_chunk_request_unpack_into(Tox_Event_File_Chunk_Request *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u64(bu, &event->position)
           && bin_unpack_u16(bu, &event->length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_File_Chunk_Request *tox_event_get_file_chunk_request(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FILE_CHUNK_REQUEST ? event->data.file_chunk_request : nullptr;
}

Tox_Event_File_Chunk_Request *tox_event_file_chunk_request_new(const Memory *mem)
{
    Tox_Event_File_Chunk_Request *const file_chunk_request =
        (Tox_Event_File_Chunk_Request *)mem_alloc(mem, sizeof(Tox_Event_File_Chunk_Request));

    if (file_chunk_request == nullptr) {
        return nullptr;
    }

    tox_event_file_chunk_request_construct(file_chunk_request);
    return file_chunk_request;
}

void tox_event_file_chunk_request_free(Tox_Event_File_Chunk_Request *file_chunk_request, const Memory *mem)
{
    if (file_chunk_request != nullptr) {
        tox_event_file_chunk_request_destruct(file_chunk_request, mem);
    }
    mem_delete(mem, file_chunk_request);
}

static Tox_Event_File_Chunk_Request *_Nullable tox_events_add_file_chunk_request(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_File_Chunk_Request *const file_chunk_request = tox_event_file_chunk_request_new(mem);

    if (file_chunk_request == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FILE_CHUNK_REQUEST;
    event.data.file_chunk_request = file_chunk_request;

    if (!tox_events_add(events, &event)) {
        tox_event_file_chunk_request_free(file_chunk_request, mem);
        return nullptr;
    }
    return file_chunk_request;
}

bool tox_event_file_chunk_request_unpack(
    Tox_Event_File_Chunk_Request **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_file_chunk_request_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_file_chunk_request_unpack_into(*event, bu);
}

static Tox_Event_File_Chunk_Request *_Nullable tox_event_file_chunk_request_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_File_Chunk_Request *file_chunk_request = tox_events_add_file_chunk_request(state->events, state->mem);

    if (file_chunk_request == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return file_chunk_request;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_file_chunk_request(
    Tox *_Nonnull tox,
    uint32_t friend_number,
    uint32_t file_number,
    uint64_t position,
    size_t length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_File_Chunk_Request *file_chunk_request = tox_event_file_chunk_request_alloc(state);

    if (file_chunk_request == nullptr) {
        return;
    }

    tox_event_file_chunk_request_set_friend_number(file_chunk_request, friend_number);
    tox_event_file_chunk_request_set_file_number(file_chunk_request, file_number);
    tox_event_file_chunk_request_set_position(file_chunk_request, position);
    tox_event_file_chunk_request_set_length(file_chunk_request, length);
}

void tox_events_handle_file_chunk_request_dispatch(Tox *tox, const Tox_Event_File_Chunk_Request *event, void *user_data)
{
    if (tox->file_chunk_request_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->file_chunk_request_callback(tox, event->friend_number, event->file_number, event->position, event->length, user_data);
    tox_lock(tox);
}
