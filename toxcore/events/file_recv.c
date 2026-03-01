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

struct Tox_Event_File_Recv {
    uint32_t friend_number;
    uint32_t file_number;
    uint32_t kind;
    uint64_t file_size;
    uint8_t *_Nullable filename;
    uint32_t filename_length;
};

static void tox_event_file_recv_set_friend_number(Tox_Event_File_Recv *_Nonnull file_recv, uint32_t friend_number)
{
    assert(file_recv != nullptr);
    file_recv->friend_number = friend_number;
}
uint32_t tox_event_file_recv_get_friend_number(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->friend_number;
}

static void tox_event_file_recv_set_file_number(Tox_Event_File_Recv *_Nonnull file_recv, uint32_t file_number)
{
    assert(file_recv != nullptr);
    file_recv->file_number = file_number;
}
uint32_t tox_event_file_recv_get_file_number(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->file_number;
}

static void tox_event_file_recv_set_kind(Tox_Event_File_Recv *_Nonnull file_recv, uint32_t kind)
{
    assert(file_recv != nullptr);
    file_recv->kind = kind;
}
uint32_t tox_event_file_recv_get_kind(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->kind;
}

static void tox_event_file_recv_set_file_size(Tox_Event_File_Recv *_Nonnull file_recv, uint64_t file_size)
{
    assert(file_recv != nullptr);
    file_recv->file_size = file_size;
}
uint64_t tox_event_file_recv_get_file_size(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->file_size;
}

static bool tox_event_file_recv_set_filename(Tox_Event_File_Recv *_Nonnull file_recv,
        const Memory *_Nonnull mem, const uint8_t *_Nullable filename, uint32_t filename_length)
{
    assert(file_recv != nullptr);
    if (file_recv->filename != nullptr) {
        mem_delete(mem, file_recv->filename);
        file_recv->filename = nullptr;
        file_recv->filename_length = 0;
    }

    if (filename == nullptr) {
        assert(filename_length == 0);
        return true;
    }

    if (filename_length == 0) {
        file_recv->filename = nullptr;
        file_recv->filename_length = 0;
        return true;
    }

    uint8_t *filename_copy = (uint8_t *)mem_balloc(mem, filename_length);

    if (filename_copy == nullptr) {
        return false;
    }

    memcpy(filename_copy, filename, filename_length);
    file_recv->filename = filename_copy;
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

static void tox_event_file_recv_construct(Tox_Event_File_Recv *_Nonnull file_recv)
{
    *file_recv = (Tox_Event_File_Recv) {
        0
    };
}
static void tox_event_file_recv_destruct(Tox_Event_File_Recv *_Nonnull file_recv, const Memory *_Nonnull mem)
{
    mem_delete(mem, file_recv->filename);
}

bool tox_event_file_recv_pack(
    const Tox_Event_File_Recv *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 5)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u32(bp, event->kind)
           && bin_pack_u64(bp, event->file_size)
           && bin_pack_bin(bp, event->filename, event->filename_length);
}

static bool tox_event_file_recv_unpack_into(Tox_Event_File_Recv *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 5, nullptr)) {
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
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_File_Recv *tox_event_get_file_recv(const Tox_Event *event)
{
    return event->type == TOX_EVENT_FILE_RECV ? event->data.file_recv : nullptr;
}

Tox_Event_File_Recv *tox_event_file_recv_new(const Memory *mem)
{
    Tox_Event_File_Recv *const file_recv =
        (Tox_Event_File_Recv *)mem_alloc(mem, sizeof(Tox_Event_File_Recv));

    if (file_recv == nullptr) {
        return nullptr;
    }

    tox_event_file_recv_construct(file_recv);
    return file_recv;
}

void tox_event_file_recv_free(Tox_Event_File_Recv *file_recv, const Memory *mem)
{
    if (file_recv != nullptr) {
        tox_event_file_recv_destruct(file_recv, mem);
    }
    mem_delete(mem, file_recv);
}

static Tox_Event_File_Recv *_Nullable tox_events_add_file_recv(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_File_Recv *const file_recv = tox_event_file_recv_new(mem);

    if (file_recv == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_FILE_RECV;
    event.data.file_recv = file_recv;

    if (!tox_events_add(events, &event)) {
        tox_event_file_recv_free(file_recv, mem);
        return nullptr;
    }
    return file_recv;
}

bool tox_event_file_recv_unpack(
    Tox_Event_File_Recv **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_file_recv_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_file_recv_unpack_into(*event, bu);
}

static Tox_Event_File_Recv *_Nullable tox_event_file_recv_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_File_Recv *file_recv = tox_events_add_file_recv(state->events, state->mem);

    if (file_recv == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return file_recv;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_file_recv(
    Tox *_Nonnull tox,
    uint32_t friend_number,
    uint32_t file_number,
    uint32_t kind,
    uint64_t file_size,
    const uint8_t *_Nullable filename, size_t filename_length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_File_Recv *file_recv = tox_event_file_recv_alloc(state);

    if (file_recv == nullptr) {
        return;
    }

    tox_event_file_recv_set_friend_number(file_recv, friend_number);
    tox_event_file_recv_set_file_number(file_recv, file_number);
    tox_event_file_recv_set_kind(file_recv, kind);
    tox_event_file_recv_set_file_size(file_recv, file_size);
    if (!tox_event_file_recv_set_filename(file_recv, state->mem, filename, filename_length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_file_recv_dispatch(Tox *tox, const Tox_Event_File_Recv *event, void *user_data)
{
    if (tox->file_recv_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->file_recv_callback(tox, event->friend_number, event->file_number, event->kind, event->file_size, event->filename, event->filename_length, user_data);
    tox_lock(tox);
}
