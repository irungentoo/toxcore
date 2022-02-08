/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_events.h"

#include <msgpack.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "events/events_alloc.h"
#include "tox.h"


/*****************************************************
 *
 * :: Set up event handlers.
 *
 *****************************************************/


void tox_events_init(Tox *tox)
{
    tox_callback_conference_connected(tox, tox_events_handle_conference_connected);
    tox_callback_conference_invite(tox, tox_events_handle_conference_invite);
    tox_callback_conference_message(tox, tox_events_handle_conference_message);
    tox_callback_conference_peer_list_changed(tox, tox_events_handle_conference_peer_list_changed);
    tox_callback_conference_peer_name(tox, tox_events_handle_conference_peer_name);
    tox_callback_conference_title(tox, tox_events_handle_conference_title);
    tox_callback_file_chunk_request(tox, tox_events_handle_file_chunk_request);
    tox_callback_file_recv_chunk(tox, tox_events_handle_file_recv_chunk);
    tox_callback_file_recv_control(tox, tox_events_handle_file_recv_control);
    tox_callback_file_recv(tox, tox_events_handle_file_recv);
    tox_callback_friend_connection_status(tox, tox_events_handle_friend_connection_status);
    tox_callback_friend_lossless_packet(tox, tox_events_handle_friend_lossless_packet);
    tox_callback_friend_lossy_packet(tox, tox_events_handle_friend_lossy_packet);
    tox_callback_friend_message(tox, tox_events_handle_friend_message);
    tox_callback_friend_name(tox, tox_events_handle_friend_name);
    tox_callback_friend_read_receipt(tox, tox_events_handle_friend_read_receipt);
    tox_callback_friend_request(tox, tox_events_handle_friend_request);
    tox_callback_friend_status_message(tox, tox_events_handle_friend_status_message);
    tox_callback_friend_status(tox, tox_events_handle_friend_status);
    tox_callback_friend_typing(tox, tox_events_handle_friend_typing);
    tox_callback_self_connection_status(tox, tox_events_handle_self_connection_status);
}

Tox_Events *tox_events_iterate(Tox *tox, Tox_Err_Events_Iterate *error)
{
    Tox_Events_State state = {TOX_ERR_EVENTS_ITERATE_OK};
    tox_iterate(tox, &state);

    if (error != nullptr) {
        *error = state.error;
    }

    return state.events;
}

void tox_events_pack(const Tox_Events *events, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 21);
    tox_events_pack_conference_connected(events, mp);
    tox_events_pack_conference_invite(events, mp);
    tox_events_pack_conference_message(events, mp);
    tox_events_pack_conference_peer_list_changed(events, mp);
    tox_events_pack_conference_peer_name(events, mp);
    tox_events_pack_conference_title(events, mp);
    tox_events_pack_file_chunk_request(events, mp);
    tox_events_pack_file_recv_chunk(events, mp);
    tox_events_pack_file_recv_control(events, mp);
    tox_events_pack_file_recv(events, mp);
    tox_events_pack_friend_connection_status(events, mp);
    tox_events_pack_friend_lossless_packet(events, mp);
    tox_events_pack_friend_lossy_packet(events, mp);
    tox_events_pack_friend_message(events, mp);
    tox_events_pack_friend_name(events, mp);
    tox_events_pack_friend_read_receipt(events, mp);
    tox_events_pack_friend_request(events, mp);
    tox_events_pack_friend_status_message(events, mp);
    tox_events_pack_friend_status(events, mp);
    tox_events_pack_friend_typing(events, mp);
    tox_events_pack_self_connection_status(events, mp);
}

bool tox_events_unpack(Tox_Events *events, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 21) {
        return false;
    }

    return tox_events_unpack_conference_connected(events,            &obj->via.array.ptr[0])
           && tox_events_unpack_conference_invite(events,            &obj->via.array.ptr[1])
           && tox_events_unpack_conference_message(events,           &obj->via.array.ptr[2])
           && tox_events_unpack_conference_peer_list_changed(events, &obj->via.array.ptr[3])
           && tox_events_unpack_conference_peer_name(events,         &obj->via.array.ptr[4])
           && tox_events_unpack_conference_title(events,             &obj->via.array.ptr[5])
           && tox_events_unpack_file_chunk_request(events,           &obj->via.array.ptr[6])
           && tox_events_unpack_file_recv_chunk(events,              &obj->via.array.ptr[7])
           && tox_events_unpack_file_recv_control(events,            &obj->via.array.ptr[8])
           && tox_events_unpack_file_recv(events,                    &obj->via.array.ptr[9])
           && tox_events_unpack_friend_connection_status(events,     &obj->via.array.ptr[10])
           && tox_events_unpack_friend_lossless_packet(events,       &obj->via.array.ptr[11])
           && tox_events_unpack_friend_lossy_packet(events,          &obj->via.array.ptr[12])
           && tox_events_unpack_friend_message(events,               &obj->via.array.ptr[13])
           && tox_events_unpack_friend_name(events,                  &obj->via.array.ptr[14])
           && tox_events_unpack_friend_read_receipt(events,          &obj->via.array.ptr[15])
           && tox_events_unpack_friend_request(events,               &obj->via.array.ptr[16])
           && tox_events_unpack_friend_status_message(events,        &obj->via.array.ptr[17])
           && tox_events_unpack_friend_status(events,                &obj->via.array.ptr[18])
           && tox_events_unpack_friend_typing(events,                &obj->via.array.ptr[19])
           && tox_events_unpack_self_connection_status(events,       &obj->via.array.ptr[20]);
}

non_null()
static int count_bytes(void *data, const char *buf, size_t len)
{
    uint32_t *count = (uint32_t *)data;
    assert(count != nullptr);
    *count += len;
    return 0;
}

uint32_t tox_events_bytes_size(const Tox_Events *events)
{
    uint32_t count = 0;
    msgpack_packer mp;
    msgpack_packer_init(&mp, &count, count_bytes);
    tox_events_pack(events, &mp);
    return count;
}

non_null()
static int write_bytes(void *data, const char *buf, size_t len)
{
    uint8_t **bytes = (uint8_t **)data;
    assert(bytes != nullptr && *bytes != nullptr);
    memcpy(*bytes, buf, len);
    *bytes += len;
    return 0;
}

void tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes)
{
    msgpack_packer mp;
    msgpack_packer_init(&mp, &bytes, write_bytes);
    tox_events_pack(events, &mp);
}

Tox_Events *tox_events_load(const uint8_t *bytes, uint32_t bytes_size)
{
    msgpack_unpacked msg;

    size_t offset = 0;
    msgpack_unpacked_init(&msg);
    const msgpack_unpack_return result = msgpack_unpack_next(&msg, (const char *)bytes, bytes_size, &offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&msg);
        return nullptr;
    }

    Tox_Events *events = (Tox_Events *)calloc(1, sizeof(Tox_Events));

    if (events == nullptr) {
        msgpack_unpacked_destroy(&msg);
        return nullptr;
    }

    *events = (Tox_Events) {
        nullptr
    };

    if (!tox_events_unpack(events, &msg.data)) {
        tox_events_free(events);
        msgpack_unpacked_destroy(&msg);
        return nullptr;
    }

    msgpack_unpacked_destroy(&msg);
    return events;
}

non_null(2, 3) nullable(1)
static bool tox_events_to_object(const Tox_Events *events, msgpack_unpacked *msg, msgpack_sbuffer *sbuf)
{
    msgpack_sbuffer_init(sbuf);
    msgpack_packer mp;
    msgpack_packer_init(&mp, sbuf, msgpack_sbuffer_write);

    tox_events_pack(events, &mp);

    size_t offset = 0;
    msgpack_unpacked_init(msg);
    const msgpack_unpack_return result = msgpack_unpack_next(msg, sbuf->data, sbuf->size, &offset);

    return result == MSGPACK_UNPACK_SUCCESS;
}

void tox_events_print(const Tox_Events *events)
{
    msgpack_sbuffer sbuf;
    msgpack_unpacked msg;
    tox_events_to_object(events, &msg, &sbuf);
    msgpack_object_print(stdout, msg.data);
    fputc('\n', stdout);
    msgpack_unpacked_destroy(&msg);
    msgpack_sbuffer_destroy(&sbuf);
}

bool tox_events_equal(const Tox_Events *a, const Tox_Events *b)
{
    msgpack_sbuffer sbuf_a = {0};
    msgpack_unpacked msg_a = {nullptr};
    msgpack_sbuffer sbuf_b = {0};
    msgpack_unpacked msg_b = {nullptr};

    const bool success = tox_events_to_object(a, &msg_a, &sbuf_a)
                         && tox_events_to_object(b, &msg_b, &sbuf_b);

    const bool ret = success && msgpack_object_equal(msg_a.data, msg_b.data);

    msgpack_unpacked_destroy(&msg_b);
    msgpack_sbuffer_destroy(&sbuf_a);
    msgpack_unpacked_destroy(&msg_a);
    msgpack_sbuffer_destroy(&sbuf_b);

    return ret;
}
