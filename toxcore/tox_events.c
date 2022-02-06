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

void tox_events_print(const Tox_Events *events)
{
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    msgpack_packer mp;
    msgpack_packer_init(&mp, &sbuf, msgpack_sbuffer_write);

    tox_events_pack(events, &mp);

    msgpack_zone mempool;
    msgpack_zone_init(&mempool, 2048);

    msgpack_object deserialized;
    msgpack_unpack(sbuf.data, sbuf.size, nullptr, &mempool, &deserialized);
    msgpack_object_print(stdout, deserialized);
    fputc('\n', stdout);

    msgpack_zone_destroy(&mempool);
    msgpack_sbuffer_destroy(&sbuf);
}
