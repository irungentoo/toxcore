/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>

#include "../ccompat.h"

Tox_Events_State *tox_events_alloc(void *user_data)
{
    Tox_Events_State *state = (Tox_Events_State *)user_data;
    assert(state != nullptr);

    if (state->events != nullptr) {
        // Already allocated.
        return state;
    }

    state->events = (Tox_Events *)calloc(1, sizeof(Tox_Events));

    if (state->events == nullptr) {
        // It's still null => allocation failed.
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    } else {
        *state->events = (Tox_Events) {
            nullptr
        };
    }

    return state;
}

void tox_events_free(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    tox_events_clear_conference_connected(events);
    tox_events_clear_conference_invite(events);
    tox_events_clear_conference_message(events);
    tox_events_clear_conference_peer_list_changed(events);
    tox_events_clear_conference_peer_name(events);
    tox_events_clear_conference_title(events);
    tox_events_clear_file_chunk_request(events);
    tox_events_clear_file_recv_chunk(events);
    tox_events_clear_file_recv_control(events);
    tox_events_clear_file_recv(events);
    tox_events_clear_friend_connection_status(events);
    tox_events_clear_friend_lossless_packet(events);
    tox_events_clear_friend_lossy_packet(events);
    tox_events_clear_friend_message(events);
    tox_events_clear_friend_name(events);
    tox_events_clear_friend_read_receipt(events);
    tox_events_clear_friend_request(events);
    tox_events_clear_friend_status(events);
    tox_events_clear_friend_status_message(events);
    tox_events_clear_friend_typing(events);
    tox_events_clear_self_connection_status(events);
    free(events);
}
