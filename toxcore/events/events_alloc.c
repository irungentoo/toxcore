/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>

#include "../ccompat.h"
#include "../mem.h"
#include "../tox_event.h"
#include "../tox_events.h"

Tox_Events_State *tox_events_alloc(void *user_data)
{
    Tox_Events_State *state = (Tox_Events_State *)user_data;
    assert(state != nullptr);
    assert(state->mem != nullptr);

    if (state->events != nullptr) {
        // Already allocated.
        return state;
    }

    Tox_Events *events = (Tox_Events *)mem_alloc(state->mem, sizeof(Tox_Events));

    if (events == nullptr) {
        // It's still null => allocation failed.
        state->events = nullptr;
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return state;
    }

    *events = (Tox_Events) {
        nullptr
    };
    state->events = events;
    state->events->mem = state->mem;

    return state;
}

void tox_events_free(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->events_size; ++i) {
        tox_event_destruct(&events->events[i], events->mem);
    }

    mem_delete(events->mem, events->events);
    mem_delete(events->mem, events);
}

bool tox_events_add(Tox_Events *events, const Tox_Event *event)
{
    if (events->events_size == UINT32_MAX) {
        return false;
    }

    if (events->events_size == events->events_capacity) {
        const uint32_t new_events_capacity = events->events_capacity * 2 + 1;
        Tox_Event *new_events = (Tox_Event *)mem_vrealloc(
                                    events->mem, events->events, new_events_capacity, sizeof(Tox_Event));

        if (new_events == nullptr) {
            return false;
        }

        events->events = new_events;
        events->events_capacity = new_events_capacity;
    }

    events->events[events->events_size] = *event;
    ++events->events_size;

    return true;
}
