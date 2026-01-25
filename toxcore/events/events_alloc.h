/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H
#define C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H

#include <stdbool.h>
#include <stdint.h>

#include "../attributes.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Memory;

struct Tox_Events {
    Tox_Event *_Nullable events;
    uint32_t events_size;
    uint32_t events_capacity;

    const struct Memory *_Nonnull mem;
};

typedef struct Tox_Events_State {
    Tox_Err_Events_Iterate error;
    const struct Memory *_Nonnull mem;
    Tox_Events *_Nullable events;
} Tox_Events_State;

Tox_Events_State *_Nonnull tox_events_alloc(Tox_Events_State *_Nonnull state);

bool tox_events_add(Tox_Events *_Nonnull events, const Tox_Event *_Nonnull event);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H */
