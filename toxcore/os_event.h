/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_EVENT_H
#define C_TOXCORE_TOXCORE_OS_EVENT_H

#include "ev.h"
#include "logger.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Create a new system-specific event loop (epoll/poll/select). */
Ev *_Nullable os_event_new(const Memory *_Nonnull mem, const Logger *_Nullable log);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_EVENT_H */
