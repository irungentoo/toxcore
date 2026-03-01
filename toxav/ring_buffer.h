/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */
#ifndef C_TOXCORE_TOXAV_RING_BUFFER_H
#define C_TOXCORE_TOXAV_RING_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

#include "../toxcore/attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Ring buffer */
typedef struct RingBuffer RingBuffer;
bool rb_full(const RingBuffer *_Nonnull b);
bool rb_empty(const RingBuffer *_Nonnull b);
void *_Nullable rb_write(RingBuffer *_Nullable b, void *_Nullable p);
bool rb_read(RingBuffer *_Nonnull b, void *_Nullable *_Nonnull p);
RingBuffer *_Nullable rb_new(int size);
void rb_kill(RingBuffer *_Nullable b);
uint16_t rb_size(const RingBuffer *_Nonnull b);
uint16_t rb_data(const RingBuffer *_Nonnull b, void *_Nonnull *_Nonnull dest, uint16_t dest_size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_RING_BUFFER_H */
