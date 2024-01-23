/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */
#ifndef C_TOXCORE_TOXAV_RING_BUFFER_H
#define C_TOXCORE_TOXAV_RING_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Ring buffer */
typedef struct RingBuffer RingBuffer;
bool rb_full(const RingBuffer *b);
bool rb_empty(const RingBuffer *b);
void *rb_write(RingBuffer *b, void *p);
bool rb_read(RingBuffer *b, void **p);
RingBuffer *rb_new(int size);
void rb_kill(RingBuffer *b);
uint16_t rb_size(const RingBuffer *b);
uint16_t rb_data(const RingBuffer *b, void **dest);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_RING_BUFFER_H */
