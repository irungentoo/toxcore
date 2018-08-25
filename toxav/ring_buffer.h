/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 * This file is donated to the Tox Project.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ring buffer */
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
}
#endif

#endif /* RING_BUFFER_H */
