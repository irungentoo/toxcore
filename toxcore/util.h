/*
 * Utilities.
 */

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
#ifndef C_TOXCORE_TOXCORE_UTIL_H
#define C_TOXCORE_TOXCORE_UTIL_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);
uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */

void host_to_net(uint8_t *num, uint16_t numbytes);
void net_to_host(uint8_t *num, uint16_t numbytes);

/* Returns -1 if failed or 0 if success */
int create_recursive_mutex(pthread_mutex_t *mutex);

int32_t max_s32(int32_t a, int32_t b);
int32_t min_s32(int32_t a, int32_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_UTIL_H
