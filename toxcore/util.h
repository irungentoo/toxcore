/*
 * util.h -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define POWER_OF_2(x) (((x) != 0) && (((x) & ((~(x)) + 1)) == (x)))

/* Enlarges static buffers returned by id_toa and ip_ntoa so that
 * they can be used multiple times in same output
 */
#define STATIC_BUFFER_COPIES    10
#define STATIC_BUFFER_DEFINE(name,len)  static char stat_buffer_##name[(len)*STATIC_BUFFER_COPIES]; \
                                        static unsigned stat_buffer_counter_##name=0;
#define STATIC_BUFFER_GETBUF(name,len)  (&stat_buffer_##name[(len)*(stat_buffer_counter_##name++%STATIC_BUFFER_COPIES)])

/* Macros for groupchat extended keys */
#define ENC_KEY(key) (key)
#define SIG_PK(key) (key + ENC_PUBLIC_KEY)
#define SIG_SK(key) (key + ENC_SECRET_KEY)
#define CHAT_ID(key) (key + ENC_PUBLIC_KEY)


void unix_time_update();
uint64_t unix_time();
int is_timeout(uint64_t timestamp, uint64_t timeout);


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);

/* compares two group chat_id's */
bool chat_id_equal(const uint8_t *dest, const uint8_t *src);

uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */

// For printing purposes
char *id_toa(const uint8_t *id);

void host_to_net(uint8_t *num, uint16_t numbytes);
#define net_to_host(x, y) host_to_net(x, y)

uint16_t lendian_to_host16(uint16_t lendian);
#define host_tolendian16(x) lendian_to_host16(x)

void host_to_lendian32(uint8_t *dest,  uint32_t num);

/* state load/save */
typedef int (*load_state_callback_func)(void *outer, const uint8_t *data, uint32_t len, uint16_t type);
int load_state(load_state_callback_func load_state_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

/* frees all pointers in a uint8_t pointer array, as well as the array itself. */
void free_uint8_t_pointer_array(uint8_t **ary, size_t n_items);

/* Converts 8 bytes to uint64_t */
void bytes_to_U64(uint64_t *dest, const uint8_t *bytes);

/* Converts 4 bytes to uint32_t */
void bytes_to_U32(uint32_t *dest, const uint8_t *bytes);

/* Converts 2 bytes to uint16_t */
void bytes_to_U16(uint16_t *dest, const uint8_t *bytes);

/* Convert uint64_t to byte string of size 8 */
void U64_to_bytes(uint8_t *dest, uint64_t value);

/* Convert uint32_t to byte string of size 4 */
void U32_to_bytes(uint8_t *dest, uint32_t value);

/* Convert uint16_t to byte string of size 2 */
void U16_to_bytes(uint8_t *dest, uint16_t value);

int create_recursive_mutex(pthread_mutex_t *mutex);

/* Returns a 32-bit hash of key of size len */
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len);

#endif /* UTIL_H */
