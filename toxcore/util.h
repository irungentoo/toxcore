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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdbool.h>
#include <stdint.h>

#define inline__ inline __attribute__((always_inline))

/* Enlarges static buffers returned by id_toa and ip_ntoa so that
 * they can be used multiple times in same output
 */
#define STATIC_BUFFER_COPIES    10
#define STATIC_BUFFER_DEFINE(name,len)  static char stat_buffer_##name[(len)*STATIC_BUFFER_COPIES]; \
                                        static unsigned stat_buffer_counter_##name=0;
#define STATIC_BUFFER_GETBUF(name,len)  (&stat_buffer_##name[(len)*(stat_buffer_counter_##name++%STATIC_BUFFER_COPIES)])

// Macroses for long keys and cert handle
#define ENC_KEY(key) (key)
#define SIG_KEY(key) (key+ENC_PUBLIC_KEY) // Don't forget, that public and secert could be different in the future
#define CERT_SOURCE_KEY(cert) (cert + 1 + EXT_PUBLIC_KEY)
#define CERT_TARGET_KEY(cert) (cert + 1)
#define CERT_INVITER_KEY(cert) (cert + SEMI_INVITE_CERTIFICATE_SIGNED_SIZE)
#define CERT_INVITEE_KEY(cert) (cert + 1)

void unix_time_update();
uint64_t unix_time();
int is_timeout(uint64_t timestamp, uint64_t timeout);


/* id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);
bool id_long_equal(const uint8_t *dest, const uint8_t *src);
uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */

// For printing purposes
char *id_toa(const uint8_t *id);

void host_to_net(uint8_t *num, uint16_t numbytes);
#define net_to_host(x, y) host_to_net(x, y)

/* state load/save */
typedef int (*load_state_callback_func)(void *outer, const uint8_t *data, uint32_t len, uint16_t type);
int load_state(load_state_callback_func load_state_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

/* Converts 4 bytes to uint32_t */
void bytes_to_U32(uint32_t *dest, const uint8_t *bytes);

/* Converts 2 bytes to uint16_t */
void bytes_to_U16(uint16_t *dest, const uint8_t *bytes);

/* Convert uint32_t to byte string of size 4 */
void U32_to_bytes(uint8_t *dest, uint32_t value);

/* Convert uint16_t to byte string of size 2 */
void U16_to_bytes(uint8_t *dest, uint16_t value);


#endif /* __UTIL_H__ */
