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

/* Enlarges static buffers returned by id_toa and ip_ntoa so that
 * they can be used multiple times in same output
 */
#define STATIC_BUFFER_COPIES    10
#define STATIC_BUFFER_DEFINE(name,len)  static char stat_buffer_##name[(len)*STATIC_BUFFER_COPIES]; \
                                        static unsigned stat_buffer_counter_##name=0;
#define STATIC_BUFFER_GETBUF(name,len)  (&stat_buffer_##name[(len)*(stat_buffer_counter_##name++%STATIC_BUFFER_COPIES)])

#define inline__ inline __attribute__((always_inline))

void unix_time_update();
uint64_t unix_time();
int is_timeout(uint64_t timestamp, uint64_t timeout);


enum id_key_t { ID_ALL_KEYS=0, ID_ENCRYPTION_KEY, ID_SIGNATURE_KEY };

/* conventional id functions */
bool id_equal(const uint8_t *dest, const uint8_t *src);
uint32_t id_copy(uint8_t *dest, const uint8_t *src); /* return value is CLIENT_ID_SIZE */
char* id_toa(const uint8_t* id);  /* WARNING: returns one of STATIC_BUFFER_COPIES static buffers */

/* extended id functions */
bool id_equal2(const uint8_t *dest, const uint8_t *src, const enum id_key_t keytype);
uint32_t id_copy2(uint8_t *dest, const uint8_t *src, const enum id_key_t keytype);
char* id_toa2(const uint8_t* id, const enum id_key_t keytype);

void id_tocolor(const uint8_t* id, uint8_t color[3]); /* Non-extended version so far */

void host_to_net(uint8_t *num, uint16_t numbytes);
#define net_to_host(x, y) host_to_net(x, y)

/* state load/save */
typedef int (*load_state_callback_func)(void *outer, const uint8_t *data, uint32_t len, uint16_t type);
int load_state(load_state_callback_func load_state_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

/* Converts 8 bytes to uint64_t */
void bytes_to_U64(uint64_t *dest, const uint8_t *bytes);

/* Converts 4 bytes to uint32_t */
void bytes_to_U32(uint32_t *dest, const uint8_t *bytes);

/* Converts 2 bytes to uint16_t */
void bytes_to_U16(uint16_t *dest, const uint8_t *bytes);

/* Converts uint64_t to byte string of size 8 */
void U64_to_bytes(uint8_t *dest, uint64_t value);

/* Convert uint32_t to byte string of size 4 */
void U32_to_bytes(uint8_t *dest, uint32_t value);

/* Convert uint16_t to byte string of size 2 */
void U16_to_bytes(uint8_t *dest, uint16_t value);

/* Easy packet construction utilities */
#define PAK_DEF(packet) struct __PACKET_##packet
#define PAK_ITM(name, len) uint8_t name[len]
 
#define PAK_LEN(packet) sizeof(struct __PACKET_##packet)
#define PAK_POS(packet, member) offsetof(struct __PACKET_##packet, member)
#define PAK_GET(packet, buf, member) buf[packetpos(packet, member)] // probably unnecessary
#define PAK(packet, buf) ((struct __PACKET_##packet*)buf)

/* Example:
 * 
 * PAK_DEF(testcat)
 * {
 *      PAK_ITM(type, 1);
 *      PAK_ITM(timestamp, sizeof(uint64_t));
 *      PAK_ITM(public_key, 32);
 * };
 * 
 * PAK_LEN(testcat) == total length of the packet
 * PAK_POS(testcat, timestamp) == shift of timestamp member in bytes
 * PAK_GET(testcat, public_key, someobj) == pointer to public key member in a packet referenced by someobj
 * PAK(testcat, someobj)->type;
 */


#endif /* __UTIL_H__ */
