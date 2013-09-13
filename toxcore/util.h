/*
 * util.h -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#ifndef __UTIL_H__
#define __UTIL_H__

uint64_t now();
uint64_t random_64b();
bool ipp_eq(IP_Port a, IP_Port b);
bool id_eq(uint8_t *dest, uint8_t *src);
void id_cpy(uint8_t *dest, uint8_t *src);

typedef uint16_t state_length_sub_t;
typedef int (*load_state_callback_func)(void *outer, uint8_t *data, uint32_t len, uint16_t type);
int load_state(load_state_callback_func load_state_callback, void *outer,
                        uint8_t *data, uint32_t length, uint16_t cookie_inner);

#endif /* __UTIL_H__ */
