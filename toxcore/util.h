/*
 * util.h -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdbool.h>
#include <stdint.h>

uint64_t random_64b();

void unix_time_update();
uint64_t unix_time();
int is_timeout(uint64_t timestamp, uint64_t timeout);


/* id functions */
bool id_equal(uint8_t *dest, uint8_t *src);
uint32_t id_copy(uint8_t *dest, uint8_t *src); /* return value is CLIENT_ID_SIZE */


/* state load/save */
typedef int (*load_state_callback_func)(void *outer, uint8_t *data, uint32_t len, uint16_t type);
int load_state(load_state_callback_func load_state_callback, void *outer,
               uint8_t *data, uint32_t length, uint16_t cookie_inner);

#ifdef LOGGING
extern char logbuffer[512];
void loginit(uint16_t port);
void loglog(char *text);
void logexit();
#endif

#endif /* __UTIL_H__ */
