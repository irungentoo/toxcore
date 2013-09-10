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

uint64_t now();
uint64_t random_64b();
bool id_eq(uint8_t *dest, uint8_t *src);
void id_cpy(uint8_t *dest, uint8_t *src);

#undef LOGGING
// #define LOGGING
#ifdef LOGGING
extern char logbuffer[512];
void loginit(uint16_t port);
void loglog(char *text);
void logexit();
#endif

#endif /* __UTIL_H__ */
