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

void unix_time_update();
size_t unix_time();
int is_timeout(size_t timestamp, size_t timeout);


/* id functions */
bool id_equal(size_t *dest, size_t *src);
size_t id_copy(size_t *dest, size_t *src); /* return value is CLIENT_ID_SIZE */

void host_to_net(size_t *num, size_t numbytes);
#define net_to_host(x, y) host_to_net(x, y)

/* state load/save */
typedef int (*load_state_callback_func)(void *outer, size_t *data, size_t len, size_t type);
int load_state(load_state_callback_func load_state_callback, void *outer,
               size_t *data, size_t length, size_t cookie_inner);

#ifdef LOGGING
extern char logbuffer[512];
void loginit(size_t port);
void loglog(char *text);
void logexit();
#endif

#endif /* __UTIL_H__ */
