%{
/*
 * Implementation of an efficient array to store that we pinged something.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
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
#ifndef PING_ARRAY_H
#define PING_ARRAY_H

#include "network.h"
%}

class ping_Array {

struct this;

/**
 * Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static this new(uint32_t size, uint32_t timeout);

/**
 * Free all the allocated memory in a Ping_Array.
 */
void kill();

/**
 * Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t add(const uint8_t *data, uint32_t length);

/**
 * Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int32_t check(uint8_t[length] data, uint64_t ping_id);

}

%{
#endif
%}
