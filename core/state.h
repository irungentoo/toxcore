/* state.h
 *
 *  Here is user self state (status, name, etc.)
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
 *
 */

#ifndef STATE_H
#define STATE_H

#include "friends.h"
#include "connection.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TOX STATE PUBLIC INTERFACE */

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   length must be at least 1 byte
   length is the length of name with the NULL terminator
   return 0 if success
   return -1 if failure */
int set_self_name(uint8_t *name, uint16_t length);

/* get our nickname
   put it in name
   return the length of the name*/
uint16_t get_self_name(uint8_t *name);

/* set our user status
    you are responsible for freeing status after
    returns 0 on success, -1 on failure */
int set_self_userstatus(uint8_t *status, uint16_t length);


/* TOX INITIALIZATION AND MAIN LOOP: */

/* run this at startup
    returns 0 if no connection problems
    returns -1 if there are problems */
int init_tox();

/* the main loop that needs to be run at least 200 times per second */
void process_tox();


/* TOX STATE SAVING AND LOADING FUNCTIONS: */

/*
 *  State consists of:
 * - DHT state data
 * - Friendlist
 */

/* returns the size of the state data (for saving) */
uint32_t tox_state_size();

/* save the state in data (must be allocated memory of size Messenger_size()) */
void save_tox_state(uint8_t *data);

/* load the messenger from data of size length */
int load_tox_state(uint8_t *data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
