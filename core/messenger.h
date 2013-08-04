/* messenger.h
 *
 * An implementation of a simple text chat only messenger on the tox network core.
 *
 * NOTE: All the text in the messages must be encoded using UTF-8
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

#ifndef MESSENGER_H
#define MESSENGER_H

#include "friends.h"
#include "connection.h"

#ifdef __cplusplus
extern "C" {
#endif

/*  MESSENGER PUBLIC INTERFACE  */

/* send a text chat message to an online friend
    returns 1 if packet was successfully put into the send queue
    return 0 if it was not */
int send_message(int friendId, uint8_t *message, uint32_t length);

/* set the function that will be executed when a message from a friend is received.
    function format is: function(int friendnumber, uint8_t * message, uint32_t length) */
void message_receive_callback(void (*function)(int, uint8_t *, uint16_t));

#include "messenger_internal.h"

#ifdef __cplusplus
}
#endif

#endif
