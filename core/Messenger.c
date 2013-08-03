/* Messenger.c
 *
 * An implementation of a simple text chat only messenger on the tox network core.
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

#include "Messenger.h"

/* send a text chat message to an online friend
   return 1 if packet was successfully put into the send queue
   return 0 if it was not */
int send_message(int friendId, uint8_t *message, uint32_t length)
{
    if (friendId < 0 ||
            friendId >= get_friends_number() ||
            !is_friend_online(friendId))
    {
        return 0;
    }
    return send_friend_packet(friendId, PACKET_ID_MESSAGE, message, length);
}

static void (*friend_message)(int, uint8_t *, uint16_t);
static uint8_t friend_message_isset = 0;

/* set the function that will be executed when a message from a friend is received. */
void message_receive_callback(void (*function)(int, uint8_t *, uint16_t))
{
    friend_message = function;
    friend_message_isset = 1;
}

void message_received(int friendId, uint8_t *data, uint16_t size)
{
    if (friend_message_isset)
        (*friend_message)(friendId, data, size);
}
