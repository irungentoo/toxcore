/* Connection.h
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

#ifndef CONNECTION_H
#define CONNECTION_H

#include "DHT.h"
#include "net_crypto.h"
#include "friend_requests.h"
#include "LAN_discovery.h"
#include "Friends.h"
#include "Messenger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PACKET_ID_NICKNAME 48
#define PACKET_ID_USERSTATUS 49
#define PACKET_ID_MESSAGE 64

/* process connection routine - handle incoming data */
void doConnection();

/*  process incoming data from friend
 * returns 1 if processed or 0 if not */
int received_friend_packet(int friendId, int connectionId);

/* sends packet to friend */
int send_friend_packet(int friendId, int packetType, uint8_t *message, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
