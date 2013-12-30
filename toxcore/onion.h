/*
* onion.h -- Implementation of the onion part of docs/Prevent_Tracking.txt
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

#include "DHT.h"

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    uint8_t secret_symmetric_key[crypto_secretbox_KEYBYTES];
} Onion;

/* Create and send a onion packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the data
 * with length length will arrive at 3.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(Onion *onion, Node_format *nodes, uint8_t *data, uint32_t length);

Onion *new_onion(DHT *dht);

void kill_onion(Onion *onion);
