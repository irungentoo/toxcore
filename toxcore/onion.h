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

#ifndef ONION_H
#define ONION_H

#include "DHT.h"

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    uint8_t secret_symmetric_key[crypto_secretbox_KEYBYTES];
    uint64_t timestamp;
} Onion;

#define ONION_RETURN_1 (crypto_secretbox_NONCEBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES)
#define ONION_RETURN_2 (crypto_secretbox_NONCEBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES + ONION_RETURN_1)
#define ONION_RETURN_3 (crypto_secretbox_NONCEBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES + ONION_RETURN_2)

#define ONION_SEND_BASE (crypto_box_PUBLICKEYBYTES + sizeof(IP_Port) + crypto_box_MACBYTES)
#define ONION_SEND_3 (crypto_box_NONCEBYTES + ONION_SEND_BASE + ONION_RETURN_2)
#define ONION_SEND_2 (crypto_box_NONCEBYTES + ONION_SEND_BASE*2 + ONION_RETURN_1)
#define ONION_SEND_1 (crypto_box_NONCEBYTES + ONION_SEND_BASE*3)


/* Create and send a onion packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the data
 * with length length will arrive at 3.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(DHT *dht, Node_format *nodes, uint8_t *data, uint32_t length);

/* Create and send a onion response sent initially to dest with.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(Networking_Core *net, IP_Port dest, uint8_t *data, uint32_t length, uint8_t *ret);

Onion *new_onion(DHT *dht);

void kill_onion(Onion *onion);


#endif
