/*
* onion_announce.h -- Implementation of the announce part of docs/Prevent_Tracking.txt
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

#ifndef ONION_ANNOUNCE_H
#define ONION_ANNOUNCE_H

#include "onion.h"

#define ONION_ANNOUNCE_MAX_ENTRIES 32
#define ONION_ANNOUNCE_TIMEOUT 300

typedef struct {
        uint8_t public_key[crypto_box_PUBLICKEYBYTES];
        IP_Port ret_ip_port;
        uint8_t ret[ONION_RETURN_3];
        uint64_t time;
} Onion_Announce_Entry;

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    Onion_Announce_Entry entries[ONION_ANNOUNCE_MAX_ENTRIES];
    /* This is crypto_secretbox_KEYBYTES long just so we can use new_symmetric_key() to fill it */
    uint8_t secret_bytes[crypto_secretbox_KEYBYTES];
} Onion_Announce;



Onion_Announce *new_onion_announce(DHT *dht);

void kill_onion_announce(Onion_Announce *onion_a);


#endif
