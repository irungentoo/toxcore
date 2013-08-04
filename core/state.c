/* State.c
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

#include "state.h"


static uint8_t self_name[MAX_NAME_LENGTH];
static uint16_t self_name_length;

static uint8_t *self_userstatus;
static uint16_t self_userstatus_len;


/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   length must be at least 1 byte
   length is the length of name with the NULL terminator
   return 0 if success
   return -1 if failure */
int set_self_name(uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;
    memcpy(self_name, name, length);
    self_name_length = length;
    friends_selfname_updated();
    return 0;
}

/* get our nickname
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return the length of the name */
uint16_t get_self_name(uint8_t *name)
{
    memcpy(name, self_name, self_name_length);
    return self_name_length;
}

int set_self_userstatus(uint8_t *status, uint16_t length)
{
    if (length > MAX_USERSTATUS_LENGTH)
        return -1;
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(self_userstatus);
    self_userstatus = newstatus;
    self_userstatus_len = length;

    friends_selfstatus_updated();
    return 0;
}


#define PORT 33445
/* run this at startup */
int init_tox()
{
    new_keys();
    set_self_userstatus((uint8_t*)"Online", sizeof("Online"));
    init_net_crypto();
    IP ip;
    ip.i = 0;

    if(init_networking(ip,PORT) == -1)
        return -1;

    return 0;
}

/*Interval in seconds between LAN discovery packet sending*/
#define LAN_DISCOVERY_INTERVAL 60

static uint64_t last_LANdiscovery;

/*Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds*/
static void LANdiscovery()
{
    if (last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(PORT));
        last_LANdiscovery = unix_time();
    }
}

/* the main loop that needs to be run at least 200 times per second. */
void process_tox()
{
    process_connection();
    process_DHT();
    process_Lossless_UDP();
    process_net_crypto();
    process_friends(self_name, self_name_length, self_userstatus, self_userstatus_len);
    LANdiscovery();
}


/* returns the size of the state data (for saving) */
uint32_t tox_state_size()
{
    return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
            + sizeof(uint32_t) + DHT_size()
            + sizeof(uint32_t) + friends_data_size();
}

/* save the state in data (must be allocated memory of size Messenger_size()) */
void save_tox_state(uint8_t *data)
{
    save_keys(data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t size = DHT_size();
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    DHT_save(data);
    data += size;

    size = friends_data_size();
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    friends_data_save(data);
}

/* load the messenger from data of size length */
int load_tox_state(uint8_t *data, uint32_t length)
{
    if (length == ~0)
        return -1;
    if (length < crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 2)
        return -1;
    length -= crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 2;
    load_keys(data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);

    if (length < size)
        return -1;
    length -= size;
    if (DHT_load(data, size) == -1)
        return -1;
    data += size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);
    if (length != size)
        return -1;

    return friends_data_load(data, size);
}
