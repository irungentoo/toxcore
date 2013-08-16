/* friend_requests.c
 *
 * Handle friend requests.
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

#include "friend_requests.h"

uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];


/* Try to send a friendrequest to peer with public_key
   data is the data in the request and length is the length.
   return -1 if failure.
   return  0 if it sent the friend request directly to the friend.
   return the number of peers it was routed through if it did not send it directly.*/
int send_friendrequest(uint8_t * public_key, uint32_t nospam_num, uint8_t * data, uint32_t length)
{
    if(length + sizeof(nospam_num) > MAX_DATA_SIZE)
        return -1;

    uint8_t temp[MAX_DATA_SIZE];
    memcpy(temp, &nospam_num, sizeof(nospam_num));
    memcpy(temp + sizeof(nospam_num), data, length);
    uint8_t packet[MAX_DATA_SIZE];
    int len = create_request(packet, public_key, temp, length + sizeof(nospam_num), 32); /* 32 is friend request packet id */

    if (len == -1)
        return -1;

    IP_Port ip_port = DHT_getfriendip(public_key);

    if (ip_port.ip.i == 1)
        return -1;

    if (ip_port.ip.i != 0) {
        if (sendpacket(ip_port, packet, len) != -1)
            return 0;
        return -1;
    }

    int num = route_tofriend(public_key, packet, len);

    if (num == 0)
        return -1;

    return num;
}

static uint32_t nospam;
/*
 * Set and get the nospam variable used to prevent one type of friend request spam
 */
void set_nospam(uint32_t num)
{
    nospam = num;
}

uint32_t get_nospam()
{
    return nospam;
}

static void (*handle_friendrequest)(uint8_t *, uint8_t *, uint16_t, void*);
static uint8_t handle_friendrequest_isset = 0;
static void* handle_friendrequest_userdata;
/* set the function that will be executed when a friend request is received. */
void callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t, void*), void* userdata)
{
    handle_friendrequest = function;
    handle_friendrequest_isset = 1;
    handle_friendrequest_userdata = userdata;
}


/*NOTE: the following is just a temporary fix for the multiple friend requests received at the same time problem
  TODO: Make this better (This will most likely tie in with the way we will handle spam.)*/

#define MAX_RECEIVED_STORED 32

static uint8_t received_requests[MAX_RECEIVED_STORED][crypto_box_PUBLICKEYBYTES];
static uint16_t received_requests_index;

/*Add to list of received friend requests*/
static void addto_receivedlist(uint8_t * client_id)
{
    if (received_requests_index >= MAX_RECEIVED_STORED)
        received_requests_index = 0;

    memcpy(received_requests[received_requests_index], client_id, crypto_box_PUBLICKEYBYTES);
    ++received_requests_index;
}

/* Check if a friend request was already received
   return 0 if not, 1 if we did  */
static int request_received(uint8_t * client_id)
{
    uint32_t i;

    for (i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (memcmp(received_requests[i], client_id, crypto_box_PUBLICKEYBYTES) == 0)
            return 1;
    }

    return 0;
}


static int friendreq_handlepacket(IP_Port source, uint8_t * source_pubkey, uint8_t * packet, uint32_t length) 
{
    if (handle_friendrequest_isset == 0)
        return 1;
    if (length <= sizeof(nospam))
        return 1;
    if (request_received(source_pubkey))
        return 1;
    if (memcmp(packet, &nospam, sizeof(nospam)) != 0)
        return 1;

    addto_receivedlist(source_pubkey);
    (*handle_friendrequest)(source_pubkey, packet + 4, length - 4, handle_friendrequest_userdata);
    return 0;
}

void friendreq_init(void)
{
    cryptopacket_registerhandler(32, &friendreq_handlepacket);
}
