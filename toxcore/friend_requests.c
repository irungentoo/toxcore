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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "friend_requests.h"
#include "util.h"


/* Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(Friend_Requests *fr, uint32_t num)
{
    fr->nospam = num;
}

uint32_t get_nospam(const Friend_Requests *fr)
{
    return fr->nospam;
}


/* Set the function that will be executed when a friend request is received. */
void callback_friendrequest(Friend_Requests *fr, void (*function)(void *, const uint8_t *, const uint8_t *, uint16_t,
                            void *), void *object, void *userdata)
{
    fr->handle_friendrequest = function;
    fr->handle_friendrequest_isset = 1;
    fr->handle_friendrequest_object = object;
    fr->handle_friendrequest_userdata = userdata;
}
/* Set the function used to check if a friend request should be displayed to the user or not. */
void set_filter_function(Friend_Requests *fr, int (*function)(const uint8_t *, void *), void *userdata)
{
    fr->filter_function = function;
    fr->filter_function_userdata = userdata;
}

/* Add to list of received friend requests. */
static void addto_receivedlist(Friend_Requests *fr, const uint8_t *real_pk)
{
    if (fr->received_requests_index >= MAX_RECEIVED_STORED)
        fr->received_requests_index = 0;

    id_copy(fr->received_requests[fr->received_requests_index], real_pk);
    ++fr->received_requests_index;
}

/* Check if a friend request was already received.
 *
 *  return 0 if it did not.
 *  return 1 if it did.
 */
static int request_received(Friend_Requests *fr, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < MAX_RECEIVED_STORED; ++i)
        if (id_equal(fr->received_requests[i], real_pk))
            return 1;

    return 0;
}

/* Remove real pk from received_requests list.
 *
 *  return 0 if it removed it successfully.
 *  return -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *fr, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received_requests[i], real_pk)) {
            memset(fr->received_requests[i], 0, crypto_box_PUBLICKEYBYTES);
            return 0;
        }
    }

    return -1;
}


static int friendreq_handlepacket(void *object, const uint8_t *source_pubkey, const uint8_t *packet, uint16_t length)
{
    Friend_Requests *fr = object;

    if (length <= 1 + sizeof(fr->nospam) || length > ONION_CLIENT_MAX_DATA_SIZE)
        return 1;

    ++packet;
    --length;

    if (fr->handle_friendrequest_isset == 0)
        return 1;

    if (request_received(fr, source_pubkey))
        return 1;

    if (memcmp(packet, &fr->nospam, sizeof(fr->nospam)) != 0)
        return 1;

    if (fr->filter_function)
        if ((*fr->filter_function)(source_pubkey, fr->filter_function_userdata) != 0)
            return 1;

    addto_receivedlist(fr, source_pubkey);

    uint32_t message_len = length - sizeof(fr->nospam);
    uint8_t message[message_len + 1];
    memcpy(message, packet + sizeof(fr->nospam), message_len);
    message[sizeof(message) - 1] = 0; /* Be sure the message is null terminated. */

    (*fr->handle_friendrequest)(fr->handle_friendrequest_object, source_pubkey, message, message_len,
                                fr->handle_friendrequest_userdata);
    return 0;
}

void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c)
{
    set_friend_request_callback(fr_c, &friendreq_handlepacket, fr);
}
