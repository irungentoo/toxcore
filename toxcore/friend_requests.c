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

#include <assert.h>

//No Spam functions
void fr_nospam_init(No_Spam *ns)
{
    memset(ns, 0, sizeof(No_Spam));
}

bool fr_nospam_set(No_Spam *ns, uint32_t value, const uint8_t *description, size_t description_length)
{

    if (description_length > MAX_NOSPAM_DESCRIPTION_LENGTH)
        return false;

    ns->nospam = value;

    if (value == 0) {
        ns->description_length = 0;
        return true;
    }

    if (description_length == 0)
        return true;
    if (description == 0) {
        ns->description_length = 0;
        return true;
    }

    ns->description_length = description_length;
    memcpy(ns->description, description, ns->description_length);

    return true;
}

uint32_t fr_nospam_value(const No_Spam *ns)
{
    return ns->nospam;
}

bool fr_nospam_valid(const No_Spam *ns)
{
    return (fr_nospam_value(ns) != NOSPAM_SPAM);
}

size_t fr_nospam_description_length(const No_Spam *ns)
{
    return ns->description_length;
}

void fr_nospam_description(const No_Spam *ns, uint8_t *buffer)
{
    memcpy(buffer, ns->description, ns->description_length);
}

size_t fr_nospam_saved_size(const No_Spam *ns)
{
    return sizeof(No_Spam);
}

void fr_nospam_save(const No_Spam *ns, uint8_t *buffer)
{
    memcpy(buffer, ns, sizeof(No_Spam));
}

void fr_nospam_load(No_Spam *ns, const uint8_t *buffer)
{
    memcpy(ns, buffer, sizeof(No_Spam));
}

uint32_t fr_packet_nospam_extract(const uint8_t *packet)
{
    return *(uint32_t*)(packet);
}

size_t fr_nospam_find_id(const Friend_Requests *fr, uint32_t num)
{
    size_t i = 0;
    for (i = 0; i < fr->nospam_amount; ++i) {
        const No_Spam *ns = fr->nospam + i;
        if (fr_nospam_value(ns) == num)
            return i;
    }

    if ((fr->nospam_amount < MAX_NOSPAM_AMOUNT) &&
        (num == NOSPAM_SPAM))
        return fr->nospam_amount;

    return MAX_NOSPAM_AMOUNT;
}

No_Spam *fr_nospam_find(Friend_Requests *fr, uint32_t num)
{
    size_t id = fr_nospam_find_id(fr, num);

    if (id >= MAX_NOSPAM_AMOUNT)
        return 0;

    return fr->nospam + id;
}

uint32_t fr_filter_spam(const Friend_Requests *fr, uint32_t num)
{
    size_t id = fr_nospam_find_id(fr, num);

    if (id < MAX_NOSPAM_AMOUNT)
        return num;

    return NOSPAM_SPAM;
}

/* Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(Friend_Requests *fr, uint32_t num)
{
    if (fr->nospam_amount == 0) {
        fr->nospam_amount = 1;
    }
    fr_nospam_set(&(fr->nospam[0]), num, 0, 0);
}

uint32_t get_nospam(const Friend_Requests *fr)
{
    return fr_nospam_value(&(fr->nospam[0]));
}

/* NSERR nospam_add(Friend_Requests *fr, uint32_t num, const uint8_t *descr, size_t descr_length) { */
/*     No_Spam *ns = 0; */

/*     if (num == NOSPAM_SPAM) */
/*         return NSERR_SUCCESS; */

/*     ns = fr_nospam_find(fr, NOSPAM_SPAM); */

/*     if (!ns) */
/*         return NSERR_TOO_MANY; */

/*     fr_nospam_set(ns, num, descr, descr_length); */

/*     if (ns == fr->nospam + fr->nospam_amount) */
/*         ++(fr->nospam_amount); */

/*     return NSERR_SUCCESS; */
/* } */

NSERR nospam_update(Friend_Requests *fr, uint32_t num, uint32_t new_num)
{
    No_Spam *ns = fr_nospam_find(fr, num);
    No_Spam *new_ns = fr_nospam_find(fr, new_num);
    bool last_id = false;

    if ((num == 0) && (new_num == 0))
        return NSERR_SUCCESS;
    if ((num != 0) && (ns == 0))
        return NSERR_NOT_FOUND;
    if (num == new_num)
        return NSERR_SUCCESS;
    if ((new_num != 0) && (new_ns))
        return NSERR_ALREADY_EXISTS;
    if ((num == 0) && (ns == 0))
        return NSERR_TOO_MANY;

    fr_nospam_set(ns, new_num, 0, 0);

    if (ns == fr->nospam + fr->nospam_amount) {
        if (new_num == 0) {
            assert(fr->nospam_amount != 0);
            --(fr->nospam_amount);
        }
        else {
            ++(fr->nospam_amount);
        }
    }

    return NSERR_SUCCESS;
}

NSERR nospam_descr_update(Friend_Requests *fr, uint32_t num, const uint8_t *descr, size_t descr_length)
{
    if (num == NOSPAM_SPAM)
        return NSERR_SUCCESS;

    No_Spam *ns = fr_nospam_find(fr, num);
    if (ns == 0)
        return NSERR_NOT_FOUND;

    if (fr_nospam_set(ns, num, descr, descr_length))
        return NSERR_SUCCESS;
    return NSERR_DESCRIPTION_TOO_LONG;
}

size_t nospam_descr_length(const Friend_Requests *fr, uint32_t num, NSERR *nserr)
{
    size_t id = fr_nospam_find_id(fr, num);
    if (id == MAX_NOSPAM_AMOUNT) {
        if (nserr)
            *nserr = NSERR_NOT_FOUND;
        return 0;
    }
    return fr_nospam_description_length(fr->nospam + id);
}

NSERR nospam_descr(const Friend_Requests *fr, uint32_t num, uint8_t *descr)
{
    size_t id = fr_nospam_find_id(fr, num);
    if (id == MAX_NOSPAM_AMOUNT)
        return NSERR_NOT_FOUND;
    fr_nospam_description(fr->nospam + id, descr);
    return NSERR_SUCCESS;
}

size_t nospam_count(const Friend_Requests *fr)
{
    size_t i = 0;
    size_t result = 0;
    for (i = 0; i < fr->nospam_amount; ++i) {
        if (fr_nospam_valid(fr->nospam + i)) {
            ++result;
        }
    }
    return result;
}

void nospam_list(const Friend_Requests *fr, uint32_t *ns_list)
{
    size_t id = 0;
    for (id = 0; id < fr->nospam_amount; ++id) {
        const No_Spam *ns = fr->nospam + id;
        if (fr_nospam_valid(ns)) {
            *ns_list = fr_nospam_value(ns);
            ++ns_list;
        }
    }
}

uint32_t nospam_saved_list_size(const Friend_Requests *fr)
{
    size_t i = 0;
    uint32_t size = 0;
    for (i = 0; i < fr->nospam_amount; ++i) {
        const No_Spam *ns = fr->nospam + i;
        if (fr_nospam_valid(ns)){
            size += fr_nospam_saved_size(ns);
        }
    }
    return size;
}

void nospam_list_save(const Friend_Requests *fr, uint8_t *data)
{
    size_t i = 0;

    for (i = 0; i < fr->nospam_amount; ++i) {
        const No_Spam *ns = fr->nospam + i;
        if (fr_nospam_valid(ns)) {
            fr_nospam_save(ns, data);
            data += fr_nospam_saved_size(ns);
        }
    }
}

void nospam_list_load(Friend_Requests *fr, const uint8_t *data, uint32_t size)
{
    size_t sz = (sizeof(fr->nospam) > size)?size:sizeof(fr->nospam);
    memset(&(fr->nospam), 0, sizeof(fr->nospam));
    memcpy(&(fr->nospam), data, sz);
    fr->nospam_amount = sz/sizeof(No_Spam);
}

/* Set the function that will be executed when a friend request is received. */
void callback_friendrequest(Friend_Requests *fr, void (*function)(void *, const uint8_t *, uint32_t, const uint8_t *, size_t,
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
    uint32_t nospam = 0;

    if (length <= 1 + NOSPAM_SIZE || length > ONION_CLIENT_MAX_DATA_SIZE)
        return 1;

    ++packet;
    --length;

    if (fr->handle_friendrequest_isset == 0)
        return 1;

    if (request_received(fr, source_pubkey))
        return 1;

    if ((nospam = fr_filter_spam(fr, fr_packet_nospam_extract(packet))) == NOSPAM_SPAM)
        return 1;

    if (fr->filter_function)
        if ((*fr->filter_function)(source_pubkey, fr->filter_function_userdata) != 0)
            return 1;

    addto_receivedlist(fr, source_pubkey);

    uint32_t message_len = length - NOSPAM_SIZE;
    uint8_t message[message_len + 1];
    memcpy(message, packet + NOSPAM_SIZE, message_len);
    message[sizeof(message) - 1] = 0; /* Be sure the message is null terminated. */

    (*fr->handle_friendrequest)(fr->handle_friendrequest_object, source_pubkey, nospam, message, message_len,
                                fr->handle_friendrequest_userdata);
    return 0;
}

void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c)
{
    set_friend_request_callback(fr_c, &friendreq_handlepacket, fr);
}
