/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Handle friend requests.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "friend_requests.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

/* NOTE: The following is just a temporary fix for the multiple friend requests received at the same time problem.
 * TODO(irungentoo): Make this better (This will most likely tie in with the way we will handle spam.)
 */
#define MAX_RECEIVED_STORED 32

struct Received_Requests {
    uint8_t requests[MAX_RECEIVED_STORED][CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t requests_index;
};

struct Friend_Requests {
    uint32_t nospam;
    fr_friend_request_cb *handle_friendrequest;
    uint8_t handle_friendrequest_isset;
    void *handle_friendrequest_object;

    filter_function_cb *filter_function;
    void *filter_function_userdata;

    struct Received_Requests received;
};

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
void callback_friendrequest(Friend_Requests *fr, fr_friend_request_cb *function, void *object)
{
    fr->handle_friendrequest = function;
    fr->handle_friendrequest_isset = 1;
    fr->handle_friendrequest_object = object;
}

/* Set the function used to check if a friend request should be displayed to the user or not. */
void set_filter_function(Friend_Requests *fr, filter_function_cb *function, void *userdata)
{
    fr->filter_function = function;
    fr->filter_function_userdata = userdata;
}

/* Add to list of received friend requests. */
static void addto_receivedlist(Friend_Requests *fr, const uint8_t *real_pk)
{
    if (fr->received.requests_index >= MAX_RECEIVED_STORED) {
        fr->received.requests_index = 0;
    }

    id_copy(fr->received.requests[fr->received.requests_index], real_pk);
    ++fr->received.requests_index;
}

/* Check if a friend request was already received.
 *
 *  return false if it did not.
 *  return true if it did.
 */
static bool request_received(const Friend_Requests *fr, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received.requests[i], real_pk)) {
            return true;
        }
    }

    return false;
}

/* Remove real pk from received.requests list.
 *
 *  return 0 if it removed it successfully.
 *  return -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *fr, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received.requests[i], real_pk)) {
            crypto_memzero(fr->received.requests[i], CRYPTO_PUBLIC_KEY_SIZE);
            return 0;
        }
    }

    return -1;
}


static int friendreq_handlepacket(void *object, const uint8_t *source_pubkey, const uint8_t *packet, uint16_t length,
                                  void *userdata)
{
    Friend_Requests *const fr = (Friend_Requests *)object;

    if (length <= 1 + sizeof(fr->nospam) || length > ONION_CLIENT_MAX_DATA_SIZE) {
        return 1;
    }

    ++packet;
    --length;

    if (fr->handle_friendrequest_isset == 0) {
        return 1;
    }

    if (request_received(fr, source_pubkey)) {
        return 1;
    }

    if (memcmp(packet, &fr->nospam, sizeof(fr->nospam)) != 0) {
        return 1;
    }

    if (fr->filter_function) {
        if (fr->filter_function(source_pubkey, fr->filter_function_userdata) != 0) {
            return 1;
        }
    }

    addto_receivedlist(fr, source_pubkey);

    const uint32_t message_len = length - sizeof(fr->nospam);
    VLA(uint8_t, message, message_len + 1);
    memcpy(message, packet + sizeof(fr->nospam), message_len);
    message[SIZEOF_VLA(message) - 1] = 0; /* Be sure the message is null terminated. */

    fr->handle_friendrequest(fr->handle_friendrequest_object, source_pubkey, message, message_len, userdata);
    return 0;
}

void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c)
{
    set_friend_request_callback(fr_c, &friendreq_handlepacket, fr);
}

Friend_Requests *friendreq_new(void)
{
    return (Friend_Requests *)calloc(1, sizeof(Friend_Requests));
}

void friendreq_kill(Friend_Requests *fr)
{
    free(fr);
}
