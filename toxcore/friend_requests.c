/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Handle friend requests.
 */
#include "friend_requests.h"

#include <string.h>

#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "friend_connection.h"
#include "mem.h"
#include "network.h"
#include "onion.h"
#include "onion_announce.h"
#include "onion_client.h"

static_assert(ONION_CLIENT_MAX_DATA_SIZE <= MAX_DATA_REQUEST_SIZE, "ONION_CLIENT_MAX_DATA_SIZE is too big");
static_assert(MAX_DATA_REQUEST_SIZE <= ONION_MAX_DATA_SIZE, "MAX_DATA_REQUEST_SIZE is too big");
static_assert(SIZE_IPPORT <= ONION_SEND_BASE, "IP_Port does not fit in the onion packet");

/**
 * NOTE: The following is just a temporary fix for the multiple friend requests received at the same time problem.
 * TODO(irungentoo): Make this better (This will most likely tie in with the way we will handle spam).
 */
#define MAX_RECEIVED_STORED 32

struct Received_Requests {
    uint8_t requests[MAX_RECEIVED_STORED][CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t requests_index;
};

struct Friend_Requests {
    const Memory *_Nonnull mem;

    uint32_t nospam;
    fr_friend_request_cb *_Nullable handle_friendrequest;
    uint8_t handle_friendrequest_isset;
    void *_Nullable handle_friendrequest_object;

    filter_function_cb *_Nullable filter_function;
    void *_Nullable filter_function_userdata;

    struct Received_Requests received;
};

/** Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(Friend_Requests *fr, uint32_t num)
{
    fr->nospam = num;
}

uint32_t get_nospam(const Friend_Requests *fr)
{
    return fr->nospam;
}

/** Set the function that will be executed when a friend request for us is received. */
void callback_friendrequest(Friend_Requests *fr, fr_friend_request_cb *function, void *object)
{
    fr->handle_friendrequest = function;
    fr->handle_friendrequest_isset = 1;
    fr->handle_friendrequest_object = object;
}

/** @brief Set the function used to check if a friend request should be displayed to the user or not.
 * It must return 0 if the request is ok (anything else if it is bad).
 */
void set_filter_function(Friend_Requests *fr, filter_function_cb *function, void *userdata)
{
    fr->filter_function = function;
    fr->filter_function_userdata = userdata;
}

/** Add to list of received friend requests. */
static void addto_receivedlist(Friend_Requests *_Nonnull fr, const uint8_t *_Nonnull real_pk)
{
    if (fr->received.requests_index >= MAX_RECEIVED_STORED) {
        fr->received.requests_index = 0;
    }

    pk_copy(fr->received.requests[fr->received.requests_index], real_pk);
    ++fr->received.requests_index;
}

/** @brief Check if a friend request was already received.
 *
 * @retval false if it did not.
 * @retval true if it did.
 */
static bool request_received(const Friend_Requests *_Nonnull fr, const uint8_t *_Nonnull real_pk)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (pk_equal(fr->received.requests[i], real_pk)) {
            return true;
        }
    }

    return false;
}

/** @brief Remove real_pk from received_requests list.
 *
 * @retval 0 if it removed it successfully.
 * @retval -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *fr, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (pk_equal(fr->received.requests[i], real_pk)) {
            crypto_memzero(fr->received.requests[i], CRYPTO_PUBLIC_KEY_SIZE);
            return 0;
        }
    }

    return -1;
}

static int friendreq_handlepacket(void *_Nonnull object, const uint8_t *_Nonnull source_pubkey, const uint8_t *_Nonnull data, uint16_t length, void *_Nonnull userdata)
{
    Friend_Requests *const fr = (Friend_Requests *)object;

    if (length <= 1 + sizeof(fr->nospam) || length > ONION_CLIENT_MAX_DATA_SIZE) {
        return 1;
    }

    ++data;
    --length;

    if (fr->handle_friendrequest_isset == 0) {
        return 1;
    }

    if (request_received(fr, source_pubkey)) {
        return 1;
    }

    if (memcmp(data, &fr->nospam, sizeof(fr->nospam)) != 0) {
        return 1;
    }

    if (fr->filter_function != nullptr) {
        if (fr->filter_function(fr->filter_function_userdata, source_pubkey) != 0) {
            return 1;
        }
    }

    addto_receivedlist(fr, source_pubkey);

    const uint16_t message_len = length - sizeof(fr->nospam);
    VLA(uint8_t, message, message_len + 1);
    memcpy(message, data + sizeof(fr->nospam), message_len);
    message[message_len] = 0; /* Be sure the message is null terminated. TODO(iphydf): But why? */

    fr->handle_friendrequest(fr->handle_friendrequest_object, source_pubkey, message, message_len, userdata);
    return 0;
}

void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c)
{
    set_friend_request_callback(fr_c, &friendreq_handlepacket, fr);
}

Friend_Requests *friendreq_new(const Memory *mem)
{
    Friend_Requests *fr = (Friend_Requests *)mem_alloc(mem, sizeof(Friend_Requests));

    if (fr == nullptr) {
        return nullptr;
    }

    fr->mem = mem;

    return fr;
}

void friendreq_kill(Friend_Requests *fr)
{
    if (fr == nullptr) {
        return;
    }

    mem_delete(fr->mem, fr);
}
