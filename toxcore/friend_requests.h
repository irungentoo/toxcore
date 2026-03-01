/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Handle friend requests.
 */
#ifndef C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H
#define C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H

#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "friend_connection.h"
#include "mem.h"

// TODO(Jfreegman): This should be the maximum size that an onion client can handle.
#define MAX_FRIEND_REQUEST_DATA_SIZE (ONION_CLIENT_MAX_DATA_SIZE - 100)

typedef struct Friend_Requests Friend_Requests;

/** Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(Friend_Requests *_Nonnull fr, uint32_t num);
uint32_t get_nospam(const Friend_Requests *_Nonnull fr);

/** @brief Remove real_pk from received_requests list.
 *
 * @retval 0 if it removed it successfully.
 * @retval -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *_Nonnull fr, const uint8_t *_Nonnull real_pk);

typedef void fr_friend_request_cb(void *_Nonnull object, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull message, size_t length,
                                  void *_Nullable user_data);

/** Set the function that will be executed when a friend request for us is received. */
void callback_friendrequest(Friend_Requests *_Nonnull fr, fr_friend_request_cb *_Nullable function, void *_Nullable object);

typedef int filter_function_cb(void *_Nonnull object, const uint8_t *_Nonnull public_key);

/** @brief Set the function used to check if a friend request should be displayed to the user or not.
 * It must return 0 if the request is ok (anything else if it is bad).
 */
void set_filter_function(Friend_Requests *_Nonnull fr, filter_function_cb *_Nullable function, void *_Nullable userdata);

/** Sets up friendreq packet handlers. */
void friendreq_init(Friend_Requests *_Nonnull fr, Friend_Connections *_Nonnull fr_c);

Friend_Requests *_Nullable friendreq_new(const Memory *_Nonnull mem);

void friendreq_kill(Friend_Requests *_Nullable fr);
#endif /* C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H */
