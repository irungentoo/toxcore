/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Handle friend requests.
 */
#ifndef C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H
#define C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H

#include "friend_connection.h"

#define MAX_FRIEND_REQUEST_DATA_SIZE (ONION_CLIENT_MAX_DATA_SIZE - (1 + sizeof(uint32_t)))

typedef struct Friend_Requests Friend_Requests;

/** Set and get the nospam variable used to prevent one type of friend request spam. */
non_null() void set_nospam(Friend_Requests *fr, uint32_t num);
non_null() uint32_t get_nospam(const Friend_Requests *fr);

/** @brief Remove real_pk from received_requests list.
 *
 * @retval 0 if it removed it successfully.
 * @retval -1 if it didn't find it.
 */
non_null()
int remove_request_received(Friend_Requests *fr, const uint8_t *real_pk);

typedef void fr_friend_request_cb(void *object, const uint8_t *public_key, const uint8_t *message, size_t length,
                                  void *user_data);

/** Set the function that will be executed when a friend request for us is received. */
non_null()
void callback_friendrequest(Friend_Requests *fr, fr_friend_request_cb *function, void *object);

typedef int filter_function_cb(const uint8_t *public_key, void *user_data);

/** @brief Set the function used to check if a friend request should be displayed to the user or not.
 * It must return 0 if the request is ok (anything else if it is bad).
 */
non_null()
void set_filter_function(Friend_Requests *fr, filter_function_cb *function, void *userdata);

/** Sets up friendreq packet handlers. */
non_null()
void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c);

Friend_Requests *friendreq_new(void);

nullable(1)
void friendreq_kill(Friend_Requests *fr);

#endif
