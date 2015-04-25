/* friend_requests.h
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

#ifndef FRIEND_REQUESTS_H
#define FRIEND_REQUESTS_H

#include "friend_connection.h"
#include <stdbool.h>

#define MAX_FRIEND_REQUEST_DATA_SIZE (ONION_CLIENT_MAX_DATA_SIZE - (1 + sizeof(uint32_t)))

/* Maximum nospam amount should be quite small to be effective against spam.
 * Maximum allowed amount is given by MAX_NOSPAM_AMOUNT.
 */

#define MAX_NOSPAM_AMOUNT 16
#define MAX_NOSPAM_DESCRIPTION_LENGTH 128
#define NOSPAM_SIZE sizeof(uint32_t)
#define NOSPAM_SPAM 0

typedef enum NSERR {
    NSERR_SUCCESS = 0,
    NSERR_NOT_FOUND = 1,
    NSERR_TOO_MANY = 2,
    NSERR_ALREADY_EXISTS = 3,
    NSERR_DESCRIPTION_TOO_LONG
} NSERR;

typedef struct No_Spam {
    uint32_t nospam;
    uint8_t  description[MAX_NOSPAM_DESCRIPTION_LENGTH];
    size_t description_length;
} No_Spam;

typedef struct {
    No_Spam nospam[MAX_NOSPAM_AMOUNT];
    uint32_t nospam_amount;

    void (*handle_friendrequest)(void *, const uint8_t *, uint32_t, const uint8_t *, size_t, void *);
    uint8_t handle_friendrequest_isset;
    void *handle_friendrequest_object;
    void *handle_friendrequest_userdata;

    int (*filter_function)(const uint8_t *, void *);
    void *filter_function_userdata;
    /* NOTE: The following is just a temporary fix for the multiple friend requests received at the same time problem.
     *  TODO: Make this better (This will most likely tie in with the way we will handle spam.)
     */

#define MAX_RECEIVED_STORED 32

    uint8_t received_requests[MAX_RECEIVED_STORED][crypto_box_PUBLICKEYBYTES];
    uint16_t received_requests_index;
} Friend_Requests;

/* Set and get the nospam variable used to prevent one type of friend request spam.
 * This is old API.
 */
void set_nospam(Friend_Requests *fr, uint32_t num);
uint32_t get_nospam(const Friend_Requests *fr);

/*
 * This function updates the nospam set. If num is in nospam set, then new_num will replace num.
 * If new_num == NOSPAM_SPAM, which is 0, then num value will be removed from nospam set.
 * If num == NOSPAM_SPAM, which is 0, then new_num will be added to nospam set.
 * Passing num == 0 and new_num == 0 will return NSERR_SUCCESS and result no effect.
 *
 * Return: NSERR_SUCCESS on success, or NSERR_* on falure.
 * If the call fails, the nospam set is unchanged.
 */
NSERR nospam_update(Friend_Requests *fr, uint32_t num, uint32_t new_num);

/*
 * Set description for num. Description in utf8 string.
 * Passing 0 as descr_length will result no effect and NSERR_SUCCESS will be returned.
 * Passing descr == 0 and descr_length != 0 will erase the description.
 * Passing descr_length > MAX_NOSPAM_DESCRIPTION_LENGTH will result and error;
 * If error happens then nothing is changed.
 * On success description for nospam num is changed.
 */
NSERR nospam_descr_update(Friend_Requests *fr, uint32_t num, const uint8_t *descr, size_t descr_length);

/*
 * Returns nospam value and set nserr to NSERR_SUCCESS on success.
 * Returns 0 and set nserr on failure.
 */
size_t nospam_descr_length(const Friend_Requests *fr, uint32_t num, NSERR *nserr);

/*
 * Copy description to descr for num.
 * If no description exists, then descr is unchanged.
 * returns NSERR_SUCCESS or NSERR_* on failure.
 */
NSERR nospam_descr(const Friend_Requests *fr, uint32_t num, uint8_t *descr);

/*
 * Returns the amount of nospams.
 * Call can't fail.
 */
size_t nospam_count(const Friend_Requests *fr);

/*
 * Write to ns_list all nospams in nospam set.
 * The size of ns_list is given with nospam_count function.
 * Call can't fail.
 */
void nospam_list(const Friend_Requests *fr, uint32_t *ns_list);

uint32_t nospam_saved_list_size(const Friend_Requests *fr);
void nospam_list_save(const Friend_Requests *fr, uint8_t *data);
void nospam_list_load(Friend_Requests *fr, const uint8_t *data, uint32_t size);

/* Remove real_pk from received_requests list.
 *
 *  return 0 if it removed it successfully.
 *  return -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *fr, const uint8_t *real_pk);

/* Set the function that will be executed when a friend request for us is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, size_t length, void * userdata)
 */
void callback_friendrequest(Friend_Requests *fr, void (*function)(void *, const uint8_t *, uint32_t, const uint8_t *, size_t,
                            void *), void *object, void *userdata);

/* Set the function used to check if a friend request should be displayed to the user or not.
 * Function format is int function(uint8_t * public_key, void * userdata)
 * It must return 0 if the request is ok (anything else if it is bad.)
 */
void set_filter_function(Friend_Requests *fr, int (*function)(const uint8_t *, void *), void *userdata);

/* Sets up friendreq packet handlers. */
void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c);


#endif
