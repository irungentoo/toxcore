/* Friends.h
 *
 * An implementation of friends manipulation stuff (add, remove, friendlists, etc.)
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

#ifndef FRIENDS_H
#define FRIENDS_H

#include "Connection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NAME_LENGTH 128
#define MAX_USERSTATUS_LENGTH 128
/* don't assume MAX_USERSTATUS_LENGTH will stay at 128, it may be increased
    to an absurdly large number later */

/* status definitions */
#define FRIEND_ONLINE 4
#define FRIEND_CONFIRMED 3
#define FRIEND_REQUESTED 2
#define FRIEND_ADDED 1
#define NOFRIEND 0

/* errors for m_addfriend
 *  FAERR - Friend Add Error */
#define FAERR_TOOLONG -1
#define FAERR_NOMESSAGE -2
#define FAERR_OWNKEY -3
#define FAERR_ALREADYSENT -4
#define FAERR_UNKNOWN -5

/*   PUBLIC INTERFACE: */

/*
 * add a friend
 * set the data that will be sent along with friend request
 * client_id is the client id of the friend
 * data is the data and length is the length
 * returns the friend number if success
 * return -1 if message length is too long
 * return -2 if no message (message length must be >= 1 byte)
 * return -3 if user's own key
 * return -4 if friend request already sent or already a friend
 * return -5 for unknown error
 */
int add_friend(uint8_t *client_id, uint8_t *data, uint16_t length);

/* add a friend without sending a friendrequest.
    returns the friend number if success
    return -1 if failure. */
int add_friend_norequest(uint8_t *client_id);

/* return the friend id associated to that client id.
    return -1 if no such friend */
int get_friend_id(uint8_t *client_id);

/* copies the public key associated to that friend id into client_id buffer.
    make sure that client_id is of size CLIENT_ID_SIZE.
    return 0 if success
    return -1 if failure */
int get_client_id(int friend_id, uint8_t *client_id);

/* remove a friend */
int del_friend(int friendnumber);

/* return 4 if friend is online
    return 3 if friend is confirmed
    return 2 if the friend request was sent
    return 1 if the friend was added
    return 0 if there is no friend with that number */
int get_friend_status(int friendnumber);

/* get name of the friend
    put it in name
    name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
    return 0 if success
    return -1 if failure */
int get_friend_name(int friendnumber, uint8_t *name);

/* return the length of friendnumber's user status,
    including null
    pass it into malloc */
int friend_userstatus_size(int friendnumber);

/* copy friendnumber's userstatus into buf, truncating if size is over maxlen
    get the size you need to allocate from m_get_userstatus_size */
int get_friend_userstatus(int friendnumber, uint8_t *buf, uint32_t maxlen);


/* set the function that will be executed when a friend request is received.
    function format is function(uint8_t * public_key, uint8_t * data, uint16_t length) */
void friend_add_request_callback(void (*function)(uint8_t *, uint8_t *, uint16_t));

/* set the callback for name changes
    function(int friendnumber, uint8_t *newname, uint16_t length)
    you are not responsible for freeing newname */
void friend_name_change_callback(void (*function)(int, uint8_t *, uint16_t));

/* set the callback for user status changes
    function(int friendnumber, uint8_t *newstatus, uint16_t length)
    you are not responsible for freeing newstatus */
void friend_userstatus_change_callback(void (*function)(int, uint8_t *, uint16_t));


/*  INTERNAL STUFF - should not be used outside core */

/* return friends count */
int get_friends_number();

/* return crypt connection id by friend id */
int get_friend_connection_id(int friendId);

/* return 1 if online; 0 if ofline */
int is_friend_online(int friendId);

/* process incoming name change packet */
void friend_change_nickname(int friendId, uint8_t* data, uint16_t size);

/* process incoming userstate change packet */
void friend_change_userstate(int friendId, uint8_t* data, uint16_t size);

/* process friend connection timeout */
void friend_disconnect(int friendId);

/* tell friends that our name has changed */
void friends_selfname_updated();

/* tell friends that our status has changed */
void friends_selfstatus_updated();

/* friends processing stuff */
void doFriends(uint8_t *self_name,
               uint16_t self_name_length,
               uint8_t *self_userstatus,
               uint16_t self_userstatus_len);


/* serialization stuff */

/* returns size of friends data (for saving) */
uint32_t friends_data_size();

/* store friends in data */
void friends_data_save(uint8_t *data);

/* loads friends from data */
int friends_data_load(uint8_t *data, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif
