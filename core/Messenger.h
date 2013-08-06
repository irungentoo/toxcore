/* Messenger.h
 *
 * An implementation of a simple text chat only messenger on the tox network core.
 *
 * NOTE: All the text in the messages must be encoded using UTF-8
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

#ifndef MESSENGER_H
#define MESSENGER_H

#include "net_crypto.h"
#include "DHT.h"
#include "friend_requests.h"
#include "LAN_discovery.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NAME_LENGTH 128
#define MAX_USERSTATUS_LENGTH 128

#define PACKET_ID_NICKNAME 48
#define PACKET_ID_USERSTATUS 49
#define PACKET_ID_MESSAGE 64

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

/* don't assume MAX_USERSTATUS_LENGTH will stay at 128, it may be increased
    to an absurdly large number later */

/* USERSTATUS_KIND
 * Represents the different kinds of userstatus
 * someone can have.
 * More on this later... */

typedef enum {
    USERSTATUS_KIND_RETAIN = (uint8_t)0, /* This is a special value that must not be returned by
                             * m_get_userstatus_kind. You can pass it into m_set_userstatus
                             * to keep the current USERSTATUS_KIND. */
    USERSTATUS_KIND_ONLINE, /* Recommended representation: Green. */
    USERSTATUS_KIND_AWAY, /* Recommended representation: Orange, or yellow. */
    USERSTATUS_KIND_BUSY, /* Recommended representation: Red. */
    USERSTATUS_KIND_OFFLINE, /* Recommended representation: Grey, semi-transparent. */
    USERSTATUS_KIND_INVALID,
} USERSTATUS_KIND;

/* a friend */
typedef struct {
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    uint64_t friend_request_id; /* id of the friend request corresponding to the current friend request to the current friend. */
    uint8_t status; /* 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online. */
    uint8_t info[MAX_DATA_SIZE]; /* the data that is sent during the friend requests we do */
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t name_sent; /* 0 if we didn't send our name to this friend 1 if we have. */
    uint8_t *userstatus;
    uint16_t userstatus_length;
    uint8_t userstatus_sent;
    USERSTATUS_KIND userstatus_kind;
    uint16_t info_size; /* length of the info */
} Friend;

/*
 * add a friend
 * set the data that will be sent along with friend request
 * f is the friend that will be created
 * client_id is the client id of the friend
 * data is the data and length is the length
 * returns the friend number if success
 * return -1 if message length is too long
 * return -2 if no message (message length must be >= 1 byte)
 * return -3 if user's own key
 * return -4 if friend request already sent or already a friend
 * return -5 for unknown error
 */
int m_addfriend(Friend *f, uint8_t *client_id, uint8_t *data, uint16_t length);


/* add a friend without sending a friendrequest.
    returns the friend number if success
    return -1 if failure. */
int m_addfriend_norequest(Friend *f, uint8_t *client_id);

/* return the friend id associated to that client id.
    return -1 if no such friend */
int getfriend_id(uint8_t *client_id);

/* copies the public key associated to that friend id into client_id buffer.
    make sure that client_id is of size CLIENT_ID_SIZE.
    return 0 if success
    return -1 if failure */
int getclient_id(Friend *f, uint8_t *client_id);

/* remove a friend */
int m_delfriend(Friend *f);

/* return 4 if friend is online
    return 3 if friend is confirmed
    return 2 if the friend request was sent
    return 1 if the friend was added
    return 0 if there is no friend with that number */
int m_friendstatus(Friend *f);

/* send a text chat message to an online friend
    returns 1 if packet was successfully put into the send queue
    return 0 if it was not */
int m_sendmessage(Friend *f, uint8_t *message, uint32_t length);

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   length must be at least 1 byte
   length is the length of name with the NULL terminator
   return 0 if success
   return -1 if failure */
int setname(uint8_t *name, uint16_t length);

/* get our nickname
   put it in name 
   return the length of the name*/
uint16_t getself_name(uint8_t *name);

/* get name of friendnumber
    put it in name
    name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
    return 0 if success
    return -1 if failure */
int getname(Friend *f, uint8_t *name);

/* set our user status
    you are responsible for freeing status after
    returns 0 on success, -1 on failure */
int m_set_userstatus(USERSTATUS_KIND kind, uint8_t *status, uint16_t length);
int m_set_userstatus_kind(USERSTATUS_KIND kind);

/* return the length of friendnumber's user status,
    including null
    pass it into malloc */
int m_get_userstatus_size(Friend *f);

/* copy friend's userstatus into buf, truncating if size is over maxlen
    get the size you need to allocate from m_get_userstatus_size
    The self variant will copy our own userstatus. */
int m_copy_userstatus(Friend *f, uint8_t *buf, uint32_t maxlen);
int m_copy_self_userstatus(uint8_t *buf, uint32_t maxlen);

/* Return one of USERSTATUS_KIND values, except USERSTATUS_KIND_RETAIN.
 * Values unknown to your application should be represented as USERSTATUS_KIND_ONLINE.
 * As above, the self variant will return our own USERSTATUS_KIND.
 * If friendnumber is invalid, this shall return USERSTATUS_KIND_INVALID. */
USERSTATUS_KIND m_get_userstatus_kind(Friend *);
USERSTATUS_KIND m_get_self_userstatus_kind(void);

/* set the function that will be executed when a friend request is received.
    function format is function(uint8_t * public_key, uint8_t * data, uint16_t length) */
void m_callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t));

/* set the function that will be executed when a message from a friend is received.
    function format is: function(Friend *f, uint8_t * message, uint32_t length) */
void m_callback_friendmessage(void (*function)(Friend *f, uint8_t *, uint16_t));

/* set the callback for name changes
    function(Friend *f, uint8_t *newname, uint16_t length)
    you are not responsible for freeing newname */
void m_callback_namechange(void (*function)(Friend *f, uint8_t *, uint16_t));

/* set the callback for user status changes
    function(Friend *f, USERSTATUS_KIND kind, uint8_t *newstatus, uint16_t length)
    you are not responsible for freeing newstatus */
void m_callback_userstatus(void (*function)(Friend *f, USERSTATUS_KIND, uint8_t *, uint16_t));

/* run this at startup
    returns 0 if no connection problems
    returns -1 if there are problems */
int initMessenger(void);

/* the main loop that needs to be run at least 200 times per second */
void doMessenger(Friend *f);

/* SAVING AND LOADING FUNCTIONS: */

/* returns the size of the messenger data (for saving) */
uint32_t Messenger_size(void);

/* save the messenger in data (must be allocated memory of size Messenger_size()) */
void Messenger_save(uint8_t *data);

/* load the messenger from data of size length */
int Messenger_load(uint8_t *data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
