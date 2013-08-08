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
#define MAX_STATUSMESSAGE_LENGTH 128

#define PACKET_ID_NICKNAME 48
#define PACKET_ID_STATUSMESSAGE 49
#define PACKET_ID_USERSTATUS 50
#define PACKET_ID_RECEIPT 65
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

/* don't assume MAX_STATUSMESSAGE_LENGTH will stay at 128, it may be increased
    to an absurdly large number later */

/* USERSTATUS
 * Represents userstatuses someone can have. */

typedef enum {
    USERSTATUS_NONE,
    USERSTATUS_AWAY,
    USERSTATUS_BUSY,
    USERSTATUS_INVALID
} USERSTATUS;

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
int m_addfriend(uint8_t *client_id, uint8_t *data, uint16_t length);


/* add a friend without sending a friendrequest.
    returns the friend number if success
    return -1 if failure. */
int m_addfriend_norequest(uint8_t *client_id);

/* return the friend id associated to that client id.
    return -1 if no such friend */
int getfriend_id(uint8_t *client_id);

/* copies the public key associated to that friend id into client_id buffer.
    make sure that client_id is of size CLIENT_ID_SIZE.
    return 0 if success
    return -1 if failure */
int getclient_id(int friend_id, uint8_t *client_id);

/* remove a friend */
int m_delfriend(int friendnumber);

/* return 4 if friend is online
    return 3 if friend is confirmed
    return 2 if the friend request was sent
    return 1 if the friend was added
    return 0 if there is no friend with that number */
int m_friendstatus(int friendnumber);

/* send a text chat message to an online friend
    returns the message id if packet was successfully put into the send queue
    return 0 if it was not
    you will want to retain the return value, it will be passed to your read receipt callback
    if one is received.
    m_sendmessage_withid will send a message with the id of your choosing,
    however we can generate an id for you by calling plain m_sendmessage. */
uint32_t m_sendmessage(int friendnumber, uint8_t *message, uint32_t length);
uint32_t m_sendmessage_withid(int friendnumber, uint32_t theid, uint8_t *message, uint32_t length);

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
int getname(int friendnumber, uint8_t *name);

/* set our user status
    you are responsible for freeing status after
    returns 0 on success, -1 on failure */
int m_set_statusmessage(uint8_t *status, uint16_t length);
int m_set_userstatus(USERSTATUS status);

/* return the length of friendnumber's status message,
    including null
    pass it into malloc */
int m_get_statusmessage_size(int friendnumber);

/* copy friendnumber's status message into buf, truncating if size is over maxlen
    get the size you need to allocate from m_get_statusmessage_size
    The self variant will copy our own status message. */
int m_copy_statusmessage(int friendnumber, uint8_t *buf, uint32_t maxlen);
int m_copy_self_statusmessage(uint8_t *buf, uint32_t maxlen);

/* Return one of USERSTATUS values.
 * Values unknown to your application should be represented as USERSTATUS_NONE.
 * As above, the self variant will return our own USERSTATUS.
 * If friendnumber is invalid, this shall return USERSTATUS_INVALID. */
USERSTATUS m_get_userstatus(int friendnumber);
USERSTATUS m_get_self_userstatus(void);

/* Sets whether we send read receipts for friendnumber.
 * This function is not lazy, and it will fail if yesno is not (0 or 1).*/
void m_set_sends_receipts(int friendnumber, int yesno);

/* set the function that will be executed when a friend request is received.
    function format is function(uint8_t * public_key, uint8_t * data, uint16_t length) */
void m_callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t));

/* set the function that will be executed when a message from a friend is received.
    function format is: function(int friendnumber, uint8_t * message, uint32_t length) */
void m_callback_friendmessage(void (*function)(int, uint8_t *, uint16_t));

/* set the callback for name changes
    function(int friendnumber, uint8_t *newname, uint16_t length)
    you are not responsible for freeing newname */
void m_callback_namechange(void (*function)(int, uint8_t *, uint16_t));

/* set the callback for status message changes
    function(int friendnumber, uint8_t *newstatus, uint16_t length)
    you are not responsible for freeing newstatus */
void m_callback_statusmessage(void (*function)(int, uint8_t *, uint16_t));

/* set the callback for read receipts
    function(int friendnumber, uint32_t receipt)
    if you are keeping a record of returns from m_sendmessage,
    receipt might be one of those values, and that means the message
    has been received on the other side. since core doesn't
    track ids for you, receipt may not correspond to any message
    in that case, you should discard it. */
void m_callback_read_receipt(void (*function)(int, uint32_t));

/* run this at startup
    returns 0 if no connection problems
    returns -1 if there are problems */
int initMessenger(void);

/* the main loop that needs to be run at least 200 times per second */
void doMessenger(void);

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
