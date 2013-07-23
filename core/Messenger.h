/* Messenger.h
*
* An implementation of a simple text chat only messenger on the tox network core.
*
* NOTE: All the text in the messages must be encoded using UTF-8
 
    Copyright (C) 2013 Tox project All Rights Reserved.

    This file is part of Tox.

    Tox is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
    
*/
 
 
#ifndef MESSENGER_H
#define MESSENGER_H

#include "net_crypto.h"
#include "DHT.h"
#include "friend_requests.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NAME_LENGTH 128
#define MAX_USERSTATUS_LENGTH 128

#define PACKET_ID_NICKNAME 48
#define PACKET_ID_USERSTATUS 49
#define PACKET_ID_MESSAGE 64

/* don't assume MAX_USERSTATUS_LENGTH will stay at 128, it may be increased
   to an absurdly large number later */

/* add a friend
   set the data that will be sent along with friend request
   client_id is the client id of the friend
   data is the data and length is the length
   returns the friend number if success
   return -1 if failure. */
int m_addfriend(uint8_t * client_id, uint8_t * data, uint16_t length);


/* add a friend without sending a friendrequest.
   returns the friend number if success
   return -1 if failure. */
int m_addfriend_norequest(uint8_t * client_id);

/* return the friend id associated to that client id.
   return -1 if no such friend */
int getfriend_id(uint8_t * client_id);

/* copies the public key associated to that friend id into client_id buffer.
   make sure that client_id is of size CLIENT_ID_SIZE.
   return 0 if success
   return -1 if failure */
int getclient_id(int friend_id, uint8_t * client_id);

/* remove a friend */
int m_delfriend(int friendnumber);

/* return 4 if friend is online
   return 3 if friend is confirmed
   return 2 if the friend request was sent
   return 1 if the friend was added
   return 0 if there is no friend with that number */
int m_friendstatus(int friendnumber);


/* send a text chat message to an online friend
   returns 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendmessage(int friendnumber, uint8_t * message, uint32_t length);

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   return 0 if success
   return -1 if failure */
int setname(uint8_t * name, uint16_t length);


/* get name of friendnumber
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
   return 0 if success
   return -1 if failure */
int getname(int friendnumber, uint8_t * name);

/* set our user status
   you are responsible for freeing status after
   returns 0 on success, -1 on failure */
int m_set_userstatus(uint8_t *status, uint16_t length);

/* return the length of friendnumber's user status,
   including null
   pass it into malloc */
int m_get_userstatus_size(int friendnumber);

/* copy friendnumber's userstatus into buf, truncating if size is over maxlen
   get the size you need to allocate from m_get_userstatus_size */
int m_copy_userstatus(int friendnumber, uint8_t * buf, uint32_t maxlen);

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

/* set the callback for user status changes
   function(int friendnumber, uint8_t *newstatus, uint16_t length)
   you are not responsible for freeing newstatus */
void m_callback_userstatus(void (*function)(int, uint8_t *, uint16_t));

/* run this at startup
   returns 0 if no connection problems
   returns -1 if there are problems */
int initMessenger();


/* the main loop that needs to be run at least 200 times per second */
void doMessenger();


/* SAVING AND LOADING FUNCTIONS: */

/* returns the size of the messenger data (for saving) */
uint32_t Messenger_size();

/* save the messenger in data (must be allocated memory of size Messenger_size()) */
void Messenger_save(uint8_t * data);

/* load the messenger from data of size length */
int Messenger_load(uint8_t * data, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
