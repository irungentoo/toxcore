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

#define MAX_NAME_LENGTH 128
#define MAX_USERSTATUS_LENGTH 128

#define PACKET_ID_NICKNAME 48
#define PACKET_ID_USERSTATUS 49
#define PACKET_ID_MESSAGE 64

#define MIN(a,b) (((a)<(b))?(a):(b))

#define MESSENGER_PORT 33445

typedef enum Friend_status {
	NO_ADDED, /* was 0, no friend here */
	ADDED, /* was 1, friend has been added */
	REQUEST_SENT, /* was 2, friend request sent */
	CONFIRMED_FRIEND, /* was 3, friend request confirmed */
	ONLINE /* was 4, friend is online */
} Friend_status;


typedef struct Friend {
    int crypt_connection_id;
    int friend_request_id; /* id of the friend request corresponding to the current friend request to the current friend. */
    Friend_status status;

    uint16_t userstatus_length;
    uint16_t info_size; /* length of the info */

    uint8_t client_id[CLIENT_ID_SIZE];
    uint8_t info[MAX_DATA_SIZE]; /* the data that is sent during the friend requests we do */
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t name_sent; /* 0 if we didn't send our name to this friend 1 if we have. */
    uint8_t *userstatus;
    uint8_t userstatus_sent;
} Friend;


typedef struct Messenger {
	/* FIXME eventually friendlist will be a dynamically growing array */
	int numfriends; /* number of elements in use in friendlist */
	int size; /* number of elements allocated for friendlist */

	Friend *friendlist;

	/* callback functions */
	void (*friend_request)(struct Messenger *, uint8_t *, uint8_t *, uint16_t);
	void (*friend_message)(struct Messenger *, int, uint8_t *, uint16_t);
	void (*friend_namechange)(struct Messenger *, int, uint8_t *, uint16_t);
	void (*friend_statuschange)(struct Messenger *, int, uint8_t *, uint16_t);

	uint16_t self_userstatus_len;
	uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
	uint8_t self_name[MAX_NAME_LENGTH];
	uint8_t *self_userstatus;

	uint8_t friend_request_isset;
	uint8_t friend_message_isset;
	uint8_t friend_namechange_isset;
	uint8_t friend_statuschange_isset;
} Messenger;

/* don't assume MAX_USERSTATUS_LENGTH will stay at 128, it may be increased
   to an absurdly large number later */

/* add a friend
   set the data that will be sent along with friend request
   client_id is the client id of the friend
   data is the data and length is the length
   returns the friend number if success
   return -1 if failure. */
int m_addfriend(Messenger *m, uint8_t * client_id, uint8_t * data, uint16_t length);


/* add a friend without sending a friendrequest.
   returns the friend number if success
   return -1 if failure. */
int m_addfriend_norequest(Messenger *m, uint8_t * client_id);

/* return the friend id associated to that client id.
   return -1 if no such friend */
int getfriend_id(Messenger *m, uint8_t * client_id);

/* copies the public key associated to that friend id into client_id buffer.
   make sure that client_id is of size CLIENT_ID_SIZE.
   return 0 if success
   return -1 if failure */
int getclient_id(Messenger *m, int friend_id, uint8_t * client_id);

/* remove a friend */
int m_delfriend(Messenger *m, int friendnumber);

Friend_status m_friendstatus(Messenger *m, int friendnumber);


/* send a text chat message to an online friend
   returns 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendmessage(Messenger *m, int friendnumber, uint8_t * message, uint32_t length);

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   return 0 if success
   return -1 if failure */
int setname(Messenger *m, uint8_t * name, uint16_t length);


/* get name of friendnumber
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
   return 0 if success
   return -1 if failure */
int getname(Messenger *m, int friendnumber, uint8_t * name);

/* set our user status
   you are responsible for freeing status after
   returns 0 on success, -1 on failure */
int m_set_userstatus(Messenger *m, uint8_t *status, uint16_t length);

/* return the length of friendnumber's user status,
   including null
   pass it into malloc */
int m_get_userstatus_size(Messenger *m, int friendnumber);

/* copy friendnumber's userstatus into buf, truncating if size is over maxlen
   get the size you need to allocate from m_get_userstatus_size */
int m_copy_userstatus(Messenger *m, int friendnumber, uint8_t * buf, uint32_t maxlen);

/* set the function that will be executed when a friend request is received.
   function format is function(uint8_t * public_key, uint8_t * data, uint16_t length) */
void m_callback_friendrequest(Messenger *m, void (*function)(Messenger *, uint8_t *, uint8_t *, uint16_t));


/* set the function that will be executed when a message from a friend is received.
   function format is: function(int friendnumber, uint8_t * message, uint32_t length) */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *, int, uint8_t *, uint16_t));

/* set the callback for name changes
   function(int friendnumber, uint8_t *newname, uint16_t length)
   you are not responsible for freeing newname */
void m_callback_namechange(Messenger *m, void (*function)(Messenger *, int, uint8_t *, uint16_t));

/* set the callback for user status changes
   function(int friendnumber, uint8_t *newstatus, uint16_t length)
   you are not responsible for freeing newstatus */
void m_callback_userstatus(Messenger *m, void (*function)(Messenger *, int, uint8_t *, uint16_t));

/* run this at startup */
Messenger * initMessenger();

/* the main loop that needs to be run at least 200 times per second */
void doMessenger(Messenger *m);


/* SAVING AND LOADING FUNCTIONS: */

/* returns the size of the messenger data (for saving) */
uint32_t Messenger_size(Messenger *m);

/* save the messenger in data (must be allocated memory of size Messenger_size()) */
void Messenger_save(Messenger *m, uint8_t * data);

/* load the messenger from data of size length */
int Messenger_load(Messenger *m, uint8_t * data, uint32_t length);

#endif
