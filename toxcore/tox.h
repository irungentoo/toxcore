/* tox.h
 *
 * The Tox public API.
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

#ifndef TOX_H
#define TOX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TOX_MAX_NAME_LENGTH 128
#define TOX_MAX_STATUSMESSAGE_LENGTH 128
#define TOX_CLIENT_ID_SIZE 32

#define TOX_FRIEND_ADDRESS_SIZE (TOX_CLIENT_ID_SIZE + sizeof(uint32_t) + sizeof(uint16_t))


typedef union {
    uint8_t c[4];
    uint16_t s[2];
    uint32_t i;
} tox_IP;

typedef struct {
    tox_IP ip;
    uint16_t port;
    /* Not used for anything right now. */
    uint16_t padding;
} tox_IP_Port;

/* Status definitions. */
enum {
    TOX_NOFRIEND,
    TOX_FRIEND_ADDED,
    TOX_FRIEND_REQUESTED,
    TOX_FRIEND_CONFIRMED,
    TOX_FRIEND_ONLINE,
};

/* Errors for m_addfriend
 * FAERR - Friend Add Error
 */
enum {
    TOX_FAERR_TOOLONG = -1,
    TOX_FAERR_NOMESSAGE = -2,
    TOX_FAERR_OWNKEY = -3,
    TOX_FAERR_ALREADYSENT = -4,
    TOX_FAERR_UNKNOWN = -5,
    TOX_FAERR_BADCHECKSUM = -6,
    TOX_FAERR_SETNEWNOSPAM = -7,
    TOX_FAERR_NOMEM = -8
};

/* USERSTATUS -
 * Represents userstatuses someone can have.
 */
typedef enum {
    TOX_USERSTATUS_NONE,
    TOX_USERSTATUS_AWAY,
    TOX_USERSTATUS_BUSY,
    TOX_USERSTATUS_INVALID
}
TOX_USERSTATUS;

typedef void Tox;

/*  return FRIEND_ADDRESS_SIZE byte address to give to others.
 * format: [client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 */
void tox_getaddress(Tox *tox, uint8_t *address);

/* Add a friend.
 * Set the data that will be sent along with friend request.
 * address is the address of the friend (returned by getaddress of the friend you wish to add) it must be FRIEND_ADDRESS_SIZE bytes. TODO: add checksum.
 * data is the data and length is the length.
 *
 *  return the friend number if success.
 *  return TOX_FA_TOOLONG if message length is too long.
 *  return TOX_FAERR_NOMESSAGE if no message (message length must be >= 1 byte).
 *  return TOX_FAERR_OWNKEY if user's own key.
 *  return TOX_FAERR_ALREADYSENT if friend request already sent or already a friend.
 *  return TOX_FAERR_UNKNOWN for unknown error.
 *  return TOX_FAERR_BADCHECKSUM if bad checksum in address.
 *  return TOX_FAERR_SETNEWNOSPAM if the friend was already there but the nospam was different.
 *  (the nospam for that friend was set to the new one).
 *  return TOX_FAERR_NOMEM if increasing the friend list size fails.
 */
int tox_addfriend(Tox *tox, uint8_t *address, uint8_t *data, uint16_t length);


/* Add a friend without sending a friendrequest.
 *  return the friend number if success.
 *  return -1 if failure.
 */
int tox_addfriend_norequest(Tox *tox, uint8_t *client_id);

/*  return the friend id associated to that client id.
    return -1 if no such friend */
int tox_getfriend_id(Tox *tox, uint8_t *client_id);

/* Copies the public key associated to that friend id into client_id buffer.
 * Make sure that client_id is of size CLIENT_ID_SIZE.
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_getclient_id(Tox *tox, int friend_id, uint8_t *client_id);

/* Remove a friend. */
int tox_delfriend(Tox *tox, int friendnumber);

/*  return TOX_FRIEND_ONLINE if friend is online.
 *  return TOX_FRIEND_CONFIRMED if friend is confirmed.
 *  return TOX_FRIEND_REQUESTED if the friend request was sent.
 *  return TOX_FRIEND_ADDED if the friend was added.
 *  return TOX_NOFRIEND if there is no friend with that number.
 */
int tox_friendstatus(Tox *tox, int friendnumber);

/* Send a text chat message to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 *
 * You will want to retain the return value, it will be passed to your read receipt callback
 * if one is received.
 * m_sendmessage_withid will send a message with the id of your choosing,
 * however we can generate an id for you by calling plain m_sendmessage.
 */
uint32_t tox_sendmessage(Tox *tox, int friendnumber, uint8_t *message, uint32_t length);
uint32_t tox_sendmessage_withid(Tox *tox, int friendnumber, uint32_t theid, uint8_t *message, uint32_t length);

/* Send an action to an online friend.
 *
 *  return 1 if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
int tox_sendaction(Tox *tox, int friendnumber, uint8_t *action, uint32_t length);

/* Set our nickname.
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_setname(Tox *tox, uint8_t *name, uint16_t length);

/*
 * Get your nickname.
 * m - The messanger context to use.
 * name - Pointer to a string for the name.
 * nlen - The length of the string buffer.
 *
 *  return length of name.
 *  return 0 on error.
 */
uint16_t tox_getselfname(Tox *tox, uint8_t *name, uint16_t nlen);

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_getname(Tox *tox, int friendnumber, uint8_t *name);

/* Set our user status.
 * You are responsible for freeing status after.
 *
 *  returns 0 on success.
 *  returns -1 on failure.
 */
int tox_set_statusmessage(Tox *tox, uint8_t *status, uint16_t length);
int tox_set_userstatus(Tox *tox, TOX_USERSTATUS status);

/*  return the length of friendnumber's status message, including null.
 *  Pass it into malloc
 */
int tox_get_statusmessage_size(Tox *tox, int friendnumber);

/* Copy friendnumber's status message into buf, truncating if size is over maxlen.
 * Get the size you need to allocate from m_get_statusmessage_size.
 * The self variant will copy our own status message.
 */
int tox_copy_statusmessage(Tox *tox, int friendnumber, uint8_t *buf, uint32_t maxlen);
int tox_copy_self_statusmessage(Tox *tox, uint8_t *buf, uint32_t maxlen);

/*  return one of USERSTATUS values.
 *  Values unknown to your application should be represented as USERSTATUS_NONE.
 *  As above, the self variant will return our own USERSTATUS.
 *  If friendnumber is invalid, this shall return USERSTATUS_INVALID.
 */
TOX_USERSTATUS tox_get_userstatus(Tox *tox, int friendnumber);
TOX_USERSTATUS tox_get_selfuserstatus(Tox *tox);

/* Sets whether we send read receipts for friendnumber.
 * This function is not lazy, and it will fail if yesno is not (0 or 1).
 */
void tox_set_sends_receipts(Tox *tox, int friendnumber, int yesno);

/* Set the function that will be executed when a friend request is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, uint16_t length)
 */
void tox_callback_friendrequest(Tox *tox, void (*function)(uint8_t *, uint8_t *, uint16_t, void *), void *userdata);

/* Set the function that will be executed when a message from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * message, uint32_t length)
 */
void tox_callback_friendmessage(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *),
                                void *userdata);

/* Set the function that will be executed when an action from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * action, uint32_t length)
 */
void tox_callback_action(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *), void *userdata);

/* Set the callback for name changes.
 *  function(int friendnumber, uint8_t *newname, uint16_t length)
 *  You are not responsible for freeing newname
 */
void tox_callback_namechange(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *),
                             void *userdata);

/* Set the callback for status message changes.
 *  function(int friendnumber, uint8_t *newstatus, uint16_t length)
 *  You are not responsible for freeing newstatus.
 */
void tox_callback_statusmessage(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *),
                                void *userdata);

/* Set the callback for status type changes.
 *  function(int friendnumber, USERSTATUS kind)
 */
void tox_callback_userstatus(Tox *tox, void (*function)(Tox *tox, int, TOX_USERSTATUS, void *), void *userdata);

/* Set the callback for read receipts.
 *  function(int friendnumber, uint32_t receipt)
 *
 *  If you are keeping a record of returns from m_sendmessage;
 *  receipt might be one of those values, meaning the message
 *  has been received on the other side.
 *  Since core doesn't track ids for you, receipt may not correspond to any message.
 *  In that case, you should discard it.
 */
void tox_callback_read_receipt(Tox *tox, void (*function)(Tox *tox, int, uint32_t, void *), void *userdata);

/* Set the callback for connection status changes.
 *  function(int friendnumber, uint8_t status)
 *
 *  Status:
 *    0 -- friend went offline after being previously online
 *    1 -- friend went online
 *
 *  NOTE: This callback is not called when adding friends, thus the "after
 *  being previously online" part. it's assumed that when adding friends,
 *  their connection status is offline.
 */
void tox_callback_connectionstatus(Tox *tox, void (*function)(Tox *tox, int, uint8_t, void *), void *userdata);

/* Use this function to bootstrap the client.
 * Sends a get nodes request to the given node with ip port and public_key.
 */
void tox_bootstrap(Tox *tox, tox_IP_Port ip_port, uint8_t *public_key);

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int tox_isconnected(Tox *tox);

/* Run this at startup.
 *
 *  return allocated instance of tox on success.
 *  return 0 if there are problems.
 */
Tox *tox_new(void);

/* Run this before closing shop.
 * Free all datastructures. */
void tox_kill(Tox *tox);

/* The main loop that needs to be run at least 20 times per second. */
void tox_do(Tox *tox);

/* SAVING AND LOADING FUNCTIONS: */

/*  return size of messenger data (for saving). */
uint32_t tox_size(Tox *tox);

/* Save the messenger in data (must be allocated memory of size Messenger_size()). */
void tox_save(Tox *tox, uint8_t *data);

/* Load the messenger from data of size length. */
int tox_load(Tox *tox, uint8_t *data, uint32_t length);


#ifdef __cplusplus
}
#endif

#endif
