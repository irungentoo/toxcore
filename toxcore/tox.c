/* tox.c
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

#include "Messenger.h"
/*
 * returns a FRIEND_ADDRESS_SIZE byte address to give to others.
 * Format: [client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 *
 */
void tox_getaddress(void *tox, uint8_t *address)
{
    Messenger *m = tox;
    getaddress(m, address);
}

/*
 * Add a friend.
 * Set the data that will be sent along with friend request.
 * address is the address of the friend (returned by getaddress of the friend you wish to add) it must be FRIEND_ADDRESS_SIZE bytes. TODO: add checksum.
 * data is the data and length is the length.
 *
 *  return the friend number if success.
 *  return FA_TOOLONG if message length is too long.
 *  return FAERR_NOMESSAGE if no message (message length must be >= 1 byte).
 *  return FAERR_OWNKEY if user's own key.
 *  return FAERR_ALREADYSENT if friend request already sent or already a friend.
 *  return FAERR_UNKNOWN for unknown error.
 *  return FAERR_BADCHECKSUM if bad checksum in address.
 *  return FAERR_SETNEWNOSPAM if the friend was already there but the nospam was different.
 *  (the nospam for that friend was set to the new one).
 *  return FAERR_NOMEM if increasing the friend list size fails.
 */
int tox_addfriend(void *tox, uint8_t *address, uint8_t *data, uint16_t length)
{
    Messenger *m = tox;
    return m_addfriend(m, address, data, length);
}

/* Add a friend without sending a friendrequest.
 *
 *  return the friend number if success.
 *  return -1 if failure.
 */
int tox_addfriend_norequest(void *tox, uint8_t *client_id)
{
    Messenger *m = tox;
    return m_addfriend_norequest(m, client_id);
}

/*  return the friend id associated to that client id.
 *  return -1 if no such friend.
 */
int tox_getfriend_id(void *tox, uint8_t *client_id)
{
    Messenger *m = tox;
    return getfriend_id(m, client_id);
}

/* Copies the public key associated to that friend id into client_id buffer.
 * Make sure that client_id is of size CLIENT_ID_SIZE.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_getclient_id(void *tox, int friend_id, uint8_t *client_id)
{
    Messenger *m = tox;
    return getclient_id(m, friend_id, client_id);
}

/* Remove a friend. */
int tox_delfriend(void *tox, int friendnumber)
{
    Messenger *m = tox;
    return m_delfriend(m, friendnumber);
}

/*  return 4 if friend is online.
 *  return 3 if friend is confirmed.
 *  return 2 if the friend request was sent.
 *  return 1 if the friend was added.
 *  return 0 if there is no friend with that number.
 */
int tox_friendstatus(void *tox, int friendnumber)
{
    Messenger *m = tox;
    return m_friendstatus(m, friendnumber);
}

/* Send a text chat message to an online friend.
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 *
 *  You will want to retain the return value, it will be passed to your read receipt callback
 *  if one is received.
 *  m_sendmessage_withid will send a message with the id of your choosing,
 *  however we can generate an id for you by calling plain m_sendmessage.
 */
uint32_t tox_sendmessage(void *tox, int friendnumber, uint8_t *message, uint32_t length)
{
    Messenger *m = tox;
    return m_sendmessage(m, friendnumber, message, length);
}

uint32_t tox_sendmessage_withid(void *tox, int friendnumber, uint32_t theid, uint8_t *message, uint32_t length)
{
    Messenger *m = tox;
    return m_sendmessage_withid(m, friendnumber, theid, message, length);
}

/* Send an action to an online friend.
 *  return 1 if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
int tox_sendaction(void *tox, int friendnumber, uint8_t *action, uint32_t length)
{
    Messenger *m = tox;
    return m_sendaction(m, friendnumber, action, length);
}

/* Set our nickname.
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_setname(void *tox, uint8_t *name, uint16_t length)
{
    Messenger *m = tox;
    return setname(m, name, length);
}

/* Get your nickname.
 * m -  The messanger context to use.
 * name - Pointer to a string for the name.
 * nlen -  The length of the string buffer.
 *
 *  return length of the name.
 *  return 0 on error.
 */
uint16_t tox_getselfname(void *tox, uint8_t *name, uint16_t nlen)
{
    Messenger *m = tox;
    return getself_name(m, name, nlen);
}

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_getname(void *tox, int friendnumber, uint8_t *name)
{
    Messenger *m = tox;
    return getname(m, friendnumber, name);
}

/* Set our user status;
 * you are responsible for freeing status after.
 *
 *  return 0 on success, -1 on failure.
 */
int tox_set_statusmessage(void *tox, uint8_t *status, uint16_t length)
{
    Messenger *m = tox;
    return m_set_statusmessage(m, status, length);
}

int tox_set_userstatus(void *tox, USERSTATUS status)
{
    Messenger *m = tox;
    return m_set_userstatus(m, status);
}

/*  return the length of friendnumber's status message, including null.
 *  Pass it into malloc.
 */
int tox_get_statusmessage_size(void *tox, int friendnumber)
{
    Messenger *m = tox;
    return m_get_statusmessage_size(m, friendnumber);
}

/* Copy friendnumber's status message into buf, truncating if size is over maxlen.
 * Get the size you need to allocate from m_get_statusmessage_size.
 * The self variant will copy our own status message.
 */
int tox_copy_statusmessage(void *tox, int friendnumber, uint8_t *buf, uint32_t maxlen)
{
    Messenger *m = tox;
    return m_copy_statusmessage(m, friendnumber, buf, maxlen);
}

int tox_copy_self_statusmessage(void *tox, uint8_t *buf, uint32_t maxlen)
{
    Messenger *m = tox;
    return m_copy_self_statusmessage(m, buf, maxlen);
}

/* Return one of USERSTATUS values.
 * Values unknown to your application should be represented as USERSTATUS_NONE.
 * As above, the self variant will return our own USERSTATUS.
 * If friendnumber is invalid, this shall return USERSTATUS_INVALID.
 */
USERSTATUS tox_get_userstatus(void *tox, int friendnumber)
{
    Messenger *m = tox;
    return m_get_userstatus(m, friendnumber);
}

USERSTATUS tox_get_selfuserstatus(void *tox)
{
    Messenger *m = tox;
    return m_get_self_userstatus(m);
}


/* Sets whether we send read receipts for friendnumber.
 * This function is not lazy, and it will fail if yesno is not (0 or 1).
 */
void tox_set_sends_receipts(void *tox, int friendnumber, int yesno)
{
    Messenger *m = tox;
    m_set_sends_receipts(m, friendnumber, yesno);
}


/* Set the function that will be executed when a friend request is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, uint16_t length)
 */
void tox_callback_friendrequest(void *tox, void (*function)(uint8_t *, uint8_t *, uint16_t, void *), void *userdata)
{
    Messenger *m = tox;
    m_callback_friendrequest(m, function, userdata);
}


/* Set the function that will be executed when a message from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * message, uint32_t length)
 */
void tox_callback_friendmessage(void *tox, void (*function)(Messenger *tox, int, uint8_t *, uint16_t, void *),
                                void *userdata)
{
    Messenger *m = tox;
    m_callback_friendmessage(m, function, userdata);
}

/* Set the function that will be executed when an action from a friend is received.
 *  function format is: function(int friendnumber, uint8_t * action, uint32_t length)
 */
void tox_callback_action(void *tox, void (*function)(Messenger *tox, int, uint8_t *, uint16_t, void *), void *userdata)
{
    Messenger *m = tox;
    m_callback_action(m, function, userdata);
}

/* Set the callback for name changes.
 *  function(int friendnumber, uint8_t *newname, uint16_t length)
 *  You are not responsible for freeing newname.
 */
void tox_callback_namechange(void *tox, void (*function)(Messenger *tox, int, uint8_t *, uint16_t, void *),
                             void *userdata)
{
    Messenger *m = tox;
    m_callback_namechange(m, function, userdata);
}

/* Set the callback for status message changes.
 *  function(int friendnumber, uint8_t *newstatus, uint16_t length)
 *  You are not responsible for freeing newstatus.
 */
void tox_callback_statusmessage(void *tox, void (*function)(Messenger *tox, int, uint8_t *, uint16_t, void *),
                                void *userdata)
{
    Messenger *m = tox;
    m_callback_statusmessage(m, function, userdata);
}

/* Set the callback for status type changes.
 *  function(int friendnumber, USERSTATUS kind)
 */
void tox_callback_userstatus(void *tox, void (*function)(Messenger *tox, int, USERSTATUS, void *), void *userdata)
{
    Messenger *m = tox;
    m_callback_userstatus(m, function, userdata);
}

/* Set the callback for read receipts.
 *  function(int friendnumber, uint32_t receipt)
 *
 *  If you are keeping a record of returns from m_sendmessage;
 *  receipt might be one of those values, meaning the message
 *  has been received on the other side.
 *  Since core doesn't track ids for you, receipt may not correspond to any message.
 *  in that case, you should discard it.
 */
void tox_callback_read_receipt(void *tox, void (*function)(Messenger *tox, int, uint32_t, void *), void *userdata)
{
    Messenger *m = tox;
    m_callback_read_receipt(m, function, userdata);
}

/* Set the callback for connection status changes.
 *  function(int friendnumber, uint8_t status)
 *
 *  Status:
 *    0 -- friend went offline after being previously online
 *    1 -- friend went online
 *
 *  NOTE: this callback is not called when adding friends, thus the "after
 *  being previously online" part. It's assumed that when adding friends,
 *  their connection status is offline.
 */
void tox_callback_connectionstatus(void *tox, void (*function)(Messenger *tox, int, uint8_t, void *), void *userdata)
{
    Messenger *m = tox;
    m_callback_connectionstatus(m, function, userdata);
}

/* Use this function to bootstrap the client.
 * Sends a get nodes request to the given node with ip port and public_key.
 */
void tox_bootstrap(void *tox, IP_Port ip_port, uint8_t *public_key)
{
    Messenger *m = tox;
    DHT_bootstrap(m->dht, ip_port, public_key);
}

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int tox_isconnected(void *tox)
{
    Messenger *m = tox;
    return DHT_isconnected(m->dht);
}

/* Run this at startup.
 *
 *  return allocated instance of tox on success.
 *  return 0 if there are problems.
 */
void *tox_new(void)
{
    return initMessenger();
}

/* Run this before closing shop.
 * Free all datastructures.
 */
void tox_kill(void *tox)
{
    Messenger *m = tox;
    cleanupMessenger(m);
}

/* The main loop that needs to be run at least 20 times per second. */
void tox_do(void *tox)
{
    Messenger *m = tox;
    doMessenger(m);
}

/* SAVING AND LOADING FUNCTIONS: */

/*  return size of the messenger data (for saving). */
uint32_t tox_size(void *tox)
{
    Messenger *m = tox;
    return Messenger_size(m);
}

/* Save the messenger in data (must be allocated memory of size Messenger_size()). */
void tox_save(void *tox, uint8_t *data)
{
    Messenger *m = tox;
    Messenger_save(m, data);
}

/* Load the messenger from data of size length. */
int tox_load(void *tox, uint8_t *data, uint32_t length)
{
    Messenger *m = tox;
    return Messenger_load(m, data, length);
}

