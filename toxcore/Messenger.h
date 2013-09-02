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

#define MAX_NAME_LENGTH 128
#define MAX_STATUSMESSAGE_LENGTH 128

#define FRIEND_ADDRESS_SIZE (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t) + sizeof(uint16_t))

#define PACKET_ID_PING 0
#define PACKET_ID_NICKNAME 48
#define PACKET_ID_STATUSMESSAGE 49
#define PACKET_ID_USERSTATUS 50
#define PACKET_ID_RECEIPT 65
#define PACKET_ID_MESSAGE 64
#define PACKET_ID_ACTION 63


/* Status definitions. */
enum {
    NOFRIEND,
    FRIEND_ADDED,
    FRIEND_REQUESTED,
    FRIEND_CONFIRMED,
    FRIEND_ONLINE,
};

/* Errors for m_addfriend
 * FAERR - Friend Add Error
 */
enum {
    FAERR_TOOLONG = -1,
    FAERR_NOMESSAGE = -2,
    FAERR_OWNKEY = -3,
    FAERR_ALREADYSENT = -4,
    FAERR_UNKNOWN = -5,
    FAERR_BADCHECKSUM = -6,
    FAERR_SETNEWNOSPAM = -7,
    FAERR_NOMEM = -8
};

/* Don't assume MAX_STATUSMESSAGE_LENGTH will stay at 128, it may be increased
 * to an absurdly large number later.
 */

/* Default start timeout in seconds between friend requests. */
#define FRIENDREQUEST_TIMEOUT 5;

/* Interval between the sending of ping packets. */
#define FRIEND_PING_INTERVAL 5

/* If no packets are recieved from friend in this time interval, kill the connection. */
#define FRIEND_CONNECTION_TIMEOUT (FRIEND_PING_INTERVAL * 2)

/* USERSTATUS -
 * Represents userstatuses someone can have.
 */

typedef enum {
    USERSTATUS_NONE,
    USERSTATUS_AWAY,
    USERSTATUS_BUSY,
    USERSTATUS_INVALID
}
USERSTATUS;

typedef struct {
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    uint64_t friendrequest_lastsent; // Time at which the last friend request was sent.
    uint32_t friendrequest_timeout; // The timeout between successful friendrequest sending attempts.
    uint8_t status; // 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online.
    uint8_t info[MAX_DATA_SIZE]; // the data that is sent during the friend requests we do.
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t name_sent; // 0 if we didn't send our name to this friend 1 if we have.
    uint8_t *statusmessage;
    uint16_t statusmessage_length;
    uint8_t statusmessage_sent;
    USERSTATUS userstatus;
    uint8_t userstatus_sent;
    uint16_t info_size; // Length of the info.
    uint32_t message_id; // a semi-unique id used in read receipts.
    uint8_t receives_read_receipts; // shall we send read receipts to this person?
    uint32_t friendrequest_nospam; // The nospam number used in the friend request.
    uint64_t ping_lastrecv;
    uint64_t ping_lastsent;
} Friend;

typedef struct Messenger {

    Networking_Core *net;
    Net_Crypto *net_crypto;
    DHT *dht;
    Friend_Requests fr;
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;

    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;

    USERSTATUS userstatus;

    Friend *friendlist;
    uint32_t numfriends;

    uint64_t last_LANdiscovery;

    void (*friend_message)(struct Messenger *m, int, uint8_t *, uint16_t, void *);
    void *friend_message_userdata;
    void (*friend_action)(struct Messenger *m, int, uint8_t *, uint16_t, void *);
    void *friend_action_userdata;
    void (*friend_namechange)(struct Messenger *m, int, uint8_t *, uint16_t, void *);
    void *friend_namechange_userdata;
    void (*friend_statusmessagechange)(struct Messenger *m, int, uint8_t *, uint16_t, void *);
    void *friend_statusmessagechange_userdata;
    void (*friend_userstatuschange)(struct Messenger *m, int, USERSTATUS, void *);
    void *friend_userstatuschange_userdata;
    void (*read_receipt)(struct Messenger *m, int, uint32_t, void *);
    void *read_receipt_userdata;
    void (*friend_statuschange)(struct Messenger *m, int, uint8_t, void *);
    void *friend_statuschange_userdata;
    void (*friend_connectionstatuschange)(struct Messenger *m, int, uint8_t, void *);
    void *friend_connectionstatuschange_userdata;


} Messenger;

/* Format: [client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 *
 *  return FRIEND_ADDRESS_SIZE byte address to give to others.
 */
void getaddress(Messenger *m, uint8_t *address);

/* Add a friend.
 * Set the data that will be sent along with friend request.
 * address is the address of the friend (returned by getaddress of the friend you wish to add) it must be FRIEND_ADDRESS_SIZE bytes. TODO: add checksum.
 * data is the data and length is the length.
 *
 *  return the friend number if success.
 *  return -1 if message length is too long.
 *  return -2 if no message (message length must be >= 1 byte).
 *  return -3 if user's own key.
 *  return -4 if friend request already sent or already a friend.
 *  return -5 for unknown error.
 *  return -6 if bad checksum in address.
 *  return -7 if the friend was already there but the nospam was different.
 *  (the nospam for that friend was set to the new one).
 *  return -8 if increasing the friend list size fails.
 */
int m_addfriend(Messenger *m, uint8_t *address, uint8_t *data, uint16_t length);


/* Add a friend without sending a friendrequest.
 *  return the friend number if success.
 *  return -1 if failure.
 */
int m_addfriend_norequest(Messenger *m, uint8_t *client_id);

/*  return the friend id associated to that client id.
 *  return -1 if no such friend.
 */
int getfriend_id(Messenger *m, uint8_t *client_id);

/* Copies the public key associated to that friend id into client_id buffer.
 * Make sure that client_id is of size CLIENT_ID_SIZE.
 *
 *  return 0 if success
 *  return -1 if failure
 */
int getclient_id(Messenger *m, int friend_id, uint8_t *client_id);

/* Remove a friend. */
int m_delfriend(Messenger *m, int friendnumber);

/*  return 4 if friend is online.
 *  return 3 if friend is confirmed.
 *  return 2 if the friend request was sent.
 *  return 1 if the friend was added.
 *  return 0 if there is no friend with that number.
 */
int m_friendstatus(Messenger *m, int friendnumber);

/* Send a text chat message to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 *
 *  You will want to retain the return value, it will be passed to your read receipt callback
 *  if one is received.
 *  m_sendmessage_withid will send a message with the id of your choosing,
 *  however we can generate an id for you by calling plain m_sendmessage.
 */
uint32_t m_sendmessage(Messenger *m, int friendnumber, uint8_t *message, uint32_t length);
uint32_t m_sendmessage_withid(Messenger *m, int friendnumber, uint32_t theid, uint8_t *message, uint32_t length);

/* Send an action to an online friend.
 *
 *  return 1 if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
int m_sendaction(Messenger *m, int friendnumber, uint8_t *action, uint32_t length);

/* Set our nickname.
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setname(Messenger *m, uint8_t *name, uint16_t length);

/*
 * Get your nickname.
 * m - The messanger context to use.
 * name - Pointer to a string for the name.
 * nlen - The length of the string buffer.
 *
 *  return length of the name.
 *  return 0 on error.
 */
uint16_t getself_name(Messenger *m, uint8_t *name, uint16_t nlen);

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int getname(Messenger *m, int friendnumber, uint8_t *name);

/* Set our user status.
 * You are responsible for freeing status after.
 *
 *  returns 0 on success.
 *  returns -1 on failure.
 */
int m_set_statusmessage(Messenger *m, uint8_t *status, uint16_t length);
int m_set_userstatus(Messenger *m, USERSTATUS status);

/*  return the length of friendnumber's status message, including null.
 *  Pass it into malloc.
 */
int m_get_statusmessage_size(Messenger *m, int friendnumber);

/* Copy friendnumber's status message into buf, truncating if size is over maxlen.
 * Get the size you need to allocate from m_get_statusmessage_size.
 * The self variant will copy our own status message.
 */
int m_copy_statusmessage(Messenger *m, int friendnumber, uint8_t *buf, uint32_t maxlen);
int m_copy_self_statusmessage(Messenger *m, uint8_t *buf, uint32_t maxlen);

/*  return one of USERSTATUS values.
 *  Values unknown to your application should be represented as USERSTATUS_NONE.
 *  As above, the self variant will return our own USERSTATUS.
 *  If friendnumber is invalid, this shall return USERSTATUS_INVALID.
 */
USERSTATUS m_get_userstatus(Messenger *m, int friendnumber);
USERSTATUS m_get_self_userstatus(Messenger *m);

/* Sets whether we send read receipts for friendnumber.
 * This function is not lazy, and it will fail if yesno is not (0 or 1).
 */
void m_set_sends_receipts(Messenger *m, int friendnumber, int yesno);

/* Set the function that will be executed when a friend request is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, uint16_t length)
 */
void m_callback_friendrequest(Messenger *m, void (*function)(uint8_t *, uint8_t *, uint16_t, void *), void *userdata);

/* Set the function that will be executed when a message from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * message, uint32_t length)
 */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                              void *userdata);

/* Set the function that will be executed when an action from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * action, uint32_t length)
 */
void m_callback_action(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *), void *userdata);

/* Set the callback for name changes.
 *  Function(int friendnumber, uint8_t *newname, uint16_t length)
 *  You are not responsible for freeing newname.
 */
void m_callback_namechange(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                           void *userdata);

/* Set the callback for status message changes.
 *  Function(int friendnumber, uint8_t *newstatus, uint16_t length)
 *
 *  You are not responsible for freeing newstatus
 */
void m_callback_statusmessage(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                              void *userdata);

/* Set the callback for status type changes.
 *  Function(int friendnumber, USERSTATUS kind)
 */
void m_callback_userstatus(Messenger *m, void (*function)(Messenger *m, int, USERSTATUS, void *), void *userdata);

/* Set the callback for read receipts.
 *  Function(int friendnumber, uint32_t receipt)
 *
 *  If you are keeping a record of returns from m_sendmessage,
 *  receipt might be one of those values, meaning the message
 *  has been received on the other side.
 *  Since core doesn't track ids for you, receipt may not correspond to any message.
 *  In that case, you should discard it.
 */
void m_callback_read_receipt(Messenger *m, void (*function)(Messenger *m, int, uint32_t, void *), void *userdata);

/* Set the callback for connection status changes.
 *  function(int friendnumber, uint8_t status)
 *
 *  Status:
 *    0 -- friend went offline after being previously online.
 *    1 -- friend went online.
 *
 *  Note that this callback is not called when adding friends, thus the "after
 *  being previously online" part.
 *  It's assumed that when adding friends, their connection status is offline.
 */
void m_callback_connectionstatus(Messenger *m, void (*function)(Messenger *m, int, uint8_t, void *), void *userdata);

/* Run this at startup.
 *  return allocated instance of Messenger on success.
 *  return 0 if there are problems.
 */
Messenger *initMessenger(void);

/* Run this before closing shop
 * Free all datastructures.
 */
void cleanupMessenger(Messenger *M);

/* The main loop that needs to be run at least 20 times per second. */
void doMessenger(Messenger *m);

/* SAVING AND LOADING FUNCTIONS: */

/* return size of the messenger data (for saving). */
uint32_t Messenger_size(Messenger *m);

/* Save the messenger in data (must be allocated memory of size Messenger_size()) */
void Messenger_save(Messenger *m, uint8_t *data);

/* Load the messenger from data of size length. */
int Messenger_load(Messenger *m, uint8_t *data, uint32_t length);


#endif
