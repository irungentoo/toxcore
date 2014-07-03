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
#include "group_chats.h"
#include "onion_client.h"

#define MAX_NAME_LENGTH 128
/* TODO: this must depend on other variable. */
#define MAX_STATUSMESSAGE_LENGTH 1007

#define FRIEND_ADDRESS_SIZE (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t) + sizeof(uint16_t))

/* NOTE: Packet ids below 16 must never be used. */
#define PACKET_ID_ALIVE 16
#define PACKET_ID_SHARE_RELAYS 17
#define PACKET_ID_NICKNAME 48
#define PACKET_ID_STATUSMESSAGE 49
#define PACKET_ID_USERSTATUS 50
#define PACKET_ID_TYPING 51
#define PACKET_ID_RECEIPT 63
#define PACKET_ID_MESSAGE 64
#define PACKET_ID_ACTION 65
#define PACKET_ID_MSI 69
#define PACKET_ID_FILE_SENDREQUEST 80
#define PACKET_ID_FILE_CONTROL 81
#define PACKET_ID_FILE_DATA 82
#define PACKET_ID_INVITE_GROUPCHAT 144
#define PACKET_ID_JOIN_GROUPCHAT 145
#define PACKET_ID_ACCEPT_GROUPCHAT 146

/* Max number of groups we can invite someone at the same time to. */
#define MAX_INVITED_GROUPS 64

/* Max number of tcp relays sent to friends */
#define MAX_SHARED_RELAYS 16

/* All packets starting with a byte in this range can be used for anything. */
#define PACKET_ID_LOSSLESS_RANGE_START 160
#define PACKET_ID_LOSSLESS_RANGE_SIZE 32

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

/* Default start timeout in seconds between friend requests. */
#define FRIENDREQUEST_TIMEOUT 5;

/* Interval between the sending of ping packets. */
#define FRIEND_PING_INTERVAL 5

/* Interval between the sending of tcp relay information */
#define FRIEND_SHARE_RELAYS_INTERVAL (5 * 60)

/* If no packets are received from friend in this time interval, kill the connection. */
#define FRIEND_CONNECTION_TIMEOUT (FRIEND_PING_INTERVAL * 3)


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

struct File_Transfers {
    uint64_t size;
    uint64_t transferred;
    uint8_t status; /* 0 == no transfer, 1 = not accepted, 2 = paused by the other, 3 = transferring, 4 = broken, 5 = paused by us */
};
enum {
    FILESTATUS_NONE,
    FILESTATUS_NOT_ACCEPTED,
    FILESTATUS_PAUSED_BY_OTHER,
    FILESTATUS_TRANSFERRING,
    FILESTATUS_BROKEN,
    FILESTATUS_PAUSED_BY_US,
    FILESTATUS_TEMPORARY
};
/* This cannot be bigger than 256 */
#define MAX_CONCURRENT_FILE_PIPES 256

enum {
    FILECONTROL_ACCEPT,
    FILECONTROL_PAUSE,
    FILECONTROL_KILL,
    FILECONTROL_FINISHED,
    FILECONTROL_RESUME_BROKEN
};

typedef struct {
    uint8_t client_id[CLIENT_ID_SIZE];
    uint32_t onion_friendnum;
    int crypt_connection_id;
    uint64_t friendrequest_lastsent; // Time at which the last friend request was sent.
    uint32_t friendrequest_timeout; // The timeout between successful friendrequest sending attempts.
    uint8_t status; // 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online.
    uint8_t info[MAX_FRIEND_REQUEST_DATA_SIZE]; // the data that is sent during the friend requests we do.
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;
    uint8_t name_sent; // 0 if we didn't send our name to this friend 1 if we have.
    uint8_t *statusmessage;
    uint16_t statusmessage_length;
    uint8_t statusmessage_sent;
    USERSTATUS userstatus;
    uint8_t userstatus_sent;
    uint8_t user_istyping;
    uint8_t user_istyping_sent;
    uint8_t is_typing;
    uint16_t info_size; // Length of the info.
    uint32_t message_id; // a semi-unique id used in read receipts.
    uint8_t receives_read_receipts; // shall we send read receipts to this person?
    uint32_t friendrequest_nospam; // The nospam number used in the friend request.
    uint64_t ping_lastrecv;
    uint64_t ping_lastsent;
    uint64_t share_relays_lastsent;
    struct File_Transfers file_sending[MAX_CONCURRENT_FILE_PIPES];
    struct File_Transfers file_receiving[MAX_CONCURRENT_FILE_PIPES];
    int invited_groups[MAX_INVITED_GROUPS];
    uint16_t invited_groups_num;

    struct {
        int (*function)(void *object, const uint8_t *data, uint32_t len);
        void *object;
    } lossy_packethandlers[PACKET_ID_LOSSY_RANGE_SIZE];

    struct {
        int (*function)(void *object, const uint8_t *data, uint32_t len);
        void *object;
    } lossless_packethandlers[PACKET_ID_LOSSLESS_RANGE_SIZE];
} Friend;


typedef struct Messenger {

    Networking_Core *net;
    Net_Crypto *net_crypto;
    DHT *dht;

    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;

    Friend_Requests fr;
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;

    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;

    USERSTATUS userstatus;

    Friend *friendlist;
    uint32_t numfriends;

    uint32_t numonline_friends;

    Group_Chat **chats;
    uint32_t numchats;

    uint64_t last_LANdiscovery;

    void (*friend_message)(struct Messenger *m, int32_t, const uint8_t *, uint16_t, void *);
    void *friend_message_userdata;
    void (*friend_action)(struct Messenger *m, int32_t, const uint8_t *, uint16_t, void *);
    void *friend_action_userdata;
    void (*friend_namechange)(struct Messenger *m, int32_t, const uint8_t *, uint16_t, void *);
    void *friend_namechange_userdata;
    void (*friend_statusmessagechange)(struct Messenger *m, int32_t, const uint8_t *, uint16_t, void *);
    void *friend_statusmessagechange_userdata;
    void (*friend_userstatuschange)(struct Messenger *m, int32_t, uint8_t, void *);
    void *friend_userstatuschange_userdata;
    void (*friend_typingchange)(struct Messenger *m, int32_t, uint8_t, void *);
    void *friend_typingchange_userdata;
    void (*read_receipt)(struct Messenger *m, int32_t, uint32_t, void *);
    void *read_receipt_userdata;
    void (*friend_statuschange)(struct Messenger *m, int32_t, uint8_t, void *);
    void *friend_statuschange_userdata;
    void (*friend_connectionstatuschange)(struct Messenger *m, int32_t, uint8_t, void *);
    void *friend_connectionstatuschange_userdata;
    void (*friend_connectionstatuschange_internal)(struct Messenger *m, int32_t, uint8_t, void *);
    void *friend_connectionstatuschange_internal_userdata;

    void (*group_invite)(struct Messenger *m, int32_t, const uint8_t *, void *);
    void *group_invite_userdata;
    void (*group_message)(struct Messenger *m, int, int, const uint8_t *, uint16_t, void *);
    void *group_message_userdata;
    void (*group_action)(struct Messenger *m, int, int, const uint8_t *, uint16_t, void *);
    void *group_action_userdata;
    void (*group_namelistchange)(struct Messenger *m, int, int, uint8_t, void *);
    void *group_namelistchange_userdata;

    void (*file_sendrequest)(struct Messenger *m, int32_t, uint8_t, uint64_t, const uint8_t *, uint16_t, void *);
    void *file_sendrequest_userdata;
    void (*file_filecontrol)(struct Messenger *m, int32_t, uint8_t, uint8_t, uint8_t, const uint8_t *, uint16_t, void *);
    void *file_filecontrol_userdata;
    void (*file_filedata)(struct Messenger *m, int32_t, uint8_t, const uint8_t *, uint16_t length, void *);
    void *file_filedata_userdata;

    void (*msi_packet)(struct Messenger *m, int32_t, const uint8_t *, uint16_t, void *);
    void *msi_packet_userdata;

} Messenger;

/* Format: [client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 *
 *  return FRIEND_ADDRESS_SIZE byte address to give to others.
 */
void getaddress(const Messenger *m, uint8_t *address);

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
int32_t m_addfriend(Messenger *m, const uint8_t *address, const uint8_t *data, uint16_t length);


/* Add a friend without sending a friendrequest.
 *  return the friend number if success.
 *  return -1 if failure.
 */
int32_t m_addfriend_norequest(Messenger *m, const uint8_t *client_id);

/*  return the friend number associated to that client id.
 *  return -1 if no such friend.
 */
int32_t getfriend_id(const Messenger *m, const uint8_t *client_id);

/* Copies the public key associated to that friend id into client_id buffer.
 * Make sure that client_id is of size CLIENT_ID_SIZE.
 *
 *  return 0 if success
 *  return -1 if failure
 */
int getclient_id(const Messenger *m, int32_t friendnumber, uint8_t *client_id);

/* Remove a friend.
 *
 *  return 0 if success
 *  return -1 if failure
 */
int m_delfriend(Messenger *m, int32_t friendnumber);

/* Checks friend's connecting status.
 *
 *  return 1 if friend is connected to us (Online).
 *  return 0 if friend is not connected to us (Offline).
 *  return -1 on failure.
 */
int m_get_friend_connectionstatus(const Messenger *m, int32_t friendnumber);

/* Checks if there exists a friend with given friendnumber.
 *
 *  return 1 if friend exists.
 *  return 0 if friend doesn't exist.
 */
int m_friend_exists(const Messenger *m, int32_t friendnumber);

/* Send a text chat message to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 *
 *  You will want to retain the return value, it will be passed to your read_receipt callback
 *  if one is received.
 *  m_sendmessage_withid will send a message with the id of your choosing,
 *  however we can generate an id for you by calling plain m_sendmessage.
 */
uint32_t m_sendmessage(Messenger *m, int32_t friendnumber, const uint8_t *message, uint32_t length);
uint32_t m_sendmessage_withid(Messenger *m, int32_t friendnumber, uint32_t theid, const uint8_t *message,
                              uint32_t length);

/* Send an action to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 *
 *  You will want to retain the return value, it will be passed to your read_receipt callback
 *  if one is received.
 *  m_sendaction_withid will send an action message with the id of your choosing,
 *  however we can generate an id for you by calling plain m_sendaction.
 */
uint32_t m_sendaction(Messenger *m, int32_t friendnumber, const uint8_t *action, uint32_t length);
uint32_t m_sendaction_withid(const Messenger *m, int32_t friendnumber, uint32_t theid, const uint8_t *action,
                             uint32_t length);

/* Set the name and name_length of a friend.
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setfriendname(Messenger *m, int32_t friendnumber, const uint8_t *name, uint16_t length);

/* Set our nickname.
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setname(Messenger *m, const uint8_t *name, uint16_t length);

/*
 * Get your nickname.
 * m - The messenger context to use.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return length of the name.
 *  return 0 on error.
 */
uint16_t getself_name(const Messenger *m, uint8_t *name);

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return length of name if success.
 *  return -1 if failure.
 */
int getname(const Messenger *m, int32_t friendnumber, uint8_t *name);

/*  return the length of name, including null on success.
 *  return -1 on failure.
 */
int m_get_name_size(const Messenger *m, int32_t friendnumber);
int m_get_self_name_size(const Messenger *m);

/* Set our user status.
 * You are responsible for freeing status after.
 *
 *  returns 0 on success.
 *  returns -1 on failure.
 */
int m_set_statusmessage(Messenger *m, const uint8_t *status, uint16_t length);
int m_set_userstatus(Messenger *m, uint8_t status);

/*  return the length of friendnumber's status message, including null on success.
 *  return -1 on failure.
 */
int m_get_statusmessage_size(const Messenger *m, int32_t friendnumber);
int m_get_self_statusmessage_size(const Messenger *m);

/* Copy friendnumber's status message into buf, truncating if size is over maxlen.
 * Get the size you need to allocate from m_get_statusmessage_size.
 * The self variant will copy our own status message.
 *
 * returns the length of the copied data on success
 * retruns -1 on failure.
 */
int m_copy_statusmessage(const Messenger *m, int32_t friendnumber, uint8_t *buf, uint32_t maxlen);
int m_copy_self_statusmessage(const Messenger *m, uint8_t *buf, uint32_t maxlen);

/*  return one of USERSTATUS values.
 *  Values unknown to your application should be represented as USERSTATUS_NONE.
 *  As above, the self variant will return our own USERSTATUS.
 *  If friendnumber is invalid, this shall return USERSTATUS_INVALID.
 */
uint8_t m_get_userstatus(const Messenger *m, int32_t friendnumber);
uint8_t m_get_self_userstatus(const Messenger *m);

/* returns timestamp of last time friendnumber was seen online, or 0 if never seen.
 * returns -1 on error.
 */
uint64_t m_get_last_online(const Messenger *m, int32_t friendnumber);

/* Set our typing status for a friend.
 * You are responsible for turning it on or off.
 *
 * returns 0 on success.
 * returns -1 on failure.
 */
int m_set_usertyping(Messenger *m, int32_t friendnumber, uint8_t is_typing);

/* Get the typing status of a friend.
 *
 * returns 0 if friend is not typing.
 * returns 1 if friend is typing.
 */
uint8_t m_get_istyping(const Messenger *m, int32_t friendnumber);

/* Sets whether we send read receipts for friendnumber.
 * This function is not lazy, and it will fail if yesno is not (0 or 1).
 */
void m_set_sends_receipts(Messenger *m, int32_t friendnumber, int yesno);

/* Set the function that will be executed when a friend request is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, uint16_t length)
 */
void m_callback_friendrequest(Messenger *m, void (*function)(Messenger *m, const uint8_t *, const uint8_t *, uint16_t,
                              void *), void *userdata);

/* Set the function that will be executed when a message from a friend is received.
 *  Function format is: function(int32_t friendnumber, uint8_t * message, uint32_t length)
 */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                              void *userdata);

/* Set the function that will be executed when an action from a friend is received.
 *  Function format is: function(int32_t friendnumber, uint8_t * action, uint32_t length)
 */
void m_callback_action(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                       void *userdata);

/* Set the callback for name changes.
 *  Function(int32_t friendnumber, uint8_t *newname, uint16_t length)
 *  You are not responsible for freeing newname.
 */
void m_callback_namechange(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                           void *userdata);

/* Set the callback for status message changes.
 *  Function(int32_t friendnumber, uint8_t *newstatus, uint16_t length)
 *
 *  You are not responsible for freeing newstatus
 */
void m_callback_statusmessage(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                              void *userdata);

/* Set the callback for status type changes.
 *  Function(int32_t friendnumber, USERSTATUS kind)
 */
void m_callback_userstatus(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, void *), void *userdata);

/* Set the callback for typing changes.
 *  Function(int32_t friendnumber, uint8_t is_typing)
 */
void m_callback_typingchange(Messenger *m, void(*function)(Messenger *m, int32_t, uint8_t, void *), void *userdata);

/* Set the callback for read receipts.
 *  Function(int32_t friendnumber, uint32_t receipt)
 *
 *  If you are keeping a record of returns from m_sendmessage,
 *  receipt might be one of those values, meaning the message
 *  has been received on the other side.
 *  Since core doesn't track ids for you, receipt may not correspond to any message.
 *  In that case, you should discard it.
 */
void m_callback_read_receipt(Messenger *m, void (*function)(Messenger *m, int32_t, uint32_t, void *), void *userdata);

/* Set the callback for connection status changes.
 *  function(int32_t friendnumber, uint8_t status)
 *
 *  Status:
 *    0 -- friend went offline after being previously online.
 *    1 -- friend went online.
 *
 *  Note that this callback is not called when adding friends, thus the "after
 *  being previously online" part.
 *  It's assumed that when adding friends, their connection status is offline.
 */
void m_callback_connectionstatus(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, void *),
                                 void *userdata);
/* Same as previous but for internal A/V core usage only */
void m_callback_connectionstatus_internal_av(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, void *),
        void *userdata);

/**********GROUP CHATS************/

/* Set the callback for group invites.
 *
 *  Function(Messenger *m, int32_t friendnumber, uint8_t *group_public_key, void *userdata)
 */
void m_callback_group_invite(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, void *),
                             void *userdata);

/* Set the callback for group messages.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void m_callback_group_message(Messenger *m, void (*function)(Messenger *m, int, int, const uint8_t *, uint16_t, void *),
                              void *userdata);

/* Set the callback for group actions.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void m_callback_group_action(Messenger *m, void (*function)(Messenger *m, int, int, const uint8_t *, uint16_t, void *),
                             void *userdata);

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Tox *tox, int groupnumber, void *userdata)
 */
void m_callback_group_namelistchange(Messenger *m, void (*function)(Messenger *m, int, int, uint8_t, void *),
                                     void *userdata);

/* Creates a new groupchat and puts it in the chats array.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Messenger *m);

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
int del_groupchat(Messenger *m, int groupnumber);

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
int m_group_peername(const Messenger *m, int groupnumber, int peernumber, uint8_t *name);

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
int invite_friend(Messenger *m, int32_t friendnumber, int groupnumber);

/* Join a group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_groupchat(Messenger *m, int32_t friendnumber, const uint8_t *friend_group_public_key);

/* send a group message
 * return 0 on success
 * return -1 on failure
 */
int group_message_send(const Messenger *m, int groupnumber, const uint8_t *message, uint32_t length);

/* send a group action
 * return 0 on success
 * return -1 on failure
 */
int group_action_send(const Messenger *m, int groupnumber, const uint8_t *action, uint32_t length);

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
int group_number_peers(const Messenger *m, int groupnumber);

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NICK_BYTES] array.
 *
 * Copies the lengths of the names to lengths[length]
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int group_names(const Messenger *m, int groupnumber, uint8_t names[][MAX_NICK_BYTES], uint16_t lengths[],
                uint16_t length);

/****************FILE SENDING*****************/


/* Set the callback for file send requests.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t filenumber, uint64_t filesize, uint8_t *filename, uint16_t filename_length, void *userdata)
 */
void callback_file_sendrequest(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, uint64_t, const uint8_t *,
                               uint16_t, void *), void *userdata);

/* Set the callback for file control requests.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t control_type, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void callback_file_control(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, uint8_t, uint8_t,
                           const uint8_t *, uint16_t, void *), void *userdata);

/* Set the callback for file data.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void callback_file_data(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, const uint8_t *, uint16_t length,
                        void *), void *userdata);

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return 1 on success
 *  return 0 on failure
 */
int file_sendrequest(const Messenger *m, int32_t friendnumber, uint8_t filenumber, uint64_t filesize,
                     const uint8_t *filename, uint16_t filename_length);

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return file number on success
 *  return -1 on failure
 */
int new_filesender(const Messenger *m, int32_t friendnumber, uint64_t filesize, const uint8_t *filename,
                   uint16_t filename_length);

/* Send a file control request.
 * send_receive is 0 if we want the control packet to target a sending file, 1 if it targets a receiving file.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int file_control(const Messenger *m, int32_t friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t message_id,
                 const uint8_t *data, uint16_t length);

/* Send file data.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int file_data(const Messenger *m, int32_t friendnumber, uint8_t filenumber, const uint8_t *data, uint16_t length);

/* Give the number of bytes left to be sent/received.
 *
 *  send_receive is 0 if we want the sending files, 1 if we want the receiving.
 *
 *  return number of bytes remaining to be sent/received on success
 *  return 0 on failure
 */
uint64_t file_dataremaining(const Messenger *m, int32_t friendnumber, uint8_t filenumber, uint8_t send_receive);

/*************** A/V related ******************/

/* Set the callback for msi packets.
 *
 *  Function(Messenger *m, int32_t friendnumber, uint8_t *data, uint16_t length, void *userdata)
 */
void m_callback_msi_packet(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                           void *userdata);

/* Send an msi packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int m_msi_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length);

/**********************************************/

/* Set handlers for custom lossy packets (RTP packets for example.)
 *
 * return -1 on failure.
 * return 0 on success.
 */
int custom_lossy_packet_registerhandler(Messenger *m, int32_t friendnumber, uint8_t byte,
                                        int (*packet_handler_callback)(void *object, const uint8_t *data, uint32_t len), void *object);

/* High level function to send custom lossy packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_custom_lossy_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length);


/* Set handlers for custom lossless packets.
 *
 * byte must be in PACKET_ID_LOSSLESS_RANGE_START PACKET_ID_LOSSLESS_RANGE_SIZE range.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int custom_lossless_packet_registerhandler(Messenger *m, int32_t friendnumber, uint8_t byte,
        int (*packet_handler_callback)(void *object, const uint8_t *data, uint32_t len), void *object);

/* High level function to send custom lossless packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_custom_lossless_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length);

/**********************************************/
/* Run this at startup.
 *  return allocated instance of Messenger on success.
 *  return 0 if there are problems.
 */
Messenger *new_messenger(uint8_t ipv6enabled);

/* Run this before closing shop
 * Free all datastructures.
 */
void kill_messenger(Messenger *M);

/* The main loop that needs to be run at least 20 times per second. */
void do_messenger(Messenger *m);

/* Return the time in milliseconds before do_messenger() should be called again
 * for optimal performance.
 *
 * returns time (in ms) before the next do_messenger() needs to be run on success.
 */
uint32_t messenger_run_interval(Messenger *m);

/* SAVING AND LOADING FUNCTIONS: */

/* return size of the messenger data (for saving). */
uint32_t messenger_size(const Messenger *m);

/* Save the messenger in data (must be allocated memory of size Messenger_size()) */
void messenger_save(const Messenger *m, uint8_t *data);

/* Load the messenger from data of size length. */
int messenger_load(Messenger *m, const uint8_t *data, uint32_t length);

/* Return the number of friends in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_friendlist. */
uint32_t count_friendlist(const Messenger *m);

/* Return the number of online friends in the instance m. */
uint32_t get_num_online_friends(const Messenger *m);

/* Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_friendlist(const Messenger *m, int32_t *out_list, uint32_t list_size);

/* Allocate and return a list of valid friend id's. List must be freed by the
 * caller.
 *
 * retun 0 if success.
 * return -1 if failure.
 */
int get_friendlist(const Messenger *m, int **out_list, uint32_t *out_list_length);

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist. */
uint32_t count_chatlist(const Messenger *m);

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(const Messenger *m, int *out_list, uint32_t list_size);

#endif
