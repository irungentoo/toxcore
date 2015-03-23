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

#include "friend_requests.h"
#include "LAN_discovery.h"
#include "friend_connection.h"

#define MAX_NAME_LENGTH 128
/* TODO: this must depend on other variable. */
#define MAX_STATUSMESSAGE_LENGTH 1007


#define FRIEND_ADDRESS_SIZE (crypto_box_PUBLICKEYBYTES + sizeof(uint32_t) + sizeof(uint16_t))

enum {
    MESSAGE_NORMAL,
    MESSAGE_ACTION
};

/* NOTE: Packet ids below 20 must never be used. */
#define PACKET_ID_SHARE_RELAYS 23
#define PACKET_ID_ONLINE 24
#define PACKET_ID_OFFLINE 25
#define PACKET_ID_NICKNAME 48
#define PACKET_ID_STATUSMESSAGE 49
#define PACKET_ID_USERSTATUS 50
#define PACKET_ID_TYPING 51
#define PACKET_ID_MESSAGE 64
#define PACKET_ID_ACTION (PACKET_ID_MESSAGE + MESSAGE_ACTION) /* 65 */
#define PACKET_ID_MSI 69
#define PACKET_ID_FILE_SENDREQUEST 80
#define PACKET_ID_FILE_CONTROL 81
#define PACKET_ID_FILE_DATA 82
#define PACKET_ID_INVITE_GROUPCHAT 96
#define PACKET_ID_ONLINE_PACKET 97
#define PACKET_ID_DIRECT_GROUPCHAT 98
#define PACKET_ID_MESSAGE_GROUPCHAT 99
#define PACKET_ID_LOSSY_GROUPCHAT 199

/* Max number of tcp relays sent to friends */
#define MAX_SHARED_RELAYS 16

/* All packets starting with a byte in this range can be used for anything. */
#define PACKET_ID_LOSSLESS_RANGE_START 160
#define PACKET_ID_LOSSLESS_RANGE_SIZE 32
#define PACKET_LOSSY_AV_RESERVED 8 /* Number of lossy packet types at start of range reserved for A/V. */

typedef struct {
    uint8_t ipv6enabled;
    uint8_t udp_disabled;
    TCP_Proxy_Info proxy_info;
    uint16_t port_range[2];
} Messenger_Options;


struct Receipts {
    uint32_t packet_num;
    uint32_t msg_id;
    struct Receipts *next;
};

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
    FAERR_BADCHECKSUM = -6,
    FAERR_SETNEWNOSPAM = -7,
    FAERR_NOMEM = -8
};


/* Default start timeout in seconds between friend requests. */
#define FRIENDREQUEST_TIMEOUT 5;

/* Interval between the sending of tcp relay information */
#define FRIEND_SHARE_RELAYS_INTERVAL (5 * 60)

enum {
    CONNECTION_NONE,
    CONNECTION_TCP,
    CONNECTION_UDP
};

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

#define FILE_ID_LENGTH 32

struct File_Transfers {
    uint64_t size;
    uint64_t transferred;
    uint8_t status; /* 0 == no transfer, 1 = not accepted, 3 = transferring, 4 = broken, 5 = finished */
    uint8_t paused; /* 0: not paused, 1 = paused by us, 2 = paused by other, 3 = paused by both. */
    uint32_t last_packet_number; /* number of the last packet sent. */
    uint64_t requested; /* total data requested by the request chunk callback */
    unsigned int slots_allocated; /* number of slots allocated to this transfer. */
    uint8_t id[FILE_ID_LENGTH];
};
enum {
    FILESTATUS_NONE,
    FILESTATUS_NOT_ACCEPTED,
    FILESTATUS_TRANSFERRING,
    //FILESTATUS_BROKEN,
    FILESTATUS_FINISHED
};

enum {
    FILE_PAUSE_NOT,
    FILE_PAUSE_US,
    FILE_PAUSE_OTHER,
    FILE_PAUSE_BOTH
};

/* This cannot be bigger than 256 */
#define MAX_CONCURRENT_FILE_PIPES 256

enum {
    FILECONTROL_ACCEPT,
    FILECONTROL_PAUSE,
    FILECONTROL_KILL,
    FILECONTROL_SEEK
};

enum {
    FILEKIND_DATA,
    FILEKIND_AVATAR
};


typedef struct Messenger Messenger;

typedef struct {
    uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
    int friendcon_id;

    uint64_t friendrequest_lastsent; // Time at which the last friend request was sent.
    uint32_t friendrequest_timeout; // The timeout between successful friendrequest sending attempts.
    uint8_t status; // 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online.
    uint8_t info[MAX_FRIEND_REQUEST_DATA_SIZE]; // the data that is sent during the friend requests we do.
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;
    uint8_t name_sent; // 0 if we didn't send our name to this friend 1 if we have.
    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;
    uint8_t statusmessage_sent;
    USERSTATUS userstatus;
    uint8_t userstatus_sent;
    uint8_t user_istyping;
    uint8_t user_istyping_sent;
    uint8_t is_typing;
    uint16_t info_size; // Length of the info.
    uint32_t message_id; // a semi-unique id used in read receipts.
    uint32_t friendrequest_nospam; // The nospam number used in the friend request.
    uint64_t ping_lastrecv;//TODO remove
    uint64_t share_relays_lastsent;
    uint8_t last_connection_udp_tcp;
    struct File_Transfers file_sending[MAX_CONCURRENT_FILE_PIPES];
    unsigned int num_sending_files;
    struct File_Transfers file_receiving[MAX_CONCURRENT_FILE_PIPES];

    struct {
        int (*function)(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t len, void *object);
        void *object;
    } lossy_rtp_packethandlers[PACKET_LOSSY_AV_RESERVED];

    struct Receipts *receipts_start;
    struct Receipts *receipts_end;
} Friend;


struct Messenger {

    Networking_Core *net;
    Net_Crypto *net_crypto;
    DHT *dht;

    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;

    Friend_Connections *fr_c;

    Friend_Requests fr;
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;

    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;

    USERSTATUS userstatus;

    Friend *friendlist;
    uint32_t numfriends;

    uint32_t numonline_friends;

    uint64_t last_LANdiscovery;

#define NUM_SAVED_TCP_RELAYS 8
    uint8_t has_added_relays; // If the first connection has occurred in do_messenger
    Node_format loaded_relays[NUM_SAVED_TCP_RELAYS]; // Relays loaded from config

    void (*friend_message)(struct Messenger *m, uint32_t, unsigned int, const uint8_t *, size_t, void *);
    void *friend_message_userdata;
    void (*friend_namechange)(struct Messenger *m, uint32_t, const uint8_t *, size_t, void *);
    void *friend_namechange_userdata;
    void (*friend_statusmessagechange)(struct Messenger *m, uint32_t, const uint8_t *, size_t, void *);
    void *friend_statusmessagechange_userdata;
    void (*friend_userstatuschange)(struct Messenger *m, uint32_t, unsigned int, void *);
    void *friend_userstatuschange_userdata;
    void (*friend_typingchange)(struct Messenger *m, uint32_t, _Bool, void *);
    void *friend_typingchange_userdata;
    void (*read_receipt)(struct Messenger *m, uint32_t, uint32_t, void *);
    void *read_receipt_userdata;
    void (*friend_connectionstatuschange)(struct Messenger *m, uint32_t, unsigned int, void *);
    void *friend_connectionstatuschange_userdata;
    void (*friend_connectionstatuschange_internal)(struct Messenger *m, uint32_t, uint8_t, void *);
    void *friend_connectionstatuschange_internal_userdata;

    void *group_chat_object; /* Set by new_groupchats()*/
    void (*group_invite)(struct Messenger *m, uint32_t, const uint8_t *, uint16_t);
    void (*group_message)(struct Messenger *m, uint32_t, const uint8_t *, uint16_t);

    void (*file_sendrequest)(struct Messenger *m, uint32_t, uint32_t, uint32_t, uint64_t, const uint8_t *, size_t,
                             void *);
    void *file_sendrequest_userdata;
    void (*file_filecontrol)(struct Messenger *m, uint32_t, uint32_t, unsigned int, void *);
    void *file_filecontrol_userdata;
    void (*file_filedata)(struct Messenger *m, uint32_t, uint32_t, uint64_t, const uint8_t *, size_t, void *);
    void *file_filedata_userdata;
    void (*file_reqchunk)(struct Messenger *m, uint32_t, uint32_t, uint64_t, size_t, void *);
    void *file_reqchunk_userdata;

    void (*msi_packet)(struct Messenger *m, uint32_t, const uint8_t *, uint16_t, void *);
    void *msi_packet_userdata;

    void (*lossy_packethandler)(struct Messenger *m, uint32_t, const uint8_t *, size_t, void *);
    void *lossy_packethandler_userdata;
    void (*lossless_packethandler)(struct Messenger *m, uint32_t, const uint8_t *, size_t, void *);
    void *lossless_packethandler_userdata;

    void (*core_connection_change)(struct Messenger *m, unsigned int, void *);
    void *core_connection_change_userdata;
    unsigned int last_connection_status;

    Messenger_Options options;
};

/* Format: [real_pk (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
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
 *  return -6 if bad checksum in address.
 *  return -7 if the friend was already there but the nospam was different.
 *  (the nospam for that friend was set to the new one).
 *  return -8 if increasing the friend list size fails.
 */
int32_t m_addfriend(Messenger *m, const uint8_t *address, const uint8_t *data, uint16_t length);


/* Add a friend without sending a friendrequest.
 *  return the friend number if success.
 *  return -3 if user's own key.
 *  return -4 if friend request already sent or already a friend.
 *  return -6 if bad checksum in address.
 *  return -8 if increasing the friend list size fails.
 */
int32_t m_addfriend_norequest(Messenger *m, const uint8_t *real_pk);

/*  return the friend number associated to that client id.
 *  return -1 if no such friend.
 */
int32_t getfriend_id(const Messenger *m, const uint8_t *real_pk);

/* Copies the public key associated to that friend id into real_pk buffer.
 * Make sure that real_pk is of size crypto_box_PUBLICKEYBYTES.
 *
 *  return 0 if success
 *  return -1 if failure
 */
int get_real_pk(const Messenger *m, int32_t friendnumber, uint8_t *real_pk);

/*  return friend connection id on success.
 *  return -1 if failure.
 */
int getfriendcon_id(const Messenger *m, int32_t friendnumber);

/* Remove a friend.
 *
 *  return 0 if success
 *  return -1 if failure
 */
int m_delfriend(Messenger *m, int32_t friendnumber);

/* Checks friend's connecting status.
 *
 *  return CONNECTION_UDP (2) if friend is directly connected to us (Online UDP).
 *  return CONNECTION_TCP (1) if friend is connected to us (Online TCP).
 *  return CONNECTION_NONE (0) if friend is not connected to us (Offline).
 *  return -1 on failure.
 */
int m_get_friend_connectionstatus(const Messenger *m, int32_t friendnumber);

/* Checks if there exists a friend with given friendnumber.
 *
 *  return 1 if friend exists.
 *  return 0 if friend doesn't exist.
 */
int m_friend_exists(const Messenger *m, int32_t friendnumber);

/* Send a message of type to an online friend.
 *
 * return -1 if friend not valid.
 * return -2 if too large.
 * return -3 if friend not online.
 * return -4 if send failed (because queue is full).
 * return -5 if bad type.
 * return 0 if success.
 *
 *  the value in message_id will be passed to your read_receipt callback when the other receives the message.
 */
int m_send_message_generic(Messenger *m, int32_t friendnumber, uint8_t type, const uint8_t *message, uint32_t length,
                           uint32_t *message_id);


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
int m_copy_self_statusmessage(const Messenger *m, uint8_t *buf);

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
int m_get_istyping(const Messenger *m, int32_t friendnumber);

/* Set the function that will be executed when a friend request is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, size_t length)
 */
void m_callback_friendrequest(Messenger *m, void (*function)(Messenger *m, const uint8_t *, const uint8_t *, size_t,
                              void *), void *userdata);

/* Set the function that will be executed when a message from a friend is received.
 *  Function format is: function(uint32_t friendnumber, unsigned int type, uint8_t * message, uint32_t length)
 */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *m, uint32_t, unsigned int, const uint8_t *,
                              size_t, void *), void *userdata);

/* Set the callback for name changes.
 *  Function(uint32_t friendnumber, uint8_t *newname, size_t length)
 *  You are not responsible for freeing newname.
 */
void m_callback_namechange(Messenger *m, void (*function)(Messenger *m, uint32_t, const uint8_t *, size_t, void *),
                           void *userdata);

/* Set the callback for status message changes.
 *  Function(uint32_t friendnumber, uint8_t *newstatus, size_t length)
 *
 *  You are not responsible for freeing newstatus
 */
void m_callback_statusmessage(Messenger *m, void (*function)(Messenger *m, uint32_t, const uint8_t *, size_t, void *),
                              void *userdata);

/* Set the callback for status type changes.
 *  Function(uint32_t friendnumber, USERSTATUS kind)
 */
void m_callback_userstatus(Messenger *m, void (*function)(Messenger *m, uint32_t, unsigned int, void *),
                           void *userdata);

/* Set the callback for typing changes.
 *  Function(uint32_t friendnumber, uint8_t is_typing)
 */
void m_callback_typingchange(Messenger *m, void(*function)(Messenger *m, uint32_t, _Bool, void *), void *userdata);

/* Set the callback for read receipts.
 *  Function(uint32_t friendnumber, uint32_t receipt)
 *
 *  If you are keeping a record of returns from m_sendmessage,
 *  receipt might be one of those values, meaning the message
 *  has been received on the other side.
 *  Since core doesn't track ids for you, receipt may not correspond to any message.
 *  In that case, you should discard it.
 */
void m_callback_read_receipt(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, void *), void *userdata);

/* Set the callback for connection status changes.
 *  function(uint32_t friendnumber, uint8_t status)
 *
 *  Status:
 *    0 -- friend went offline after being previously online.
 *    1 -- friend went online.
 *
 *  Note that this callback is not called when adding friends, thus the "after
 *  being previously online" part.
 *  It's assumed that when adding friends, their connection status is offline.
 */
void m_callback_connectionstatus(Messenger *m, void (*function)(Messenger *m, uint32_t, unsigned int, void *),
                                 void *userdata);
/* Same as previous but for internal A/V core usage only */
void m_callback_connectionstatus_internal_av(Messenger *m, void (*function)(Messenger *m, uint32_t, uint8_t, void *),
        void *userdata);


/* Set the callback for typing changes.
 *  Function(unsigned int connection_status (0 = not connected, 1 = TCP only, 2 = UDP + TCP))
 */
void m_callback_core_connection(Messenger *m, void (*function)(Messenger *m, unsigned int, void *), void *userdata);

/**********GROUP CHATS************/

/* Set the callback for group invites.
 *
 *  Function(Messenger *m, uint32_t friendnumber, uint8_t *data, uint16_t length)
 */
void m_callback_group_invite(Messenger *m, void (*function)(Messenger *m, uint32_t, const uint8_t *, uint16_t));

/* Send a group invite packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int send_group_invite_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length);

/****************FILE SENDING*****************/


/* Set the callback for file send requests.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint32_t filetype, uint64_t filesize, uint8_t *filename, size_t filename_length, void *userdata)
 */
void callback_file_sendrequest(Messenger *m, void (*function)(Messenger *m,  uint32_t, uint32_t, uint32_t, uint64_t,
                               const uint8_t *, size_t, void *), void *userdata);


/* Set the callback for file control requests.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, unsigned int control_type, void *userdata)
 *
 */
void callback_file_control(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, unsigned int, void *),
                           void *userdata);

/* Set the callback for file data.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, uint8_t *data, size_t length, void *userdata)
 *
 */
void callback_file_data(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, uint64_t, const uint8_t *,
                        size_t, void *), void *userdata);

/* Set the callback for file request chunk.
 *
 *  Function(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, size_t length, void *userdata)
 *
 */
void callback_file_reqchunk(Messenger *m, void (*function)(Messenger *m, uint32_t, uint32_t, uint64_t, size_t, void *),
                            void *userdata);


/* Copy the file transfer file id to file_id
 *
 * return 0 on success.
 * return -1 if friend not valid.
 * return -2 if filenumber not valid
 */
int file_get_id(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint8_t *file_id);

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return file number on success
 *  return -1 if friend not found.
 *  return -2 if filename length invalid.
 *  return -3 if no more file sending slots left.
 *  return -4 if could not send packet (friend offline).
 *
 */
long int new_filesender(const Messenger *m, int32_t friendnumber, uint32_t file_type, uint64_t filesize,
                        const uint8_t *file_id, const uint8_t *filename, uint16_t filename_length);

/* Send a file control request.
 *
 *  return 0 on success
 *  return -1 if friend not valid.
 *  return -2 if friend not online.
 *  return -3 if file number invalid.
 *  return -4 if file control is bad.
 *  return -5 if file already paused.
 *  return -6 if resume file failed because it was only paused by the other.
 *  return -7 if resume file failed because it wasn't paused.
 *  return -8 if packet failed to send.
 */
int file_control(const Messenger *m, int32_t friendnumber, uint32_t filenumber, unsigned int control);

/* Send a seek file control request.
 *
 *  return 0 on success
 *  return -1 if friend not valid.
 *  return -2 if friend not online.
 *  return -3 if file number invalid.
 *  return -4 if not receiving file.
 *  return -5 if file status wrong.
 *  return -6 if position bad.
 *  return -8 if packet failed to send.
 */
int file_seek(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint64_t position);

/* Send file data.
 *
 *  return 0 on success
 *  return -1 if friend not valid.
 *  return -2 if friend not online.
 *  return -3 if filenumber invalid.
 *  return -4 if file transfer not transferring.
 *  return -5 if bad data size.
 *  return -6 if packet queue full.
 *  return -7 if wrong position.
 */
int file_data(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
              uint16_t length);

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
 *  Function(Messenger *m, uint32_t friendnumber, uint8_t *data, uint16_t length, void *userdata)
 */
void m_callback_msi_packet(Messenger *m, void (*function)(Messenger *m, uint32_t, const uint8_t *, uint16_t, void *),
                           void *userdata);

/* Send an msi packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int m_msi_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length);

/* Set handlers for lossy rtp packets.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int m_callback_rtp_packet(Messenger *m, int32_t friendnumber, uint8_t byte, int (*packet_handler_callback)(Messenger *m,
                          uint32_t friendnumber, const uint8_t *data, uint16_t len, void *object), void *object);

/**********************************************/

/* Set handlers for custom lossy packets.
 *
 */
void custom_lossy_packet_registerhandler(Messenger *m, void (*packet_handler_callback)(Messenger *m,
        uint32_t friendnumber, const uint8_t *data, size_t len, void *object), void *object);

/* High level function to send custom lossy packets.
 *
 * return -1 if friend invalid.
 * return -2 if length wrong.
 * return -3 if first byte invalid.
 * return -4 if friend offline.
 * return -5 if packet failed to send because of other error.
 * return 0 on success.
 */
int send_custom_lossy_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length);


/* Set handlers for custom lossless packets.
 *
 */
void custom_lossless_packet_registerhandler(Messenger *m, void (*packet_handler_callback)(Messenger *m,
        uint32_t friendnumber, const uint8_t *data, size_t len, void *object), void *object);

/* High level function to send custom lossless packets.
 *
 * return -1 if friend invalid.
 * return -2 if length wrong.
 * return -3 if first byte invalid.
 * return -4 if friend offline.
 * return -5 if packet failed to send because of other error.
 * return 0 on success.
 */
int send_custom_lossless_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length);

/**********************************************/

enum {
    MESSENGER_ERROR_NONE,
    MESSENGER_ERROR_PORT,
    MESSENGER_ERROR_OTHER
};

/* Run this at startup.
 *  return allocated instance of Messenger on success.
 *  return 0 if there are problems.
 *
 *  if error is not NULL it will be set to one of the values in the enum above.
 */
Messenger *new_messenger(Messenger_Options *options, unsigned int *error);

/* Run this before closing shop
 * Free all datastructures.
 */
void kill_messenger(Messenger *m);

/* The main loop that needs to be run at least 20 times per second. */
void do_messenger(Messenger *m);

/* Return the time in milliseconds before do_messenger() should be called again
 * for optimal performance.
 *
 * returns time (in ms) before the next do_messenger() needs to be run on success.
 */
uint32_t messenger_run_interval(const Messenger *m);

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
uint32_t copy_friendlist(const Messenger *m, uint32_t *out_list, uint32_t list_size);

#endif
