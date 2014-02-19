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

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

/* sa_family_t is the sockaddr_in / sockaddr_in6 family field */
typedef short sa_family_t;

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#else

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

#define TOX_MAX_NAME_LENGTH 128
#define TOX_MAX_STATUSMESSAGE_LENGTH 128
#define TOX_CLIENT_ID_SIZE 32

#define TOX_FRIEND_ADDRESS_SIZE (TOX_CLIENT_ID_SIZE + sizeof(uint32_t) + sizeof(uint16_t))

#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

typedef union {
    uint8_t  c[4];
    uint16_t s[2];
    uint32_t i;
} tox_IP4;

typedef union {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    struct in6_addr in6_addr;
} tox_IP6;

typedef struct {
    sa_family_t family;
    union {
        tox_IP4 ip4;
        tox_IP6 ip6;
    };
} tox_IP;

/* will replace IP_Port as soon as the complete infrastructure is in place
 * removed the unused union and padding also */
typedef struct {
    tox_IP    ip;
    uint16_t  port;
} tox_IP_Port;

#define TOX_ENABLE_IPV6_DEFAULT 1


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

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

/* NOTE: Strings in Tox are all UTF-8, also the last byte in all strings must be NULL (0).
 *
 * The length when passing those strings to the core includes that NULL character.
 *
 * If you send non NULL terminated strings Tox will force NULL terminates them when it receives them.
 */

/*  return TOX_FRIEND_ADDRESS_SIZE byte address to give to others.
 * format: [client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 */
void tox_get_address(Tox *tox, uint8_t *address);

/* Add a friend.
 * Set the data that will be sent along with friend request.
 * address is the address of the friend (returned by getaddress of the friend you wish to add) it must be TOX_FRIEND_ADDRESS_SIZE bytes. TODO: add checksum.
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
int tox_add_friend(Tox *tox, uint8_t *address, uint8_t *data, uint16_t length);


/* Add a friend without sending a friendrequest.
 *  return the friend number if success.
 *  return -1 if failure.
 */
int tox_add_friend_norequest(Tox *tox, uint8_t *client_id);

/*  return the friend id associated to that client id.
    return -1 if no such friend */
int tox_get_friend_id(Tox *tox, uint8_t *client_id);

/* Copies the public key associated to that friend id into client_id buffer.
 * Make sure that client_id is of size CLIENT_ID_SIZE.
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_get_client_id(Tox *tox, int friend_id, uint8_t *client_id);

/* Remove a friend. */
int tox_del_friend(Tox *tox, int friendnumber);

/* Checks friend's connecting status.
 *
 *  return 1 if friend is connected to us (Online).
 *  return 0 if friend is not connected to us (Offline).
 *  return -1 on failure.
 */
int tox_get_friend_connection_status(Tox *tox, int friendnumber);

/* Checks if there exists a friend with given friendnumber.
 *
 *  return 1 if friend exists.
 *  return 0 if friend doesn't exist.
 */
int tox_friend_exists(Tox *tox, int friendnumber);

/* Send a text chat message to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 *
 * You will want to retain the return value, it will be passed to your read_receipt callback
 * if one is received.
 * m_sendmessage_withid will send a message with the id of your choosing,
 * however we can generate an id for you by calling plain m_sendmessage.
 */
uint32_t tox_send_message(Tox *tox, int friendnumber, uint8_t *message, uint32_t length);
uint32_t tox_send_message_withid(Tox *tox, int friendnumber, uint32_t theid, uint8_t *message, uint32_t length);

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
uint32_t tox_send_action(Tox *tox, int friendnumber, uint8_t *action, uint32_t length);
uint32_t tox_send_action_withid(Tox *tox, int friendnumber, uint32_t theid, uint8_t *action, uint32_t length);

/* Set our nickname.
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int tox_set_name(Tox *tox, uint8_t *name, uint16_t length);

/*
 * Get your nickname.
 * m - The messanger context to use.
 * name - Pointer to a string for the name.
 * nlen - The length of the string buffer.
 *
 *  return length of name.
 *  return 0 on error.
 */
uint16_t tox_get_self_name(Tox *tox, uint8_t *name, uint16_t nlen);

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return length of name (with the NULL terminator) if success.
 *  return -1 if failure.
 */
int tox_get_name(Tox *tox, int friendnumber, uint8_t *name);

/* Set our user status.
 * You are responsible for freeing status after.
 *
 *  returns 0 on success.
 *  returns -1 on failure.
 */
int tox_set_status_message(Tox *tox, uint8_t *status, uint16_t length);
int tox_set_user_status(Tox *tox, TOX_USERSTATUS status);

/*  return the length of friendnumber's status message, including null.
 *  Pass it into malloc
 */
int tox_get_status_message_size(Tox *tox, int friendnumber);

/* Copy friendnumber's status message into buf, truncating if size is over maxlen.
 * Get the size you need to allocate from m_get_statusmessage_size.
 * The self variant will copy our own status message.
 *
 * returns the length of the copied data on success
 * retruns -1 on failure.
 */
int tox_get_status_message(Tox *tox, int friendnumber, uint8_t *buf, uint32_t maxlen);
int tox_get_self_status_message(Tox *tox, uint8_t *buf, uint32_t maxlen);

/*  return one of USERSTATUS values.
 *  Values unknown to your application should be represented as USERSTATUS_NONE.
 *  As above, the self variant will return our own USERSTATUS.
 *  If friendnumber is invalid, this shall return USERSTATUS_INVALID.
 */
TOX_USERSTATUS tox_get_user_status(Tox *tox, int friendnumber);
TOX_USERSTATUS tox_get_self_user_status(Tox *tox);

/* Set our typing status for a friend.
 * You are responsible for turning it on or off.
 *
 * returns 0 on success.
 * returns -1 on failure.
 */
int tox_set_user_is_typing(Tox *tox, int friendnumber, uint8_t is_typing);

/* Get the typing status of a friend.
 *
 * returns 0 if friend is not typing.
 * returns 1 if friend is typing.
 */
int tox_get_is_typing(Tox *tox, int friendnumber);

/* Sets whether we send read receipts for friendnumber.
 * This function is not lazy, and it will fail if yesno is not (0 or 1).
 */
void tox_set_sends_receipts(Tox *tox, int friendnumber, int yesno);

/* Return the number of friends in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_friendlist. */
uint32_t tox_count_friendlist(Tox *tox);

/* Return the number of online friends in the instance m. */
uint32_t tox_get_num_online_friends(Tox *tox);

/* Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t tox_get_friendlist(Tox *tox, int *out_list, uint32_t list_size);

/* Set the function that will be executed when a friend request is received.
 *  Function format is function(uint8_t * public_key, uint8_t * data, uint16_t length)
 */
void tox_callback_friend_request(Tox *tox, void (*function)(uint8_t *, uint8_t *, uint16_t, void *), void *userdata);

/* Set the function that will be executed when a message from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * message, uint32_t length)
 */
void tox_callback_friend_message(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *),
                                 void *userdata);

/* Set the function that will be executed when an action from a friend is received.
 *  Function format is: function(int friendnumber, uint8_t * action, uint32_t length)
 */
void tox_callback_friend_action(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *), void *userdata);

/* Set the callback for name changes.
 *  function(int friendnumber, uint8_t *newname, uint16_t length)
 *  You are not responsible for freeing newname
 */
void tox_callback_name_change(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *),
                              void *userdata);

/* Set the callback for status message changes.
 *  function(int friendnumber, uint8_t *newstatus, uint16_t length)
 *  You are not responsible for freeing newstatus.
 */
void tox_callback_status_message(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, uint16_t, void *),
                                 void *userdata);

/* Set the callback for status type changes.
 *  function(int friendnumber, USERSTATUS kind)
 */
void tox_callback_user_status(Tox *tox, void (*function)(Tox *tox, int, TOX_USERSTATUS, void *), void *userdata);

/* Set the callback for typing changes.
 *  function (int friendnumber, int is_typing)
 */
void tox_callback_typing_change(Tox *tox, void (*function)(Tox *tox, int, int, void *), void *userdata);

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
void tox_callback_connection_status(Tox *tox, void (*function)(Tox *tox, int, uint8_t, void *), void *userdata);

/**********GROUP CHAT FUNCTIONS: WARNING WILL BREAK A LOT************/

/* Set the callback for group invites.
 *
 *  Function(Tox *tox, int friendnumber, uint8_t *group_public_key, void *userdata)
 */
void tox_callback_group_invite(Tox *tox, void (*function)(Tox *tox, int, uint8_t *, void *), void *userdata);

/* Set the callback for group messages.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void tox_callback_group_message(Tox *tox, void (*function)(Tox *tox, int, int, uint8_t *, uint16_t, void *),
                                void *userdata);

/* Set the callback for group actions.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * action, uint16_t length, void *userdata)
 */
void tox_callback_group_action(Tox *tox, void (*function)(Tox *tox, int, int, uint8_t *, uint16_t, void *),
                               void *userdata);

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Tox *tox, int groupnumber, int peernumber, TOX_CHAT_CHANGE change, void *userdata)
 */
typedef enum {
    TOX_CHAT_CHANGE_PEER_ADD,
    TOX_CHAT_CHANGE_PEER_DEL,
    TOX_CHAT_CHANGE_PEER_NAME,
} TOX_CHAT_CHANGE;

void tox_callback_group_namelist_change(Tox *tox, void (*function)(Tox *tox, int, int, uint8_t, void *),
                                        void *userdata);

/* Creates a new groupchat and puts it in the chats array.
 *
 * return group number on success.
 * return -1 on failure.
 */
int tox_add_groupchat(Tox *tox);

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
int tox_del_groupchat(Tox *tox, int groupnumber);

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least TOX_MAX_NAME_LENGTH long.
 *
 * return length of name if success
 * return -1 if failure
 */
int tox_group_peername(Tox *tox, int groupnumber, int peernumber, uint8_t *name);

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
int tox_invite_friend(Tox *tox, int friendnumber, int groupnumber);

/* Join a group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int tox_join_groupchat(Tox *tox, int friendnumber, uint8_t *friend_group_public_key);

/* send a group message
 * return 0 on success
 * return -1 on failure
 */
int tox_group_message_send(Tox *tox, int groupnumber, uint8_t *message, uint32_t length);

/* send a group action
 * return 0 on success
 * return -1 on failure
 */
int tox_group_action_send(Tox *tox, int groupnumber, uint8_t *action, uint32_t length);

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
int tox_group_number_peers(Tox *tox, int groupnumber);

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][TOX_MAX_NAME_LENGTH] array.
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int tox_group_get_names(Tox *tox, int groupnumber, uint8_t names[][TOX_MAX_NAME_LENGTH], uint16_t length);

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist. */
uint32_t tox_count_chatlist(Tox *tox);

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t tox_get_chatlist(Tox *tox, int *out_list, uint32_t list_size);


/****************FILE SENDING FUNCTIONS*****************/
/* NOTE: This how to will be updated.
 *
 * HOW TO SEND FILES CORRECTLY:
 * 1. Use tox_new_file_sender(...) to create a new file sender.
 * 2. Wait for the callback set with tox_callback_file_control(...) to be called with receive_send == 1 and control_type == TOX_FILECONTROL_ACCEPT
 * 3. Send the data with tox_file_send_data(...) with chunk size tox_file_data_size(...)
 * 4. When sending is done, send a tox_file_send_control(...) with send_receive = 0 and message_id = TOX_FILECONTROL_FINISHED
 *
 * HOW TO RECEIVE FILES CORRECTLY:
 * 1. wait for the callback set with tox_callback_file_send_request(...)
 * 2. accept or refuse the connection with tox_file_send_control(...) with send_receive = 1 and message_id = TOX_FILECONTROL_ACCEPT or TOX_FILECONTROL_KILL
 * 3. save all the data received with the callback set with tox_callback_file_data(...) to a file.
 * 4. when the callback set with tox_callback_file_control(...) is called with receive_send == 0 and control_type == TOX_FILECONTROL_FINISHED
 * the file is done transferring.
 *
 * tox_file_data_remaining(...) can be used to know how many bytes are left to send/receive.
 *
 * If the connection breaks during file sending (The other person goes offline without pausing the sending and then comes back)
 * the reciever must send a control packet with receive_send == 0 message_id = TOX_FILECONTROL_RESUME_BROKEN and the data being
 * a uint64_t (in host byte order) containing the number of bytes recieved.
 *
 * If the sender recieves this packet, he must send a control packet with receive_send == 1 and control_type == TOX_FILECONTROL_ACCEPT
 * then he must start sending file data from the position (data , uint64_t in host byte order) recieved in the TOX_FILECONTROL_RESUME_BROKEN packet.
 *
 * More to come...
 */

enum {
    TOX_FILECONTROL_ACCEPT,
    TOX_FILECONTROL_PAUSE,
    TOX_FILECONTROL_KILL,
    TOX_FILECONTROL_FINISHED,
    TOX_FILECONTROL_RESUME_BROKEN
};
/* Set the callback for file send requests.
 *
 *  Function(Tox *tox, int friendnumber, uint8_t filenumber, uint64_t filesize, uint8_t *filename, uint16_t filename_length, void *userdata)
 */
void tox_callback_file_send_request(Tox *tox, void (*function)(Tox *m, int, uint8_t, uint64_t, uint8_t *, uint16_t,
                                    void *), void *userdata);

/* Set the callback for file control requests.
 *
 *  receive_send is 1 if the message is for a slot on which we are currently sending a file and 0 if the message
 *  is for a slot on which we are receiving the file
 *
 *  Function(Tox *tox, int friendnumber, uint8_t receive_send, uint8_t filenumber, uint8_t control_type, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void tox_callback_file_control(Tox *tox, void (*function)(Tox *m, int, uint8_t, uint8_t, uint8_t, uint8_t *,
                               uint16_t, void *), void *userdata);

/* Set the callback for file data.
 *
 *  Function(Tox *tox, int friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void tox_callback_file_data(Tox *tox, void (*function)(Tox *m, int, uint8_t, uint8_t *, uint16_t length, void *),
                            void *userdata);


/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return file number on success
 *  return -1 on failure
 */
int tox_new_file_sender(Tox *tox, int friendnumber, uint64_t filesize, uint8_t *filename, uint16_t filename_length);

/* Send a file control request.
 *
 * send_receive is 0 if we want the control packet to target a file we are currently sending,
 * 1 if it targets a file we are currently receiving.
 *
 *  return 0 on success
 *  return -1 on failure
 */
int tox_file_send_control(Tox *tox, int friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t message_id,
                          uint8_t *data, uint16_t length);

/* Send file data.
 *
 *  return 0 on success
 *  return -1 on failure
 */
int tox_file_send_data(Tox *tox, int friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length);

/* Returns the recommended/maximum size of the filedata you send with tox_file_send_data()
 *
 *  return size on success
 *  return -1 on failure (currently will never return -1)
 */
int tox_file_data_size(Tox *tox, int friendnumber);

/* Give the number of bytes left to be sent/received.
 *
 *  send_receive is 0 if we want the sending files, 1 if we want the receiving.
 *
 *  return number of bytes remaining to be sent/received on success
 *  return 0 on failure
 */
uint64_t tox_file_data_remaining(Tox *tox, int friendnumber, uint8_t filenumber, uint8_t send_receive);

/***************END OF FILE SENDING FUNCTIONS******************/


/*
 * Use these two functions to bootstrap the client.
 */
/* Sends a "get nodes" request to the given node with ip, port and public_key
 *   to setup connections
 */
void tox_bootstrap_from_ip(Tox *tox, tox_IP_Port ip_port, uint8_t *public_key);

/* Resolves address into an IP address. If successful, sends a "get nodes"
 *   request to the given node with ip, port (in network byte order, HINT: use htons())
 *   and public_key to setup connections
 *
 * address can be a hostname or an IP address (IPv4 or IPv6).
 * if ipv6enabled is 0 (zero), the resolving sticks STRICTLY to IPv4 addresses
 * if ipv6enabled is not 0 (zero), the resolving looks for IPv6 addresses first,
 *   then IPv4 addresses.
 *
 *  returns 1 if the address could be converted into an IP address
 *  returns 0 otherwise
 */
int tox_bootstrap_from_address(Tox *tox, const char *address, uint8_t ipv6enabled,
                               uint16_t port, uint8_t *public_key);

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int tox_isconnected(Tox *tox);

/*
 *  Run this function at startup.
 *
 * Initializes a tox structure
 *  The type of communication socket depends on ipv6enabled:
 *  If set to 0 (zero), creates an IPv4 socket which subsequently only allows
 *    IPv4 communication
 *  If set to anything else, creates an IPv6 socket which allows both IPv4 AND
 *    IPv6 communication
 *
 *  return allocated instance of tox on success.
 *  return 0 if there are problems.
 */
Tox *tox_new(uint8_t ipv6enabled);

/* Run this before closing shop.
 * Free all datastructures. */
void tox_kill(Tox *tox);

/* The main loop that needs to be run at least 20 times per second. */
void tox_do(Tox *tox);

/*
 * tox_wait_prepare(): function should be called under lock
 * Prepares the data required to call tox_wait_execute() asynchronously
 *
 * data[] is reserved and kept by the caller
 * *lenptr is in/out: in = reserved data[], out = required data[]
 *
 *  returns  1 on success
 *  returns  0 if *lenptr is insufficient
 *  returns -1 if lenptr is NULL
 *
 *
 * tox_wait_execute(): function can be called asynchronously
 * Waits for something to happen on the socket for up to milliseconds milliseconds.
 * *** Function MUSTN'T poll. ***
 * The function mustn't modify anything at all, so it can be called completely
 * asynchronously without any worry.
 *
 *  returns  1 if there is socket activity (i.e. tox_do() should be called)
 *  returns  0 if the timeout was reached
 *  returns -1 if data was NULL or len too short
 *
 *
 * tox_wait_cleanup(): function should be called under lock
 * Stores results from tox_wait_execute().
 *
 * data[]/len shall be the exact same as given to tox_wait_execute()
 *
 */
int tox_wait_prepare(Tox *tox, uint8_t *data, uint16_t *lenptr);
int tox_wait_execute(Tox *tox, uint8_t *data, uint16_t len, uint16_t milliseconds);
void tox_wait_cleanup(Tox *tox, uint8_t *data, uint16_t len);


/* SAVING AND LOADING FUNCTIONS: */

/*  return size of messenger data (for saving). */
uint32_t tox_size(Tox *tox);

/* Save the messenger in data (must be allocated memory of size Messenger_size()). */
void tox_save(Tox *tox, uint8_t *data);

/* Load the messenger from data of size length.
 *
 *  returns 0 on success
 *  returns -1 on failure
 */
int tox_load(Tox *tox, uint8_t *data, uint32_t length);

/**/

/* return the size of data to pass to messenger_save_encrypted(...)
 */
uint32_t tox_size_encrypted(Tox *tox);

/* Save the messenger, encrypting the data with key of length key_length
 *
 * This functions simply calls and then encrypt the output of tox_save(..)
 * with crypto_secretbox(...) from NaCl/libsodium with the key
 * given to crypto_secretbox(...) being the SHA256 sum of the key
 * passed to this function.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tox_save_encrypted(Tox *tox, uint8_t *data, uint8_t *key, uint16_t key_length);

/* Load the messenger from data of size length encrypted with key of key_length.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tox_load_encrypted(Tox *tox, uint8_t *data, uint32_t length, uint8_t *key, uint16_t key_length);


#ifdef __cplusplus
}
#endif

#endif

