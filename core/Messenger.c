/* Messenger.c
 *
 * An implementation of a simple text chat only messenger on the tox network core.
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
#define MIN(a,b) (((a)<(b))?(a):(b))

typedef struct {
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    uint64_t friend_request_id; /* id of the friend request corresponding to the current friend request to the current friend. */
    uint8_t status; /* 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online. */
    uint8_t info[MAX_DATA_SIZE]; /* the data that is sent during the friend requests we do */
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t name_sent; /* 0 if we didn't send our name to this friend 1 if we have. */
    uint8_t *statusmessage;
    uint16_t statusmessage_length;
    uint8_t statusmessage_sent;
    USERSTATUS userstatus;
    uint8_t userstatus_sent;
    uint16_t info_size; /* length of the info */
    uint32_t message_id; /* a semi-unique id used in read receipts */
    uint8_t receives_read_receipts; /* shall we send read receipts to this person? */
} Friend;

uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];

static uint8_t self_name[MAX_NAME_LENGTH];
static uint16_t self_name_length;

static uint8_t self_statusmessage[MAX_STATUSMESSAGE_LENGTH];
static uint16_t self_statusmessage_length;

static USERSTATUS self_userstatus;

static Friend *friendlist;
static uint32_t numfriends;


static void set_friend_status(int friendnumber, uint8_t status);
static int write_cryptpacket_id(int friendnumber, uint8_t packet_id, uint8_t *data, uint32_t length);

/* 1 if we are online
   0 if we are offline
   static uint8_t online; */

/* set the size of the friend list to numfriends
   return -1 if realloc fails */
int realloc_friendlist(uint32_t num) {
    Friend *newfriendlist = realloc(friendlist, num*sizeof(Friend));
    if (newfriendlist == NULL)
        return -1;
    memset(&newfriendlist[num-1], 0, sizeof(Friend));
    friendlist = newfriendlist;
    return 0;
}

/* return the friend id associated to that public key.
   return -1 if no such friend */
int getfriend_id(uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < numfriends; ++i) {
        if (friendlist[i].status > 0)
            if (memcmp(client_id, friendlist[i].client_id, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
    }

    return -1;
}

/* copies the public key associated to that friend id into client_id buffer.
   make sure that client_id is of size CLIENT_ID_SIZE.
   return 0 if success
   return -1 if failure. */
int getclient_id(int friend_id, uint8_t *client_id)
{
    if (friend_id >= numfriends || friend_id < 0)
        return -1;

    if (friendlist[friend_id].status > 0) {
        memcpy(client_id, friendlist[friend_id].client_id, CLIENT_ID_SIZE);
        return 0;
    }

    return -1;
}

/*
 * add a friend
 * set the data that will be sent along with friend request
 * client_id is the client id of the friend
 * data is the data and length is the length
 * returns the friend number if success
 * return FA_TOOLONG if message length is too long
 * return FAERR_NOMESSAGE if no message (message length must be >= 1 byte)
 * return FAERR_OWNKEY if user's own key
 * return FAERR_ALREADYSENT if friend request already sent or already a friend
 * return FAERR_UNKNOWN for unknown error
 */
int m_addfriend(uint8_t *client_id, uint8_t *data, uint16_t length)
{
    if (length >= (MAX_DATA_SIZE - crypto_box_PUBLICKEYBYTES
                         - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES
                         + crypto_box_ZEROBYTES))
        return FAERR_TOOLONG;
    if (length < 1)
        return FAERR_NOMESSAGE;
    if (memcmp(client_id, self_public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return FAERR_OWNKEY;
    if (getfriend_id(client_id) != -1)
        return FAERR_ALREADYSENT;

    /* resize the friend list if necessary */
    realloc_friendlist(numfriends + 1);

    uint32_t i;
    for (i = 0; i <= numfriends; ++i)  {
        if (friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            set_friend_status(i, FRIEND_ADDED);
            friendlist[i].crypt_connection_id = -1;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            friendlist[i].statusmessage = calloc(1, 1);
            friendlist[i].statusmessage_length = 1;
            friendlist[i].userstatus = USERSTATUS_NONE;
            memcpy(friendlist[i].info, data, length);
            friendlist[i].info_size = length;
            friendlist[i].message_id = 0;
            friendlist[i].receives_read_receipts = 1; /* default: YES */

            ++numfriends;
            return i;
        }
    }
    return FAERR_UNKNOWN;
}

int m_addfriend_norequest(uint8_t * client_id)
{
    if (getfriend_id(client_id) != -1)
        return -1;

    /* resize the friend list if necessary */
    realloc_friendlist(numfriends + 1);

    uint32_t i;
    for (i = 0; i <= numfriends; ++i) {
        if(friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            set_friend_status(i, FRIEND_REQUESTED);
            friendlist[i].crypt_connection_id = -1;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            friendlist[i].statusmessage = calloc(1, 1);
            friendlist[i].statusmessage_length = 1;
            friendlist[i].userstatus = USERSTATUS_NONE;
            friendlist[i].message_id = 0;
            friendlist[i].receives_read_receipts = 1; /* default: YES */
            ++numfriends;
            return i;
        }
    }
    return -1;
}

/* remove a friend
   return 0 if success
   return -1 if failure */
int m_delfriend(int friendnumber)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;

    DHT_delfriend(friendlist[friendnumber].client_id);
    crypto_kill(friendlist[friendnumber].crypt_connection_id);
    free(friendlist[friendnumber].statusmessage);
    memset(&friendlist[friendnumber], 0, sizeof(Friend));
    uint32_t i;

    for (i = numfriends; i != 0; --i) {
        if (friendlist[i-1].status != NOFRIEND)
            break;
    }
    numfriends = i;
    realloc_friendlist(numfriends + 1);

    return 0;
}

/* return FRIEND_ONLINE if friend is online
   return FRIEND_CONFIRMED if friend is confirmed
   return FRIEND_REQUESTED if the friend request was sent
   return FRIEND_ADDED if the friend was added
   return NOFRIEND if there is no friend with that number */
int m_friendstatus(int friendnumber)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return NOFRIEND;
    return friendlist[friendnumber].status;
}

/* send a text chat message to an online friend
   return the message id if packet was successfully put into the send queue
   return 0 if it was not */
uint32_t m_sendmessage(int friendnumber, uint8_t *message, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return 0;
    uint32_t msgid = ++friendlist[friendnumber].message_id;
    if (msgid == 0)
        msgid = 1; /* otherwise, false error */
    return m_sendmessage_withid(friendnumber, msgid, message, length);
}

uint32_t m_sendmessage_withid(int friendnumber, uint32_t theid, uint8_t *message, uint32_t length)
{
    if (length >= (MAX_DATA_SIZE - sizeof(theid)))
        return 0;
    uint8_t temp[MAX_DATA_SIZE];
    theid = htonl(theid);
    memcpy(temp, &theid, sizeof(theid));
    memcpy(temp + sizeof(theid), message, length);
    return write_cryptpacket_id(friendnumber, PACKET_ID_MESSAGE, temp, length + sizeof(theid));
}

/* send an action to an online friend
   return 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendaction(int friendnumber, uint8_t *action, uint32_t length)
{
    return write_cryptpacket_id(friendnumber, PACKET_ID_ACTION, action, length);
}

/* send a name packet to friendnumber
   length is the length with the NULL terminator*/
static int m_sendname(int friendnumber, uint8_t * name, uint16_t length)
{
    if(length > MAX_NAME_LENGTH || length == 0)
        return 0;
    return write_cryptpacket_id(friendnumber, PACKET_ID_NICKNAME, name, length);
}

/* set the name of a friend
   return 0 if success
   return -1 if failure */
static int setfriendname(int friendnumber, uint8_t * name)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    memcpy(friendlist[friendnumber].name, name, MAX_NAME_LENGTH);
    return 0;
}

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   length must be at least 1 byte
   length is the length of name with the NULL terminator
   return 0 if success
   return -1 if failure */
int setname(uint8_t * name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;
    memcpy(self_name, name, length);
    self_name_length = length;
    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].name_sent = 0;
    return 0;
}

/* get our nickname
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return the length of the name */
uint16_t getself_name(uint8_t *name)
{
    memcpy(name, self_name, self_name_length);
    return self_name_length;
}

/* get name of friendnumber
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return 0 if success
   return -1 if failure */
int getname(int friendnumber, uint8_t * name)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    memcpy(name, friendlist[friendnumber].name, MAX_NAME_LENGTH);
    return 0;
}

int m_set_statusmessage(uint8_t *status, uint16_t length)
{
    if (length > MAX_STATUSMESSAGE_LENGTH)
        return -1;
    memcpy(self_statusmessage, status, length);
    self_statusmessage_length = length;

    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].statusmessage_sent = 0;
    return 0;
}

int m_set_userstatus(USERSTATUS status)
{
    if (status >= USERSTATUS_INVALID) {
        return -1;
    }
    self_userstatus = status;
    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].userstatus_sent = 0;
    return 0;
}

/*  return the size of friendnumber's user status
    guaranteed to be at most MAX_STATUSMESSAGE_LENGTH */
int m_get_statusmessage_size(int friendnumber)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    return friendlist[friendnumber].statusmessage_length;
}

/*  copy the user status of friendnumber into buf, truncating if needed to maxlen
    bytes, use m_get_statusmessage_size to find out how much you need to allocate */
int m_copy_statusmessage(int friendnumber, uint8_t * buf, uint32_t maxlen)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    memset(buf, 0, maxlen);
    memcpy(buf, friendlist[friendnumber].statusmessage, MIN(maxlen, MAX_STATUSMESSAGE_LENGTH) - 1);
    return 0;
}

int m_copy_self_statusmessage(uint8_t * buf, uint32_t maxlen)
{
    memset(buf, 0, maxlen);
    memcpy(buf, self_statusmessage, MIN(maxlen, MAX_STATUSMESSAGE_LENGTH) - 1);
    return 0;
}

USERSTATUS m_get_userstatus(int friendnumber)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return USERSTATUS_INVALID;
    USERSTATUS status = friendlist[friendnumber].userstatus;
    if (status >= USERSTATUS_INVALID) {
        status = USERSTATUS_NONE;
    }
    return status;
}

USERSTATUS m_get_self_userstatus(void)
{
    return self_userstatus;
}

static int send_statusmessage(int friendnumber, uint8_t * status, uint16_t length)
{
    return write_cryptpacket_id(friendnumber, PACKET_ID_STATUSMESSAGE, status, length);
}

static int send_userstatus(int friendnumber, USERSTATUS status)
{
    return write_cryptpacket_id(friendnumber, PACKET_ID_USERSTATUS, &((uint8_t)status), 1);
}

static int set_friend_statusmessage(int friendnumber, uint8_t * status, uint16_t length)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(friendlist[friendnumber].statusmessage);
    friendlist[friendnumber].statusmessage = newstatus;
    friendlist[friendnumber].statusmessage_length = length;
    return 0;
}

static void set_friend_userstatus(int friendnumber, USERSTATUS status)
{
    friendlist[friendnumber].userstatus = status;
}

/* Sets whether we send read receipts for friendnumber. */
void m_set_sends_receipts(int friendnumber, int yesno)
{
    if (yesno != 0 || yesno != 1)
        return;
    if (friendnumber >= numfriends || friendnumber < 0)
        return;
    friendlist[friendnumber].receives_read_receipts = yesno;
}

/* static void (*friend_request)(uint8_t *, uint8_t *, uint16_t);
static uint8_t friend_request_isset = 0; */
/* set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t))
{
    callback_friendrequest(function);
}

static void (*friend_message)(int, uint8_t *, uint16_t);
static uint8_t friend_message_isset = 0;

/* set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(void (*function)(int, uint8_t *, uint16_t))
{
    friend_message = function;
    friend_message_isset = 1;
}

static void (*friend_action)(int, uint8_t *, uint16_t);
static uint8_t friend_action_isset = 0;
void m_callback_action(void (*function)(int, uint8_t *, uint16_t))
{
    friend_action = function;
    friend_action_isset = 1;
}

static void (*friend_namechange)(int, uint8_t *, uint16_t);
static uint8_t friend_namechange_isset = 0;
void m_callback_namechange(void (*function)(int, uint8_t *, uint16_t))
{
    friend_namechange = function;
    friend_namechange_isset = 1;
}

static void (*friend_statusmessagechange)(int, uint8_t *, uint16_t);
static uint8_t friend_statusmessagechange_isset = 0;
void m_callback_statusmessage(void (*function)(int, uint8_t *, uint16_t))
{
    friend_statusmessagechange = function;
    friend_statusmessagechange_isset = 1;
}

static void (*friend_userstatuschange)(int, USERSTATUS);
static uint8_t friend_userstatuschange_isset = 0;
void m_callback_userstatus(void (*function)(int, USERSTATUS))
{
    friend_userstatuschange = function;
    friend_userstatuschange_isset = 1;
}

static void (*read_receipt)(int, uint32_t);
static uint8_t read_receipt_isset = 0;
void m_callback_read_receipt(void (*function)(int, uint32_t))
{
    read_receipt = function;
    read_receipt_isset = 1;
}

static void (*friend_statuschange)(int, uint8_t);
static uint8_t friend_statuschange_isset = 0;
void m_callback_friendstatus(void (*function)(int, uint8_t))
{
    friend_statuschange = function;
    friend_statuschange_isset = 1;
}

static void set_friend_status(int friendnumber, uint8_t status)
{
    if (friendlist[friendnumber].status != status && friend_statuschange_isset)
        friend_statuschange(friendnumber, status);
    friendlist[friendnumber].status = status;
}

static int write_cryptpacket_id(int friendnumber, uint8_t packet_id, uint8_t *data, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return 0;
    if (length >= MAX_DATA_SIZE || friendlist[friendnumber].status != FRIEND_ONLINE)
        return 0;
    uint8_t packet[length + 1];
    packet[0] = packet_id;
    memcpy(packet + 1, data, length);
    return write_cryptpacket(friendlist[friendnumber].crypt_connection_id, packet, length + 1);
}

#define PORT 33445
/* run this at startup */
int initMessenger(void)
{
    new_keys();
    m_set_statusmessage((uint8_t*)"Online", sizeof("Online"));
    initNetCrypto();
    IP ip;
    ip.i = 0;

    if(init_networking(ip,PORT) == -1)
        return -1;

    return 0;
}

//TODO: make this function not suck.
static void doFriends(void)
{
    /* TODO: add incoming connections and some other stuff. */
    uint32_t i;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    for (i = 0; i < numfriends; ++i) {
        if (friendlist[i].status == FRIEND_ADDED) {
            int fr = send_friendrequest(friendlist[i].client_id, friendlist[i].info, friendlist[i].info_size);
            if (fr == 0) /* TODO: This needs to be fixed so that it sends the friend requests a couple of times in case of packet loss */
                set_friend_status(i, FRIEND_REQUESTED);
            else if (fr > 0)
                set_friend_status(i, FRIEND_REQUESTED);
        }
        if (friendlist[i].status == FRIEND_REQUESTED || friendlist[i].status == FRIEND_CONFIRMED) { /* friend is not online */
            if (friendlist[i].status == FRIEND_REQUESTED) {
                if (friendlist[i].friend_request_id + 10 < unix_time()) { /*I know this is hackish but it should work.*/
                    send_friendrequest(friendlist[i].client_id, friendlist[i].info, friendlist[i].info_size);
                    friendlist[i].friend_request_id = unix_time();
                }
            }
            IP_Port friendip = DHT_getfriendip(friendlist[i].client_id);
            switch (is_cryptoconnected(friendlist[i].crypt_connection_id)) {
            case 0:
                if (friendip.ip.i > 1)
                    friendlist[i].crypt_connection_id = crypto_connect(friendlist[i].client_id, friendip);
                break;
            case 3: /*  Connection is established */
                set_friend_status(i, FRIEND_ONLINE);
                break;
            case 4:
                crypto_kill(friendlist[i].crypt_connection_id);
                friendlist[i].crypt_connection_id = -1;
                break;
            default:
                break;
            }
        }
        while (friendlist[i].status == FRIEND_ONLINE) { /* friend is online */
            if (friendlist[i].name_sent == 0) {
                if (m_sendname(i, self_name, self_name_length))
                    friendlist[i].name_sent = 1;
            }
            if (friendlist[i].statusmessage_sent == 0) {
                if (send_statusmessage(i, self_statusmessage, self_statusmessage_length))
                    friendlist[i].statusmessage_sent = 1;
            }
            if (friendlist[i].userstatus_sent == 0) {
                if (send_userstatus(i, self_userstatus))
                    friendlist[i].userstatus_sent = 1;
            }
            len = read_cryptpacket(friendlist[i].crypt_connection_id, temp);
            uint8_t packet_id = temp[0];
            uint8_t* data = temp + 1;
            int data_length = len - 1;
            if (len > 0) {
                switch (packet_id) {
                case PACKET_ID_NICKNAME: {
                    if (data_length >= MAX_NAME_LENGTH || data_length == 0)
                        break;
                    if(friend_namechange_isset)
                        friend_namechange(i, data, data_length);
                    memcpy(friendlist[i].name, data, data_length);
                    friendlist[i].name[data_length - 1] = 0; /* make sure the NULL terminator is present. */
                    break;
                }
                case PACKET_ID_STATUSMESSAGE: {
                    if (data_length == 0)
                        break;
                    uint8_t *status = calloc(MIN(data_length, MAX_STATUSMESSAGE_LENGTH), 1);
                    memcpy(status, data, MIN(data_length, MAX_STATUSMESSAGE_LENGTH));
                    if (friend_statusmessagechange_isset)
                        friend_statusmessagechange(i, status, MIN(data_length, MAX_STATUSMESSAGE_LENGTH));
                    set_friend_statusmessage(i, status, MIN(data_length, MAX_STATUSMESSAGE_LENGTH));
                    free(status);
                    break;
                }
                case PACKET_ID_USERSTATUS: {
                    if (data_length != 1)
                        break;
                    USERSTATUS status = data[0];
                    if (friend_userstatuschange_isset)
                        friend_userstatuschange(i, status);
                    set_friend_userstatus(i, status);
                    break;
                }
                case PACKET_ID_MESSAGE: {
                    uint8_t *message_id = data;
                    uint8_t message_id_length = 4;
                    uint8_t *message = data + message_id_length;
                    uint16_t message_length = data_length - message_id_length;
                    if (friendlist[i].receives_read_receipts) {
                        write_cryptpacket_id(i, PACKET_ID_RECEIPT, message_id, message_id_length);
                    }
                    if (friend_message_isset)
                        (*friend_message)(i, message, message_length);
                    break;
                }
                case PACKET_ID_ACTION: {
                    if (friend_action_isset)
                        (*friend_action)(i, data, data_length);
                    break;
                }
                case PACKET_ID_RECEIPT: {
                    uint32_t msgid;
                    if (data_length < sizeof(msgid))
                        break;
                    memcpy(&msgid, data, sizeof(msgid));
                    msgid = ntohl(msgid);
                    if (read_receipt_isset)
                        (*read_receipt)(i, msgid);
                    break;
                }
                }
            } else {
                if (is_cryptoconnected(friendlist[i].crypt_connection_id) == 4) { /* if the connection timed out, kill it */
                    crypto_kill(friendlist[i].crypt_connection_id);
                    friendlist[i].crypt_connection_id = -1;
                    set_friend_status(i, FRIEND_CONFIRMED);
                }
                break;
            }
        }
    }
}

static void doInbound(void)
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(public_key, secret_nonce, session_key);
    if (inconnection != -1) {
        int friend_id = getfriend_id(public_key);
        if (friend_id != -1) {
            crypto_kill(friendlist[friend_id].crypt_connection_id);
            friendlist[friend_id].crypt_connection_id =
                accept_crypto_inbound(inconnection, public_key, secret_nonce, session_key);

            set_friend_status(friend_id, FRIEND_CONFIRMED);
        }
    }
}

/*Interval in seconds between LAN discovery packet sending*/
#define LAN_DISCOVERY_INTERVAL 60

static uint64_t last_LANdiscovery;

/*Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds*/
static void LANdiscovery(void)
{
    if (last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(PORT));
        last_LANdiscovery = unix_time();
    }
}


/* the main loop that needs to be run at least 200 times per second. */
void doMessenger(void)
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while (receivepacket(&ip_port, data, &length) != -1) {
#ifdef DEBUG
        /* if(rand() % 3 != 1) //simulate packet loss */
        /* { */
        if (DHT_handlepacket(data, length, ip_port) && LosslessUDP_handlepacket(data, length, ip_port) &&
            friendreq_handlepacket(data, length, ip_port) && LANdiscovery_handlepacket(data, length, ip_port))
            /* if packet is discarded */
            printf("Received unhandled packet with length: %u\n", length);
        else
            printf("Received handled packet with length: %u\n", length);
        /* } */
        printf("Status: %u %u %u\n",friendlist[0].status ,is_cryptoconnected(friendlist[0].crypt_connection_id),  friendlist[0].crypt_connection_id);
#else
        DHT_handlepacket(data, length, ip_port);
        LosslessUDP_handlepacket(data, length, ip_port);
        friendreq_handlepacket(data, length, ip_port);
        LANdiscovery_handlepacket(data, length, ip_port);
#endif

    }
    doDHT();
    doLossless_UDP();
    doNetCrypto();
    doInbound();
    doFriends();
    LANdiscovery();
}

/* returns the size of the messenger data (for saving) */
uint32_t Messenger_size(void)
{
    return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
           + sizeof(uint32_t) + DHT_size() + sizeof(uint32_t) + sizeof(Friend) * numfriends;
}

/* save the messenger in data of size Messenger_size() */
void Messenger_save(uint8_t *data)
{
    save_keys(data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t size = DHT_size();
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    DHT_save(data);
    data += size;
    size = sizeof(Friend) * numfriends;
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    memcpy(data, friendlist, sizeof(Friend) * numfriends);
}

/* load the messenger from data of size length. */
int Messenger_load(uint8_t * data, uint32_t length)
{
    if (length == ~0)
        return -1;
    if (length < crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 2)
        return -1;
    length -= crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 2;
    load_keys(data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);

    if (length < size)
        return -1;
    length -= size;
    if (DHT_load(data, size) == -1)
        return -1;
    data += size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);
    if (length != size || length % sizeof(Friend) != 0)
        return -1;

    Friend * temp = malloc(size);
    memcpy(temp, data, size);

    uint16_t num = size / sizeof(Friend);

    uint32_t i;
    for (i = 0; i < num; ++i) {
        if(temp[i].status != 0) {
            int fnum = m_addfriend_norequest(temp[i].client_id);
            setfriendname(fnum, temp[i].name);
            /* set_friend_statusmessage(fnum, temp[i].statusmessage, temp[i].statusmessage_length); */
        }
    }
    free(temp);
    return 0;
}
