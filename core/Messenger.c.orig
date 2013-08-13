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
#include "timer.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

static void set_friend_status(Messenger *m, int friendnumber, uint8_t status);
static int write_cryptpacket_id(Messenger *m, int friendnumber, uint8_t packet_id, uint8_t *data, uint32_t length);

/* 1 if we are online
   0 if we are offline
   static uint8_t online; */

/* set the size of the friend list to numfriends
   return -1 if realloc fails */
int realloc_friendlist(Messenger *m, uint32_t num) {
    Friend *newfriendlist = realloc(m->friendlist, num*sizeof(Friend));
    if (newfriendlist == NULL)
        return -1;
    memset(&newfriendlist[num-1], 0, sizeof(Friend));
    m->friendlist = newfriendlist;
    return 0;
}

/* return the friend id associated to that public key.
   return -1 if no such friend */
int getfriend_id(Messenger *m, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status > 0)
            if (memcmp(client_id, m->friendlist[i].client_id, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
    }

    return -1;
}

/* copies the public key associated to that friend id into client_id buffer.
   make sure that client_id is of size CLIENT_ID_SIZE.
   return 0 if success
   return -1 if failure. */
int getclient_id(Messenger *m, int friend_id, uint8_t *client_id)
{
    if (friend_id >= m->numfriends || friend_id < 0)
        return -1;

    if (m->friendlist[friend_id].status > 0) {
        memcpy(client_id, m->friendlist[friend_id].client_id, CLIENT_ID_SIZE);
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
int m_addfriend(Messenger *m, uint8_t *client_id, uint8_t *data, uint16_t length)
{
    if (length >= (MAX_DATA_SIZE - crypto_box_PUBLICKEYBYTES
                         - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES
                         + crypto_box_ZEROBYTES))
        return FAERR_TOOLONG;
    if (length < 1)
        return FAERR_NOMESSAGE;
    if (memcmp(client_id, self_public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return FAERR_OWNKEY;
    if (getfriend_id(m, client_id) != -1)
        return FAERR_ALREADYSENT;

    /* resize the friend list if necessary */
    realloc_friendlist(m, m->numfriends + 1);

    uint32_t i;
    for (i = 0; i <= m->numfriends; ++i)  {
        if (m->friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            m->friendlist[i].status = FRIEND_ADDED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friend_request_id = -1;
            memcpy(m->friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            m->friendlist[i].statusmessage = calloc(1, 1);
            m->friendlist[i].statusmessage_length = 1;
            m->friendlist[i].userstatus = USERSTATUS_NONE;
            memcpy(m->friendlist[i].info, data, length);
            m->friendlist[i].info_size = length;
            m->friendlist[i].message_id = 0;
            m->friendlist[i].receives_read_receipts = 1; /* default: YES */

            ++ m->numfriends;
            return i;
        }
    }
    return FAERR_UNKNOWN;
}

int m_addfriend_norequest(Messenger *m, uint8_t * client_id)
{
    if (getfriend_id(m, client_id) != -1)
        return -1;

    /* resize the friend list if necessary */
    realloc_friendlist(m, m->numfriends + 1);

    uint32_t i;
    for (i = 0; i <= m->numfriends; ++i) {
        if(m->friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            m->friendlist[i].status = FRIEND_REQUESTED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friend_request_id = -1;
            memcpy(m->friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            m->friendlist[i].statusmessage = calloc(1, 1);
            m->friendlist[i].statusmessage_length = 1;
            m->friendlist[i].userstatus = USERSTATUS_NONE;
            m->friendlist[i].message_id = 0;
            m->friendlist[i].receives_read_receipts = 1; /* default: YES */
            ++ m->numfriends;
            return i;
        }
    }
    return -1;
}

/* remove a friend
   return 0 if success
   return -1 if failure */
int m_delfriend(Messenger *m, int friendnumber)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return -1;

    DHT_delfriend(m->friendlist[friendnumber].client_id);
    crypto_kill(m->friendlist[friendnumber].crypt_connection_id);
    free(m->friendlist[friendnumber].statusmessage);
    memset(&(m->friendlist[friendnumber]), 0, sizeof(Friend));
    uint32_t i;

    for (i = m->numfriends; i != 0; --i) {
        if (m->friendlist[i-1].status != NOFRIEND)
            break;
    }
    m->numfriends = i;
    realloc_friendlist(m, m->numfriends + 1);

    return 0;
}

/* return FRIEND_ONLINE if friend is online
   return FRIEND_CONFIRMED if friend is confirmed
   return FRIEND_REQUESTED if the friend request was sent
   return FRIEND_ADDED if the friend was added
   return NOFRIEND if there is no friend with that number */
int m_friendstatus(Messenger *m, int friendnumber)
{
    if (friendnumber < 0 || friendnumber >= m->numfriends)
        return NOFRIEND;
    return m->friendlist[friendnumber].status;
}

/* send a text chat message to an online friend
   return the message id if packet was successfully put into the send queue
   return 0 if it was not */
uint32_t m_sendmessage(Messenger *m, int friendnumber, uint8_t *message, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= m->numfriends)
        return 0;
    uint32_t msgid = ++m->friendlist[friendnumber].message_id;
    if (msgid == 0)
        msgid = 1; /* otherwise, false error */
    if(m_sendmessage_withid(m, friendnumber, msgid, message, length)) {
        return msgid;
    }

    return 0;
}

uint32_t m_sendmessage_withid(Messenger *m, int friendnumber, uint32_t theid, uint8_t *message, uint32_t length)
{
    if (length >= (MAX_DATA_SIZE - sizeof(theid)))
        return 0;
    uint8_t temp[MAX_DATA_SIZE];
    theid = htonl(theid);
    memcpy(temp, &theid, sizeof(theid));
    memcpy(temp + sizeof(theid), message, length);
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_MESSAGE, temp, length + sizeof(theid));
}

/* send an action to an online friend
   return 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendaction(Messenger *m, int friendnumber, uint8_t *action, uint32_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_ACTION, action, length);
}

/* send a name packet to friendnumber
   length is the length with the NULL terminator*/
static int m_sendname(Messenger *m, int friendnumber, uint8_t * name, uint16_t length)
{
    if(length > MAX_NAME_LENGTH || length == 0)
        return 0;
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_NICKNAME, name, length);
}

/* set the name of a friend
   return 0 if success
   return -1 if failure */
static int setfriendname(Messenger *m, int friendnumber, uint8_t * name)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return -1;
    memcpy(m->friendlist[friendnumber].name, name, MAX_NAME_LENGTH);
    return 0;
}

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   length must be at least 1 byte
   length is the length of name with the NULL terminator
   return 0 if success
   return -1 if failure */
int setname(Messenger *m, uint8_t * name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;
    memcpy(m->name, name, length);
    m->name_length = length;
    uint32_t i;
    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].name_sent = 0;
    return 0;
}

/* get our nickname
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return the length of the name */
uint16_t getself_name(Messenger *m, uint8_t *name)
{
    memcpy(name, m->name, m->name_length);
    return m->name_length;
}

/* get name of friendnumber
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return 0 if success
   return -1 if failure */
int getname(Messenger *m, int friendnumber, uint8_t * name)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return -1;
    memcpy(name, m->friendlist[friendnumber].name, MAX_NAME_LENGTH);
    return 0;
}

int m_set_statusmessage(Messenger *m, uint8_t *status, uint16_t length)
{
    if (length > MAX_STATUSMESSAGE_LENGTH)
        return -1;
    memcpy(m->statusmessage, status, length);
    m->statusmessage_length = length;

    uint32_t i;
    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].statusmessage_sent = 0;
    return 0;
}

int m_set_userstatus(Messenger *m, USERSTATUS status)
{
    if (status >= USERSTATUS_INVALID) {
        return -1;
    }
    m->userstatus = status;
    uint32_t i;
    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].userstatus_sent = 0;
    return 0;
}

/*  return the size of friendnumber's user status
    guaranteed to be at most MAX_STATUSMESSAGE_LENGTH */
int m_get_statusmessage_size(Messenger *m, int friendnumber)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return -1;
    return m->friendlist[friendnumber].statusmessage_length;
}

/*  copy the user status of friendnumber into buf, truncating if needed to maxlen
    bytes, use m_get_statusmessage_size to find out how much you need to allocate */
int m_copy_statusmessage(Messenger *m, int friendnumber, uint8_t * buf, uint32_t maxlen)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return -1;
    memset(buf, 0, maxlen);
    memcpy(buf, m->friendlist[friendnumber].statusmessage, MIN(maxlen, MAX_STATUSMESSAGE_LENGTH) - 1);
    return 0;
}

int m_copy_self_statusmessage(Messenger *m, uint8_t * buf, uint32_t maxlen)
{
    memset(buf, 0, maxlen);
    memcpy(buf, m->statusmessage, MIN(maxlen, MAX_STATUSMESSAGE_LENGTH) - 1);
    return 0;
}

USERSTATUS m_get_userstatus(Messenger *m, int friendnumber)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return USERSTATUS_INVALID;
    USERSTATUS status = m->friendlist[friendnumber].userstatus;
    if (status >= USERSTATUS_INVALID) {
        status = USERSTATUS_NONE;
    }
    return status;
}

USERSTATUS m_get_self_userstatus(Messenger *m)
{
    return m->userstatus;
}

static int send_statusmessage(Messenger *m, int friendnumber, uint8_t * status, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_STATUSMESSAGE, status, length);
}

static int send_userstatus(Messenger *m, int friendnumber, USERSTATUS status)
{
    uint8_t stat = status;
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_USERSTATUS, &stat, sizeof(stat));
}

static int set_friend_statusmessage(Messenger *m, int friendnumber, uint8_t * status, uint16_t length)
{
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return -1;
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(m->friendlist[friendnumber].statusmessage);
    m->friendlist[friendnumber].statusmessage = newstatus;
    m->friendlist[friendnumber].statusmessage_length = length;
    return 0;
}

static void set_friend_userstatus(Messenger *m, int friendnumber, USERSTATUS status)
{
    m->friendlist[friendnumber].userstatus = status;
}

/* Sets whether we send read receipts for friendnumber. */
void m_set_sends_receipts(Messenger *m, int friendnumber, int yesno)
{
    if (yesno != 0 || yesno != 1)
        return;
    if (friendnumber >= m->numfriends || friendnumber < 0)
        return;
    m->friendlist[friendnumber].receives_read_receipts = yesno;
}

/* static void (*friend_request)(uint8_t *, uint8_t *, uint16_t);
static uint8_t friend_request_isset = 0; */
/* set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(Messenger *m, void (*function)(uint8_t *, uint8_t *, uint16_t, void*), void* userdata)
{
    callback_friendrequest(function, userdata);
}

/* set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void*), void* userdata)
{
    m->friend_message = function;
    m->friend_message_isset = 1;
    m->friend_message_userdata = userdata;
}

void m_callback_action(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void*), void* userdata)
{
    m->friend_action = function;
    m->friend_action_isset = 1;
    m->friend_action_userdata = userdata;
}

void m_callback_namechange(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void*), void* userdata)
{
    m->friend_namechange = function;
    m->friend_namechange_isset = 1;
    m->friend_namechange_userdata = userdata;
}

void m_callback_statusmessage(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void*), void* userdata)
{
    m->friend_statusmessagechange = function;
    m->friend_statusmessagechange_isset = 1;
    m->friend_statuschange_userdata = userdata;
}

void m_callback_userstatus(Messenger *m, void (*function)(Messenger *m, int, USERSTATUS, void*), void* userdata)
{
    m->friend_userstatuschange = function;
    m->friend_userstatuschange_isset = 1;
    m->friend_userstatuschange_userdata = userdata;
}

void m_callback_read_receipt(Messenger *m, void (*function)(Messenger *m, int, uint32_t, void*), void* userdata)
{
    m->read_receipt = function;
    m->read_receipt_isset = 1;
    m->read_receipt_userdata = userdata;
}

void m_callback_connectionstatus(Messenger *m, void (*function)(Messenger *m, int, uint8_t, void*), void* userdata)
{
    m->friend_connectionstatuschange = function;
    m->friend_connectionstatuschange_isset = 1;
    m->friend_connectionstatuschange_userdata = userdata;
}

static void check_friend_connectionstatus(Messenger *m, int friendnumber, uint8_t status)
{
    if (!m->friend_connectionstatuschange_isset)
        return;
    if (status == NOFRIEND)
        return;
    const uint8_t was_connected = m->friendlist[friendnumber].status == FRIEND_ONLINE;
    const uint8_t is_connected = status == FRIEND_ONLINE;
    if (is_connected != was_connected)
        m->friend_connectionstatuschange(m, friendnumber, is_connected, m->friend_connectionstatuschange_userdata);
}

void set_friend_status(Messenger *m, int friendnumber, uint8_t status)
{
    check_friend_connectionstatus(m, friendnumber, status);
    m->friendlist[friendnumber].status = status;
}

int write_cryptpacket_id(Messenger *m, int friendnumber, uint8_t packet_id, uint8_t *data, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= m->numfriends)
        return 0;
    if (length >= MAX_DATA_SIZE || m->friendlist[friendnumber].status != FRIEND_ONLINE)
        return 0;
    uint8_t packet[length + 1];
    packet[0] = packet_id;
    memcpy(packet + 1, data, length);
    return write_cryptpacket(m->friendlist[friendnumber].crypt_connection_id, packet, length + 1);
}

<<<<<<< HEAD
=======
#define PORT 33445
/* run this at startup */
Messenger * initMessenger(void)
{
    Messenger *m = calloc(1, sizeof(Messenger));
    if( ! m )
        return 0;

    new_keys();
    m_set_statusmessage(m, (uint8_t*)"Online", sizeof("Online"));
    initNetCrypto();
    IP ip;
    ip.i = 0;

    if(init_networking(ip,PORT) == -1)
        return 0;

    DHT_init();
    LosslessUDP_init();
    friendreq_init();
    LANdiscovery_init();

    return m;
}

/* run this before closing shop */
void cleanupMessenger(Messenger *m){
    /* FIXME TODO it seems no one frees friendlist or all the elements status */
    free(m);
}

>>>>>>> upstream/master
//TODO: make this function not suck.
void doFriends(Messenger *m)
{
    /* TODO: add incoming connections and some other stuff. */
    uint32_t i;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status == FRIEND_ADDED) {
            int fr = send_friendrequest(m->friendlist[i].client_id, m->friendlist[i].info, m->friendlist[i].info_size);
            if (fr == 0) /* TODO: This needs to be fixed so that it sends the friend requests a couple of times in case of packet loss */
                set_friend_status(m, i, FRIEND_REQUESTED);
            else if (fr > 0)
                set_friend_status(m, i, FRIEND_REQUESTED);
        }
        if (m->friendlist[i].status == FRIEND_REQUESTED || m->friendlist[i].status == FRIEND_CONFIRMED) { /* friend is not online */
            if (m->friendlist[i].status == FRIEND_REQUESTED) {
                if (m->friendlist[i].friend_request_id + 10 < unix_time()) { /*I know this is hackish but it should work.*/
                    send_friendrequest(m->friendlist[i].client_id, m->friendlist[i].info, m->friendlist[i].info_size);
                    m->friendlist[i].friend_request_id = unix_time();
                }
            }
            IP_Port friendip = DHT_getfriendip(m->friendlist[i].client_id);
            switch (is_cryptoconnected(m->friendlist[i].crypt_connection_id)) {
            case 0:
                if (friendip.ip.i > 1)
                    m->friendlist[i].crypt_connection_id = crypto_connect(m->friendlist[i].client_id, friendip);
                break;
            case 3: /*  Connection is established */
                set_friend_status(m, i, FRIEND_ONLINE);
                m->friendlist[i].name_sent = 0;
                m->friendlist[i].userstatus_sent = 0;
                m->friendlist[i].statusmessage_sent = 0;
                break;
            case 4:
                crypto_kill(m->friendlist[i].crypt_connection_id);
                m->friendlist[i].crypt_connection_id = -1;
                break;
            default:
                break;
            }
        }
        while (m->friendlist[i].status == FRIEND_ONLINE) { /* friend is online */
            if (m->friendlist[i].name_sent == 0) {
                if (m_sendname(m, i, m->name, m->name_length))
                    m->friendlist[i].name_sent = 1;
            }
            if (m->friendlist[i].statusmessage_sent == 0) {
                if (send_statusmessage(m, i, m->statusmessage, m->statusmessage_length))
                    m->friendlist[i].statusmessage_sent = 1;
            }
            if (m->friendlist[i].userstatus_sent == 0) {
                if (send_userstatus(m, i, m->userstatus))
                    m->friendlist[i].userstatus_sent = 1;
            }
            len = read_cryptpacket(m->friendlist[i].crypt_connection_id, temp);
            uint8_t packet_id = temp[0];
            uint8_t* data = temp + 1;
            int data_length = len - 1;
            if (len > 0) {
                switch (packet_id) {
                case PACKET_ID_NICKNAME: {
                    if (data_length >= MAX_NAME_LENGTH || data_length == 0)
                        break;
                    if(m->friend_namechange_isset)
                        m->friend_namechange(m, i, data, data_length, m->friend_namechange_userdata);
                    memcpy(m->friendlist[i].name, data, data_length);
                    m->friendlist[i].name[data_length - 1] = 0; /* make sure the NULL terminator is present. */
                    break;
                }
                case PACKET_ID_STATUSMESSAGE: {
                    if (data_length == 0)
                        break;
                    uint8_t *status = calloc(MIN(data_length, MAX_STATUSMESSAGE_LENGTH), 1);
                    memcpy(status, data, MIN(data_length, MAX_STATUSMESSAGE_LENGTH));
                    if (m->friend_statusmessagechange_isset)
                        m->friend_statusmessagechange(m, i, status, MIN(data_length, MAX_STATUSMESSAGE_LENGTH),
                                                      m->friend_statuschange_userdata);
                    set_friend_statusmessage(m, i, status, MIN(data_length, MAX_STATUSMESSAGE_LENGTH));
                    free(status);
                    break;
                }
                case PACKET_ID_USERSTATUS: {
                    if (data_length != 1)
                        break;
                    USERSTATUS status = data[0];
                    if (m->friend_userstatuschange_isset)
                        m->friend_userstatuschange(m, i, status, m->friend_userstatuschange_userdata);
                    set_friend_userstatus(m, i, status);
                    break;
                }
                case PACKET_ID_MESSAGE: {
                    uint8_t *message_id = data;
                    uint8_t message_id_length = 4;
                    uint8_t *message = data + message_id_length;
                    uint16_t message_length = data_length - message_id_length;
                    if (m->friendlist[i].receives_read_receipts) {
                        write_cryptpacket_id(m, i, PACKET_ID_RECEIPT, message_id, message_id_length);
                    }
                    if (m->friend_message_isset)
                        (*m->friend_message)(m, i, message, message_length, m->friend_message_userdata);
                    break;
                }
                case PACKET_ID_ACTION: {
                    if (m->friend_action_isset)
                        (*m->friend_action)(m, i, data, data_length, m->friend_action_userdata);
                    break;
                }
                case PACKET_ID_RECEIPT: {
                    uint32_t msgid;
                    if (data_length < sizeof(msgid))
                        break;
                    memcpy(&msgid, data, sizeof(msgid));
                    msgid = ntohl(msgid);
                    if (m->read_receipt_isset)
                        (*m->read_receipt)(m, i, msgid, m->read_receipt_userdata);
                    break;
                }
                }
            } else {
                if (is_cryptoconnected(m->friendlist[i].crypt_connection_id) == 4) { /* if the connection timed out, kill it */
                    crypto_kill(m->friendlist[i].crypt_connection_id);
                    m->friendlist[i].crypt_connection_id = -1;
                    set_friend_status(m, i, FRIEND_CONFIRMED);
                }
                break;
            }
        }
    }
}

void doInbound(Messenger *m)
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(public_key, secret_nonce, session_key);
    if (inconnection != -1) {
        int friend_id = getfriend_id(m, public_key);
        if (friend_id != -1) {
            crypto_kill(m->friendlist[friend_id].crypt_connection_id);
            m->friendlist[friend_id].crypt_connection_id =
                accept_crypto_inbound(inconnection, public_key, secret_nonce, session_key);

            set_friend_status(m, friend_id, FRIEND_CONFIRMED);
        }
    }
}

#define PORT 33445

/*Interval in seconds between LAN discovery packet sending*/
#define LAN_DISCOVERY_INTERVAL 60

/*Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds*/
<<<<<<< HEAD
static int LANdiscovery_timercallback(timer* t, void* ignore)
=======
void LANdiscovery(Messenger *m)
>>>>>>> upstream/master
{
    send_LANdiscovery(htons(PORT));
    timer_start(t, LAN_DISCOVERY_INTERVAL);
    return 0;
}

/* run this at startup */
int initMessenger(void)
{
    timer_init();
    new_keys();
    m_set_statusmessage((uint8_t*)"Online", sizeof("Online"));
    initNetCrypto();
    IP ip;
    ip.i = 0;

    if(init_networking(ip,PORT) == -1)
        return -1;

    DHT_init();
    LosslessUDP_init();
    friendreq_init();
    LANdiscovery_init();

    timer_single(&LANdiscovery_timercallback, 0, LAN_DISCOVERY_INTERVAL);

    return 0;
}

/* the main loop that needs to be run at least 200 times per second. */
void doMessenger(Messenger *m)
{
    networking_poll();
<<<<<<< HEAD
    timer_poll();
	
    doDHT();
    doLossless_UDP();
    doNetCrypto();
    doInbound();
    doFriends();
=======

    doDHT();
    doLossless_UDP();
    doNetCrypto();
    doInbound(m);
    doFriends(m);
    LANdiscovery(m);
>>>>>>> upstream/master
}

/* returns the size of the messenger data (for saving) */
uint32_t Messenger_size(Messenger *m)
{
    return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
           + sizeof(uint32_t) + DHT_size() + sizeof(uint32_t) + sizeof(Friend) * m->numfriends;
}

/* save the messenger in data of size Messenger_size() */
void Messenger_save(Messenger *m, uint8_t *data)
{
    save_keys(data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t size = DHT_size();
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    DHT_save(data);
    data += size;
    size = sizeof(Friend) * m->numfriends;
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    memcpy(data, m->friendlist, sizeof(Friend) * m->numfriends);
}

/* load the messenger from data of size length. */
int Messenger_load(Messenger *m, uint8_t * data, uint32_t length)
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
            int fnum = m_addfriend_norequest(m, temp[i].client_id);
            setfriendname(m, fnum, temp[i].name);
            /* set_friend_statusmessage(fnum, temp[i].statusmessage, temp[i].statusmessage_length); */
        }
    }
    free(temp);
    return 0;
}

