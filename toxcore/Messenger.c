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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "Messenger.h"
#include "assoc.h"
#include "network.h"
#include "util.h"


#define MIN(a,b) (((a)<(b))?(a):(b))


void host_to_net(uint8_t *num, uint16_t numbytes)
{
    union {
        uint32_t i;
        uint8_t c[4];
    } a;
    a.i = 1;

    if (a.c[0] == 1) {
        uint32_t i;
        uint8_t buff[numbytes];

        for (i = 0; i < numbytes; ++i) {
            buff[i] = num[numbytes - i - 1];
        }

        memcpy(num, buff, numbytes);
    }
}
#define net_to_host(x, y) host_to_net(x, y)

static void set_friend_status(Messenger *m, int friendnumber, uint8_t status);
static int write_cryptpacket_id(Messenger *m, int friendnumber, uint8_t packet_id, uint8_t *data, uint32_t length);

// friend_not_valid determines if the friendnumber passed is valid in the Messenger object
static uint8_t friend_not_valid(Messenger *m, int friendnumber)
{
    return (unsigned int)friendnumber >= m->numfriends;
}

/* Set the size of the friend list to numfriends.
 *
 *  return -1 if realloc fails.
 */
int realloc_friendlist(Messenger *m, uint32_t num)
{
    if (num == 0) {
        free(m->friendlist);
        m->friendlist = NULL;
        return 0;
    }

    Friend *newfriendlist = realloc(m->friendlist, num * sizeof(Friend));

    if (newfriendlist == NULL)
        return -1;

    m->friendlist = newfriendlist;
    return 0;
}

/*  return the friend id associated to that public key.
 *  return -1 if no such friend.
 */
int getfriend_id(Messenger *m, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status > 0)
            if (id_equal(client_id, m->friendlist[i].client_id))
                return i;
    }

    return -1;
}

/* Copies the public key associated to that friend id into client_id buffer.
 * Make sure that client_id is of size CLIENT_ID_SIZE.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int getclient_id(Messenger *m, int friend_id, uint8_t *client_id)
{
    if (friend_not_valid(m, friend_id))
        return -1;

    if (m->friendlist[friend_id].status > 0) {
        memcpy(client_id, m->friendlist[friend_id].client_id, CLIENT_ID_SIZE);
        return 0;
    }

    return -1;
}
/* TODO: Another checksum algorithm might be better.
 *
 *  return a uint16_t that represents the checksum of address of length len.
 */
static uint16_t address_checksum(uint8_t *address, uint32_t len)
{
    uint8_t checksum[2] = {0};
    uint16_t check;
    uint32_t i;

    for (i = 0; i < len; ++i)
        checksum[i % 2] ^= address[i];

    memcpy(&check, checksum, sizeof(check));
    return check;
}

/* Format: [client_id (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 *
 *  return FRIEND_ADDRESS_SIZE byte address to give to others.
 */
void getaddress(Messenger *m, uint8_t *address)
{
    id_copy(address, m->net_crypto->self_public_key);
    uint32_t nospam = get_nospam(&(m->fr));
    memcpy(address + crypto_box_PUBLICKEYBYTES, &nospam, sizeof(nospam));
    uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(nospam), &checksum, sizeof(checksum));
}

/*
 * Add a friend.
 * Set the data that will be sent along with friend request.
 * Address is the address of the friend (returned by getaddress of the friend you wish to add) it must be FRIEND_ADDRESS_SIZE bytes.
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
int m_addfriend(Messenger *m, uint8_t *address, uint8_t *data, uint16_t length)
{
    if (length >= (MAX_DATA_SIZE - crypto_box_PUBLICKEYBYTES
                   - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES
                   + crypto_box_ZEROBYTES))
        return FAERR_TOOLONG;

    uint8_t client_id[crypto_box_PUBLICKEYBYTES];
    id_copy(client_id, address);
    uint16_t check, checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(&check, address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), sizeof(check));

    if (check != checksum)
        return FAERR_BADCHECKSUM;

    if (length < 1)
        return FAERR_NOMESSAGE;

    if (id_equal(client_id, m->net_crypto->self_public_key))
        return FAERR_OWNKEY;

    int friend_id = getfriend_id(m, client_id);

    if (friend_id != -1) {
        uint32_t nospam;
        memcpy(&nospam, address + crypto_box_PUBLICKEYBYTES, sizeof(nospam));

        if (m->friendlist[friend_id].friendrequest_nospam == nospam)
            return FAERR_ALREADYSENT;

        m->friendlist[friend_id].friendrequest_nospam = nospam;
        return FAERR_SETNEWNOSPAM;
    }

    /* Resize the friend list if necessary. */
    if (realloc_friendlist(m, m->numfriends + 1) != 0)
        return FAERR_NOMEM;

    memset(&(m->friendlist[m->numfriends]), 0, sizeof(Friend));

    int onion_friendnum = onion_addfriend(m->onion_c, client_id);

    if (onion_friendnum == -1)
        return FAERR_UNKNOWN;

    uint32_t i;

    for (i = 0; i <= m->numfriends; ++i)  {
        if (m->friendlist[i].status == NOFRIEND) {
            m->friendlist[i].onion_friendnum = onion_friendnum;
            m->friendlist[i].status = FRIEND_ADDED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friendrequest_lastsent = 0;
            m->friendlist[i].friendrequest_timeout = FRIENDREQUEST_TIMEOUT;
            id_copy(m->friendlist[i].client_id, client_id);
            m->friendlist[i].statusmessage = calloc(1, 1);
            m->friendlist[i].statusmessage_length = 1;
            m->friendlist[i].userstatus = USERSTATUS_NONE;
            memcpy(m->friendlist[i].info, data, length);
            m->friendlist[i].info_size = length;
            m->friendlist[i].message_id = 0;
            m->friendlist[i].receives_read_receipts = 1; /* Default: YES. */
            memcpy(&(m->friendlist[i].friendrequest_nospam), address + crypto_box_PUBLICKEYBYTES, sizeof(uint32_t));

            if (m->numfriends == i)
                ++ m->numfriends;

            return i;
        }
    }

    return FAERR_UNKNOWN;
}

int m_addfriend_norequest(Messenger *m, uint8_t *client_id)
{
    if (getfriend_id(m, client_id) != -1)
        return -1;

    /* Resize the friend list if necessary. */
    if (realloc_friendlist(m, m->numfriends + 1) != 0)
        return FAERR_NOMEM;

    if (id_equal(client_id, m->net_crypto->self_public_key))
        return FAERR_OWNKEY;

    memset(&(m->friendlist[m->numfriends]), 0, sizeof(Friend));

    int onion_friendnum = onion_addfriend(m->onion_c, client_id);

    if (onion_friendnum == -1)
        return FAERR_UNKNOWN;

    uint32_t i;

    for (i = 0; i <= m->numfriends; ++i) {
        if (m->friendlist[i].status == NOFRIEND) {
            m->friendlist[i].onion_friendnum = onion_friendnum;
            m->friendlist[i].status = FRIEND_CONFIRMED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friendrequest_lastsent = 0;
            id_copy(m->friendlist[i].client_id, client_id);
            m->friendlist[i].statusmessage = calloc(1, 1);
            m->friendlist[i].statusmessage_length = 1;
            m->friendlist[i].userstatus = USERSTATUS_NONE;
            m->friendlist[i].message_id = 0;
            m->friendlist[i].receives_read_receipts = 1; /* Default: YES. */

            if (m->numfriends == i)
                ++ m->numfriends;

            return i;
        }
    }

    return -1;
}

/* Remove a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int m_delfriend(Messenger *m, int friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    onion_delfriend(m->onion_c, m->friendlist[friendnumber].onion_friendnum);
    crypto_kill(m->net_crypto, m->friendlist[friendnumber].crypt_connection_id);
    free(m->friendlist[friendnumber].statusmessage);
    memset(&(m->friendlist[friendnumber]), 0, sizeof(Friend));
    uint32_t i;

    for (i = m->numfriends; i != 0; --i) {
        if (m->friendlist[i - 1].status != NOFRIEND)
            break;
    }

    m->numfriends = i;

    if (realloc_friendlist(m, m->numfriends) != 0)
        return FAERR_NOMEM;

    return 0;
}

int m_get_friend_connectionstatus(Messenger *m, int friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].status == FRIEND_ONLINE;
}

int m_friend_exists(Messenger *m, int friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    return m->friendlist[friendnumber].status > NOFRIEND;
}

/* Send a text chat message to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
uint32_t m_sendmessage(Messenger *m, int friendnumber, uint8_t *message, uint32_t length)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    uint32_t msgid = ++m->friendlist[friendnumber].message_id;

    if (msgid == 0)
        msgid = 1; // Otherwise, false error

    if (m_sendmessage_withid(m, friendnumber, msgid, message, length)) {
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

/* Send an action to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
uint32_t m_sendaction(Messenger *m, int friendnumber, uint8_t *action, uint32_t length)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    uint32_t msgid = ++m->friendlist[friendnumber].message_id;

    if (msgid == 0)
        msgid = 1; // Otherwise, false error

    if (m_sendaction_withid(m, friendnumber, msgid, action, length)) {
        return msgid;
    }

    return 0;
}

uint32_t m_sendaction_withid(Messenger *m, int friendnumber, uint32_t theid, uint8_t *action, uint32_t length)
{
    if (length >= (MAX_DATA_SIZE - sizeof(theid)))
        return 0;

    uint8_t temp[MAX_DATA_SIZE];
    theid = htonl(theid);
    memcpy(temp, &theid, sizeof(theid));
    memcpy(temp + sizeof(theid), action, length);
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_ACTION, temp, length + sizeof(theid));
}

/* Send a name packet to friendnumber.
 * length is the length with the NULL terminator.
 */
static int m_sendname(Messenger *m, int friendnumber, uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return 0;

    return write_cryptpacket_id(m, friendnumber, PACKET_ID_NICKNAME, name, length);
}

/* Set the name and name_length of a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setfriendname(Messenger *m, int friendnumber, uint8_t *name, uint16_t length)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;

    m->friendlist[friendnumber].name_length = length;
    memcpy(m->friendlist[friendnumber].name, name, length);
    return 0;
}

/* Set our nickname
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setname(Messenger *m, uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;

    memcpy(m->name, name, length);
    m->name_length = length;
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].name_sent = 0;

    for (i = 0; i < m->numchats; i++)
        if (m->chats[i] != NULL)
            set_nick(m->chats[i], name, length); /* TODO: remove this (group nicks should not be tied to the global one) */

    return 0;
}

/* Get our nickname and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return the length of the name.
 */
uint16_t getself_name(Messenger *m, uint8_t *name, uint16_t nlen)
{
    uint16_t len;

    if (name == NULL || nlen == 0) {
        return 0;
    }

    len = MIN(nlen, m->name_length);
    memcpy(name, m->name, len);

    return len;
}

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return length of name if success.
 *  return -1 if failure.
 */
int getname(Messenger *m, int friendnumber, uint8_t *name)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    memcpy(name, m->friendlist[friendnumber].name, m->friendlist[friendnumber].name_length);
    return m->friendlist[friendnumber].name_length;
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

/* return the size of friendnumber's user status.
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 */
int m_get_statusmessage_size(Messenger *m, int friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].statusmessage_length;
}

/*  Copy the user status of friendnumber into buf, truncating if needed to maxlen
 *  bytes, use m_get_statusmessage_size to find out how much you need to allocate.
 */
int m_copy_statusmessage(Messenger *m, int friendnumber, uint8_t *buf, uint32_t maxlen)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    memset(buf, 0, maxlen);
    memcpy(buf, m->friendlist[friendnumber].statusmessage, MIN(maxlen, m->friendlist[friendnumber].statusmessage_length));
    return MIN(maxlen, m->friendlist[friendnumber].statusmessage_length);
}

int m_copy_self_statusmessage(Messenger *m, uint8_t *buf, uint32_t maxlen)
{
    memset(buf, 0, maxlen);
    memcpy(buf, m->statusmessage, MIN(maxlen, m->statusmessage_length));
    return MIN(maxlen, m->statusmessage_length);
}

USERSTATUS m_get_userstatus(Messenger *m, int friendnumber)
{
    if (friend_not_valid(m, friendnumber))
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

static int send_statusmessage(Messenger *m, int friendnumber, uint8_t *status, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_STATUSMESSAGE, status, length);
}

static int send_userstatus(Messenger *m, int friendnumber, USERSTATUS status)
{
    uint8_t stat = status;
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_USERSTATUS, &stat, sizeof(stat));
}

static int send_ping(Messenger *m, int friendnumber)
{
    int ret = write_cryptpacket_id(m, friendnumber, PACKET_ID_PING, 0, 0);

    if (ret == 1)
        m->friendlist[friendnumber].ping_lastsent = unix_time();

    return ret;
}

static int set_friend_statusmessage(Messenger *m, int friendnumber, uint8_t *status, uint16_t length)
{
    if (friend_not_valid(m, friendnumber))
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
    if (yesno != 0 && yesno != 1)
        return;

    if (friend_not_valid(m, friendnumber))
        return;

    m->friendlist[friendnumber].receives_read_receipts = yesno;
}

/* static void (*friend_request)(uint8_t *, uint8_t *, uint16_t); */
/* Set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(Messenger *m, void (*function)(uint8_t *, uint8_t *, uint16_t, void *), void *userdata)
{
    callback_friendrequest(&(m->fr), function, userdata);
}

/* Set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                              void *userdata)
{
    m->friend_message = function;
    m->friend_message_userdata = userdata;
}

void m_callback_action(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *), void *userdata)
{
    m->friend_action = function;
    m->friend_action_userdata = userdata;
}

void m_callback_namechange(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                           void *userdata)
{
    m->friend_namechange = function;
    m->friend_namechange_userdata = userdata;
}

void m_callback_statusmessage(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                              void *userdata)
{
    m->friend_statusmessagechange = function;
    m->friend_statuschange_userdata = userdata;
}

void m_callback_userstatus(Messenger *m, void (*function)(Messenger *m, int, USERSTATUS, void *), void *userdata)
{
    m->friend_userstatuschange = function;
    m->friend_userstatuschange_userdata = userdata;
}

void m_callback_read_receipt(Messenger *m, void (*function)(Messenger *m, int, uint32_t, void *), void *userdata)
{
    m->read_receipt = function;
    m->read_receipt_userdata = userdata;
}

void m_callback_connectionstatus(Messenger *m, void (*function)(Messenger *m, int, uint8_t, void *), void *userdata)
{
    m->friend_connectionstatuschange = function;
    m->friend_connectionstatuschange_userdata = userdata;
}
static void break_files(Messenger *m, int friendnumber);
static void check_friend_connectionstatus(Messenger *m, int friendnumber, uint8_t status)
{
    if (!m->friend_connectionstatuschange)
        return;

    if (status == NOFRIEND)
        return;

    const uint8_t was_online = m->friendlist[friendnumber].status == FRIEND_ONLINE;
    const uint8_t is_online = status == FRIEND_ONLINE;

    if (is_online != was_online) {
        if (was_online)
            break_files(m, friendnumber);

        m->friend_connectionstatuschange(m, friendnumber, is_online, m->friend_connectionstatuschange_userdata);
    }
}

void set_friend_status(Messenger *m, int friendnumber, uint8_t status)
{
    check_friend_connectionstatus(m, friendnumber, status);
    m->friendlist[friendnumber].status = status;
}

int write_cryptpacket_id(Messenger *m, int friendnumber, uint8_t packet_id, uint8_t *data, uint32_t length)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    if (length >= MAX_DATA_SIZE || m->friendlist[friendnumber].status != FRIEND_ONLINE)
        return 0;

    uint8_t packet[length + 1];
    packet[0] = packet_id;

    if (length != 0)
        memcpy(packet + 1, data, length);

    return write_cryptpacket(m->net_crypto, m->friendlist[friendnumber].crypt_connection_id, packet, length + 1);
}

/**********GROUP CHATS************/

/* return 1 if the groupnumber is not valid.
 * return 0 if the groupnumber is valid.
 */
static uint8_t groupnumber_not_valid(Messenger *m, int groupnumber)
{
    if ((unsigned int)groupnumber >= m->numchats)
        return 1;

    if (m->chats == NULL)
        return 1;

    if (m->chats[groupnumber] == NULL)
        return 1;

    return 0;
}


/* returns valid ip port of connected friend on success
 * returns zeroed out IP_Port on failure
 */
IP_Port get_friend_ipport(Messenger *m, int friendnumber)
{
    IP_Port zero;
    memset(&zero, 0, sizeof(zero));

    if (friend_not_valid(m, friendnumber))
        return zero;

    int crypt_id = m->friendlist[friendnumber].crypt_connection_id;

    if (is_cryptoconnected(m->net_crypto, crypt_id) != CRYPTO_CONN_ESTABLISHED)
        return zero;

    return connection_ip(m->net_crypto->lossless_udp, m->net_crypto->crypto_connections[crypt_id].number);
}

/* returns the group number of the chat with public key group_public_key.
 * returns -1 on failure.
 */
static int group_num(Messenger *m, uint8_t *group_public_key)
{
    uint32_t i;

    for (i = 0; i < m->numchats; ++i) {
        if (m->chats[i] != NULL)
            if (id_equal(m->chats[i]->self_public_key, group_public_key))
                return i;
    }

    return -1;
}

/* Set the callback for group invites.
 *
 *  Function(Messenger *m, int friendnumber, uint8_t *group_public_key, void *userdata)
 */
void m_callback_group_invite(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, void *), void *userdata)
{
    m->group_invite = function;
    m->group_invite_userdata = userdata;
}

/* Set the callback for group messages.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void m_callback_group_message(Messenger *m, void (*function)(Messenger *m, int, int, uint8_t *, uint16_t, void *),
                              void *userdata)
{
    m->group_message = function;
    m->group_message_userdata = userdata;
}

/* Set the callback for group actions.
 *
 *  Function(Tox *tox, int groupnumber, int friendgroupnumber, uint8_t * message, uint16_t length, void *userdata)
 */
void m_callback_group_action(Messenger *m, void (*function)(Messenger *m, int, int, uint8_t *, uint16_t, void *),
                             void *userdata)
{
    m->group_action = function;
    m->group_action_userdata = userdata;
}

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Tox *tox, int groupnumber, void *userdata)
 */
void m_callback_group_namelistchange(Messenger *m, void (*function)(Messenger *m, int, int, uint8_t, void *),
                                     void *userdata)
{
    m->group_namelistchange = function;
    m->group_namelistchange_userdata = userdata;
}

static int get_chat_num(Messenger *m, Group_Chat *chat)
{
    uint32_t i;

    for (i = 0; i < m->numchats; ++i) { //TODO: remove this
        if (m->chats[i] == chat)
            return i;
    }

    return -1;
}

static void group_message_function(Group_Chat *chat, int peer_number, uint8_t *message, uint16_t length, void *userdata)
{
    Messenger *m = userdata;
    int i = get_chat_num(m, chat);

    if (i == -1)
        return;

    if (m->group_message)
        (*m->group_message)(m, i, peer_number, message, length, m->group_message_userdata);
}

static void group_action_function(Group_Chat *chat, int peer_number, uint8_t *action, uint16_t length, void *userdata)
{
    Messenger *m = userdata;
    int i = get_chat_num(m, chat);

    if (i == -1)
        return;

    if (m->group_action)
        (*m->group_action)(m, i, peer_number, action, length, m->group_action_userdata);
}

static void group_namelistchange_function(Group_Chat *chat, int peer, uint8_t change, void *userdata)
{
    Messenger *m = userdata;
    int i = get_chat_num(m, chat);

    if (i == -1)
        return;

    if (m->group_namelistchange)
        (*m->group_namelistchange)(m, i, peer, change, m->group_namelistchange_userdata);
}


/* Creates a new groupchat and puts it in the chats array.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_groupchat(Messenger *m)
{
    uint32_t i;

    for (i = 0; i < m->numchats; ++i) {
        if (m->chats[i] == NULL) {
            Group_Chat *newchat = new_groupchat(m->net);

            if (newchat == NULL)
                return -1;

            callback_groupmessage(newchat, &group_message_function, m);
            callback_groupaction(newchat, &group_action_function, m);
            callback_namelistchange(newchat, &group_namelistchange_function, m);
            /* TODO: remove this (group nicks should not be tied to the global one) */
            set_nick(newchat, m->name, m->name_length);
            m->chats[i] = newchat;
            return i;
        }
    }

    Group_Chat **temp;
    temp = realloc(m->chats, sizeof(Group_Chat *) * (m->numchats + 1));

    if (temp == NULL)
        return -1;

    m->chats = temp;
    temp[m->numchats] = new_groupchat(m->net);

    if (temp[m->numchats] == NULL)
        return -1;

    callback_groupmessage(temp[m->numchats], &group_message_function, m);
    callback_groupaction(temp[m->numchats], &group_action_function, m);
    callback_namelistchange(temp[m->numchats], &group_namelistchange_function, m);
    /* TODO: remove this (group nicks should not be tied to the global one) */
    set_nick(temp[m->numchats], m->name, m->name_length);
    ++m->numchats;
    return (m->numchats - 1);
}

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
int del_groupchat(Messenger *m, int groupnumber)
{
    if ((unsigned int)groupnumber >= m->numchats)
        return -1;

    if (m->chats == NULL)
        return -1;

    if (m->chats[groupnumber] == NULL)
        return -1;

    kill_groupchat(m->chats[groupnumber]);
    m->chats[groupnumber] = NULL;

    uint32_t i;

    for (i = m->numchats; i != 0; --i) {
        if (m->chats[i - 1] != NULL)
            break;
    }

    m->numchats = i;

    if (i == 0) {
        free(m->chats);
        m->chats = NULL;
    } else {
        Group_Chat **temp = realloc(m->chats, sizeof(Group_Chat *) * i);

        if (temp != NULL)
            m->chats = temp;
    }

    return 0;
}

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
int m_group_peername(Messenger *m, int groupnumber, int peernumber, uint8_t *name)
{
    if ((unsigned int)groupnumber >= m->numchats)
        return -1;

    if (m->chats == NULL)
        return -1;

    if (m->chats[groupnumber] == NULL)
        return -1;

    return group_peername(m->chats[groupnumber], peernumber, name);
}

/* Store the fact that we invited a specific friend.
 */
static void group_store_friendinvite(Messenger *m, int friendnumber, int groupnumber)
{
    /* Add 1 to the groupchat number because 0 (default value in invited_groups) is a valid groupchat number */
    m->friendlist[friendnumber].invited_groups[m->friendlist[friendnumber].invited_groups_num % MAX_INVITED_GROUPS] =
        groupnumber + 1;
    ++m->friendlist[friendnumber].invited_groups_num;
}

/* return 1 if that friend was invited to the group
 * return 0 if the friend was not or error.
 */
static uint8_t group_invited(Messenger *m, int friendnumber, int groupnumber)
{

    uint32_t i;
    uint16_t num = MAX_INVITED_GROUPS;

    if (MAX_INVITED_GROUPS > m->friendlist[friendnumber].invited_groups_num)
        num = m->friendlist[friendnumber].invited_groups_num;

    for (i = 0; i < num; ++i) {
        if (m->friendlist[friendnumber].invited_groups[i] == groupnumber + 1) {
            return 1;
        }
    }

    return 0;
}

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
int invite_friend(Messenger *m, int friendnumber, int groupnumber)
{
    if (friend_not_valid(m, friendnumber) || (unsigned int)groupnumber >= m->numchats)
        return -1;

    if (m->chats == NULL)
        return -1;

    if (m->friendlist[friendnumber].status == NOFRIEND || m->chats[groupnumber] == NULL)
        return -1;

    group_store_friendinvite(m, friendnumber, groupnumber);

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_INVITE_GROUPCHAT, m->chats[groupnumber]->self_public_key,
                             crypto_box_PUBLICKEYBYTES) == 0)
        return -1;

    return 0;
}


/* Join a group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 */
int join_groupchat(Messenger *m, int friendnumber, uint8_t *friend_group_public_key)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    uint8_t data[crypto_box_PUBLICKEYBYTES * 2];
    int groupnum = add_groupchat(m);

    if (groupnum == -1)
        return -1;

    id_copy(data, friend_group_public_key);
    id_copy(data + crypto_box_PUBLICKEYBYTES, m->chats[groupnum]->self_public_key);

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_JOIN_GROUPCHAT, data, sizeof(data))) {
        chat_bootstrap_nonlazy(m->chats[groupnum], get_friend_ipport(m, friendnumber),
                               friend_group_public_key); //TODO: check if ip returned is zero?
        return groupnum;
    }

    return -1;
}


/* send a group message
 * return 0 on success
 * return -1 on failure
 */
int group_message_send(Messenger *m, int groupnumber, uint8_t *message, uint32_t length)
{
    if (groupnumber_not_valid(m, groupnumber))
        return -1;

    if (group_sendmessage(m->chats[groupnumber], message, length) > 0)
        return 0;

    return -1;
}

/* send a group action
 * return 0 on success
 * return -1 on failure
 */
int group_action_send(Messenger *m, int groupnumber, uint8_t *action, uint32_t length)
{
    if (groupnumber_not_valid(m, groupnumber))
        return -1;

    if (group_sendaction(m->chats[groupnumber], action, length) > 0)
        return 0;

    return -1;
}

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
int group_number_peers(Messenger *m, int groupnumber)
{
    if (groupnumber_not_valid(m, groupnumber))
        return -1;

    return group_numpeers(m->chats[groupnumber]);
}

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NICK_BYTES] array.
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int group_names(Messenger *m, int groupnumber, uint8_t names[][MAX_NICK_BYTES], uint16_t length)
{
    if (groupnumber_not_valid(m, groupnumber))
        return -1;

    return group_client_names(m->chats[groupnumber], names, length);
}

static int handle_group(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Messenger *m = object;

    if (length < crypto_box_PUBLICKEYBYTES + 1) {
        return 1;
    }

    uint32_t i;

    for (i = 0; i < m->numchats; ++i) {
        if (m->chats[i] == NULL)
            continue;

        if (id_equal(packet + 1, m->chats[i]->self_public_key))
            return handle_groupchatpacket(m->chats[i], source, packet, length);
    }

    return 1;
}

static void do_allgroupchats(Messenger *m)
{
    uint32_t i;

    for (i = 0; i < m->numchats; ++i) {
        if (m->chats[i] != NULL)
            do_groupchat(m->chats[i]);
    }
}

/****************FILE SENDING*****************/


/* Set the callback for file send requests.
 *
 *  Function(Tox *tox, int friendnumber, uint8_t filenumber, uint64_t filesize, uint8_t *filename, uint16_t filename_length, void *userdata)
 */
void callback_file_sendrequest(Messenger *m, void (*function)(Messenger *m, int, uint8_t, uint64_t, uint8_t *, uint16_t,
                               void *), void *userdata)
{
    m->file_sendrequest = function;
    m->file_sendrequest_userdata = userdata;
}

/* Set the callback for file control requests.
 *
 *  Function(Tox *tox, int friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t control_type, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void callback_file_control(Messenger *m, void (*function)(Messenger *m, int, uint8_t, uint8_t, uint8_t, uint8_t *,
                           uint16_t,
                           void *), void *userdata)
{
    m->file_filecontrol = function;
    m->file_filecontrol_userdata = userdata;
}

/* Set the callback for file data.
 *
 *  Function(Tox *tox, int friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void callback_file_data(Messenger *m, void (*function)(Messenger *m, int, uint8_t, uint8_t *, uint16_t length, void *),
                        void *userdata)
{
    m->file_filedata = function;
    m->file_filedata_userdata = userdata;
}

#define MAX_FILENAME_LENGTH 255

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return 1 on success
 *  return 0 on failure
 */
int file_sendrequest(Messenger *m, int friendnumber, uint8_t filenumber, uint64_t filesize, uint8_t *filename,
                     uint16_t filename_length)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    if (filename_length > MAX_FILENAME_LENGTH)
        return 0;

    uint8_t packet[MAX_FILENAME_LENGTH + 1 + sizeof(filesize)];
    packet[0] = filenumber;
    host_to_net((uint8_t *)&filesize, sizeof(filesize));
    memcpy(packet + 1, &filesize, sizeof(filesize));
    memcpy(packet + 1 + sizeof(filesize), filename, filename_length);
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_SENDREQUEST, packet,
                                1 + sizeof(filesize) + filename_length);
}

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return file number on success
 *  return -1 on failure
 */
int new_filesender(Messenger *m, int friendnumber, uint64_t filesize, uint8_t *filename, uint16_t filename_length)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (m->friendlist[friendnumber].file_sending[i].status == FILESTATUS_NONE)
            break;
    }

    if (i == MAX_CONCURRENT_FILE_PIPES)
        return -1;

    if (file_sendrequest(m, friendnumber, i, filesize, filename, filename_length) == 0)
        return -1;

    m->friendlist[friendnumber].file_sending[i].status = FILESTATUS_NOT_ACCEPTED;
    m->friendlist[friendnumber].file_sending[i].size = filesize;
    m->friendlist[friendnumber].file_sending[i].transferred = 0;
    return i;
}

/* Send a file control request.
 * send_receive is 0 if we want the control packet to target a sending file, 1 if it targets a receiving file.
 *
 *  return 0 on success
 *  return -1 on failure
 */
int file_control(Messenger *m, int friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t message_id,
                 uint8_t *data, uint16_t length)
{
    if (length > MAX_DATA_SIZE - 3)
        return -1;

    if (friend_not_valid(m, friendnumber))
        return -1;

    if (send_receive == 1) {
        if (m->friendlist[friendnumber].file_receiving[filenumber].status == FILESTATUS_NONE)
            return -1;
    } else {
        if (m->friendlist[friendnumber].file_sending[filenumber].status == FILESTATUS_NONE)
            return -1;
    }

    if (send_receive > 1)
        return -1;

    uint8_t packet[MAX_DATA_SIZE];
    packet[0] = send_receive;
    packet[1] = filenumber;
    packet[2] = message_id;
    uint64_t transferred = 0;

    if (message_id ==  FILECONTROL_RESUME_BROKEN) {
        if (length != sizeof(uint64_t))
            return -1;

        uint8_t remaining[sizeof(uint64_t)];
        memcpy(remaining, data, sizeof(uint64_t));
        host_to_net(remaining, sizeof(uint64_t));
        memcpy(packet + 3, remaining, sizeof(uint64_t));
        memcpy(&transferred, data, sizeof(uint64_t));
    } else {
        memcpy(packet + 3, data, length);
    }

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_CONTROL, packet, length + 3)) {
        if (send_receive == 1)
            switch (message_id) {
                case FILECONTROL_ACCEPT:
                    m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_TRANSFERRING;
                    break;

                case FILECONTROL_PAUSE:
                    m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_PAUSED_BY_US;
                    break;

                case FILECONTROL_KILL:
                case FILECONTROL_FINISHED:
                    m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_NONE;
                    break;

                case FILECONTROL_RESUME_BROKEN:
                    m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_PAUSED_BY_OTHER;
                    m->friendlist[friendnumber].file_receiving[filenumber].transferred = transferred;
                    break;
            }
        else
            switch (message_id) {
                case FILECONTROL_ACCEPT:
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_TRANSFERRING;
                    break;

                case FILECONTROL_PAUSE:
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_PAUSED_BY_US;
                    break;

                case FILECONTROL_KILL:
                case FILECONTROL_FINISHED:
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_NONE;
                    break;
            }

        return 0;
    } else {
        return -1;
    }
}

#define MIN_SLOTS_FREE 4
/* Send file data.
 *
 *  return 0 on success
 *  return -1 on failure
 */
int file_data(Messenger *m, int friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length)
{
    if (length > MAX_DATA_SIZE - 1)
        return -1;

    if (friend_not_valid(m, friendnumber))
        return -1;

    if (m->friendlist[friendnumber].file_sending[filenumber].status != FILESTATUS_TRANSFERRING)
        return -1;

    /* Prevent file sending from filling up the entire buffer preventing messages from being sent. */
    if (crypto_num_free_sendqueue_slots(m->net_crypto, m->friendlist[friendnumber].crypt_connection_id) < MIN_SLOTS_FREE)
        return -1;

    uint8_t packet[MAX_DATA_SIZE];
    packet[0] = filenumber;
    memcpy(packet + 1, data, length);

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_DATA, packet, length + 1)) {
        m->friendlist[friendnumber].file_sending[filenumber].transferred += length;
        return 0;
    }

    return -1;

}

/* Give the number of bytes left to be sent/received.
 *
 *  send_receive is 0 if we want the sending files, 1 if we want the receiving.
 *
 *  return number of bytes remaining to be sent/received on success
 *  return 0 on failure
 */
uint64_t file_dataremaining(Messenger *m, int friendnumber, uint8_t filenumber, uint8_t send_receive)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    if (send_receive == 0) {
        if (m->friendlist[friendnumber].file_sending[filenumber].status == FILESTATUS_NONE)
            return 0;

        return m->friendlist[friendnumber].file_sending[filenumber].size -
               m->friendlist[friendnumber].file_sending[filenumber].transferred;
    } else {
        if (m->friendlist[friendnumber].file_receiving[filenumber].status == FILESTATUS_NONE)
            return 0;

        return m->friendlist[friendnumber].file_receiving[filenumber].size -
               m->friendlist[friendnumber].file_receiving[filenumber].transferred;
    }
}

/* Run this when the friend disconnects.
 *  Sets all current file transfers to broken.
 */
static void break_files(Messenger *m, int friendnumber)
{
    uint32_t i;

    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (m->friendlist[friendnumber].file_sending[i].status != FILESTATUS_NONE)
            m->friendlist[friendnumber].file_sending[i].status = FILESTATUS_BROKEN;

        if (m->friendlist[friendnumber].file_receiving[i].status != FILESTATUS_NONE)
            m->friendlist[friendnumber].file_receiving[i].status = FILESTATUS_BROKEN;
    }
}

static int handle_filecontrol(Messenger *m, int friendnumber, uint8_t receive_send, uint8_t filenumber,
                              uint8_t message_id, uint8_t *data,
                              uint16_t length)
{
    if (receive_send > 1)
        return -1;

    if (receive_send == 0) {
        if (m->friendlist[friendnumber].file_receiving[filenumber].status == FILESTATUS_NONE) {
            /* Tell the other to kill the file sending if we don't know this one. */
            m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_TEMPORARY;
            file_control(m, friendnumber, !receive_send, filenumber, FILECONTROL_KILL, NULL, 0);
            m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_NONE;
            return -1;

        }

        switch (message_id) {
            case FILECONTROL_ACCEPT:
                if (m->friendlist[friendnumber].file_receiving[filenumber].status != FILESTATUS_PAUSED_BY_US) {
                    m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_TRANSFERRING;
                    return 0;
                }

                return -1;

            case FILECONTROL_PAUSE:
                if (m->friendlist[friendnumber].file_receiving[filenumber].status != FILESTATUS_PAUSED_BY_US) {
                    m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_PAUSED_BY_OTHER;
                    return 0;
                }

                return -1;

            case FILECONTROL_KILL:
            case FILECONTROL_FINISHED:
                m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_NONE;
                return 0;
        }
    } else {
        if (m->friendlist[friendnumber].file_sending[filenumber].status == FILESTATUS_NONE) {
            /* Tell the other to kill the file sending if we don't know this one. */
            m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_TEMPORARY;
            file_control(m, friendnumber, !receive_send, filenumber, FILECONTROL_KILL, NULL, 0);
            m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_NONE;
            return -1;
        }

        switch (message_id) {
            case FILECONTROL_ACCEPT:
                if (m->friendlist[friendnumber].file_sending[filenumber].status != FILESTATUS_PAUSED_BY_US) {
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_TRANSFERRING;
                    return 0;
                }

                return -1;

            case FILECONTROL_PAUSE:
                if (m->friendlist[friendnumber].file_sending[filenumber].status != FILESTATUS_PAUSED_BY_US) {
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_PAUSED_BY_OTHER;
                }

                return 0;

            case FILECONTROL_KILL:
            case FILECONTROL_FINISHED:
                m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_NONE;
                return 0;

            case FILECONTROL_RESUME_BROKEN: {
                if (m->friendlist[friendnumber].file_sending[filenumber].status == FILESTATUS_BROKEN && length == sizeof(uint64_t)) {
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_PAUSED_BY_US;
                    net_to_host(data, sizeof(uint64_t));
                    return 0;
                }

                return -1;
            }
        }
    }

    return -1;
}

/**************************************/

/* Set the callback for msi packets.
 *
 *  Function(Messenger *m, int friendnumber, uint8_t *data, uint16_t length, void *userdata)
 */
void m_callback_msi_packet(Messenger *m, void (*function)(Messenger *m, int, uint8_t *, uint16_t, void *),
                           void *userdata)
{
    m->msi_packet = function;
    m->msi_packet_userdata = userdata;
}

/* Send an msi packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int m_msi_packet(Messenger *m, int friendnumber, uint8_t *data, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_MSI, data, length);
}

/* Function to filter out some friend requests*/
static int friend_already_added(uint8_t *client_id, void *data)
{
    Messenger *m = data;

    if (getfriend_id(m, client_id) == -1)
        return 0;

    return -1;
}

/* Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
static void LANdiscovery(Messenger *m)
{
    if (m->last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(TOX_PORT_DEFAULT), m->dht);
        m->last_LANdiscovery = unix_time();
    }
}

/* Run this at startup. */
Messenger *new_messenger(uint8_t ipv6enabled)
{
    Messenger *m = calloc(1, sizeof(Messenger));

    if ( ! m )
        return NULL;

    IP ip;
    ip_init(&ip, ipv6enabled);
    m->net = new_networking(ip, TOX_PORT_DEFAULT);

    if (m->net == NULL) {
        free(m);
        return NULL;
    }

    m->net_crypto = new_net_crypto(m->net);

    if (m->net_crypto == NULL) {
        kill_networking(m->net);
        free(m);
        return NULL;
    }

    m->dht = new_DHT(m->net_crypto);

    if (m->dht == NULL) {
        kill_net_crypto(m->net_crypto);
        kill_networking(m->net);
        free(m);
        return NULL;
    }

    m->onion = new_onion(m->dht);
    m->onion_a = new_onion_announce(m->dht);
    m->onion_c =  new_onion_client(m->dht);

    if (!(m->onion && m->onion_a && m->onion_c)) {
        kill_onion(m->onion);
        kill_onion_announce(m->onion_a);
        kill_onion_client(m->onion_c);
        kill_DHT(m->dht);
        kill_net_crypto(m->net_crypto);
        kill_networking(m->net);
        free(m);
        return NULL;
    }

    m_set_statusmessage(m, (uint8_t *)"Online", sizeof("Online"));

    friendreq_init(&(m->fr), m->onion_c);
    LANdiscovery_init(m->dht);
    set_nospam(&(m->fr), random_int());
    set_filter_function(&(m->fr), &friend_already_added, m);

    networking_registerhandler(m->net, NET_PACKET_GROUP_CHATS, &handle_group, m);

    return m;
}

/* Run this before closing shop. */
void kill_messenger(Messenger *m)
{
    /* FIXME TODO: ideally cleanupMessenger will mirror initMessenger.
     * This requires the other modules to expose cleanup functions.
     */
    uint32_t i, numchats = m->numchats;

    for (i = 0; i < numchats; ++i)
        del_groupchat(m, i);

    kill_DHT(m->dht);
    kill_net_crypto(m->net_crypto);
    kill_networking(m->net);
    free(m->friendlist);
    free(m);
}

/* Check for and handle a timed-out friend request. If the request has
 * timed-out then the friend status is set back to FRIEND_ADDED.
 *   i: friendlist index of the timed-out friend
 *   t: time
 */
static void check_friend_request_timed_out(Messenger *m, uint32_t i, uint64_t t)
{
    Friend *f = &m->friendlist[i];

    if (f->friendrequest_lastsent + f->friendrequest_timeout < t) {
        set_friend_status(m, i, FRIEND_ADDED);
        /* Double the default timeout everytime if friendrequest is assumed
         * to have been sent unsuccessfully.
         */
        f->friendrequest_timeout *= 2;
    }
}

/* TODO: Make this function not suck. */
void do_friends(Messenger *m)
{
    uint32_t i;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    uint64_t temp_time = unix_time();

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status == FRIEND_ADDED) {
            int fr = send_friendrequest(m->onion_c, m->friendlist[i].client_id, m->friendlist[i].friendrequest_nospam,
                                        m->friendlist[i].info,
                                        m->friendlist[i].info_size);

            if (fr >= 0) {
                set_friend_status(m, i, FRIEND_REQUESTED);
                m->friendlist[i].friendrequest_lastsent = temp_time;
            }
        }

        if (m->friendlist[i].status == FRIEND_REQUESTED
                || m->friendlist[i].status == FRIEND_CONFIRMED) { /* friend is not online. */
            if (m->friendlist[i].status == FRIEND_REQUESTED) {
                /* If we didn't connect to friend after successfully sending him a friend request the request is deemed
                 * unsuccessful so we set the status back to FRIEND_ADDED and try again.
                 */
                check_friend_request_timed_out(m, i, temp_time);
            }

            IP_Port friendip;
            int friendok = onion_getfriendip(m->onion_c, m->friendlist[i].onion_friendnum, &friendip);

            switch (is_cryptoconnected(m->net_crypto, m->friendlist[i].crypt_connection_id)) {
                case CRYPTO_CONN_NO_CONNECTION:
                    if (friendok == 1)
                        m->friendlist[i].crypt_connection_id = crypto_connect(m->net_crypto, m->friendlist[i].client_id, friendip);

                    break;

                case CRYPTO_CONN_ESTABLISHED: /* Connection is established. */
                    set_friend_status(m, i, FRIEND_ONLINE);
                    m->friendlist[i].name_sent = 0;
                    m->friendlist[i].userstatus_sent = 0;
                    m->friendlist[i].statusmessage_sent = 0;
                    m->friendlist[i].ping_lastrecv = temp_time;
                    break;

                case CRYPTO_CONN_TIMED_OUT:
                    crypto_kill(m->net_crypto, m->friendlist[i].crypt_connection_id);
                    m->friendlist[i].crypt_connection_id = -1;
                    break;

                default:
                    break;
            }
        }

        while (m->friendlist[i].status == FRIEND_ONLINE) { /* friend is online. */
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

            if (m->friendlist[i].ping_lastsent + FRIEND_PING_INTERVAL < temp_time) {
                send_ping(m, i);
            }

            len = read_cryptpacket(m->net_crypto, m->friendlist[i].crypt_connection_id, temp);

            if (len > 0) {
                uint8_t packet_id = temp[0];
                uint8_t *data = temp + 1;
                uint32_t data_length = len - 1;

                switch (packet_id) {
                    case PACKET_ID_PING: {
                        m->friendlist[i].ping_lastrecv = temp_time;
                        break;
                    }

                    case PACKET_ID_NICKNAME: {
                        if (data_length >= MAX_NAME_LENGTH || data_length == 0)
                            break;

                        /* Make sure the NULL terminator is present. */
                        data[data_length - 1] = 0;

                        /* inform of namechange before we overwrite the old name */
                        if (m->friend_namechange)
                            m->friend_namechange(m, i, data, data_length, m->friend_namechange_userdata);

                        memcpy(m->friendlist[i].name, data, data_length);
                        m->friendlist[i].name_length = data_length;

                        break;
                    }

                    case PACKET_ID_STATUSMESSAGE: {
                        if (data_length == 0 || data_length > MAX_STATUSMESSAGE_LENGTH)
                            break;

                        data[data_length - 1] = 0; /* Make sure the NULL terminator is present. */

                        if (m->friend_statusmessagechange)
                            m->friend_statusmessagechange(m, i, data, data_length,
                                                          m->friend_statuschange_userdata);

                        set_friend_statusmessage(m, i, data, data_length);
                        break;
                    }

                    case PACKET_ID_USERSTATUS: {
                        if (data_length != 1)
                            break;

                        USERSTATUS status = data[0];

                        if (m->friend_userstatuschange)
                            m->friend_userstatuschange(m, i, status, m->friend_userstatuschange_userdata);

                        set_friend_userstatus(m, i, status);
                        break;
                    }

                    case PACKET_ID_MESSAGE: {
                        uint8_t *message_id = data;
                        uint8_t message_id_length = 4;

                        if (data_length <= message_id_length)
                            break;

                        uint8_t *message = data + message_id_length;
                        uint16_t message_length = data_length - message_id_length;

                        message[message_length - 1] = 0;/* Make sure the NULL terminator is present. */

                        if (m->friendlist[i].receives_read_receipts) {
                            write_cryptpacket_id(m, i, PACKET_ID_RECEIPT, message_id, message_id_length);
                        }

                        if (m->friend_message)
                            (*m->friend_message)(m, i, message, message_length, m->friend_message_userdata);

                        break;
                    }

                    case PACKET_ID_ACTION: {
                        uint8_t *message_id = data;
                        uint8_t message_id_length = 4;

                        if (data_length <= message_id_length)
                            break;

                        uint8_t *action = data + message_id_length;
                        uint16_t action_length = data_length - message_id_length;

                        action[action_length - 1] = 0;/* Make sure the NULL terminator is present. */

                        if (m->friendlist[i].receives_read_receipts) {
                            write_cryptpacket_id(m, i, PACKET_ID_RECEIPT, message_id, message_id_length);
                        }

                        if (m->friend_action)
                            (*m->friend_action)(m, i, action, action_length, m->friend_action_userdata);

                        break;
                    }

                    case PACKET_ID_RECEIPT: {
                        uint32_t msgid;

                        if (data_length < sizeof(msgid))
                            break;

                        memcpy(&msgid, data, sizeof(msgid));
                        msgid = ntohl(msgid);

                        if (m->read_receipt)
                            (*m->read_receipt)(m, i, msgid, m->read_receipt_userdata);

                        break;
                    }

                    case PACKET_ID_INVITE_GROUPCHAT: {
                        if (data_length != crypto_box_PUBLICKEYBYTES)
                            break;

                        if (m->group_invite)
                            (*m->group_invite)(m, i, data, m->group_invite_userdata);

                        break;
                    }

                    case PACKET_ID_JOIN_GROUPCHAT: {
                        if (data_length != crypto_box_PUBLICKEYBYTES * 2)
                            break;

                        int groupnum = group_num(m, data);

                        if (groupnum == -1)
                            break;

                        if (!group_invited(m, i, groupnum))
                            break;

                        group_newpeer(m->chats[groupnum], data + crypto_box_PUBLICKEYBYTES);
                        chat_bootstrap(m->chats[groupnum], get_friend_ipport(m, i), data + crypto_box_PUBLICKEYBYTES);
                        break;
                    }

                    case PACKET_ID_FILE_SENDREQUEST: {
                        if (data_length < 1 + sizeof(uint64_t) + 1)
                            break;

                        uint8_t filenumber = data[0];
                        uint64_t filesize;
                        net_to_host(data + 1, sizeof(filesize));
                        memcpy(&filesize, data + 1, sizeof(filesize));
                        m->friendlist[i].file_receiving[filenumber].status = FILESTATUS_NOT_ACCEPTED;
                        m->friendlist[i].file_receiving[filenumber].size = filesize;
                        m->friendlist[i].file_receiving[filenumber].transferred = 0;

                        if (m->file_sendrequest)
                            (*m->file_sendrequest)(m, i, filenumber, filesize, data + 1 + sizeof(uint64_t), data_length - 1 - sizeof(uint64_t),
                                                   m->file_sendrequest_userdata);

                        break;
                    }

                    case PACKET_ID_FILE_CONTROL: {
                        if (data_length < 3)
                            break;

                        uint8_t send_receive = data[0];
                        uint8_t filenumber = data[1];
                        uint8_t control_type = data[2];

                        if (handle_filecontrol(m, i, send_receive, filenumber, control_type, data + 3, data_length - 3) == -1)
                            break;

                        if (m->file_filecontrol)
                            (*m->file_filecontrol)(m, i, send_receive, filenumber, control_type, data + 3, data_length - 3,
                                                   m->file_filecontrol_userdata);

                        break;
                    }

                    case PACKET_ID_FILE_DATA: {
                        if (data_length < 2)
                            break;

                        uint8_t filenumber = data[0];

                        if (m->friendlist[i].file_receiving[filenumber].status == FILESTATUS_NONE)
                            break;

                        m->friendlist[i].file_receiving[filenumber].transferred += (data_length - 1);

                        if (m->file_filedata)
                            (*m->file_filedata)(m, i, filenumber, data + 1, data_length - 1, m->file_filedata_userdata);

                        break;
                    }

                    case PACKET_ID_MSI: {
                        if (data_length == 0)
                            break;

                        if (m->msi_packet)
                            (*m->msi_packet)(m, i, data, data_length, m->msi_packet_userdata);
                    }

                    default: {
                        break;
                    }
                }
            } else {
                if (is_cryptoconnected(m->net_crypto,
                                       m->friendlist[i].crypt_connection_id) == CRYPTO_CONN_TIMED_OUT) { /* If the connection timed out, kill it. */
                    crypto_kill(m->net_crypto, m->friendlist[i].crypt_connection_id);
                    m->friendlist[i].crypt_connection_id = -1;
                    set_friend_status(m, i, FRIEND_CONFIRMED);
                }

                if (m->friendlist[i].ping_lastrecv + FRIEND_CONNECTION_TIMEOUT < temp_time) {
                    /* If we stopped recieving ping packets, kill it. */
                    crypto_kill(m->net_crypto, m->friendlist[i].crypt_connection_id);
                    m->friendlist[i].crypt_connection_id = -1;
                    set_friend_status(m, i, FRIEND_CONFIRMED);
                }

                break;
            }
        }
    }
}

void do_inbound(Messenger *m)
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(m->net_crypto, public_key, secret_nonce, session_key);

    if (inconnection != -1) {
        int friend_id = getfriend_id(m, public_key);

        if (friend_id != -1) {
            if (m_get_friend_connectionstatus(m, friend_id) == 1) {
                kill_connection(m->net_crypto->lossless_udp, inconnection);
                return;
            }

            crypto_kill(m->net_crypto, m->friendlist[friend_id].crypt_connection_id);
            m->friendlist[friend_id].crypt_connection_id =
                accept_crypto_inbound(m->net_crypto, inconnection, public_key, secret_nonce, session_key);

            set_friend_status(m, friend_id, FRIEND_CONFIRMED);
        }
    }
}

#ifdef LOGGING
#define DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS 60UL
static time_t lastdump = 0;
static char IDString[CLIENT_ID_SIZE * 2 + 1];
static char *ID2String(uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < CLIENT_ID_SIZE; i++)
        sprintf(&IDString[i * 2], "%02X", client_id[i]);

    IDString[CLIENT_ID_SIZE * 2] = 0;
    return IDString;
}
#endif

/* The main loop that needs to be run at least 20 times per second. */
void do_messenger(Messenger *m)
{
    unix_time_update();

    networking_poll(m->net);

    do_DHT(m->dht);
    do_net_crypto(m->net_crypto);
    do_onion_client(m->onion_c);
    do_friends(m);
    do_inbound(m);
    do_allgroupchats(m);
    LANdiscovery(m);

#ifdef LOGGING

    if (unix_time() > lastdump + DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS) {
        loglog(" = = = = = = = = \n");
        Assoc_status(m->dht->assoc);

        if (m->numchats > 0) {
            size_t c;

            for (c = 0; c < m->numchats; c++) {
                loglog("---------------- \n");
                Assoc_status(m->chats[c]->assoc);
            }
        }

        loglog(" = = = = = = = = \n");

        lastdump = unix_time();
        uint32_t client, last_pinged;

        for (client = 0; client < LCLIENT_LIST; client++) {
            Client_data *cptr = &m->dht->close_clientlist[client];
            IPPTsPng *assoc = NULL;
            uint32_t a;

            for (a = 0, assoc = &cptr->assoc4; a < 2; a++, assoc = &cptr->assoc6)
                if (ip_isset(&assoc->ip_port.ip)) {
                    last_pinged = lastdump - assoc->last_pinged;

                    if (last_pinged > 999)
                        last_pinged = 999;

                    snprintf(logbuffer, sizeof(logbuffer), "C[%2u] %s:%u [%3u] %s\n",
                             client, ip_ntoa(&assoc->ip_port.ip), ntohs(assoc->ip_port.port),
                             last_pinged, ID2String(cptr->client_id));
                    loglog(logbuffer);
                }
        }

        loglog(" = = = = = = = = \n");

        uint32_t friend, dhtfriend;

        /* dht contains additional "friends" (requests) */
        uint32_t num_dhtfriends = m->dht->num_friends;
        int32_t m2dht[num_dhtfriends];
        int32_t dht2m[num_dhtfriends];

        for (friend = 0; friend < num_dhtfriends; friend++) {
            m2dht[friend] = -1;
            dht2m[friend] = -1;

            if (friend >= m->numfriends)
                continue;

            for (dhtfriend = 0; dhtfriend < m->dht->num_friends; dhtfriend++)
                if (id_equal(m->friendlist[friend].client_id, m->dht->friends_list[dhtfriend].client_id)) {
                    m2dht[friend] = dhtfriend;
                    break;
                }
        }

        for (friend = 0; friend < num_dhtfriends; friend++)
            if (m2dht[friend] >= 0)
                dht2m[m2dht[friend]] = friend;

        if (m->numfriends != m->dht->num_friends) {
            sprintf(logbuffer, "Friend num in DHT %u != friend num in msger %u\n",
                    m->dht->num_friends, m->numfriends);
            loglog(logbuffer);
        }

        uint32_t ping_lastrecv;
        Friend *msgfptr;
        DHT_Friend *dhtfptr;

        for (friend = 0; friend < num_dhtfriends; friend++) {
            if (dht2m[friend] >= 0)
                msgfptr = &m->friendlist[dht2m[friend]];
            else
                msgfptr = NULL;

            dhtfptr = &m->dht->friends_list[friend];

            if (msgfptr) {
                ping_lastrecv = lastdump - msgfptr->ping_lastrecv;

                if (ping_lastrecv > 999)
                    ping_lastrecv = 999;

                snprintf(logbuffer, sizeof(logbuffer), "F[%2u:%2u] <%s> %02i [%03u] %s\n",
                         dht2m[friend], friend, msgfptr->name, msgfptr->crypt_connection_id,
                         ping_lastrecv, ID2String(msgfptr->client_id));
                loglog(logbuffer);
            } else {
                snprintf(logbuffer, sizeof(logbuffer), "F[--:%2u] %s\n",
                         friend, ID2String(dhtfptr->client_id));
                loglog(logbuffer);
            }

            for (client = 0; client < MAX_FRIEND_CLIENTS; client++) {
                Client_data *cptr = &dhtfptr->client_list[client];
                IPPTsPng *assoc = NULL;
                uint32_t a;

                for (a = 0, assoc = &cptr->assoc4; a < 2; a++, assoc = &cptr->assoc6)
                    if (ip_isset(&assoc->ip_port.ip)) {
                        last_pinged = lastdump - assoc->last_pinged;

                        if (last_pinged > 999)
                            last_pinged = 999;

                        snprintf(logbuffer, sizeof(logbuffer), "F[%2u] => C[%2u] %s:%u [%3u] %s\n",
                                 friend, client, ip_ntoa(&assoc->ip_port.ip),
                                 ntohs(assoc->ip_port.port), last_pinged,
                                 ID2String(cptr->client_id));
                        loglog(logbuffer);
                    }
            }
        }

        loglog(" = = = = = = = = \n");
    }

#endif
}

/*
 * functions to avoid excessive polling
 */
int wait_prepare_messenger(Messenger *m, uint8_t *data, uint16_t *lenptr)
{
    return networking_wait_prepare(m->net, sendqueue_total(m->net_crypto->lossless_udp), data, lenptr);
}

int wait_execute_messenger(Messenger *m, uint8_t *data, uint16_t len, uint16_t milliseconds)
{
    return networking_wait_execute(data, len, milliseconds);
};

void wait_cleanup_messenger(Messenger *m, uint8_t *data, uint16_t len)
{
    networking_wait_cleanup(m->net, data, len);
}

/* new messenger format for load/save, more robust and forward compatible */

#define MESSENGER_STATE_COOKIE_GLOBAL 0x15ed1b1e

#define MESSENGER_STATE_COOKIE_TYPE      0x01ce
#define MESSENGER_STATE_TYPE_NOSPAMKEYS  1
#define MESSENGER_STATE_TYPE_DHT         2
#define MESSENGER_STATE_TYPE_FRIENDS     3
#define MESSENGER_STATE_TYPE_NAME        4

/*  return size of the messenger data (for saving) */
uint32_t messenger_size(Messenger *m)
{
    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    return   size32 * 2                                      // global cookie
             + sizesubhead + sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
             + sizesubhead + DHT_size(m->dht)                  // DHT
             + sizesubhead + sizeof(Friend) * m->numfriends    // Friendlist itself.
             + sizesubhead + m->name_length                    // Own nickname.
             ;
}

static uint8_t *z_state_save_subheader(uint8_t *data, uint32_t len, uint16_t type)
{
    uint32_t *data32 = (uint32_t *)data;
    data32[0] = len;
    data32[1] = (MESSENGER_STATE_COOKIE_TYPE << 16) | type;
    data += sizeof(uint32_t) * 2;
    return data;
}

/* Save the messenger in data of size Messenger_size(). */
void messenger_save(Messenger *m, uint8_t *data)
{
    uint32_t len;
    uint16_t type;
    uint32_t *data32, size32 = sizeof(uint32_t);

    data32 = (uint32_t *)data;
    data32[0] = 0;
    data32[1] = MESSENGER_STATE_COOKIE_GLOBAL;
    data += size32 * 2;

#ifdef DEBUG
    assert(sizeof(get_nospam(&(m->fr))) == sizeof(uint32_t));
#endif
    len = size32 + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    type = MESSENGER_STATE_TYPE_NOSPAMKEYS;
    data = z_state_save_subheader(data, len, type);
    *(uint32_t *)data = get_nospam(&(m->fr));
    save_keys(m->net_crypto, data + size32);
    data += len;

    len = DHT_size(m->dht);
    type = MESSENGER_STATE_TYPE_DHT;
    data = z_state_save_subheader(data, len, type);
    DHT_save(m->dht, data);
    data += len;

    len = sizeof(Friend) * m->numfriends;
    type = MESSENGER_STATE_TYPE_FRIENDS;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, m->friendlist, len);
    data += len;

    len = m->name_length;
    type = MESSENGER_STATE_TYPE_NAME;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, m->name, len);
    data += len;
}

static int messenger_load_state_callback(void *outer, uint8_t *data, uint32_t length, uint16_t type)
{
    Messenger *m = outer;

    switch (type) {
        case MESSENGER_STATE_TYPE_NOSPAMKEYS:
            if (length == crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t)) {
                set_nospam(&(m->fr), *(uint32_t *)data);
                load_keys(m->net_crypto, &data[sizeof(uint32_t)]);
#ifdef ENABLE_ASSOC_DHT

                if (m->dht->assoc)
                    Assoc_self_client_id_changed(m->dht->assoc, m->net_crypto->self_public_key);

#endif
            } else
                return -1;    /* critical */

            break;

        case MESSENGER_STATE_TYPE_DHT:
            DHT_load(m->dht, data, length);
            break;

        case MESSENGER_STATE_TYPE_FRIENDS:
            if (!(length % sizeof(Friend))) {
                uint16_t num = length / sizeof(Friend);
                Friend *friends = (Friend *)data;
                uint32_t i;

                for (i = 0; i < num; ++i) {
                    if (friends[i].status >= 3) {
                        int fnum = m_addfriend_norequest(m, friends[i].client_id);
                        setfriendname(m, fnum, friends[i].name, friends[i].name_length);
                        /* set_friend_statusmessage(fnum, temp[i].statusmessage, temp[i].statusmessage_length); */
                    } else if (friends[i].status != 0) {
                        /* TODO: This is not a good way to do this. */
                        uint8_t address[FRIEND_ADDRESS_SIZE];
                        id_copy(address, friends[i].client_id);
                        memcpy(address + crypto_box_PUBLICKEYBYTES, &(friends[i].friendrequest_nospam), sizeof(uint32_t));
                        uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
                        memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), &checksum, sizeof(checksum));
                        m_addfriend(m, address, friends[i].info, friends[i].info_size);
                    }
                }
            }

            break;

        case MESSENGER_STATE_TYPE_NAME:
            if ((length > 0) && (length < MAX_NAME_LENGTH)) {
                setname(m, data, length);
            }

            break;

#ifdef DEBUG

        default:
            fprintf(stderr, "Load state: contains unrecognized part (len %u, type %u)\n",
                    length, type);
            break;
#endif
    }

    return 0;
}

/* Load the messenger from data of size length. */
int messenger_load(Messenger *m, uint8_t *data, uint32_t length)
{
    uint32_t cookie_len = 2 * sizeof(uint32_t);

    if (length < cookie_len)
        return -1;

    uint32_t *data32 = (uint32_t *)data;

    if (!data32[0] && (data32[1] == MESSENGER_STATE_COOKIE_GLOBAL))
        return load_state(messenger_load_state_callback, m, data + cookie_len,
                          length - cookie_len, MESSENGER_STATE_COOKIE_TYPE);
    else       /* old state file */
        return -1;
}

/* return the size of data to pass to messenger_save_encrypted(...)
 *
 */
uint32_t messenger_size_encrypted(Messenger *m)
{
    return messenger_size(m) + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
}

/* Save the messenger, encrypting the data with key of length key_length
 *
 * return 0 on success.
 * return -1 on failure.
 */
int messenger_save_encrypted(Messenger *m, uint8_t *data, uint8_t *key, uint16_t key_length)
{
    uint32_t m_size = messenger_size(m);
    uint8_t *plain_messenger = malloc(m_size);

    if (plain_messenger == NULL)
        return -1;

    messenger_save(m, plain_messenger);

    /* Hash the key with SHA256 to get a 32byte key. */
    uint8_t hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, key, key_length);
    random_nonce(data);
    encrypt_data_symmetric(hash, data, plain_messenger, m_size, data + crypto_secretbox_NONCEBYTES);

    memset(plain_messenger, 0, m_size);
    free(plain_messenger);
    memset(hash, 0, crypto_hash_sha256_BYTES);
    return 0;
}

/* Load the messenger from data of size length encrypted with key of key_length.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int messenger_load_encrypted(Messenger *m, uint8_t *data, uint32_t length, uint8_t *key, uint16_t key_length)
{
    if (length <= crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES)
        return -1;

    uint8_t *plain_messenger = malloc(length);

    if (plain_messenger == NULL)
        return -1;

    /* Hash the key with SHA256 to get a 32byte key. */
    uint8_t hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, key, key_length);
    int len = decrypt_data_symmetric(hash, data, data + crypto_secretbox_NONCEBYTES, length - crypto_secretbox_NONCEBYTES,
                                     plain_messenger);
    int ret;

    if ((uint32_t)len == length - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES) {
        ret = messenger_load(m, plain_messenger, length - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES);
    } else {
        ret = -1;
    }

    memset(plain_messenger, 0, length);
    free(plain_messenger);
    memset(hash, 0, crypto_hash_sha256_BYTES);
    return ret;
}

/* Return the number of friends in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_friendlist. */
uint32_t count_friendlist(Messenger *m)
{
    uint32_t ret = 0;
    uint32_t i;

    for (i = 0; i < m->numfriends; i++) {
        if (m->friendlist[i].status > 0) {
            ret++;
        }
    }

    return ret;
}

/* Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_friendlist(Messenger *m, int *out_list, uint32_t list_size)
{
    if (!out_list)
        return 0;

    if (m->numfriends == 0) {
        return 0;
    }

    uint32_t i;
    uint32_t ret = 0;

    for (i = 0; i < m->numfriends; i++) {
        if (ret >= list_size) {
            break; /* Abandon ship */
        }

        if (m->friendlist[i].status > 0) {
            out_list[ret] = i;
            ret++;
        }
    }

    return ret;
}

/* Allocate and return a list of valid friend id's. List must be freed by the
 * caller.
 *
 * retun 0 if success.
 * return -1 if failure.
 */
int get_friendlist(Messenger *m, int **out_list, uint32_t *out_list_length)
{
    uint32_t i;

    *out_list_length = 0;

    if (m->numfriends == 0) {
        *out_list = NULL;
        return 0;
    }

    *out_list = malloc(m->numfriends * sizeof(int));

    if (*out_list == NULL) {
        return -1;
    }

    for (i = 0; i < m->numfriends; i++) {
        if (m->friendlist[i].status > 0) {
            (*out_list)[i] = i;
            (*out_list_length)++;
        }
    }

    return 0;
}

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist. */
uint32_t count_chatlist(Messenger *m)
{
    uint32_t ret = 0;
    uint32_t i;

    for (i = 0; i < m->numchats; i++) {
        if (m->chats[i]) {
            ret++;
        }
    }

    return ret;
}

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_chatlist(Messenger *m, int *out_list, uint32_t list_size)
{
    if (!out_list)
        return 0;

    if (m->numchats == 0) {
        return 0;
    }

    uint32_t i;
    uint32_t ret = 0;

    for (i = 0; i < m->numchats; i++) {
        if (ret >= list_size) {
            break; /* Abandon ship */
        }

        if (m->chats[i]) {
            out_list[ret] = i;
            ret++;
        }
    }

    return ret;
}

