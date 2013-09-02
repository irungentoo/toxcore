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
            if (memcmp(client_id, m->friendlist[i].client_id, crypto_box_PUBLICKEYBYTES) == 0)
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
    memcpy(address, m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES);
    uint32_t nospam = get_nospam(&(m->fr));
    memcpy(address + crypto_box_PUBLICKEYBYTES, &nospam, sizeof(nospam));
    uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(nospam), &checksum, sizeof(checksum));
}

/*
 * Add a friend.
 * Set the data that will be sent along with friend request.
 * Address is the address of the friend (returned by getaddress of the friend you wish to add) it must be FRIEND_ADDRESS_SIZE bytes.
 * TODO: add checksum.
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
    memcpy(client_id, address, crypto_box_PUBLICKEYBYTES);
    uint16_t check, checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(&check, address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), sizeof(check));

    if (check != checksum)
        return FAERR_BADCHECKSUM;

    if (length < 1)
        return FAERR_NOMESSAGE;

    if (memcmp(client_id, m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES) == 0)
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

    uint32_t i;

    for (i = 0; i <= m->numfriends; ++i)  {
        if (m->friendlist[i].status == NOFRIEND) {
            DHT_addfriend(m->dht, client_id);
            m->friendlist[i].status = FRIEND_ADDED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friendrequest_lastsent = 0;
            m->friendlist[i].friendrequest_timeout = FRIENDREQUEST_TIMEOUT;
            memcpy(m->friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
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

    memset(&(m->friendlist[m->numfriends]), 0, sizeof(Friend));

    uint32_t i;

    for (i = 0; i <= m->numfriends; ++i) {
        if (m->friendlist[i].status == NOFRIEND) {
            DHT_addfriend(m->dht, client_id);
            m->friendlist[i].status = FRIEND_CONFIRMED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friendrequest_lastsent = 0;
            memcpy(m->friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
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

    DHT_delfriend(m->dht, m->friendlist[friendnumber].client_id);
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

/*  return FRIEND_ONLINE if friend is online.
 *  return FRIEND_CONFIRMED if friend is confirmed.
 *  return FRIEND_REQUESTED if the friend request was sent.
 *  return FRIEND_ADDED if the friend was added.
 *  return NOFRIEND if there is no friend with that number.
 */
int m_friendstatus(Messenger *m, int friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return NOFRIEND;

    return m->friendlist[friendnumber].status;
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
 *  return 1 if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
int m_sendaction(Messenger *m, int friendnumber, uint8_t *action, uint32_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_ACTION, action, length);
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

/* Set the name of a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
static int setfriendname(Messenger *m, int friendnumber, uint8_t *name)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    memcpy(m->friendlist[friendnumber].name, name, MAX_NAME_LENGTH);
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
 *  return 0 if success.
 *  return -1 if failure.
 */
int getname(Messenger *m, int friendnumber, uint8_t *name)
{
    if (friend_not_valid(m, friendnumber))
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
    memcpy(buf, m->friendlist[friendnumber].statusmessage, MIN(maxlen, MAX_STATUSMESSAGE_LENGTH) - 1);
    return 0;
}

int m_copy_self_statusmessage(Messenger *m, uint8_t *buf, uint32_t maxlen)
{
    memset(buf, 0, maxlen);
    memcpy(buf, m->statusmessage, MIN(maxlen, MAX_STATUSMESSAGE_LENGTH) - 1);
    return 0;
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
    m->friendlist[friendnumber].ping_lastsent = unix_time();
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_PING, 0, 0);
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
    if (yesno != 0 || yesno != 1)
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

static void check_friend_connectionstatus(Messenger *m, int friendnumber, uint8_t status)
{
    if (!m->friend_connectionstatuschange)
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

/* Interval in seconds between LAN discovery packet sending. */
#define LAN_DISCOVERY_INTERVAL 60
#define PORT 33445

/* Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
static void LANdiscovery(Messenger *m)
{
    if (m->last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(PORT), m->net_crypto);
        m->last_LANdiscovery = unix_time();
    }
}

/* Run this at startup. */
Messenger *initMessenger(void)
{
    Messenger *m = calloc(1, sizeof(Messenger));

    if ( ! m )
        return NULL;

    IP ip;
    ip.uint32 = 0;
    m->net = new_networking(ip, PORT);

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

    new_keys(m->net_crypto);
    m_set_statusmessage(m, (uint8_t *)"Online", sizeof("Online"));

    friendreq_init(&(m->fr), m->net_crypto);
    LANdiscovery_init(m->dht);
    set_nospam(&(m->fr), random_int());

    return m;
}

/* Run this before closing shop. */
void cleanupMessenger(Messenger *m)
{
    /* FIXME TODO: ideally cleanupMessenger will mirror initMessenger.
     * This requires the other modules to expose cleanup functions.
     */
    kill_DHT(m->dht);
    kill_net_crypto(m->net_crypto);
    kill_networking(m->net);
    free(m->friendlist);
    free(m);
}

/* TODO: Make this function not suck. */
void doFriends(Messenger *m)
{
    /* TODO: Add incoming connections and some other stuff. */
    uint32_t i;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    uint64_t temp_time = unix_time();

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status == FRIEND_ADDED) {
            int fr = send_friendrequest(m->dht, m->friendlist[i].client_id, m->friendlist[i].friendrequest_nospam,
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
                if (m->friendlist[i].friendrequest_lastsent + m->friendlist[i].friendrequest_timeout < temp_time) {
                    set_friend_status(m, i, FRIEND_ADDED);
                    /* Double the default timeout everytime if friendrequest is assumed to have been
                     * sent unsuccessfully.
                     */
                    m->friendlist[i].friendrequest_timeout *= 2;
                }
            }

            IP_Port friendip = DHT_getfriendip(m->dht, m->friendlist[i].client_id);

            switch (is_cryptoconnected(m->net_crypto, m->friendlist[i].crypt_connection_id)) {
                case 0:
                    if (friendip.ip.uint32 > 1)
                        m->friendlist[i].crypt_connection_id = crypto_connect(m->net_crypto, m->friendlist[i].client_id, friendip);

                    break;

                case 3: /* Connection is established. */
                    set_friend_status(m, i, FRIEND_ONLINE);
                    m->friendlist[i].name_sent = 0;
                    m->friendlist[i].userstatus_sent = 0;
                    m->friendlist[i].statusmessage_sent = 0;
                    m->friendlist[i].ping_lastrecv = temp_time;
                    break;

                case 4:
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
            uint8_t packet_id = temp[0];
            uint8_t *data = temp + 1;
            uint32_t data_length = len - 1;

            if (len > 0) {
                switch (packet_id) {
                    case PACKET_ID_PING: {
                        m->friendlist[i].ping_lastrecv = temp_time;
                        break;
                    }

                    case PACKET_ID_NICKNAME: {
                        if (data_length >= MAX_NAME_LENGTH || data_length == 0)
                            break;

                        if (m->friend_namechange)
                            m->friend_namechange(m, i, data, data_length, m->friend_namechange_userdata);

                        memcpy(m->friendlist[i].name, data, data_length);
                        m->friendlist[i].name[data_length - 1] = 0; /* Make sure the NULL terminator is present. */
                        break;
                    }

                    case PACKET_ID_STATUSMESSAGE: {
                        if (data_length == 0)
                            break;

                        uint8_t *status = calloc(MIN(data_length, MAX_STATUSMESSAGE_LENGTH), 1);
                        memcpy(status, data, MIN(data_length, MAX_STATUSMESSAGE_LENGTH));

                        if (m->friend_statusmessagechange)
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

                        if (m->friend_userstatuschange)
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

                        if (m->friend_message)
                            (*m->friend_message)(m, i, message, message_length, m->friend_message_userdata);

                        break;
                    }

                    case PACKET_ID_ACTION: {
                        if (m->friend_action)
                            (*m->friend_action)(m, i, data, data_length, m->friend_action_userdata);

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
                }
            } else {
                if (is_cryptoconnected(m->net_crypto,
                                       m->friendlist[i].crypt_connection_id) == 4) { /* If the connection timed out, kill it. */
                    crypto_kill(m->net_crypto, m->friendlist[i].crypt_connection_id);
                    m->friendlist[i].crypt_connection_id = -1;
                    set_friend_status(m, i, FRIEND_CONFIRMED);
                }

                break;
            }

            if (m->friendlist[i].ping_lastrecv + FRIEND_CONNECTION_TIMEOUT < temp_time) {
                /* If we stopped recieving ping packets, kill it. */
                crypto_kill(m->net_crypto, m->friendlist[i].crypt_connection_id);
                m->friendlist[i].crypt_connection_id = -1;
                set_friend_status(m, i, FRIEND_CONFIRMED);
            }
        }
    }
}

void doInbound(Messenger *m)
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(m->net_crypto, public_key, secret_nonce, session_key);

    if (inconnection != -1) {
        int friend_id = getfriend_id(m, public_key);

        if (friend_id != -1) {
            crypto_kill(m->net_crypto, m->friendlist[friend_id].crypt_connection_id);
            m->friendlist[friend_id].crypt_connection_id =
                accept_crypto_inbound(m->net_crypto, inconnection, public_key, secret_nonce, session_key);

            set_friend_status(m, friend_id, FRIEND_CONFIRMED);
        }
    }
}

/* The main loop that needs to be run at least 20 times per second. */
void doMessenger(Messenger *m)
{
    networking_poll(m->net);

    do_DHT(m->dht);
    do_net_crypto(m->net_crypto);
    doInbound(m);
    doFriends(m);
    LANdiscovery(m);
}

/*  return size of the messenger data (for saving) */
uint32_t Messenger_size(Messenger *m)
{
    return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
           + sizeof(uint32_t)                  // nospam.
           + sizeof(uint32_t)                  // DHT size.
           + DHT_size(m->dht)                  // DHT itself.
           + sizeof(uint32_t)                  // Friendlist size.
           + sizeof(Friend) * m->numfriends    // Friendlist itself.
           + sizeof(uint16_t)                  // Own nickname length.
           + m->name_length                    // Own nickname.
           ;
}

/* Save the messenger in data of size Messenger_size(). */
void Messenger_save(Messenger *m, uint8_t *data)
{
    save_keys(m->net_crypto, data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t nospam = get_nospam(&(m->fr));
    memcpy(data, &nospam, sizeof(nospam));
    data += sizeof(nospam);
    uint32_t size = DHT_size(m->dht);
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    DHT_save(m->dht, data);
    data += size;
    size = sizeof(Friend) * m->numfriends;
    memcpy(data, &size, sizeof(size));
    data += sizeof(size);
    memcpy(data, m->friendlist, sizeof(Friend) * m->numfriends);
    data += size;
    uint16_t small_size = m->name_length;
    memcpy(data, &small_size, sizeof(small_size));
    data += sizeof(small_size);
    memcpy(data, m->name, small_size);
}

/* Load the messenger from data of size length. */
int Messenger_load(Messenger *m, uint8_t *data, uint32_t length)
{
    if (length == ~((uint32_t)0))
        return -1;

    if (length < crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 3)
        return -1;

    length -= crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 3;
    load_keys(m->net_crypto, data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t nospam;
    memcpy(&nospam, data, sizeof(nospam));
    set_nospam(&(m->fr), nospam);
    data += sizeof(nospam);
    uint32_t size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);

    if (length < size)
        return -1;

    length -= size;

    if (DHT_load(m->dht, data, size) == -1)
        return -1;

    data += size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);

    if (length < size || size % sizeof(Friend) != 0)
        return -1;

    Friend *temp = malloc(size);
    memcpy(temp, data, size);

    uint16_t num = size / sizeof(Friend);

    uint32_t i;

    for (i = 0; i < num; ++i) {
        if (temp[i].status >= 3) {
            int fnum = m_addfriend_norequest(m, temp[i].client_id);
            setfriendname(m, fnum, temp[i].name);
            /* set_friend_statusmessage(fnum, temp[i].statusmessage, temp[i].statusmessage_length); */
        } else if (temp[i].status != 0) {
            /* TODO: This is not a good way to do this. */
            uint8_t address[FRIEND_ADDRESS_SIZE];
            memcpy(address, temp[i].client_id, crypto_box_PUBLICKEYBYTES);
            memcpy(address + crypto_box_PUBLICKEYBYTES, &(temp[i].friendrequest_nospam), sizeof(uint32_t));
            uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
            memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), &checksum, sizeof(checksum));
            m_addfriend(m, address, temp[i].info, temp[i].info_size);
        }
    }

    free(temp);
    data += size;
    length -= size;

    uint16_t small_size;

    if (length < sizeof(small_size))
        return -1;

    memcpy(&small_size, data, sizeof(small_size));
    data += sizeof(small_size);
    length -= sizeof(small_size);

    if (length != small_size)
        return -1;

    setname(m, data, small_size);

    return 0;
}
