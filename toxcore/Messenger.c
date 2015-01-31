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

#ifdef DEBUG
#include <assert.h>
#endif

#include "logger.h"
#include "Messenger.h"
#include "assoc.h"
#include "network.h"
#include "util.h"


static void set_friend_status(Messenger *m, int32_t friendnumber, uint8_t status);
static int write_cryptpacket_id(const Messenger *m, int32_t friendnumber, uint8_t packet_id, const uint8_t *data,
                                uint32_t length, uint8_t congestion_control);
static int send_avatar_data_control(const Messenger *m, const uint32_t friendnumber, uint8_t op);

// friend_not_valid determines if the friendnumber passed is valid in the Messenger object
static uint8_t friend_not_valid(const Messenger *m, int32_t friendnumber)
{
    return (unsigned int)friendnumber >= m->numfriends;
}

static int add_online_friend(Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    ++m->numonline_friends;
    return 0;
}


static int remove_online_friend(Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    --m->numonline_friends;
    return 0;
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
int32_t getfriend_id(const Messenger *m, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status > 0)
            if (id_equal(real_pk, m->friendlist[i].real_pk))
                return i;
    }

    return -1;
}

/* Copies the public key associated to that friend id into real_pk buffer.
 * Make sure that real_pk is of size crypto_box_PUBLICKEYBYTES.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int get_real_pk(const Messenger *m, int32_t friendnumber, uint8_t *real_pk)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (m->friendlist[friendnumber].status > 0) {
        memcpy(real_pk, m->friendlist[friendnumber].real_pk, crypto_box_PUBLICKEYBYTES);
        return 0;
    }

    return -1;
}

/*  return friend connection id on success.
 *  return -1 if failure.
 */
int getfriendcon_id(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].friendcon_id;
}

/* TODO: Another checksum algorithm might be better.
 *
 *  return a uint16_t that represents the checksum of address of length len.
 */
static uint16_t address_checksum(const uint8_t *address, uint32_t len)
{
    uint8_t checksum[2] = {0};
    uint16_t check;
    uint32_t i;

    for (i = 0; i < len; ++i)
        checksum[i % 2] ^= address[i];

    memcpy(&check, checksum, sizeof(check));
    return check;
}

/* Format: [real_pk (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]
 *
 *  return FRIEND_ADDRESS_SIZE byte address to give to others.
 */
void getaddress(const Messenger *m, uint8_t *address)
{
    id_copy(address, m->net_crypto->self_public_key);
    uint32_t nospam = get_nospam(&(m->fr));
    memcpy(address + crypto_box_PUBLICKEYBYTES, &nospam, sizeof(nospam));
    uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(nospam), &checksum, sizeof(checksum));
}

static int send_online_packet(Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    uint8_t packet = PACKET_ID_ONLINE;
    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                             m->friendlist[friendnumber].friendcon_id), &packet, sizeof(packet), 0) != -1;
}

static int send_offine_packet(Messenger *m, int friendcon_id)
{
    uint8_t packet = PACKET_ID_OFFLINE;
    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c, friendcon_id), &packet,
                             sizeof(packet), 0) != -1;
}

static int handle_status(void *object, int i, uint8_t status);
static int handle_packet(void *object, int i, uint8_t *temp, uint16_t len);
static int handle_custom_lossy_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length);

static int32_t init_new_friend(Messenger *m, const uint8_t *real_pk, uint8_t status)
{
    /* Resize the friend list if necessary. */
    if (realloc_friendlist(m, m->numfriends + 1) != 0)
        return FAERR_NOMEM;

    memset(&(m->friendlist[m->numfriends]), 0, sizeof(Friend));

    int friendcon_id = new_friend_connection(m->fr_c, real_pk);

    if (friendcon_id == -1)
        return FAERR_UNKNOWN;

    uint32_t i;

    for (i = 0; i <= m->numfriends; ++i) {
        if (m->friendlist[i].status == NOFRIEND) {
            m->friendlist[i].status = status;
            m->friendlist[i].friendcon_id = friendcon_id;
            m->friendlist[i].friendrequest_lastsent = 0;
            id_copy(m->friendlist[i].real_pk, real_pk);
            m->friendlist[i].statusmessage = calloc(1, 1);
            m->friendlist[i].statusmessage_length = 1;
            m->friendlist[i].userstatus = USERSTATUS_NONE;
            m->friendlist[i].avatar_info_sent = 0;
            m->friendlist[i].avatar_recv_data = NULL;
            m->friendlist[i].avatar_send_data.bytes_sent = 0;
            m->friendlist[i].avatar_send_data.last_reset = 0;
            m->friendlist[i].is_typing = 0;
            m->friendlist[i].message_id = 0;
            m->friendlist[i].receives_read_receipts = 1; /* Default: YES. */
            friend_connection_callbacks(m->fr_c, friendcon_id, MESSENGER_CALLBACK_INDEX, &handle_status, &handle_packet,
                                        &handle_custom_lossy_packet, m, i);

            if (m->numfriends == i)
                ++m->numfriends;

            if (friend_con_connected(m->fr_c, friendcon_id) == FRIENDCONN_STATUS_CONNECTED) {
                send_online_packet(m, i);
            }

            return i;
        }
    }

    return FAERR_UNKNOWN;
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
int32_t m_addfriend(Messenger *m, const uint8_t *address, const uint8_t *data, uint16_t length)
{
    if (length > MAX_FRIEND_REQUEST_DATA_SIZE)
        return FAERR_TOOLONG;

    uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
    id_copy(real_pk, address);

    if (!public_key_valid(real_pk))
        return FAERR_BADCHECKSUM;

    uint16_t check, checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(&check, address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), sizeof(check));

    if (check != checksum)
        return FAERR_BADCHECKSUM;

    if (length < 1)
        return FAERR_NOMESSAGE;

    if (id_equal(real_pk, m->net_crypto->self_public_key))
        return FAERR_OWNKEY;

    int32_t friend_id = getfriend_id(m, real_pk);

    if (friend_id != -1) {
        if (m->friendlist[friend_id].status >= FRIEND_CONFIRMED)
            return FAERR_ALREADYSENT;

        uint32_t nospam;
        memcpy(&nospam, address + crypto_box_PUBLICKEYBYTES, sizeof(nospam));

        if (m->friendlist[friend_id].friendrequest_nospam == nospam)
            return FAERR_ALREADYSENT;

        m->friendlist[friend_id].friendrequest_nospam = nospam;
        return FAERR_SETNEWNOSPAM;
    }

    int32_t ret = init_new_friend(m, real_pk, FRIEND_ADDED);

    if (ret < 0) {
        return ret;
    }

    m->friendlist[ret].friendrequest_timeout = FRIENDREQUEST_TIMEOUT;
    memcpy(m->friendlist[ret].info, data, length);
    m->friendlist[ret].info_size = length;
    memcpy(&(m->friendlist[ret].friendrequest_nospam), address + crypto_box_PUBLICKEYBYTES, sizeof(uint32_t));

    return ret;
}

int32_t m_addfriend_norequest(Messenger *m, const uint8_t *real_pk)
{
    if (getfriend_id(m, real_pk) != -1)
        return -1;

    if (!public_key_valid(real_pk))
        return -1;

    if (id_equal(real_pk, m->net_crypto->self_public_key))
        return -1;

    int32_t ret = init_new_friend(m, real_pk, FRIEND_CONFIRMED);

    if (ret < 0) {
        return -1;
    } else {
        return ret;
    }
}

/* Remove a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int m_delfriend(Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (m->friendlist[friendnumber].status == FRIEND_ONLINE)
        remove_online_friend(m, friendnumber);

    free(m->friendlist[friendnumber].statusmessage);
    free(m->friendlist[friendnumber].avatar_recv_data);
    remove_request_received(&(m->fr), m->friendlist[friendnumber].real_pk);
    friend_connection_callbacks(m->fr_c, m->friendlist[friendnumber].friendcon_id, MESSENGER_CALLBACK_INDEX, 0, 0, 0, 0, 0);
    kill_friend_connection(m->fr_c, m->friendlist[friendnumber].friendcon_id);

    if (friend_con_connected(m->fr_c, m->friendlist[friendnumber].friendcon_id) == FRIENDCONN_STATUS_CONNECTED) {
        send_offine_packet(m, m->friendlist[friendnumber].friendcon_id);
    }

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

int m_get_friend_connectionstatus(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].status == FRIEND_ONLINE;
}

int m_friend_exists(const Messenger *m, int32_t friendnumber)
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
uint32_t m_sendmessage(Messenger *m, int32_t friendnumber, const uint8_t *message, uint32_t length)
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

uint32_t m_sendmessage_withid(Messenger *m, int32_t friendnumber, uint32_t theid, const uint8_t *message,
                              uint32_t length)
{
    if (length >= (MAX_CRYPTO_DATA_SIZE - sizeof(theid)) || length == 0)
        return 0;

    uint8_t temp[sizeof(theid) + length];
    theid = htonl(theid);
    memcpy(temp, &theid, sizeof(theid));
    memcpy(temp + sizeof(theid), message, length);
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_MESSAGE, temp, sizeof(temp), 0);
}

/* Send an action to an online friend.
 *
 *  return the message id if packet was successfully put into the send queue.
 *  return 0 if it was not.
 */
uint32_t m_sendaction(Messenger *m, int32_t friendnumber, const uint8_t *action, uint32_t length)
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

uint32_t m_sendaction_withid(const Messenger *m, int32_t friendnumber, uint32_t theid, const uint8_t *action,
                             uint32_t length)
{
    if (length >= (MAX_CRYPTO_DATA_SIZE - sizeof(theid)) || length == 0)
        return 0;

    uint8_t temp[sizeof(theid) + length];
    theid = htonl(theid);
    memcpy(temp, &theid, sizeof(theid));
    memcpy(temp + sizeof(theid), action, length);
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_ACTION, temp, sizeof(temp), 0);
}

/* Send a name packet to friendnumber.
 * length is the length with the NULL terminator.
 */
static int m_sendname(const Messenger *m, int32_t friendnumber, const uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return 0;

    return write_cryptpacket_id(m, friendnumber, PACKET_ID_NICKNAME, name, length, 0);
}

/* Set the name and name_length of a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setfriendname(Messenger *m, int32_t friendnumber, const uint8_t *name, uint16_t length)
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
int setname(Messenger *m, const uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;

    if (m->name_length == length && memcmp(name, m->name, length) == 0)
        return 0;

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
uint16_t getself_name(const Messenger *m, uint8_t *name)
{
    if (name == NULL) {
        return 0;
    }

    memcpy(name, m->name, m->name_length);

    return m->name_length;
}

/* Get name of friendnumber and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return length of name if success.
 *  return -1 if failure.
 */
int getname(const Messenger *m, int32_t friendnumber, uint8_t *name)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    memcpy(name, m->friendlist[friendnumber].name, m->friendlist[friendnumber].name_length);
    return m->friendlist[friendnumber].name_length;
}

int m_get_name_size(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].name_length;
}

int m_get_self_name_size(const Messenger *m)
{
    return m->name_length;
}

int m_set_statusmessage(Messenger *m, const uint8_t *status, uint16_t length)
{
    if (length > MAX_STATUSMESSAGE_LENGTH)
        return -1;

    if (m->statusmessage_length == length && memcmp(m->statusmessage, status, length) == 0)
        return 0;

    memcpy(m->statusmessage, status, length);
    m->statusmessage_length = length;

    uint32_t i;

    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].statusmessage_sent = 0;

    return 0;
}

int m_set_userstatus(Messenger *m, uint8_t status)
{
    if (status >= USERSTATUS_INVALID)
        return -1;

    if (m->userstatus == status)
        return 0;

    m->userstatus = status;
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].userstatus_sent = 0;

    return 0;
}

int m_unset_avatar(Messenger *m)
{
    if (m->avatar_data != NULL)
        free(m->avatar_data);

    m->avatar_data = NULL;
    m->avatar_data_length = 0;
    m->avatar_format = AVATAR_FORMAT_NONE;
    memset(m->avatar_hash, 0, AVATAR_HASH_LENGTH);

    uint32_t i;

    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].avatar_info_sent = 0;

    return 0;
}

int m_set_avatar(Messenger *m, uint8_t format, const uint8_t *data, uint32_t length)
{
    if (format == AVATAR_FORMAT_NONE) {
        m_unset_avatar(m);
        return 0;
    }

    if (length > AVATAR_MAX_DATA_LENGTH || length == 0)
        return -1;

    if (data == NULL)
        return -1;

    uint8_t *tmp = realloc(m->avatar_data, length);

    if (tmp == NULL)
        return -1;

    m->avatar_format = format;
    m->avatar_data = tmp;
    m->avatar_data_length = length;
    memcpy(m->avatar_data, data, length);

    m_avatar_hash(m->avatar_hash, m->avatar_data, m->avatar_data_length);

    uint32_t i;

    for (i = 0; i < m->numfriends; ++i)
        m->friendlist[i].avatar_info_sent = 0;

    return 0;
}

int m_get_self_avatar(const Messenger *m, uint8_t *format, uint8_t *buf, uint32_t *length, uint32_t maxlen,
                      uint8_t *hash)
{
    if (format)
        *format = m->avatar_format;

    if (length)
        *length = m->avatar_data_length;

    if (hash)
        memcpy(hash, m->avatar_hash, AVATAR_HASH_LENGTH);

    if (buf != NULL && maxlen > 0) {
        if (m->avatar_data_length <= maxlen)
            memcpy(buf, m->avatar_data, m->avatar_data_length);
        else
            return -1;
    }

    return 0;
}

int m_hash(uint8_t *hash, const uint8_t *data, const uint32_t datalen)
{
    if (hash == NULL)
        return -1;

    return crypto_hash_sha256(hash, data, datalen);
}

int m_avatar_hash(uint8_t *hash, const uint8_t *data, const uint32_t datalen)
{
    return m_hash(hash, data, datalen);
}

int m_request_avatar_info(const Messenger *m, const int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_AVATAR_INFO_REQ, 0, 0, 0))
        return 0;
    else
        return -1;
}

int m_send_avatar_info(const Messenger *m, const int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    uint8_t data[sizeof(uint8_t) + AVATAR_HASH_LENGTH];
    data[0] = m->avatar_format;
    memcpy(data + 1, m->avatar_hash, AVATAR_HASH_LENGTH);

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_AVATAR_INFO, data, sizeof(data), 0))
        return 0;
    else
        return -1;
}

int m_request_avatar_data(const Messenger *m, const int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    AVATAR_RECEIVEDATA *avrd = m->friendlist[friendnumber].avatar_recv_data;

    if (avrd == NULL) {
        avrd = calloc(sizeof(AVATAR_RECEIVEDATA), 1);

        if (avrd == NULL)
            return -1;

        avrd->started = 0;
        m->friendlist[friendnumber].avatar_recv_data = avrd;
    }

    if (avrd->started) {
        LOGGER_DEBUG("Resetting already started data request. "
                     "friendnumber == %u", friendnumber);
    }

    avrd->started = 0;
    avrd->bytes_received = 0;
    avrd->total_length = 0;
    avrd->format = AVATAR_FORMAT_NONE;

    return send_avatar_data_control(m, friendnumber, AVATAR_DATACONTROL_REQ);
}


/* return the size of friendnumber's user status.
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 */
int m_get_statusmessage_size(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].statusmessage_length;
}

/*  Copy the user status of friendnumber into buf, truncating if needed to maxlen
 *  bytes, use m_get_statusmessage_size to find out how much you need to allocate.
 */
int m_copy_statusmessage(const Messenger *m, int32_t friendnumber, uint8_t *buf, uint32_t maxlen)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    int msglen = MIN(maxlen, m->friendlist[friendnumber].statusmessage_length);

    memcpy(buf, m->friendlist[friendnumber].statusmessage, msglen);
    memset(buf + msglen, 0, maxlen - msglen);
    return msglen;
}

/* return the size of friendnumber's user status.
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 */
int m_get_self_statusmessage_size(const Messenger *m)
{
    return m->statusmessage_length;
}

int m_copy_self_statusmessage(const Messenger *m, uint8_t *buf, uint32_t maxlen)
{
    int msglen = MIN(maxlen, m->statusmessage_length);
    memcpy(buf, m->statusmessage, msglen);
    memset(buf + msglen, 0, maxlen - msglen);
    return msglen;
}

uint8_t m_get_userstatus(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return USERSTATUS_INVALID;

    uint8_t status = m->friendlist[friendnumber].userstatus;

    if (status >= USERSTATUS_INVALID) {
        status = USERSTATUS_NONE;
    }

    return status;
}

uint8_t m_get_self_userstatus(const Messenger *m)
{
    return m->userstatus;
}

uint64_t m_get_last_online(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].ping_lastrecv;
}

int m_set_usertyping(Messenger *m, int32_t friendnumber, uint8_t is_typing)

{
    if (is_typing != 0 && is_typing != 1)
        return -1;

    if (friend_not_valid(m, friendnumber))
        return -1;

    if (m->friendlist[friendnumber].user_istyping == is_typing)
        return 0;

    m->friendlist[friendnumber].user_istyping = is_typing;
    m->friendlist[friendnumber].user_istyping_sent = 0;

    return 0;
}

uint8_t m_get_istyping(const Messenger *m, int32_t friendnumber)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    return m->friendlist[friendnumber].is_typing;
}

static int send_statusmessage(const Messenger *m, int32_t friendnumber, const uint8_t *status, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_STATUSMESSAGE, status, length, 0);
}

static int send_userstatus(const Messenger *m, int32_t friendnumber, uint8_t status)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_USERSTATUS, &status, sizeof(status), 0);
}

static int send_user_istyping(const Messenger *m, int32_t friendnumber, uint8_t is_typing)
{
    uint8_t typing = is_typing;
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_TYPING, &typing, sizeof(typing), 0);
}

static int send_relays(const Messenger *m, int32_t friendnumber)
{
    Node_format nodes[MAX_SHARED_RELAYS];
    uint8_t data[1024];
    int n, length;

    n = copy_connected_tcp_relays(m->net_crypto, nodes, MAX_SHARED_RELAYS);
    length = pack_nodes(data, sizeof(data), nodes, n);

    int ret = write_cryptpacket_id(m, friendnumber, PACKET_ID_SHARE_RELAYS, data, length, 0);

    if (ret == 1)
        m->friendlist[friendnumber].share_relays_lastsent = unix_time();

    return ret;
}



static int set_friend_statusmessage(const Messenger *m, int32_t friendnumber, const uint8_t *status, uint16_t length)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    uint8_t *newstatus = calloc(length + 1, 1);
    memcpy(newstatus, status, length);
    free(m->friendlist[friendnumber].statusmessage);
    m->friendlist[friendnumber].statusmessage = newstatus;
    m->friendlist[friendnumber].statusmessage_length = length;
    return 0;
}

static void set_friend_userstatus(const Messenger *m, int32_t friendnumber, uint8_t status)
{
    m->friendlist[friendnumber].userstatus = status;
}

static void set_friend_typing(const Messenger *m, int32_t friendnumber, uint8_t is_typing)
{
    m->friendlist[friendnumber].is_typing = is_typing;
}

/* Sets whether we send read receipts for friendnumber. */
void m_set_sends_receipts(Messenger *m, int32_t friendnumber, int yesno)
{
    if (yesno != 0 && yesno != 1)
        return;

    if (friend_not_valid(m, friendnumber))
        return;

    m->friendlist[friendnumber].receives_read_receipts = yesno;
}

/* static void (*friend_request)(uint8_t *, uint8_t *, uint16_t); */
/* Set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(Messenger *m, void (*function)(Messenger *m, const uint8_t *, const uint8_t *, uint16_t,
                              void *), void *userdata)
{
    void (*handle_friendrequest)(void *, const uint8_t *, const uint8_t *, uint16_t, void *) = (void *)function;
    callback_friendrequest(&(m->fr), handle_friendrequest, m, userdata);
}

/* Set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                              void *userdata)
{
    m->friend_message = function;
    m->friend_message_userdata = userdata;
}

void m_callback_action(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                       void *userdata)
{
    m->friend_action = function;
    m->friend_action_userdata = userdata;
}

void m_callback_namechange(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                           void *userdata)
{
    m->friend_namechange = function;
    m->friend_namechange_userdata = userdata;
}

void m_callback_statusmessage(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
                              void *userdata)
{
    m->friend_statusmessagechange = function;
    m->friend_statuschange_userdata = userdata;
}

void m_callback_userstatus(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, void *), void *userdata)
{
    m->friend_userstatuschange = function;
    m->friend_userstatuschange_userdata = userdata;
}

void m_callback_typingchange(Messenger *m, void(*function)(Messenger *m, int32_t, uint8_t, void *), void *userdata)
{
    m->friend_typingchange = function;
    m->friend_typingchange_userdata = userdata;
}

void m_callback_read_receipt(Messenger *m, void (*function)(Messenger *m, int32_t, uint32_t, void *), void *userdata)
{
    m->read_receipt = function;
    m->read_receipt_userdata = userdata;
}

void m_callback_connectionstatus(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, void *), void *userdata)
{
    m->friend_connectionstatuschange = function;
    m->friend_connectionstatuschange_userdata = userdata;
}

void m_callback_connectionstatus_internal_av(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, void *),
        void *userdata)
{
    m->friend_connectionstatuschange_internal = function;
    m->friend_connectionstatuschange_internal_userdata = userdata;
}

void m_callback_avatar_info(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, uint8_t *, void *),
                            void *userdata)
{
    m->avatar_info_recv = function;
    m->avatar_info_recv_userdata = userdata;
}

void m_callback_avatar_data(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, uint8_t *, uint8_t *,
                            uint32_t, void *), void *userdata)
{
    m->avatar_data_recv = function;
    m->avatar_data_recv_userdata = userdata;
}

static void break_files(const Messenger *m, int32_t friendnumber);
static void check_friend_connectionstatus(Messenger *m, int32_t friendnumber, uint8_t status)
{
    if (status == NOFRIEND)
        return;

    const uint8_t was_online = m->friendlist[friendnumber].status == FRIEND_ONLINE;
    const uint8_t is_online = status == FRIEND_ONLINE;

    if (is_online != was_online) {
        if (was_online) {
            break_files(m, friendnumber);
            remove_online_friend(m, friendnumber);
        } else {
            add_online_friend(m, friendnumber);
        }

        m->friendlist[friendnumber].status = status;

        if (m->friend_connectionstatuschange)
            m->friend_connectionstatuschange(m, friendnumber, is_online, m->friend_connectionstatuschange_userdata);

        if (m->friend_connectionstatuschange_internal)
            m->friend_connectionstatuschange_internal(m, friendnumber, is_online,
                    m->friend_connectionstatuschange_internal_userdata);
    }
}

void set_friend_status(Messenger *m, int32_t friendnumber, uint8_t status)
{
    check_friend_connectionstatus(m, friendnumber, status);
    m->friendlist[friendnumber].status = status;
}

static int write_cryptpacket_id(const Messenger *m, int32_t friendnumber, uint8_t packet_id, const uint8_t *data,
                                uint32_t length, uint8_t congestion_control)
{
    if (friend_not_valid(m, friendnumber))
        return 0;

    if (length >= MAX_CRYPTO_DATA_SIZE || m->friendlist[friendnumber].status != FRIEND_ONLINE)
        return 0;

    uint8_t packet[length + 1];
    packet[0] = packet_id;

    if (length != 0)
        memcpy(packet + 1, data, length);

    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                             m->friendlist[friendnumber].friendcon_id), packet, length + 1, congestion_control) != -1;
}

/**********GROUP CHATS************/


/* Set the callback for group invites.
 *
 *  Function(Messenger *m, int32_t friendnumber, uint8_t *data, uint16_t length)
 */
void m_callback_group_invite(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t))
{
    m->group_invite = function;
}


/* Send a group invite packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int send_group_invite_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_INVITE_GROUPCHAT, data, length, 0);
}

/****************FILE SENDING*****************/


/* Set the callback for file send requests.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t filenumber, uint64_t filesize, uint8_t *filename, uint16_t filename_length, void *userdata)
 */
void callback_file_sendrequest(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, uint64_t, const uint8_t *,
                               uint16_t, void *), void *userdata)
{
    m->file_sendrequest = function;
    m->file_sendrequest_userdata = userdata;
}

/* Set the callback for file control requests.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t control_type, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void callback_file_control(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, uint8_t, uint8_t,
                           const uint8_t *, uint16_t, void *), void *userdata)
{
    m->file_filecontrol = function;
    m->file_filecontrol_userdata = userdata;
}

/* Set the callback for file data.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t filenumber, uint8_t *data, uint16_t length, void *userdata)
 *
 */
void callback_file_data(Messenger *m, void (*function)(Messenger *m, int32_t, uint8_t, const uint8_t *, uint16_t length,
                        void *), void *userdata)
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
int file_sendrequest(const Messenger *m, int32_t friendnumber, uint8_t filenumber, uint64_t filesize,
                     const uint8_t *filename, uint16_t filename_length)
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
                                1 + sizeof(filesize) + filename_length, 0);
}

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return file number on success
 *  return -1 on failure
 */
int new_filesender(const Messenger *m, int32_t friendnumber, uint64_t filesize, const uint8_t *filename,
                   uint16_t filename_length)
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
int file_control(const Messenger *m, int32_t friendnumber, uint8_t send_receive, uint8_t filenumber, uint8_t message_id,
                 const uint8_t *data, uint16_t length)
{
    if (length > MAX_CRYPTO_DATA_SIZE - 3)
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

    uint8_t packet[MAX_CRYPTO_DATA_SIZE];
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

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_CONTROL, packet, length + 3, 0)) {
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
                    m->friendlist[friendnumber].file_sending[filenumber].status = FILESTATUS_NONE;
                    break;

                case FILECONTROL_FINISHED:
                    break;
            }

        return 0;
    } else {
        return -1;
    }
}

#define MIN_SLOTS_FREE (CRYPTO_MIN_QUEUE_LENGTH / 2)
/* Send file data.
 *
 *  return 0 on success
 *  return -1 on failure
 */
int file_data(const Messenger *m, int32_t friendnumber, uint8_t filenumber, const uint8_t *data, uint16_t length)
{
    if (length > MAX_CRYPTO_DATA_SIZE - 1)
        return -1;

    if (friend_not_valid(m, friendnumber))
        return -1;

    if (m->friendlist[friendnumber].file_sending[filenumber].status != FILESTATUS_TRANSFERRING)
        return -1;

    /* Prevent file sending from filling up the entire buffer preventing messages from being sent. TODO: remove */
    if (crypto_num_free_sendqueue_slots(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                                        m->friendlist[friendnumber].friendcon_id)) < MIN_SLOTS_FREE)
        return -1;

    uint8_t packet[MAX_CRYPTO_DATA_SIZE];
    packet[0] = filenumber;
    memcpy(packet + 1, data, length);

    if (write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_DATA, packet, length + 1, 1)) {
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
uint64_t file_dataremaining(const Messenger *m, int32_t friendnumber, uint8_t filenumber, uint8_t send_receive)
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
static void break_files(const Messenger *m, int32_t friendnumber)
{
    uint32_t i;

    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (m->friendlist[friendnumber].file_sending[i].status != FILESTATUS_NONE)
            m->friendlist[friendnumber].file_sending[i].status = FILESTATUS_BROKEN;

        if (m->friendlist[friendnumber].file_receiving[i].status != FILESTATUS_NONE)
            m->friendlist[friendnumber].file_receiving[i].status = FILESTATUS_BROKEN;
    }
}

static int handle_filecontrol(const Messenger *m, int32_t friendnumber, uint8_t receive_send, uint8_t filenumber,
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
                m->friendlist[friendnumber].file_receiving[filenumber].status = FILESTATUS_NONE;

            case FILECONTROL_FINISHED:
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
void m_callback_msi_packet(Messenger *m, void (*function)(Messenger *m, int32_t, const uint8_t *, uint16_t, void *),
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
int m_msi_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_MSI, data, length, 0);
}

static int handle_custom_lossy_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length)
{
    Messenger *m = object;

    if (friend_not_valid(m, friend_num))
        return 1;

    if (m->friendlist[friend_num].lossy_packethandlers[packet[0] % PACKET_ID_LOSSY_RANGE_SIZE].function)
        return m->friendlist[friend_num].lossy_packethandlers[packet[0] % PACKET_ID_LOSSY_RANGE_SIZE].function(
                   m, friend_num, packet, length, m->friendlist[friend_num].lossy_packethandlers[packet[0] %
                           PACKET_ID_LOSSY_RANGE_SIZE].object);

    return 1;
}

int custom_lossy_packet_registerhandler(Messenger *m, int32_t friendnumber, uint8_t byte,
                                        int (*packet_handler_callback)(Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t len, void *object),
                                        void *object)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (byte < PACKET_ID_LOSSY_RANGE_START)
        return -1;

    if (byte >= (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE))
        return -1;

    m->friendlist[friendnumber].lossy_packethandlers[byte % PACKET_ID_LOSSY_RANGE_SIZE].function = packet_handler_callback;
    m->friendlist[friendnumber].lossy_packethandlers[byte % PACKET_ID_LOSSY_RANGE_SIZE].object = object;
    return 0;
}

int send_custom_lossy_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE)
        return -1;

    return send_lossy_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                                  m->friendlist[friendnumber].friendcon_id), data, length);
}

static int handle_custom_lossless_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length)
{
    Messenger *m = object;

    if (friend_not_valid(m, friend_num))
        return -1;

    if (packet[0] < PACKET_ID_LOSSLESS_RANGE_START)
        return -1;

    if (packet[0] >= (PACKET_ID_LOSSLESS_RANGE_START + PACKET_ID_LOSSLESS_RANGE_SIZE))
        return -1;

    if (m->friendlist[friend_num].lossless_packethandlers[packet[0] % PACKET_ID_LOSSLESS_RANGE_SIZE].function)
        return m->friendlist[friend_num].lossless_packethandlers[packet[0] % PACKET_ID_LOSSLESS_RANGE_SIZE].function(
                   m, friend_num, packet, length, m->friendlist[friend_num].lossless_packethandlers[packet[0] %
                           PACKET_ID_LOSSLESS_RANGE_SIZE].object);

    return 1;
}

int custom_lossless_packet_registerhandler(Messenger *m, int32_t friendnumber, uint8_t byte,
        int (*packet_handler_callback)(Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t len, void *object),
        void *object)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (byte < PACKET_ID_LOSSLESS_RANGE_START)
        return -1;

    if (byte >= (PACKET_ID_LOSSLESS_RANGE_START + PACKET_ID_LOSSLESS_RANGE_SIZE))
        return -1;

    m->friendlist[friendnumber].lossless_packethandlers[byte % PACKET_ID_LOSSLESS_RANGE_SIZE].function =
        packet_handler_callback;
    m->friendlist[friendnumber].lossless_packethandlers[byte % PACKET_ID_LOSSLESS_RANGE_SIZE].object = object;
    return 0;
}

int send_custom_lossless_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length)
{
    if (friend_not_valid(m, friendnumber))
        return -1;

    if (length == 0)
        return -1;

    if (data[0] < PACKET_ID_LOSSLESS_RANGE_START)
        return -1;

    if (data[0] >= (PACKET_ID_LOSSLESS_RANGE_START + PACKET_ID_LOSSLESS_RANGE_SIZE))
        return -1;

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE)
        return -1;

    if (write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                          m->friendlist[friendnumber].friendcon_id), data, length, 1) == -1) {
        return -1;
    } else {
        return 0;
    }
}

/* Function to filter out some friend requests*/
static int friend_already_added(const uint8_t *real_pk, void *data)
{
    const Messenger *m = data;

    if (getfriend_id(m, real_pk) == -1)
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
Messenger *new_messenger(Messenger_Options *options)
{
    Messenger *m = calloc(1, sizeof(Messenger));

    if ( ! m )
        return NULL;

    if (options->udp_disabled) {
        /* this is the easiest way to completely disable UDP without changing too much code. */
        m->net = calloc(1, sizeof(Networking_Core));
    } else {
        IP ip;
        ip_init(&ip, options->ipv6enabled);
        m->net = new_networking(ip, TOX_PORT_DEFAULT);
    }

    m->avatar_format = AVATAR_FORMAT_NONE;
    m->avatar_data = NULL;

    if (m->net == NULL) {
        free(m);
        return NULL;
    }

    m->dht = new_DHT(m->net);

    if (m->dht == NULL) {
        kill_networking(m->net);
        free(m);
        return NULL;
    }

    m->net_crypto = new_net_crypto(m->dht, &options->proxy_info);

    if (m->net_crypto == NULL) {
        kill_networking(m->net);
        kill_DHT(m->dht);
        free(m);
        return NULL;
    }

    m->onion = new_onion(m->dht);
    m->onion_a = new_onion_announce(m->dht);
    m->onion_c =  new_onion_client(m->net_crypto);
    m->fr_c = new_friend_connections(m->onion_c);

    if (!(m->onion && m->onion_a && m->onion_c)) {
        kill_friend_connections(m->fr_c);
        kill_onion(m->onion);
        kill_onion_announce(m->onion_a);
        kill_onion_client(m->onion_c);
        kill_DHT(m->dht);
        kill_net_crypto(m->net_crypto);
        kill_networking(m->net);
        free(m);
        return NULL;
    }

    m->options = *options;
    friendreq_init(&(m->fr), m->fr_c);
    LANdiscovery_init(m->dht);
    set_nospam(&(m->fr), random_int());
    set_filter_function(&(m->fr), &friend_already_added, m);

    return m;
}

/* Run this before closing shop. */
void kill_messenger(Messenger *m)
{
    if (!m)
        return;

    uint32_t i;

    kill_friend_connections(m->fr_c);
    kill_onion(m->onion);
    kill_onion_announce(m->onion_a);
    kill_onion_client(m->onion_c);
    kill_net_crypto(m->net_crypto);
    kill_DHT(m->dht);
    kill_networking(m->net);

    for (i = 0; i < m->numfriends; ++i) {
        free(m->friendlist[i].statusmessage);
        free(m->friendlist[i].avatar_recv_data);
    }

    free(m->avatar_data);
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
        /* Double the default timeout every time if friendrequest is assumed
         * to have been sent unsuccessfully.
         */
        f->friendrequest_timeout *= 2;
    }
}

static int handle_status(void *object, int i, uint8_t status)
{
    uint64_t temp_time = unix_time();
    Messenger *m = object;

    if (status) { /* Went online. */
        send_online_packet(m, i);
        m->friendlist[i].name_sent = 0;
        m->friendlist[i].userstatus_sent = 0;
        m->friendlist[i].statusmessage_sent = 0;
        m->friendlist[i].user_istyping_sent = 0;
        m->friendlist[i].avatar_info_sent = 0;
        m->friendlist[i].ping_lastrecv = temp_time;
    } else { /* Went offline. */
        if (m->friendlist[i].status == FRIEND_ONLINE) {
            set_friend_status(m, i, FRIEND_CONFIRMED);
        }

        /* Clear avatar transfer state */
        if (m->friendlist[i].avatar_recv_data) {
            free(m->friendlist[i].avatar_recv_data);
            m->friendlist[i].avatar_recv_data = NULL;
        }
    }

    return 0;
}


/* Sends an avatar data control packet to the peer. Usually to return status
 * values or request data.
 */
static int send_avatar_data_control(const Messenger *m, const uint32_t friendnumber,
                                    uint8_t op)
{
    int ret = write_cryptpacket_id(m, friendnumber, PACKET_ID_AVATAR_DATA_CONTROL,
                                   &op, sizeof(op), 0);
    LOGGER_DEBUG("friendnumber = %u, op = %u, ret = %d",
                 friendnumber, op, ret);
    return ret ? 0 : -1;
}


static int handle_avatar_data_control(Messenger *m, uint32_t friendnumber,
                                      uint8_t *data, uint32_t data_length)
{
    if (data_length != 1) {
        LOGGER_DEBUG("Error: PACKET_ID_AVATAR_DATA_CONTROL with bad "
                     "data_length = %u, friendnumber = %u",
                     data_length, friendnumber);
        send_avatar_data_control(m, friendnumber, AVATAR_DATACONTROL_ERROR);
        return -1;  /* Error */
    }

    LOGGER_DEBUG("friendnumber = %u, op = %u", friendnumber, data[0]);

    switch (data[0]) {
        case AVATAR_DATACONTROL_REQ: {

            /* Check data transfer limits for this friend */
            AVATAR_SENDDATA *const avsd = &(m->friendlist[friendnumber].avatar_send_data);

            if (avsd->bytes_sent >= AVATAR_DATA_TRANSFER_LIMIT) {
                /* User reached data limit. Check timeout */
                uint64_t now = unix_time();

                if (avsd->last_reset > 0
                        && (avsd->last_reset + AVATAR_DATA_TRANSFER_TIMEOUT < now)) {
                    avsd->bytes_sent = 0;
                    avsd->last_reset = now;
                } else {
                    /* Friend still rate-limitted. Send an error and stops. */
                    LOGGER_DEBUG("Avatar data transfer limit reached. "
                                 "friendnumber = %u", friendnumber);
                    send_avatar_data_control(m, friendnumber, AVATAR_DATACONTROL_ERROR);
                    return 0;
                }
            }

            /* Start the transmission with a DATA_START message. Format:
             *  uint8_t format
             *  uint8_t hash[AVATAR_HASH_LENGTH]
             *  uint32_t total_length
             */
            LOGGER_DEBUG("Sending start msg to friend number %u. "
                         "m->avatar_format = %u, m->avatar_data_length = %u",
                         friendnumber, m->avatar_format, m->avatar_data_length);
            uint8_t start_data[1 + AVATAR_HASH_LENGTH + sizeof(uint32_t)];
            uint32_t avatar_len = htonl(m->avatar_data_length);

            start_data[0] = m->avatar_format;
            memcpy(start_data + 1, m->avatar_hash, AVATAR_HASH_LENGTH);
            memcpy(start_data + 1 + AVATAR_HASH_LENGTH, &avatar_len, sizeof(uint32_t));

            avsd->bytes_sent += sizeof(start_data);  /* For rate limit */

            int ret = write_cryptpacket_id(m, friendnumber, PACKET_ID_AVATAR_DATA_START,
                                           start_data, sizeof(start_data), 0);

            if (!ret) {
                /* Something went wrong, try to signal the error so the friend
                 * can clear up the state. */
                send_avatar_data_control(m, friendnumber, AVATAR_DATACONTROL_ERROR);
                return 0;
            }

            /* User have no avatar data, nothing more to do. */
            if (m->avatar_format == AVATAR_FORMAT_NONE)
                return 0;

            /* Send the actual avatar data. */
            uint32_t offset = 0;

            while (offset < m->avatar_data_length) {
                uint32_t chunk_len = m->avatar_data_length - offset;

                if (chunk_len > AVATAR_DATA_MAX_CHUNK_SIZE)
                    chunk_len = AVATAR_DATA_MAX_CHUNK_SIZE;

                uint8_t chunk[AVATAR_DATA_MAX_CHUNK_SIZE];
                memcpy(chunk, m->avatar_data + offset, chunk_len);
                offset += chunk_len;
                avsd->bytes_sent += chunk_len;  /* For rate limit */

                int ret = write_cryptpacket_id(m, friendnumber,
                                               PACKET_ID_AVATAR_DATA_PUSH,
                                               chunk, chunk_len, 0);

                if (!ret) {
                    LOGGER_DEBUG("write_cryptpacket_id failed. ret = %d, "
                                 "friendnumber = %u, offset = %u",
                                 ret, friendnumber, offset);
                    send_avatar_data_control(m, friendnumber, AVATAR_DATACONTROL_ERROR);
                    return -1;
                }
            }

            return 0;
        }

        case AVATAR_DATACONTROL_ERROR: {
            if (m->friendlist[friendnumber].avatar_recv_data) {
                /* We were receiving the data, sender detected an error
                  (eg. changing avatar) and asked us to stop. */
                free(m->friendlist[friendnumber].avatar_recv_data);
                m->friendlist[friendnumber].avatar_recv_data = NULL;
            }

            return 0;
        }
    }

    return -1;
}


static int handle_avatar_data_start(Messenger *m, uint32_t friendnumber,
                                    uint8_t *data, uint32_t data_length)
{
    LOGGER_DEBUG("data_length = %u, friendnumber = %u", data_length, friendnumber);

    if (data_length != 1 + AVATAR_HASH_LENGTH + sizeof(uint32_t)) {
        LOGGER_DEBUG("Invalid msg length = %u, friendnumber = %u",
                     data_length, friendnumber);
        return -1;
    }

    AVATAR_RECEIVEDATA *avrd = m->friendlist[friendnumber].avatar_recv_data;

    if (avrd == NULL) {
        LOGGER_DEBUG("Received an unrequested DATA_START, friendnumber = %u",
                     friendnumber);
        return -1;
    }

    if (avrd->started) {
        /* Already receiving data from this friend. Must be an error
         * or an malicious request, because we zeroed the started bit
         * when we requested the data. */
        LOGGER_DEBUG("Received an unrequested duplicated DATA_START, "
                     "friendnumber = %u", friendnumber);
        return -1;
    }

    /* Copy data from message to our control structure */
    avrd->started = 1;
    avrd->format = data[0];
    memcpy(avrd->hash, data + 1, AVATAR_HASH_LENGTH);
    uint32_t tmp_len;
    memcpy(&tmp_len, data + 1 + AVATAR_HASH_LENGTH, sizeof(uint32_t));
    avrd->total_length = ntohl(tmp_len);
    avrd->bytes_received = 0;

    LOGGER_DEBUG("friendnumber = %u, avrd->format = %u, "
                 "avrd->total_length = %u, avrd->bytes_received = %u",
                 friendnumber, avrd->format, avrd->total_length,
                 avrd->bytes_received);

    if (avrd->total_length > AVATAR_MAX_DATA_LENGTH) {
        /* Invalid data length. Stops. */
        LOGGER_DEBUG("Error: total_length > MAX_AVATAR_DATA_LENGTH, "
                     "friendnumber = %u", friendnumber);
        free(avrd);
        avrd = NULL;
        m->friendlist[friendnumber].avatar_recv_data = NULL;
        return 0;
    }

    if (avrd->format == AVATAR_FORMAT_NONE || avrd->total_length == 0) {
        /* No real data to receive. Run callback function and finish. */
        LOGGER_DEBUG("format == NONE, friendnumber = %u", friendnumber);

        if (m->avatar_data_recv) {
            memset(avrd->hash, 0, AVATAR_HASH_LENGTH);
            (m->avatar_data_recv)(m, friendnumber, avrd->format, avrd->hash,
                                  NULL, 0, m->avatar_data_recv_userdata);
        }

        free(avrd);
        avrd = NULL;
        m->friendlist[friendnumber].avatar_recv_data = NULL;
        return 0;
    }

    /* Waits for more data to be received */
    return 0;
}


static int handle_avatar_data_push(Messenger *m, uint32_t friendnumber,
                                   uint8_t *data, uint32_t data_length)
{
    LOGGER_DEBUG("friendnumber = %u, data_length = %u", friendnumber, data_length);

    AVATAR_RECEIVEDATA *avrd = m->friendlist[friendnumber].avatar_recv_data;

    if (avrd == NULL) {
        /* No active transfer. It must be an error or a malicious request,
         * because we set the avatar_recv_data on the first DATA_START. */
        LOGGER_DEBUG("Error: avrd == NULL, friendnumber = %u", friendnumber);
        return -1;  /* Error */
    }

    if (avrd->started == 0) {
        /* Receiving data for a non-started request. Must be an error
         * or an malicious request. */
        LOGGER_DEBUG("Received an data push for a yet non started data "
                     "request. friendnumber = %u", friendnumber);
        return -1;  /* Error */
    }

    uint32_t new_length = avrd->bytes_received + data_length;

    if (new_length > avrd->total_length
            || new_length >= AVATAR_MAX_DATA_LENGTH) {
        /* Invalid data length due to error or malice. Stops. */
        LOGGER_DEBUG("Invalid data length. friendnumber = %u, "
                     "new_length = %u, avrd->total_length = %u",
                     friendnumber, new_length,  avrd->total_length);
        free(avrd);
        m->friendlist[friendnumber].avatar_recv_data = NULL;
        return 0;
    }

    memcpy(avrd->data + avrd->bytes_received, data, data_length);
    avrd->bytes_received += data_length;

    if (avrd->bytes_received == avrd->total_length) {
        LOGGER_DEBUG("All data received. friendnumber = %u", friendnumber);

        /* All data was received. Check if the hashes match. It the
         * requester's responsability to do this. The sender may have done
         * anything with its avatar data between the DATA_START and now.
         */
        uint8_t cur_hash[AVATAR_HASH_LENGTH];
        m_avatar_hash(cur_hash, avrd->data, avrd->bytes_received);

        if (memcmp(cur_hash, avrd->hash, AVATAR_HASH_LENGTH) == 0) {
            /* Avatar successfuly received! */
            if (m->avatar_data_recv) {
                (m->avatar_data_recv)(m, friendnumber, avrd->format, cur_hash,
                                      avrd->data, avrd->bytes_received, m->avatar_data_recv_userdata);
            }
        } else {
            LOGGER_DEBUG("Avatar hash error. friendnumber = %u", friendnumber);
        }

        free(avrd);
        m->friendlist[friendnumber].avatar_recv_data = NULL;
        return 0;
    }

    /* Waits for more data to be received */
    return 0;
}



static int handle_packet(void *object, int i, uint8_t *temp, uint16_t len)
{
    if (len == 0)
        return -1;

    Messenger *m = object;
    uint8_t packet_id = temp[0];
    uint8_t *data = temp + 1;
    uint32_t data_length = len - 1;

    if (m->friendlist[i].status != FRIEND_ONLINE) {
        if (packet_id == PACKET_ID_ONLINE && len == 1) {
            set_friend_status(m, i, FRIEND_ONLINE);
            send_online_packet(m, i);
        } else if (packet_id == PACKET_ID_NICKNAME || packet_id == PACKET_ID_STATUSMESSAGE
                   || packet_id == PACKET_ID_USERSTATUS) {
            /* Some backward compatibility, TODO: remove. */
            set_friend_status(m, i, FRIEND_ONLINE);
            send_online_packet(m, i);
        } else {
            return -1;
        }
    }

    switch (packet_id) {
        case PACKET_ID_OFFLINE: {
            if (data_length != 0)
                break;

            set_friend_status(m, i, FRIEND_CONFIRMED);
        }

        case PACKET_ID_NICKNAME: {
            if (data_length > MAX_NAME_LENGTH || data_length == 0)
                break;

            /* Make sure the NULL terminator is present. */
            uint8_t data_terminated[data_length + 1];
            memcpy(data_terminated, data, data_length);
            data_terminated[data_length] = 0;

            /* inform of namechange before we overwrite the old name */
            if (m->friend_namechange)
                m->friend_namechange(m, i, data_terminated, data_length, m->friend_namechange_userdata);

            memcpy(m->friendlist[i].name, data_terminated, data_length);
            m->friendlist[i].name_length = data_length;

            break;
        }

        case PACKET_ID_STATUSMESSAGE: {
            if (data_length == 0 || data_length > MAX_STATUSMESSAGE_LENGTH)
                break;

            /* Make sure the NULL terminator is present. */
            uint8_t data_terminated[data_length + 1];
            memcpy(data_terminated, data, data_length);
            data_terminated[data_length] = 0;

            if (m->friend_statusmessagechange)
                m->friend_statusmessagechange(m, i, data_terminated, data_length,
                                              m->friend_statuschange_userdata);

            set_friend_statusmessage(m, i, data_terminated, data_length);
            break;
        }

        case PACKET_ID_USERSTATUS: {
            if (data_length != 1)
                break;

            USERSTATUS status = data[0];

            if (status >= USERSTATUS_INVALID)
                break;

            if (m->friend_userstatuschange)
                m->friend_userstatuschange(m, i, status, m->friend_userstatuschange_userdata);

            set_friend_userstatus(m, i, status);
            break;
        }

        case PACKET_ID_TYPING: {
            if (data_length != 1)
                break;

            uint8_t typing = data[0];

            set_friend_typing(m, i, typing);

            if (m->friend_typingchange)
                m->friend_typingchange(m, i, typing, m->friend_typingchange_userdata);

            break;
        }

        case PACKET_ID_MESSAGE: {
            const uint8_t *message_id = data;
            uint8_t message_id_length = 4;

            if (data_length <= message_id_length)
                break;

            const uint8_t *message = data + message_id_length;
            uint16_t message_length = data_length - message_id_length;

            /* Make sure the NULL terminator is present. */
            uint8_t message_terminated[message_length + 1];
            memcpy(message_terminated, message, message_length);
            message_terminated[message_length] = 0;

            if (m->friendlist[i].receives_read_receipts) {
                write_cryptpacket_id(m, i, PACKET_ID_RECEIPT, message_id, message_id_length, 0);
            }

            if (m->friend_message)
                (*m->friend_message)(m, i, message_terminated, message_length, m->friend_message_userdata);

            break;
        }

        case PACKET_ID_ACTION: {
            const uint8_t *message_id = data;
            uint8_t message_id_length = 4;

            if (data_length <= message_id_length)
                break;

            const uint8_t *action = data + message_id_length;
            uint16_t action_length = data_length - message_id_length;

            /* Make sure the NULL terminator is present. */
            uint8_t action_terminated[action_length + 1];
            memcpy(action_terminated, action, action_length);
            action_terminated[action_length] = 0;

            if (m->friendlist[i].receives_read_receipts) {
                write_cryptpacket_id(m, i, PACKET_ID_RECEIPT, message_id, message_id_length, 0);
            }

            if (m->friend_action)
                (*m->friend_action)(m, i, action_terminated, action_length, m->friend_action_userdata);


            break;
        }

        case PACKET_ID_AVATAR_INFO_REQ: {
            /* Send our avatar information */
            m_send_avatar_info(m, i);
            break;
        }

        case PACKET_ID_AVATAR_INFO: {
            if (m->avatar_info_recv) {
                /*
                 * A malicious user may send an incomplete avatar info message.
                 * Check if it have the correct size for the format:
                 * [1 uint8_t: avatar format] [32 uint8_t: hash]
                 */
                if (data_length == AVATAR_HASH_LENGTH + 1) {
                    (m->avatar_info_recv)(m, i, data[0], data + 1, m->avatar_info_recv_userdata);
                }
            }

            break;
        }

        case PACKET_ID_AVATAR_DATA_CONTROL: {
            handle_avatar_data_control(m, i, data, data_length);
            break;
        }

        case PACKET_ID_AVATAR_DATA_START: {
            handle_avatar_data_start(m, i, data, data_length);
            break;
        }

        case PACKET_ID_AVATAR_DATA_PUSH: {
            handle_avatar_data_push(m, i, data, data_length);
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
            if (data_length == 0)
                break;

            if (m->group_invite)
                (*m->group_invite)(m, i, data, data_length);

            break;
        }

        case PACKET_ID_FILE_SENDREQUEST: {
            if (data_length < 1 + sizeof(uint64_t) + 1)
                break;

            uint8_t filenumber = data[0];
            uint64_t filesize;
            memcpy(&filesize, data + 1, sizeof(filesize));
            net_to_host((uint8_t *) &filesize, sizeof(filesize));
            m->friendlist[i].file_receiving[filenumber].status = FILESTATUS_NOT_ACCEPTED;
            m->friendlist[i].file_receiving[filenumber].size = filesize;
            m->friendlist[i].file_receiving[filenumber].transferred = 0;

            /* Force NULL terminate file name. */
            uint8_t filename_terminated[data_length - 1 - sizeof(uint64_t) + 1];
            memcpy(filename_terminated, data + 1 + sizeof(uint64_t), data_length - 1 - sizeof(uint64_t));
            filename_terminated[data_length - 1 - sizeof(uint64_t)] = 0;

            if (m->file_sendrequest)
                (*m->file_sendrequest)(m, i, filenumber, filesize, filename_terminated, data_length - 1 - sizeof(uint64_t),
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

            break;
        }

        case PACKET_ID_SHARE_RELAYS: {
            Node_format nodes[MAX_SHARED_RELAYS];
            int n;

            if ((n = unpack_nodes(nodes, MAX_SHARED_RELAYS, NULL, data, data_length, 1)) == -1)
                break;

            int i;

            for (i = 0; i < n; i++) {
                add_tcp_relay(m->net_crypto, nodes[i].ip_port, nodes[i].public_key);
            }

            break;
        }

        default: {
            handle_custom_lossless_packet(object, i, temp, len);
            break;
        }
    }

    return 0;
}

/* TODO: Make this function not suck. */
void do_friends(Messenger *m)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status == FRIEND_ADDED) {
            int fr = send_friend_request_packet(m->fr_c, m->friendlist[i].friendcon_id, m->friendlist[i].friendrequest_nospam,
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
        }

        if (m->friendlist[i].status == FRIEND_ONLINE) { /* friend is online. */
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

            if (m->friendlist[i].avatar_info_sent == 0) {
                if (m_send_avatar_info(m, i) == 0)
                    m->friendlist[i].avatar_info_sent = 1;
            }

            if (m->friendlist[i].user_istyping_sent == 0) {
                if (send_user_istyping(m, i, m->friendlist[i].user_istyping))
                    m->friendlist[i].user_istyping_sent = 1;
            }

            if (m->friendlist[i].share_relays_lastsent + FRIEND_SHARE_RELAYS_INTERVAL < temp_time) {
                send_relays(m, i);
            }
        }
    }
}




#ifdef LOGGING
#define DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS 60UL
static time_t lastdump = 0;
static char IDString[crypto_box_PUBLICKEYBYTES * 2 + 1];
static char *ID2String(const uint8_t *pk)
{
    uint32_t i;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
        sprintf(&IDString[i * 2], "%02X", pk[i]);

    IDString[crypto_box_PUBLICKEYBYTES * 2] = 0;
    return IDString;
}
#endif

/* Minimum messenger run interval in ms
   TODO: A/V */
#define MIN_RUN_INTERVAL 50

/* Return the time in milliseconds before do_messenger() should be called again
 * for optimal performance.
 *
 * returns time (in ms) before the next do_messenger() needs to be run on success.
 */
uint32_t messenger_run_interval(Messenger *m)
{
    uint32_t crypto_interval = crypto_run_interval(m->net_crypto);

    if (crypto_interval > MIN_RUN_INTERVAL) {
        return MIN_RUN_INTERVAL;
    } else {
        return crypto_interval;
    }
}

/* The main loop that needs to be run at least 20 times per second. */
void do_messenger(Messenger *m)
{
    // Add the TCP relays, but only if this is the first time calling do_messenger
    if (m->has_added_relays == 0) {
        m->has_added_relays = 1;

        int i;

        for (i = 0; i < NUM_SAVED_TCP_RELAYS; ++i) {
            add_tcp_relay(m->net_crypto, m->loaded_relays[i].ip_port, m->loaded_relays[i].public_key);
        }
    }

    unix_time_update();

    if (!m->options.udp_disabled) {
        networking_poll(m->net);
        do_DHT(m->dht);
    }

    do_net_crypto(m->net_crypto);
    do_onion_client(m->onion_c);
    do_friend_connections(m->fr_c);
    do_friends(m);
    LANdiscovery(m);

#ifdef LOGGING

    if (unix_time() > lastdump + DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS) {

#ifdef ENABLE_ASSOC_DHT
        Assoc_status(m->dht->assoc);
#endif

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

                    LOGGER_TRACE("C[%2u] %s:%u [%3u] %s",
                                 client, ip_ntoa(&assoc->ip_port.ip), ntohs(assoc->ip_port.port),
                                 last_pinged, ID2String(cptr->client_id));
                }
        }


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
                if (id_equal(m->friendlist[friend].real_pk, m->dht->friends_list[dhtfriend].client_id)) {
                    m2dht[friend] = dhtfriend;
                    break;
                }
        }

        for (friend = 0; friend < num_dhtfriends; friend++)
            if (m2dht[friend] >= 0)
                dht2m[m2dht[friend]] = friend;

        if (m->numfriends != m->dht->num_friends) {
            LOGGER_TRACE("Friend num in DHT %u != friend num in msger %u\n", m->dht->num_friends, m->numfriends);
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

                LOGGER_TRACE("F[%2u:%2u] <%s> [%03u] %s",
                             dht2m[friend], friend, msgfptr->name,
                             ping_lastrecv, ID2String(msgfptr->real_pk));
            } else {
                LOGGER_TRACE("F[--:%2u] %s", friend, ID2String(dhtfptr->client_id));
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

                        LOGGER_TRACE("F[%2u] => C[%2u] %s:%u [%3u] %s",
                                     friend, client, ip_ntoa(&assoc->ip_port.ip),
                                     ntohs(assoc->ip_port.port), last_pinged,
                                     ID2String(cptr->client_id));
                    }
            }
        }
    }

#endif /* LOGGING */
}

/* new messenger format for load/save, more robust and forward compatible */

#define MESSENGER_STATE_COOKIE_GLOBAL 0x15ed1b1f

#define MESSENGER_STATE_COOKIE_TYPE      0x01ce
#define MESSENGER_STATE_TYPE_NOSPAMKEYS    1
#define MESSENGER_STATE_TYPE_DHT           2
#define MESSENGER_STATE_TYPE_FRIENDS       3
#define MESSENGER_STATE_TYPE_NAME          4
#define MESSENGER_STATE_TYPE_STATUSMESSAGE 5
#define MESSENGER_STATE_TYPE_STATUS        6
#define MESSENGER_STATE_TYPE_TCP_RELAY     10
#define MESSENGER_STATE_TYPE_PATH_NODE     11

#define SAVED_FRIEND_REQUEST_SIZE 1024
#define NUM_SAVED_PATH_NODES 8
struct SAVED_FRIEND {
    uint8_t status;
    uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t info[SAVED_FRIEND_REQUEST_SIZE]; // the data that is sent during the friend requests we do.
    uint16_t info_size; // Length of the info.
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;
    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;
    uint8_t userstatus;
    uint32_t friendrequest_nospam;
    uint64_t ping_lastrecv;
};

static uint32_t saved_friendslist_size(const Messenger *m)
{
    return count_friendlist(m) * sizeof(struct SAVED_FRIEND);
}

static uint32_t friends_list_save(const Messenger *m, uint8_t *data)
{
    uint32_t i;
    uint32_t num = 0;

    for (i = 0; i < m->numfriends; i++) {
        if (m->friendlist[i].status > 0) {
            struct SAVED_FRIEND temp;
            memset(&temp, 0, sizeof(struct SAVED_FRIEND));
            temp.status = m->friendlist[i].status;
            memcpy(temp.real_pk, m->friendlist[i].real_pk, crypto_box_PUBLICKEYBYTES);

            if (temp.status < 3) {
                if (m->friendlist[i].info_size > SAVED_FRIEND_REQUEST_SIZE) {
                    memcpy(temp.info, m->friendlist[i].info, SAVED_FRIEND_REQUEST_SIZE);
                } else {
                    memcpy(temp.info, m->friendlist[i].info, m->friendlist[i].info_size);
                }

                temp.info_size = htons(m->friendlist[i].info_size);
                temp.friendrequest_nospam = m->friendlist[i].friendrequest_nospam;
            } else {
                memcpy(temp.name, m->friendlist[i].name, m->friendlist[i].name_length);
                temp.name_length = htons(m->friendlist[i].name_length);
                memcpy(temp.statusmessage, m->friendlist[i].statusmessage, m->friendlist[i].statusmessage_length);
                temp.statusmessage_length = htons(m->friendlist[i].statusmessage_length);
                temp.userstatus = m->friendlist[i].userstatus;

                uint8_t lastonline[sizeof(uint64_t)];
                memcpy(lastonline, &m->friendlist[i].ping_lastrecv, sizeof(uint64_t));
                host_to_net(lastonline, sizeof(uint64_t));
                memcpy(&temp.ping_lastrecv, lastonline, sizeof(uint64_t));
            }

            memcpy(data + num * sizeof(struct SAVED_FRIEND), &temp, sizeof(struct SAVED_FRIEND));
            num++;
        }
    }

    return num * sizeof(struct SAVED_FRIEND);
}

static int friends_list_load(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length % sizeof(struct SAVED_FRIEND) != 0) {
        return -1;
    }

    uint32_t num = length / sizeof(struct SAVED_FRIEND);
    uint32_t i;

    for (i = 0; i < num; ++i) {
        struct SAVED_FRIEND temp;
        memcpy(&temp, data + i * sizeof(struct SAVED_FRIEND), sizeof(struct SAVED_FRIEND));

        if (temp.status >= 3) {
            int fnum = m_addfriend_norequest(m, temp.real_pk);

            if (fnum < 0)
                continue;

            setfriendname(m, fnum, temp.name, ntohs(temp.name_length));
            set_friend_statusmessage(m, fnum, temp.statusmessage, ntohs(temp.statusmessage_length));
            set_friend_userstatus(m, fnum, temp.userstatus);
            uint8_t lastonline[sizeof(uint64_t)];
            memcpy(lastonline, &temp.ping_lastrecv, sizeof(uint64_t));
            net_to_host(lastonline, sizeof(uint64_t));
            memcpy(&m->friendlist[fnum].ping_lastrecv, lastonline, sizeof(uint64_t));
        } else if (temp.status != 0) {
            /* TODO: This is not a good way to do this. */
            uint8_t address[FRIEND_ADDRESS_SIZE];
            id_copy(address, temp.real_pk);
            memcpy(address + crypto_box_PUBLICKEYBYTES, &(temp.friendrequest_nospam), sizeof(uint32_t));
            uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
            memcpy(address + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t), &checksum, sizeof(checksum));
            m_addfriend(m, address, temp.info, ntohs(temp.info_size));
        }
    }

    return num;
}

/*  return size of the messenger data (for saving) */
uint32_t messenger_size(const Messenger *m)
{
    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    return   size32 * 2                                      // global cookie
             + sizesubhead + sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
             + sizesubhead + DHT_size(m->dht)                  // DHT
             + sizesubhead + saved_friendslist_size(m)         // Friendlist itself.
             + sizesubhead + m->name_length                    // Own nickname.
             + sizesubhead + m->statusmessage_length           // status message
             + sizesubhead + 1                                 // status
             + sizesubhead + NUM_SAVED_TCP_RELAYS * sizeof(Node_format) //TCP relays
             + sizesubhead + NUM_SAVED_PATH_NODES * sizeof(Node_format) //saved path nodes
             ;
}

static uint8_t *z_state_save_subheader(uint8_t *data, uint32_t len, uint16_t type)
{
    host_to_lendian32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian32(data, (host_tolendian16(MESSENGER_STATE_COOKIE_TYPE) << 16) | host_tolendian16(type));
    data += sizeof(uint32_t);
    return data;
}

/* Save the messenger in data of size Messenger_size(). */
void messenger_save(const Messenger *m, uint8_t *data)
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

    len = saved_friendslist_size(m);
    type = MESSENGER_STATE_TYPE_FRIENDS;
    data = z_state_save_subheader(data, len, type);
    friends_list_save(m, data);
    data += len;

    len = m->name_length;
    type = MESSENGER_STATE_TYPE_NAME;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, m->name, len);
    data += len;

    len = m->statusmessage_length;
    type = MESSENGER_STATE_TYPE_STATUSMESSAGE;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, m->statusmessage, len);
    data += len;

    len = 1;
    type = MESSENGER_STATE_TYPE_STATUS;
    data = z_state_save_subheader(data, len, type);
    *data = m->userstatus;
    data += len;

    Node_format relays[NUM_SAVED_TCP_RELAYS];
    len = sizeof(relays);
    type = MESSENGER_STATE_TYPE_TCP_RELAY;
    data = z_state_save_subheader(data, len, type);
    memset(relays, 0, len);
    copy_connected_tcp_relays(m->net_crypto, relays, NUM_SAVED_TCP_RELAYS);
    memcpy(data, relays, len);
    data += len;

    Node_format nodes[NUM_SAVED_PATH_NODES];
    len = sizeof(nodes);
    type = MESSENGER_STATE_TYPE_PATH_NODE;
    data = z_state_save_subheader(data, len, type);
    memset(nodes, 0, len);
    onion_backup_nodes(m->onion_c, nodes, NUM_SAVED_PATH_NODES);
    memcpy(data, nodes, len);
}

static int messenger_load_state_callback(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
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
            friends_list_load(m, data, length);
            break;

        case MESSENGER_STATE_TYPE_NAME:
            if ((length > 0) && (length <= MAX_NAME_LENGTH)) {
                setname(m, data, length);
            }

            break;

        case MESSENGER_STATE_TYPE_STATUSMESSAGE:
            if ((length > 0) && (length < MAX_STATUSMESSAGE_LENGTH)) {
                m_set_statusmessage(m, data, length);
            }

            break;

        case MESSENGER_STATE_TYPE_STATUS:
            if (length == 1) {
                m_set_userstatus(m, *data);
            }

            break;

        case MESSENGER_STATE_TYPE_TCP_RELAY: {
            if (length != sizeof(m->loaded_relays)) {
                return -1;
            }

            memcpy(m->loaded_relays, data, length);
            m->has_added_relays = 0;

            break;
        }

        case MESSENGER_STATE_TYPE_PATH_NODE: {
            Node_format nodes[NUM_SAVED_PATH_NODES];

            if (length != sizeof(nodes)) {
                return -1;
            }

            memcpy(nodes, data, length);
            uint32_t i;

            for (i = 0; i < NUM_SAVED_PATH_NODES; ++i) {
                onion_add_bs_path_node(m->onion_c, nodes[i].ip_port, nodes[i].public_key);
            }

            break;
        }

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
int messenger_load(Messenger *m, const uint8_t *data, uint32_t length)
{
    uint32_t data32[2];
    uint32_t cookie_len = sizeof(data32);

    if (length < cookie_len)
        return -1;

    memcpy(data32, data, sizeof(data32));

    if (!data32[0] && (data32[1] == MESSENGER_STATE_COOKIE_GLOBAL))
        return load_state(messenger_load_state_callback, m, data + cookie_len,
                          length - cookie_len, MESSENGER_STATE_COOKIE_TYPE);
    else
        return -1;
}

/* Return the number of friends in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_friendlist. */
uint32_t count_friendlist(const Messenger *m)
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

/* Return the number of online friends in the instance m. */
uint32_t get_num_online_friends(const Messenger *m)
{
    return m->numonline_friends;
}

/* Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_friendlist(Messenger const *m, int32_t *out_list, uint32_t list_size)
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
