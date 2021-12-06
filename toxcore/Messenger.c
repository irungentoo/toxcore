/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * An implementation of a simple text chat only messenger on the tox network core.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "Messenger.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logger.h"
#include "mono_time.h"
#include "network.h"
#include "state.h"
#include "util.h"

static int write_cryptpacket_id(const Messenger *m, int32_t friendnumber, uint8_t packet_id, const uint8_t *data,
                                uint32_t length, uint8_t congestion_control);
static void m_register_default_plugins(Messenger *m);

/**
 * Determines if the friendnumber passed is valid in the Messenger object.
 *
 * @param friendnumber The index in the friend list.
 */
static bool friend_is_valid(const Messenger *m, int32_t friendnumber)
{
    return (unsigned int)friendnumber < m->numfriends && m->friendlist[friendnumber].status != 0;
}

/* Set the size of the friend list to numfriends.
 *
 *  return -1 if realloc fails.
 */
static int realloc_friendlist(Messenger *m, uint32_t num)
{
    if (num == 0) {
        free(m->friendlist);
        m->friendlist = nullptr;
        return 0;
    }

    Friend *newfriendlist = (Friend *)realloc(m->friendlist, num * sizeof(Friend));

    if (newfriendlist == nullptr) {
        return -1;
    }

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
        if (m->friendlist[i].status > 0) {
            if (id_equal(real_pk, m->friendlist[i].real_pk)) {
                return i;
            }
        }
    }

    return -1;
}

/* Copies the public key associated to that friend id into real_pk buffer.
 * Make sure that real_pk is of size CRYPTO_PUBLIC_KEY_SIZE.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int get_real_pk(const Messenger *m, int32_t friendnumber, uint8_t *real_pk)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    memcpy(real_pk, m->friendlist[friendnumber].real_pk, CRYPTO_PUBLIC_KEY_SIZE);
    return 0;
}

/*  return friend connection id on success.
 *  return -1 if failure.
 */
int getfriendcon_id(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    return m->friendlist[friendnumber].friendcon_id;
}

/*
 *  return a uint16_t that represents the checksum of address of length len.
 */
static uint16_t address_checksum(const uint8_t *address, uint32_t len)
{
    uint8_t checksum[2] = {0};
    uint16_t check;
    uint32_t i;

    for (i = 0; i < len; ++i) {
        checksum[i % 2] ^= address[i];
    }

    memcpy(&check, checksum, sizeof(check));
    return check;
}

/* Format: `[real_pk (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]`
 *
 *  return FRIEND_ADDRESS_SIZE byte address to give to others.
 */
void getaddress(const Messenger *m, uint8_t *address)
{
    id_copy(address, nc_get_self_public_key(m->net_crypto));
    uint32_t nospam = get_nospam(m->fr);
    memcpy(address + CRYPTO_PUBLIC_KEY_SIZE, &nospam, sizeof(nospam));
    uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(address + CRYPTO_PUBLIC_KEY_SIZE + sizeof(nospam), &checksum, sizeof(checksum));
}

static int send_online_packet(Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return 0;
    }

    uint8_t packet = PACKET_ID_ONLINE;
    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                             m->friendlist[friendnumber].friendcon_id), &packet, sizeof(packet), 0) != -1;
}

static int send_offline_packet(Messenger *m, int friendcon_id)
{
    uint8_t packet = PACKET_ID_OFFLINE;
    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c, friendcon_id), &packet,
                             sizeof(packet), 0) != -1;
}

static int m_handle_status(void *object, int i, uint8_t status, void *userdata);
static int m_handle_packet(void *object, int i, const uint8_t *temp, uint16_t len, void *userdata);
static int m_handle_lossy_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length,
                                 void *userdata);

static int32_t init_new_friend(Messenger *m, const uint8_t *real_pk, uint8_t status)
{
    if (m->numfriends == UINT32_MAX) {
        LOGGER_ERROR(m->log, "Friend list full: we have more than 4 billion friends");
        /* This is technically incorrect, but close enough. */
        return FAERR_NOMEM;
    }

    /* Resize the friend list if necessary. */
    if (realloc_friendlist(m, m->numfriends + 1) != 0) {
        return FAERR_NOMEM;
    }

    memset(&m->friendlist[m->numfriends], 0, sizeof(Friend));

    int friendcon_id = new_friend_connection(m->fr_c, real_pk);

    if (friendcon_id == -1) {
        return FAERR_NOMEM;
    }

    uint32_t i;

    for (i = 0; i <= m->numfriends; ++i) {
        if (m->friendlist[i].status == NOFRIEND) {
            m->friendlist[i].status = status;
            m->friendlist[i].friendcon_id = friendcon_id;
            m->friendlist[i].friendrequest_lastsent = 0;
            id_copy(m->friendlist[i].real_pk, real_pk);
            m->friendlist[i].statusmessage_length = 0;
            m->friendlist[i].userstatus = USERSTATUS_NONE;
            m->friendlist[i].is_typing = 0;
            m->friendlist[i].message_id = 0;
            friend_connection_callbacks(m->fr_c, friendcon_id, MESSENGER_CALLBACK_INDEX, &m_handle_status, &m_handle_packet,
                                        &m_handle_lossy_packet, m, i);

            if (m->numfriends == i) {
                ++m->numfriends;
            }

            if (friend_con_connected(m->fr_c, friendcon_id) == FRIENDCONN_STATUS_CONNECTED) {
                send_online_packet(m, i);
            }

            return i;
        }
    }

    return FAERR_NOMEM;
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
 *  return FAERR_BADCHECKSUM if bad checksum in address.
 *  return FAERR_SETNEWNOSPAM if the friend was already there but the nospam was different.
 *  (the nospam for that friend was set to the new one).
 *  return FAERR_NOMEM if increasing the friend list size fails.
 */
int32_t m_addfriend(Messenger *m, const uint8_t *address, const uint8_t *data, uint16_t length)
{
    if (length > MAX_FRIEND_REQUEST_DATA_SIZE) {
        return FAERR_TOOLONG;
    }

    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    id_copy(real_pk, address);

    if (!public_key_valid(real_pk)) {
        return FAERR_BADCHECKSUM;
    }

    uint16_t check;
    uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
    memcpy(&check, address + CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t), sizeof(check));

    if (check != checksum) {
        return FAERR_BADCHECKSUM;
    }

    if (length < 1) {
        return FAERR_NOMESSAGE;
    }

    if (id_equal(real_pk, nc_get_self_public_key(m->net_crypto))) {
        return FAERR_OWNKEY;
    }

    int32_t friend_id = getfriend_id(m, real_pk);

    if (friend_id != -1) {
        if (m->friendlist[friend_id].status >= FRIEND_CONFIRMED) {
            return FAERR_ALREADYSENT;
        }

        uint32_t nospam;
        memcpy(&nospam, address + CRYPTO_PUBLIC_KEY_SIZE, sizeof(nospam));

        if (m->friendlist[friend_id].friendrequest_nospam == nospam) {
            return FAERR_ALREADYSENT;
        }

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
    memcpy(&m->friendlist[ret].friendrequest_nospam, address + CRYPTO_PUBLIC_KEY_SIZE, sizeof(uint32_t));

    return ret;
}

int32_t m_addfriend_norequest(Messenger *m, const uint8_t *real_pk)
{
    if (getfriend_id(m, real_pk) != -1) {
        return FAERR_ALREADYSENT;
    }

    if (!public_key_valid(real_pk)) {
        return FAERR_BADCHECKSUM;
    }

    if (id_equal(real_pk, nc_get_self_public_key(m->net_crypto))) {
        return FAERR_OWNKEY;
    }

    return init_new_friend(m, real_pk, FRIEND_CONFIRMED);
}

static int clear_receipts(Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    struct Receipts *receipts = m->friendlist[friendnumber].receipts_start;

    while (receipts) {
        struct Receipts *temp_r = receipts->next;
        free(receipts);
        receipts = temp_r;
    }

    m->friendlist[friendnumber].receipts_start = nullptr;
    m->friendlist[friendnumber].receipts_end = nullptr;
    return 0;
}

static int add_receipt(Messenger *m, int32_t friendnumber, uint32_t packet_num, uint32_t msg_id)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    struct Receipts *new_receipts = (struct Receipts *)calloc(1, sizeof(struct Receipts));

    if (!new_receipts) {
        return -1;
    }

    new_receipts->packet_num = packet_num;
    new_receipts->msg_id = msg_id;

    if (!m->friendlist[friendnumber].receipts_start) {
        m->friendlist[friendnumber].receipts_start = new_receipts;
    } else {
        m->friendlist[friendnumber].receipts_end->next = new_receipts;
    }

    m->friendlist[friendnumber].receipts_end = new_receipts;
    new_receipts->next = nullptr;
    return 0;
}
/*
 * return -1 on failure.
 * return 0 if packet was received.
 */
static int friend_received_packet(const Messenger *m, int32_t friendnumber, uint32_t number)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    return cryptpacket_received(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                                m->friendlist[friendnumber].friendcon_id), number);
}

static int do_receipts(Messenger *m, int32_t friendnumber, void *userdata)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    struct Receipts *receipts = m->friendlist[friendnumber].receipts_start;

    while (receipts) {
        if (friend_received_packet(m, friendnumber, receipts->packet_num) == -1) {
            break;
        }

        if (m->read_receipt) {
            m->read_receipt(m, friendnumber, receipts->msg_id, userdata);
        }

        struct Receipts *r_next = receipts->next;

        free(receipts);

        m->friendlist[friendnumber].receipts_start = r_next;

        receipts = r_next;
    }

    if (!m->friendlist[friendnumber].receipts_start) {
        m->friendlist[friendnumber].receipts_end = nullptr;
    }

    return 0;
}

/* Remove a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int m_delfriend(Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friend_connectionstatuschange_internal) {
        m->friend_connectionstatuschange_internal(m, friendnumber, 0, m->friend_connectionstatuschange_internal_userdata);
    }

    clear_receipts(m, friendnumber);
    remove_request_received(m->fr, m->friendlist[friendnumber].real_pk);
    friend_connection_callbacks(m->fr_c, m->friendlist[friendnumber].friendcon_id, MESSENGER_CALLBACK_INDEX, nullptr,
                                nullptr, nullptr, nullptr, 0);

    if (friend_con_connected(m->fr_c, m->friendlist[friendnumber].friendcon_id) == FRIENDCONN_STATUS_CONNECTED) {
        send_offline_packet(m, m->friendlist[friendnumber].friendcon_id);
    }

    kill_friend_connection(m->fr_c, m->friendlist[friendnumber].friendcon_id);
    memset(&m->friendlist[friendnumber], 0, sizeof(Friend));
    uint32_t i;

    for (i = m->numfriends; i != 0; --i) {
        if (m->friendlist[i - 1].status != NOFRIEND) {
            break;
        }
    }

    m->numfriends = i;

    if (realloc_friendlist(m, m->numfriends) != 0) {
        return FAERR_NOMEM;
    }

    return 0;
}

int m_get_friend_connectionstatus(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return CONNECTION_NONE;
    }

    bool direct_connected = 0;
    unsigned int num_online_relays = 0;
    int crypt_conn_id = friend_connection_crypt_connection_id(m->fr_c, m->friendlist[friendnumber].friendcon_id);

    if (!crypto_connection_status(m->net_crypto, crypt_conn_id, &direct_connected, &num_online_relays)) {
        return CONNECTION_NONE;
    }

    if (direct_connected) {
        return CONNECTION_UDP;
    }

    if (num_online_relays) {
        return CONNECTION_TCP;
    }

    /* if we have a valid friend connection but do not have an established connection
     * we leave the connection status unchanged until the friend connection is either
     * established or dropped.
     */
    return m->friendlist[friendnumber].last_connection_udp_tcp;
}

int m_friend_exists(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return 0;
    }

    return 1;
}

/* Send a message of type.
 *
 * return -1 if friend not valid.
 * return -2 if too large.
 * return -3 if friend not online.
 * return -4 if send failed (because queue is full).
 * return -5 if bad type.
 * return 0 if success.
 */
int m_send_message_generic(Messenger *m, int32_t friendnumber, uint8_t type, const uint8_t *message, uint32_t length,
                           uint32_t *message_id)
{
    if (type > MESSAGE_ACTION) {
        LOGGER_ERROR(m->log, "Message type %d is invalid", type);
        return -5;
    }

    if (!friend_is_valid(m, friendnumber)) {
        LOGGER_ERROR(m->log, "Friend number %d is invalid", friendnumber);
        return -1;
    }

    if (length >= MAX_CRYPTO_DATA_SIZE) {
        LOGGER_ERROR(m->log, "Message length %u is too large", length);
        return -2;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        LOGGER_ERROR(m->log, "Friend %d is not online", friendnumber);
        return -3;
    }

    VLA(uint8_t, packet, length + 1);
    packet[0] = PACKET_ID_MESSAGE + type;

    if (length != 0) {
        memcpy(packet + 1, message, length);
    }

    int64_t packet_num = write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                                           m->friendlist[friendnumber].friendcon_id), packet, length + 1, 0);

    if (packet_num == -1) {
        LOGGER_ERROR(m->log, "Failed to write crypto packet for message of length %d to friend %d",
                     length, friendnumber);
        return -4;
    }

    uint32_t msg_id = ++m->friendlist[friendnumber].message_id;

    add_receipt(m, friendnumber, packet_num, msg_id);

    if (message_id) {
        *message_id = msg_id;
    }

    return 0;
}

/* Send a name packet to friendnumber.
 * length is the length with the NULL terminator.
 */
static int m_sendname(const Messenger *m, int32_t friendnumber, const uint8_t *name, uint16_t length)
{
    if (length > MAX_NAME_LENGTH) {
        return 0;
    }

    return write_cryptpacket_id(m, friendnumber, PACKET_ID_NICKNAME, name, length, 0);
}

/* Set the name and name_length of a friend.
 *
 *  return 0 if success.
 *  return -1 if failure.
 */
int setfriendname(Messenger *m, int32_t friendnumber, const uint8_t *name, uint16_t length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (length > MAX_NAME_LENGTH || length == 0) {
        return -1;
    }

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
    if (length > MAX_NAME_LENGTH) {
        return -1;
    }

    if (m->name_length == length && (length == 0 || memcmp(name, m->name, length) == 0)) {
        return 0;
    }

    if (length) {
        memcpy(m->name, name, length);
    }

    m->name_length = length;
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        m->friendlist[i].name_sent = 0;
    }

    return 0;
}

/* Get our nickname and put it in name.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 *  return the length of the name.
 */
uint16_t getself_name(const Messenger *m, uint8_t *name)
{
    if (name == nullptr) {
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
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    memcpy(name, m->friendlist[friendnumber].name, m->friendlist[friendnumber].name_length);
    return m->friendlist[friendnumber].name_length;
}

int m_get_name_size(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    return m->friendlist[friendnumber].name_length;
}

int m_get_self_name_size(const Messenger *m)
{
    return m->name_length;
}

int m_set_statusmessage(Messenger *m, const uint8_t *status, uint16_t length)
{
    if (length > MAX_STATUSMESSAGE_LENGTH) {
        return -1;
    }

    if (m->statusmessage_length == length && (length == 0 || memcmp(m->statusmessage, status, length) == 0)) {
        return 0;
    }

    if (length) {
        memcpy(m->statusmessage, status, length);
    }

    m->statusmessage_length = length;

    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        m->friendlist[i].statusmessage_sent = 0;
    }

    return 0;
}

int m_set_userstatus(Messenger *m, uint8_t status)
{
    if (status >= USERSTATUS_INVALID) {
        return -1;
    }

    if (m->userstatus == status) {
        return 0;
    }

    m->userstatus = (Userstatus)status;
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        m->friendlist[i].userstatus_sent = 0;
    }

    return 0;
}

/* return the size of friendnumber's user status.
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 */
int m_get_statusmessage_size(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    return m->friendlist[friendnumber].statusmessage_length;
}

/*  Copy the user status of friendnumber into buf, truncating if needed to maxlen
 *  bytes, use m_get_statusmessage_size to find out how much you need to allocate.
 */
int m_copy_statusmessage(const Messenger *m, int32_t friendnumber, uint8_t *buf, uint32_t maxlen)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    // TODO(iphydf): This should be uint16_t and min_u16. If maxlen exceeds
    // uint16_t's range, it won't affect the result.
    uint32_t msglen = min_u32(maxlen, m->friendlist[friendnumber].statusmessage_length);

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

int m_copy_self_statusmessage(const Messenger *m, uint8_t *buf)
{
    memcpy(buf, m->statusmessage, m->statusmessage_length);
    return m->statusmessage_length;
}

uint8_t m_get_userstatus(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return USERSTATUS_INVALID;
    }

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
    if (!friend_is_valid(m, friendnumber)) {
        return UINT64_MAX;
    }

    return m->friendlist[friendnumber].last_seen_time;
}

int m_set_usertyping(Messenger *m, int32_t friendnumber, uint8_t is_typing)
{
    if (is_typing != 0 && is_typing != 1) {
        return -1;
    }

    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friendlist[friendnumber].user_istyping == is_typing) {
        return 0;
    }

    m->friendlist[friendnumber].user_istyping = is_typing;
    m->friendlist[friendnumber].user_istyping_sent = 0;

    return 0;
}

int m_get_istyping(const Messenger *m, int32_t friendnumber)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

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

static int set_friend_statusmessage(const Messenger *m, int32_t friendnumber, const uint8_t *status, uint16_t length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (length > MAX_STATUSMESSAGE_LENGTH) {
        return -1;
    }

    if (length) {
        memcpy(m->friendlist[friendnumber].statusmessage, status, length);
    }

    m->friendlist[friendnumber].statusmessage_length = length;
    return 0;
}

static void set_friend_userstatus(const Messenger *m, int32_t friendnumber, uint8_t status)
{
    m->friendlist[friendnumber].userstatus = (Userstatus)status;
}

static void set_friend_typing(const Messenger *m, int32_t friendnumber, uint8_t is_typing)
{
    m->friendlist[friendnumber].is_typing = is_typing;
}

/* Set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(Messenger *m, m_friend_request_cb *function)
{
    callback_friendrequest(m->fr, (fr_friend_request_cb *)function, m);
}

/* Set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(Messenger *m, m_friend_message_cb *function)
{
    m->friend_message = function;
}

void m_callback_namechange(Messenger *m, m_friend_name_cb *function)
{
    m->friend_namechange = function;
}

void m_callback_statusmessage(Messenger *m, m_friend_status_message_cb *function)
{
    m->friend_statusmessagechange = function;
}

void m_callback_userstatus(Messenger *m, m_friend_status_cb *function)
{
    m->friend_userstatuschange = function;
}

void m_callback_typingchange(Messenger *m, m_friend_typing_cb *function)
{
    m->friend_typingchange = function;
}

void m_callback_read_receipt(Messenger *m, m_friend_read_receipt_cb *function)
{
    m->read_receipt = function;
}

void m_callback_connectionstatus(Messenger *m, m_friend_connection_status_cb *function)
{
    m->friend_connectionstatuschange = function;
}

void m_callback_core_connection(Messenger *m, m_self_connection_status_cb *function)
{
    m->core_connection_change = function;
}

void m_callback_connectionstatus_internal_av(Messenger *m, m_friend_connectionstatuschange_internal_cb *function,
        void *userdata)
{
    m->friend_connectionstatuschange_internal = function;
    m->friend_connectionstatuschange_internal_userdata = userdata;
}

static void check_friend_tcp_udp(Messenger *m, int32_t friendnumber, void *userdata)
{
    int last_connection_udp_tcp = m->friendlist[friendnumber].last_connection_udp_tcp;

    int ret = m_get_friend_connectionstatus(m, friendnumber);

    if (ret == -1) {
        return;
    }

    if (last_connection_udp_tcp != ret) {
        if (m->friend_connectionstatuschange) {
            m->friend_connectionstatuschange(m, friendnumber, ret, userdata);
        }
    }

    m->friendlist[friendnumber].last_connection_udp_tcp = (Connection_Status)ret;
}

static void break_files(const Messenger *m, int32_t friendnumber);
static void check_friend_connectionstatus(Messenger *m, int32_t friendnumber, uint8_t status, void *userdata)
{
    if (status == NOFRIEND) {
        return;
    }

    const uint8_t was_online = m->friendlist[friendnumber].status == FRIEND_ONLINE;
    const uint8_t is_online = status == FRIEND_ONLINE;

    if (is_online != was_online) {
        if (was_online) {
            break_files(m, friendnumber);
            clear_receipts(m, friendnumber);
        } else {
            m->friendlist[friendnumber].name_sent = 0;
            m->friendlist[friendnumber].userstatus_sent = 0;
            m->friendlist[friendnumber].statusmessage_sent = 0;
            m->friendlist[friendnumber].user_istyping_sent = 0;
        }

        m->friendlist[friendnumber].status = status;

        check_friend_tcp_udp(m, friendnumber, userdata);

        if (m->friend_connectionstatuschange_internal) {
            m->friend_connectionstatuschange_internal(m, friendnumber, is_online,
                    m->friend_connectionstatuschange_internal_userdata);
        }
    }
}

static void set_friend_status(Messenger *m, int32_t friendnumber, uint8_t status, void *userdata)
{
    check_friend_connectionstatus(m, friendnumber, status, userdata);
    m->friendlist[friendnumber].status = status;
}

static int write_cryptpacket_id(const Messenger *m, int32_t friendnumber, uint8_t packet_id, const uint8_t *data,
                                uint32_t length, uint8_t congestion_control)
{
    if (!friend_is_valid(m, friendnumber)) {
        return 0;
    }

    if (length >= MAX_CRYPTO_DATA_SIZE || m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return 0;
    }

    VLA(uint8_t, packet, length + 1);
    packet[0] = packet_id;

    if (length != 0) {
        memcpy(packet + 1, data, length);
    }

    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                             m->friendlist[friendnumber].friendcon_id), packet, length + 1, congestion_control) != -1;
}

/** CONFERENCES */


/* Set the callback for conference invites.
 */
void m_callback_conference_invite(Messenger *m, m_conference_invite_cb *function)
{
    m->conference_invite = function;
}


/* Send a conference invite packet.
 *
 *  return 1 on success
 *  return 0 on failure
 */
int send_conference_invite_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    return write_cryptpacket_id(m, friendnumber, PACKET_ID_INVITE_CONFERENCE, data, length, 0);
}

/** FILE SENDING */


/* Set the callback for file send requests.
 */
void callback_file_sendrequest(Messenger *m, m_file_recv_cb *function)
{
    m->file_sendrequest = function;
}

/* Set the callback for file control requests.
 */
void callback_file_control(Messenger *m, m_file_recv_control_cb *function)
{
    m->file_filecontrol = function;
}

/* Set the callback for file data.
 */
void callback_file_data(Messenger *m, m_file_recv_chunk_cb *function)
{
    m->file_filedata = function;
}

/* Set the callback for file request chunk.
 */
void callback_file_reqchunk(Messenger *m, m_file_chunk_request_cb *function)
{
    m->file_reqchunk = function;
}

#define MAX_FILENAME_LENGTH 255

/* Copy the file transfer file id to file_id
 *
 * return 0 on success.
 * return -1 if friend not valid.
 * return -2 if filenumber not valid
 */
int file_get_id(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint8_t *file_id)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return -2;
    }

    uint32_t temp_filenum;
    uint8_t send_receive;
    uint8_t file_number;

    if (filenumber >= (1 << 16)) {
        send_receive = 1;
        temp_filenum = (filenumber >> 16) - 1;
    } else {
        send_receive = 0;
        temp_filenum = filenumber;
    }

    if (temp_filenum >= MAX_CONCURRENT_FILE_PIPES) {
        return -2;
    }

    file_number = temp_filenum;

    struct File_Transfers *ft;

    if (send_receive) {
        ft = &m->friendlist[friendnumber].file_receiving[file_number];
    } else {
        ft = &m->friendlist[friendnumber].file_sending[file_number];
    }

    if (ft->status == FILESTATUS_NONE) {
        return -2;
    }

    memcpy(file_id, ft->id, FILE_ID_LENGTH);
    return 0;
}

/* Send a file send request.
 * Maximum filename length is 255 bytes.
 *  return 1 on success
 *  return 0 on failure
 */
static int file_sendrequest(const Messenger *m, int32_t friendnumber, uint8_t filenumber, uint32_t file_type,
                            uint64_t filesize, const uint8_t *file_id, const uint8_t *filename, uint16_t filename_length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return 0;
    }

    if (filename_length > MAX_FILENAME_LENGTH) {
        return 0;
    }

    VLA(uint8_t, packet, 1 + sizeof(file_type) + sizeof(filesize) + FILE_ID_LENGTH + filename_length);
    packet[0] = filenumber;
    file_type = net_htonl(file_type);
    memcpy(packet + 1, &file_type, sizeof(file_type));
    net_pack_u64(packet + 1 + sizeof(file_type), filesize);
    memcpy(packet + 1 + sizeof(file_type) + sizeof(filesize), file_id, FILE_ID_LENGTH);

    if (filename_length) {
        memcpy(packet + 1 + sizeof(file_type) + sizeof(filesize) + FILE_ID_LENGTH, filename, filename_length);
    }

    return write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_SENDREQUEST, packet, SIZEOF_VLA(packet), 0);
}

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
                        const uint8_t *file_id, const uint8_t *filename, uint16_t filename_length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (filename_length > MAX_FILENAME_LENGTH) {
        return -2;
    }

    uint32_t i;

    for (i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (m->friendlist[friendnumber].file_sending[i].status == FILESTATUS_NONE) {
            break;
        }
    }

    if (i == MAX_CONCURRENT_FILE_PIPES) {
        return -3;
    }

    if (file_sendrequest(m, friendnumber, i, file_type, filesize, file_id, filename, filename_length) == 0) {
        return -4;
    }

    struct File_Transfers *ft = &m->friendlist[friendnumber].file_sending[i];

    ft->status = FILESTATUS_NOT_ACCEPTED;

    ft->size = filesize;

    ft->transferred = 0;

    ft->requested = 0;

    ft->paused = FILE_PAUSE_NOT;

    memcpy(ft->id, file_id, FILE_ID_LENGTH);

    ++m->friendlist[friendnumber].num_sending_files;

    return i;
}

static int send_file_control_packet(const Messenger *m, int32_t friendnumber, uint8_t send_receive, uint8_t filenumber,
                                    uint8_t control_type, uint8_t *data, uint16_t data_length)
{
    if ((unsigned int)(1 + 3 + data_length) > MAX_CRYPTO_DATA_SIZE) {
        return -1;
    }

    VLA(uint8_t, packet, 3 + data_length);

    packet[0] = send_receive;
    packet[1] = filenumber;
    packet[2] = control_type;

    if (data_length) {
        memcpy(packet + 3, data, data_length);
    }

    return write_cryptpacket_id(m, friendnumber, PACKET_ID_FILE_CONTROL, packet, SIZEOF_VLA(packet), 0);
}

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
int file_control(const Messenger *m, int32_t friendnumber, uint32_t filenumber, unsigned int control)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return -2;
    }

    uint32_t temp_filenum;
    uint8_t send_receive;
    uint8_t file_number;

    if (filenumber >= (1 << 16)) {
        send_receive = 1;
        temp_filenum = (filenumber >> 16) - 1;
    } else {
        send_receive = 0;
        temp_filenum = filenumber;
    }

    if (temp_filenum >= MAX_CONCURRENT_FILE_PIPES) {
        return -3;
    }

    file_number = temp_filenum;

    struct File_Transfers *ft;

    if (send_receive) {
        ft = &m->friendlist[friendnumber].file_receiving[file_number];
    } else {
        ft = &m->friendlist[friendnumber].file_sending[file_number];
    }

    if (ft->status == FILESTATUS_NONE) {
        return -3;
    }

    if (control > FILECONTROL_KILL) {
        return -4;
    }

    if (control == FILECONTROL_PAUSE && ((ft->paused & FILE_PAUSE_US) || ft->status != FILESTATUS_TRANSFERRING)) {
        return -5;
    }

    if (control == FILECONTROL_ACCEPT) {
        if (ft->status == FILESTATUS_TRANSFERRING) {
            if (!(ft->paused & FILE_PAUSE_US)) {
                if (ft->paused & FILE_PAUSE_OTHER) {
                    return -6;
                }

                return -7;
            }
        } else {
            if (ft->status != FILESTATUS_NOT_ACCEPTED) {
                return -7;
            }

            if (!send_receive) {
                return -6;
            }
        }
    }

    if (send_file_control_packet(m, friendnumber, send_receive, file_number, control, nullptr, 0)) {
        if (control == FILECONTROL_KILL) {
            ft->status = FILESTATUS_NONE;

            if (send_receive == 0) {
                --m->friendlist[friendnumber].num_sending_files;
            }
        } else if (control == FILECONTROL_PAUSE) {
            ft->paused |= FILE_PAUSE_US;
        } else if (control == FILECONTROL_ACCEPT) {
            ft->status = FILESTATUS_TRANSFERRING;

            if (ft->paused & FILE_PAUSE_US) {
                ft->paused ^=  FILE_PAUSE_US;
            }
        }
    } else {
        return -8;
    }

    return 0;
}

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
int file_seek(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint64_t position)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return -2;
    }

    if (filenumber < (1 << 16)) {
        // Not receiving.
        return -4;
    }

    uint32_t temp_filenum = (filenumber >> 16) - 1;

    if (temp_filenum >= MAX_CONCURRENT_FILE_PIPES) {
        return -3;
    }

    assert(temp_filenum <= UINT8_MAX);
    uint8_t file_number = temp_filenum;

    // We're always receiving at this point.
    struct File_Transfers *ft = &m->friendlist[friendnumber].file_receiving[file_number];

    if (ft->status == FILESTATUS_NONE) {
        return -3;
    }

    if (ft->status != FILESTATUS_NOT_ACCEPTED) {
        return -5;
    }

    if (position >= ft->size) {
        return -6;
    }

    uint8_t sending_pos[sizeof(uint64_t)];
    net_pack_u64(sending_pos, position);

    if (send_file_control_packet(m, friendnumber, 1, file_number, FILECONTROL_SEEK, sending_pos,
                                 sizeof(sending_pos))) {
        ft->transferred = position;
    } else {
        return -8;
    }

    return 0;
}

/* return packet number on success.
 * return -1 on failure.
 */
static int64_t send_file_data_packet(const Messenger *m, int32_t friendnumber, uint8_t filenumber, const uint8_t *data,
                                     uint16_t length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    VLA(uint8_t, packet, 2 + length);
    packet[0] = PACKET_ID_FILE_DATA;
    packet[1] = filenumber;

    if (length) {
        memcpy(packet + 2, data, length);
    }

    return write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                             m->friendlist[friendnumber].friendcon_id), packet, SIZEOF_VLA(packet), 1);
}

#define MAX_FILE_DATA_SIZE (MAX_CRYPTO_DATA_SIZE - 2)
#define MIN_SLOTS_FREE (CRYPTO_MIN_QUEUE_LENGTH / 4)
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
              uint16_t length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return -2;
    }

    if (filenumber >= MAX_CONCURRENT_FILE_PIPES) {
        return -3;
    }

    struct File_Transfers *ft = &m->friendlist[friendnumber].file_sending[filenumber];

    if (ft->status != FILESTATUS_TRANSFERRING) {
        return -4;
    }

    if (length > MAX_FILE_DATA_SIZE) {
        return -5;
    }

    if (ft->size - ft->transferred < length) {
        return -5;
    }

    if (ft->size != UINT64_MAX && length != MAX_FILE_DATA_SIZE && (ft->transferred + length) != ft->size) {
        return -5;
    }

    if (position != ft->transferred || (ft->requested <= position && ft->size != 0)) {
        return -7;
    }

    /* Prevent file sending from filling up the entire buffer preventing messages from being sent.
     * TODO(irungentoo): remove */
    if (crypto_num_free_sendqueue_slots(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                                        m->friendlist[friendnumber].friendcon_id)) < MIN_SLOTS_FREE) {
        return -6;
    }

    int64_t ret = send_file_data_packet(m, friendnumber, filenumber, data, length);

    if (ret != -1) {
        // TODO(irungentoo): record packet ids to check if other received complete file.
        ft->transferred += length;

        if (length != MAX_FILE_DATA_SIZE || ft->size == ft->transferred) {
            ft->status = FILESTATUS_FINISHED;
            ft->last_packet_number = ret;
        }

        return 0;
    }

    return -6;
}

/**
 * Iterate over all file transfers and request chunks (from the client) for each
 * of them.
 *
 * The free_slots parameter is updated by this function.
 *
 * @param m Our messenger object.
 * @param friendnumber The friend we're sending files to.
 * @param userdata The client userdata to pass along to chunk request callbacks.
 * @param free_slots A pointer to the number of free send queue slots in the
 *   crypto connection.
 * @return true if there's still work to do, false otherwise.
 *
 */
static bool do_all_filetransfers(Messenger *m, int32_t friendnumber, void *userdata, uint32_t *free_slots)
{
    Friend *const friendcon = &m->friendlist[friendnumber];

    // Iterate over file transfers as long as we're sending files
    for (uint32_t i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (friendcon->num_sending_files == 0) {
            // no active file transfers anymore
            return false;
        }

        if (*free_slots == 0) {
            // send buffer full enough
            return false;
        }

        if (max_speed_reached(m->net_crypto, friend_connection_crypt_connection_id(
                                  m->fr_c, friendcon->friendcon_id))) {
            LOGGER_TRACE(m->log, "Maximum connection speed reached");
            // connection doesn't support any more data
            return false;
        }

        struct File_Transfers *const ft = &friendcon->file_sending[i];

        // If the file transfer is complete, we request a chunk of size 0.
        if (ft->status == FILESTATUS_FINISHED && friend_received_packet(m, friendnumber, ft->last_packet_number) == 0) {
            if (m->file_reqchunk) {
                m->file_reqchunk(m, friendnumber, i, ft->transferred, 0, userdata);
            }

            // Now it's inactive, we're no longer sending this.
            ft->status = FILESTATUS_NONE;
            --friendcon->num_sending_files;
        }

        if (ft->status == FILESTATUS_TRANSFERRING && ft->paused == FILE_PAUSE_NOT) {
            if (ft->size == 0) {
                /* Send 0 data to friend if file is 0 length. */
                file_data(m, friendnumber, i, 0, nullptr, 0);
                continue;
            }

            if (ft->size == ft->requested) {
                // This file transfer is done.
                continue;
            }

            const uint16_t length = min_u64(ft->size - ft->requested, MAX_FILE_DATA_SIZE);
            const uint64_t position = ft->requested;
            ft->requested += length;

            if (m->file_reqchunk) {
                m->file_reqchunk(m, friendnumber, i, position, length, userdata);
            }

            // The allocated slot is no longer free.
            --*free_slots;
        }
    }

    return true;
}

static void do_reqchunk_filecb(Messenger *m, int32_t friendnumber, void *userdata)
{
    // We're not currently doing any file transfers.
    if (m->friendlist[friendnumber].num_sending_files == 0) {
        return;
    }

    // The number of packet slots left in the sendbuffer.
    // This is a per friend count (CRYPTO_PACKET_BUFFER_SIZE).
    uint32_t free_slots = crypto_num_free_sendqueue_slots(
                              m->net_crypto,
                              friend_connection_crypt_connection_id(
                                  m->fr_c,
                                  m->friendlist[friendnumber].friendcon_id));

    // We keep MIN_SLOTS_FREE slots free for other packets, otherwise file
    // transfers might block other traffic for a long time.
    free_slots = max_s32(0, (int32_t)free_slots - MIN_SLOTS_FREE);

    // Maximum number of outer loops below. If the client doesn't send file
    // chunks from within the chunk request callback handler, we never realise
    // that the file transfer has finished and may end up in an infinite loop.
    //
    // Request up to that number of chunks per file from the client
    const uint32_t max_ft_loops = 16;

    for (uint32_t i = 0; i < max_ft_loops; ++i) {
        if (!do_all_filetransfers(m, friendnumber, userdata, &free_slots)) {
            break;
        }

        if (free_slots == 0) {
            // stop when the buffer is full enough
            break;
        }
    }
}


/* Run this when the friend disconnects.
 *  Kill all current file transfers.
 */
static void break_files(const Messenger *m, int32_t friendnumber)
{
    // TODO(irungentoo): Inform the client which file transfers get killed with a callback?
    for (uint32_t i = 0; i < MAX_CONCURRENT_FILE_PIPES; ++i) {
        if (m->friendlist[friendnumber].file_sending[i].status != FILESTATUS_NONE) {
            m->friendlist[friendnumber].file_sending[i].status = FILESTATUS_NONE;
        }

        if (m->friendlist[friendnumber].file_receiving[i].status != FILESTATUS_NONE) {
            m->friendlist[friendnumber].file_receiving[i].status = FILESTATUS_NONE;
        }
    }
}

static struct File_Transfers *get_file_transfer(uint8_t receive_send, uint8_t filenumber,
        uint32_t *real_filenumber, Friend *sender)
{
    struct File_Transfers *ft;

    if (receive_send == 0) {
        *real_filenumber = (filenumber + 1) << 16;
        ft = &sender->file_receiving[filenumber];
    } else {
        *real_filenumber = filenumber;
        ft = &sender->file_sending[filenumber];
    }

    if (ft->status == FILESTATUS_NONE) {
        return nullptr;
    }

    return ft;
}

/* return -1 on failure, 0 on success.
 */
static int handle_filecontrol(Messenger *m, int32_t friendnumber, uint8_t receive_send, uint8_t filenumber,
                              uint8_t control_type, const uint8_t *data, uint16_t length, void *userdata)
{
    if (receive_send > 1) {
        LOGGER_DEBUG(m->log, "file control (friend %d, file %d): receive_send value is invalid (should be 0 or 1): %d",
                     friendnumber, filenumber, receive_send);
        return -1;
    }

    uint32_t real_filenumber;
    struct File_Transfers *ft = get_file_transfer(receive_send, filenumber, &real_filenumber, &m->friendlist[friendnumber]);

    if (ft == nullptr) {
        LOGGER_DEBUG(m->log, "file control (friend %d, file %d): file transfer does not exist; telling the other to kill it",
                     friendnumber, filenumber);
        send_file_control_packet(m, friendnumber, !receive_send, filenumber, FILECONTROL_KILL, nullptr, 0);
        return -1;
    }

    switch (control_type) {
        case FILECONTROL_ACCEPT: {
            if (receive_send && ft->status == FILESTATUS_NOT_ACCEPTED) {
                ft->status = FILESTATUS_TRANSFERRING;
            } else {
                if (ft->paused & FILE_PAUSE_OTHER) {
                    ft->paused ^= FILE_PAUSE_OTHER;
                } else {
                    LOGGER_DEBUG(m->log, "file control (friend %d, file %d): friend told us to resume file transfer that wasn't paused",
                                 friendnumber, filenumber);
                    return -1;
                }
            }

            if (m->file_filecontrol) {
                m->file_filecontrol(m, friendnumber, real_filenumber, control_type, userdata);
            }

            return 0;
        }

        case FILECONTROL_PAUSE: {
            if ((ft->paused & FILE_PAUSE_OTHER) || ft->status != FILESTATUS_TRANSFERRING) {
                LOGGER_DEBUG(m->log, "file control (friend %d, file %d): friend told us to pause file transfer that is already paused",
                             friendnumber, filenumber);
                return -1;
            }

            ft->paused |= FILE_PAUSE_OTHER;

            if (m->file_filecontrol) {
                m->file_filecontrol(m, friendnumber, real_filenumber, control_type, userdata);
            }

            return 0;
        }

        case FILECONTROL_KILL: {
            if (m->file_filecontrol) {
                m->file_filecontrol(m, friendnumber, real_filenumber, control_type, userdata);
            }

            ft->status = FILESTATUS_NONE;

            if (receive_send) {
                --m->friendlist[friendnumber].num_sending_files;
            }

            return 0;
        }

        case FILECONTROL_SEEK: {
            uint64_t position;

            if (length != sizeof(position)) {
                LOGGER_DEBUG(m->log, "file control (friend %d, file %d): expected payload of length %d, but got %d",
                             friendnumber, filenumber, (uint32_t)sizeof(position), length);
                return -1;
            }

            /* seek can only be sent by the receiver to seek before resuming broken transfers. */
            if (ft->status != FILESTATUS_NOT_ACCEPTED || !receive_send) {
                LOGGER_DEBUG(m->log,
                             "file control (friend %d, file %d): seek was either sent by a sender or by the receiver after accepting",
                             friendnumber, filenumber);
                return -1;
            }

            net_unpack_u64(data, &position);

            if (position >= ft->size) {
                LOGGER_DEBUG(m->log,
                             "file control (friend %d, file %d): seek position %ld exceeds file size %ld",
                             friendnumber, filenumber, (unsigned long)position, (unsigned long)ft->size);
                return -1;
            }

            ft->requested = position;
            ft->transferred = position;
            return 0;
        }

        default: {
            LOGGER_DEBUG(m->log, "file control (friend %d, file %d): invalid file control: %d",
                         friendnumber, filenumber, control_type);
            return -1;
        }
    }
}

/* Set the callback for msi packets.
 */
void m_callback_msi_packet(Messenger *m, m_msi_packet_cb *function, void *userdata)
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

static int m_handle_lossy_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length,
                                 void *userdata)
{
    Messenger *m = (Messenger *)object;

    if (!friend_is_valid(m, friend_num)) {
        return 1;
    }

    if (packet[0] <= PACKET_ID_RANGE_LOSSY_AV_END) {
        const RTP_Packet_Handler *const ph =
            &m->friendlist[friend_num].lossy_rtp_packethandlers[packet[0] % PACKET_ID_RANGE_LOSSY_AV_SIZE];

        if (ph->function) {
            return ph->function(m, friend_num, packet, length, ph->object);
        }

        return 1;
    }

    if (m->lossy_packethandler) {
        m->lossy_packethandler(m, friend_num, packet[0], packet, length, userdata);
    }

    return 1;
}

void custom_lossy_packet_registerhandler(Messenger *m, m_friend_lossy_packet_cb *lossy_packethandler)
{
    m->lossy_packethandler = lossy_packethandler;
}

int m_callback_rtp_packet(Messenger *m, int32_t friendnumber, uint8_t byte, m_lossy_rtp_packet_cb *function,
                          void *object)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (byte < PACKET_ID_RANGE_LOSSY_AV_START || byte > PACKET_ID_RANGE_LOSSY_AV_END) {
        return -1;
    }

    m->friendlist[friendnumber].lossy_rtp_packethandlers[byte % PACKET_ID_RANGE_LOSSY_AV_SIZE].function = function;
    m->friendlist[friendnumber].lossy_rtp_packethandlers[byte % PACKET_ID_RANGE_LOSSY_AV_SIZE].object = object;
    return 0;
}


/* TODO(oxij): this name is confusing, because this function sends both av and custom lossy packets.
 * Meanwhile, m_handle_lossy_packet routes custom packets to custom_lossy_packet_registerhandler
 * as you would expect from its name.
 *
 * I.e. custom_lossy_packet_registerhandler's "custom lossy packet" and this "custom lossy packet"
 * are not the same set of packets.
 */
int m_send_custom_lossy_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        return -2;
    }

    // TODO(oxij): send_lossy_cryptpacket makes this check already, similarly for other similar places
    if (data[0] < PACKET_ID_RANGE_LOSSY_START || data[0] > PACKET_ID_RANGE_LOSSY_END) {
        return -3;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return -4;
    }

    if (send_lossy_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                               m->friendlist[friendnumber].friendcon_id), data, length) == -1) {
        return -5;
    }

    return 0;
}

static int handle_custom_lossless_packet(void *object, int friend_num, const uint8_t *packet, uint16_t length,
        void *userdata)
{
    Messenger *m = (Messenger *)object;

    if (!friend_is_valid(m, friend_num)) {
        return -1;
    }

    if (packet[0] < PACKET_ID_RANGE_LOSSLESS_CUSTOM_START || packet[0] > PACKET_ID_RANGE_LOSSLESS_CUSTOM_END) {
        return -1;
    }

    if (m->lossless_packethandler) {
        m->lossless_packethandler(m, friend_num, packet[0], packet, length, userdata);
    }

    return 1;
}

void custom_lossless_packet_registerhandler(Messenger *m, m_friend_lossless_packet_cb *lossless_packethandler)
{
    m->lossless_packethandler = lossless_packethandler;
}

int send_custom_lossless_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length)
{
    if (!friend_is_valid(m, friendnumber)) {
        return -1;
    }

    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE) {
        return -2;
    }

    if ((data[0] < PACKET_ID_RANGE_LOSSLESS_CUSTOM_START || data[0] > PACKET_ID_RANGE_LOSSLESS_CUSTOM_END)
            && data[0] != PACKET_ID_MSI) {
        return -3;
    }

    if (m->friendlist[friendnumber].status != FRIEND_ONLINE) {
        return -4;
    }

    if (write_cryptpacket(m->net_crypto, friend_connection_crypt_connection_id(m->fr_c,
                          m->friendlist[friendnumber].friendcon_id), data, length, 1) == -1) {
        return -5;
    }

    return 0;
}

/* Function to filter out some friend requests*/
static int friend_already_added(const uint8_t *real_pk, void *data)
{
    const Messenger *m = (const Messenger *)data;

    if (getfriend_id(m, real_pk) == -1) {
        return 0;
    }

    return -1;
}

/* Run this at startup. */
Messenger *new_messenger(Mono_Time *mono_time, Messenger_Options *options, unsigned int *error)
{
    if (!options) {
        return nullptr;
    }

    if (error) {
        *error = MESSENGER_ERROR_OTHER;
    }

    Messenger *m = (Messenger *)calloc(1, sizeof(Messenger));

    if (!m) {
        return nullptr;
    }

    m->mono_time = mono_time;

    m->fr = friendreq_new();

    if (!m->fr) {
        free(m);
        return nullptr;
    }

    m->log = logger_new();

    if (m->log == nullptr) {
        friendreq_kill(m->fr);
        free(m);
        return nullptr;
    }

    logger_callback_log(m->log, options->log_callback, options->log_context, options->log_user_data);

    unsigned int net_err = 0;

    if (!options->udp_disabled && options->proxy_info.proxy_type != TCP_PROXY_NONE) {
        // We don't currently support UDP over proxy.
        LOGGER_WARNING(m->log, "UDP enabled and proxy set: disabling UDP");
        options->udp_disabled = true;
    }

    if (options->udp_disabled) {
        m->net = new_networking_no_udp(m->log);
    } else {
        IP ip;
        ip_init(&ip, options->ipv6enabled);
        m->net = new_networking_ex(m->log, ip, options->port_range[0], options->port_range[1], &net_err);
    }

    if (m->net == nullptr) {
        friendreq_kill(m->fr);
        logger_kill(m->log);
        free(m);

        if (error && net_err == 1) {
            *error = MESSENGER_ERROR_PORT;
        }

        return nullptr;
    }

    m->dht = new_dht(m->log, m->mono_time, m->net, options->hole_punching_enabled);

    if (m->dht == nullptr) {
        kill_networking(m->net);
        friendreq_kill(m->fr);
        logger_kill(m->log);
        free(m);
        return nullptr;
    }

    m->net_crypto = new_net_crypto(m->log, m->mono_time, m->dht, &options->proxy_info);

    if (m->net_crypto == nullptr) {
        kill_dht(m->dht);
        kill_networking(m->net);
        friendreq_kill(m->fr);
        logger_kill(m->log);
        free(m);
        return nullptr;
    }

    m->onion = new_onion(m->mono_time, m->dht);
    m->onion_a = new_onion_announce(m->mono_time, m->dht);
    m->onion_c =  new_onion_client(m->log, m->mono_time, m->net_crypto);
    m->fr_c = new_friend_connections(m->log, m->mono_time, m->onion_c, options->local_discovery_enabled);

    if (!(m->onion && m->onion_a && m->onion_c && m->fr_c)) {
        kill_friend_connections(m->fr_c);
        kill_onion(m->onion);
        kill_onion_announce(m->onion_a);
        kill_onion_client(m->onion_c);
        kill_net_crypto(m->net_crypto);
        kill_dht(m->dht);
        kill_networking(m->net);
        friendreq_kill(m->fr);
        logger_kill(m->log);
        free(m);
        return nullptr;
    }

    if (options->tcp_server_port) {
        m->tcp_server = new_TCP_server(m->log, options->ipv6enabled, 1, &options->tcp_server_port,
                                       dht_get_self_secret_key(m->dht), m->onion);

        if (m->tcp_server == nullptr) {
            kill_friend_connections(m->fr_c);
            kill_onion(m->onion);
            kill_onion_announce(m->onion_a);
            kill_onion_client(m->onion_c);
            kill_net_crypto(m->net_crypto);
            kill_dht(m->dht);
            kill_networking(m->net);
            friendreq_kill(m->fr);
            logger_kill(m->log);
            free(m);

            if (error) {
                *error = MESSENGER_ERROR_TCP_SERVER;
            }

            return nullptr;
        }
    }

    m->options = *options;
    friendreq_init(m->fr, m->fr_c);
    set_nospam(m->fr, random_u32());
    set_filter_function(m->fr, &friend_already_added, m);

    m->lastdump = 0;

    m_register_default_plugins(m);

    if (error) {
        *error = MESSENGER_ERROR_NONE;
    }

    return m;
}

/* Run this before closing shop. */
void kill_messenger(Messenger *m)
{
    if (!m) {
        return;
    }

    uint32_t i;

    if (m->tcp_server) {
        kill_TCP_server(m->tcp_server);
    }

    kill_friend_connections(m->fr_c);
    kill_onion(m->onion);
    kill_onion_announce(m->onion_a);
    kill_onion_client(m->onion_c);
    kill_net_crypto(m->net_crypto);
    kill_dht(m->dht);
    kill_networking(m->net);

    for (i = 0; i < m->numfriends; ++i) {
        clear_receipts(m, i);
    }

    logger_kill(m->log);
    free(m->friendlist);
    friendreq_kill(m->fr);

    free(m->options.state_plugins);
    free(m);
}

/* Check for and handle a timed-out friend request. If the request has
 * timed-out then the friend status is set back to FRIEND_ADDED.
 *   i: friendlist index of the timed-out friend
 *   t: time
 */
static void check_friend_request_timed_out(Messenger *m, uint32_t i, uint64_t t, void *userdata)
{
    Friend *f = &m->friendlist[i];

    if (f->friendrequest_lastsent + f->friendrequest_timeout < t) {
        set_friend_status(m, i, FRIEND_ADDED, userdata);
        /* Double the default timeout every time if friendrequest is assumed
         * to have been sent unsuccessfully.
         */
        f->friendrequest_timeout *= 2;
    }
}

static int m_handle_status(void *object, int i, uint8_t status, void *userdata)
{
    Messenger *m = (Messenger *)object;

    if (status) { /* Went online. */
        send_online_packet(m, i);
    } else { /* Went offline. */
        if (m->friendlist[i].status == FRIEND_ONLINE) {
            set_friend_status(m, i, FRIEND_CONFIRMED, userdata);
        }
    }

    return 0;
}

static int m_handle_packet(void *object, int i, const uint8_t *temp, uint16_t len, void *userdata)
{
    if (len == 0) {
        return -1;
    }

    Messenger *m = (Messenger *)object;
    uint8_t packet_id = temp[0];
    const uint8_t *data = temp + 1;
    uint32_t data_length = len - 1;

    if (m->friendlist[i].status != FRIEND_ONLINE) {
        if (packet_id == PACKET_ID_ONLINE && len == 1) {
            set_friend_status(m, i, FRIEND_ONLINE, userdata);
            send_online_packet(m, i);
        } else {
            return -1;
        }
    }

    switch (packet_id) {
        case PACKET_ID_OFFLINE: {
            if (data_length != 0) {
                break;
            }

            set_friend_status(m, i, FRIEND_CONFIRMED, userdata);
            break;
        }

        case PACKET_ID_NICKNAME: {
            if (data_length > MAX_NAME_LENGTH) {
                break;
            }

            /* Make sure the NULL terminator is present. */
            VLA(uint8_t, data_terminated, data_length + 1);
            memcpy(data_terminated, data, data_length);
            data_terminated[data_length] = 0;

            /* inform of namechange before we overwrite the old name */
            if (m->friend_namechange) {
                m->friend_namechange(m, i, data_terminated, data_length, userdata);
            }

            memcpy(m->friendlist[i].name, data_terminated, data_length);
            m->friendlist[i].name_length = data_length;

            break;
        }

        case PACKET_ID_STATUSMESSAGE: {
            if (data_length > MAX_STATUSMESSAGE_LENGTH) {
                break;
            }

            /* Make sure the NULL terminator is present. */
            VLA(uint8_t, data_terminated, data_length + 1);
            memcpy(data_terminated, data, data_length);
            data_terminated[data_length] = 0;

            if (m->friend_statusmessagechange) {
                m->friend_statusmessagechange(m, i, data_terminated, data_length, userdata);
            }

            set_friend_statusmessage(m, i, data_terminated, data_length);
            break;
        }

        case PACKET_ID_USERSTATUS: {
            if (data_length != 1) {
                break;
            }

            Userstatus status = (Userstatus)data[0];

            if (status >= USERSTATUS_INVALID) {
                break;
            }

            if (m->friend_userstatuschange) {
                m->friend_userstatuschange(m, i, status, userdata);
            }

            set_friend_userstatus(m, i, status);
            break;
        }

        case PACKET_ID_TYPING: {
            if (data_length != 1) {
                break;
            }

            bool typing = !!data[0];

            set_friend_typing(m, i, typing);

            if (m->friend_typingchange) {
                m->friend_typingchange(m, i, typing, userdata);
            }

            break;
        }

        case PACKET_ID_MESSAGE: // fall-through
        case PACKET_ID_ACTION: {
            if (data_length == 0) {
                break;
            }

            const uint8_t *message = data;
            uint16_t message_length = data_length;

            /* Make sure the NULL terminator is present. */
            VLA(uint8_t, message_terminated, message_length + 1);
            memcpy(message_terminated, message, message_length);
            message_terminated[message_length] = 0;
            uint8_t type = packet_id - PACKET_ID_MESSAGE;

            if (m->friend_message) {
                (*m->friend_message)(m, i, type, message_terminated, message_length, userdata);
            }

            break;
        }

        case PACKET_ID_INVITE_CONFERENCE: {
            if (data_length == 0) {
                break;
            }

            if (m->conference_invite) {
                (*m->conference_invite)(m, i, data, data_length, userdata);
            }

            break;
        }

        case PACKET_ID_FILE_SENDREQUEST: {
            const unsigned int head_length = 1 + sizeof(uint32_t) + sizeof(uint64_t) + FILE_ID_LENGTH;

            if (data_length < head_length) {
                break;
            }

            uint8_t filenumber = data[0];

#if UINT8_MAX >= MAX_CONCURRENT_FILE_PIPES

            if (filenumber >= MAX_CONCURRENT_FILE_PIPES) {
                break;
            }

#endif

            uint64_t filesize;
            uint32_t file_type;
            uint16_t filename_length = data_length - head_length;

            if (filename_length > MAX_FILENAME_LENGTH) {
                break;
            }

            memcpy(&file_type, data + 1, sizeof(file_type));
            file_type = net_ntohl(file_type);

            net_unpack_u64(data + 1 + sizeof(uint32_t), &filesize);
            struct File_Transfers *ft = &m->friendlist[i].file_receiving[filenumber];

            if (ft->status != FILESTATUS_NONE) {
                break;
            }

            ft->status = FILESTATUS_NOT_ACCEPTED;
            ft->size = filesize;
            ft->transferred = 0;
            ft->paused = FILE_PAUSE_NOT;
            memcpy(ft->id, data + 1 + sizeof(uint32_t) + sizeof(uint64_t), FILE_ID_LENGTH);

            VLA(uint8_t, filename_terminated, filename_length + 1);
            uint8_t *filename = nullptr;

            if (filename_length) {
                /* Force NULL terminate file name. */
                memcpy(filename_terminated, data + head_length, filename_length);
                filename_terminated[filename_length] = 0;
                filename = filename_terminated;
            }

            uint32_t real_filenumber = filenumber;
            real_filenumber += 1;
            real_filenumber <<= 16;

            if (m->file_sendrequest) {
                (*m->file_sendrequest)(m, i, real_filenumber, file_type, filesize, filename, filename_length,
                                       userdata);
            }

            break;
        }

        case PACKET_ID_FILE_CONTROL: {
            if (data_length < 3) {
                break;
            }

            uint8_t send_receive = data[0];
            uint8_t filenumber = data[1];
            uint8_t control_type = data[2];

#if UINT8_MAX >= MAX_CONCURRENT_FILE_PIPES

            if (filenumber >= MAX_CONCURRENT_FILE_PIPES) {
                break;
            }

#endif

            if (handle_filecontrol(m, i, send_receive, filenumber, control_type, data + 3, data_length - 3, userdata) == -1) {
                // TODO(iphydf): Do something different here? Right now, this
                // check is pointless.
                break;
            }

            break;
        }

        case PACKET_ID_FILE_DATA: {
            if (data_length < 1) {
                break;
            }

            uint8_t filenumber = data[0];

#if UINT8_MAX >= MAX_CONCURRENT_FILE_PIPES

            if (filenumber >= MAX_CONCURRENT_FILE_PIPES) {
                break;
            }

#endif

            struct File_Transfers *ft = &m->friendlist[i].file_receiving[filenumber];

            if (ft->status != FILESTATUS_TRANSFERRING) {
                break;
            }

            uint64_t position = ft->transferred;
            uint32_t real_filenumber = filenumber;
            real_filenumber += 1;
            real_filenumber <<= 16;
            uint16_t file_data_length = (data_length - 1);
            const uint8_t *file_data;

            if (file_data_length == 0) {
                file_data = nullptr;
            } else {
                file_data = data + 1;
            }

            /* Prevent more data than the filesize from being passed to clients. */
            if ((ft->transferred + file_data_length) > ft->size) {
                file_data_length = ft->size - ft->transferred;
            }

            if (m->file_filedata) {
                (*m->file_filedata)(m, i, real_filenumber, position, file_data, file_data_length, userdata);
            }

            ft->transferred += file_data_length;

            if (file_data_length && (ft->transferred >= ft->size || file_data_length != MAX_FILE_DATA_SIZE)) {
                file_data_length = 0;
                file_data = nullptr;
                position = ft->transferred;

                /* Full file received. */
                if (m->file_filedata) {
                    (*m->file_filedata)(m, i, real_filenumber, position, file_data, file_data_length, userdata);
                }
            }

            /* Data is zero, filetransfer is over. */
            if (file_data_length == 0) {
                ft->status = FILESTATUS_NONE;
            }

            break;
        }

        case PACKET_ID_MSI: {
            if (data_length == 0) {
                break;
            }

            if (m->msi_packet) {
                (*m->msi_packet)(m, i, data, data_length, m->msi_packet_userdata);
            }

            break;
        }

        default: {
            handle_custom_lossless_packet(object, i, temp, len, userdata);
            break;
        }
    }

    return 0;
}

static void do_friends(Messenger *m, void *userdata)
{
    uint32_t i;
    uint64_t temp_time = mono_time_get(m->mono_time);

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status == FRIEND_ADDED) {
            int fr = send_friend_request_packet(m->fr_c, m->friendlist[i].friendcon_id, m->friendlist[i].friendrequest_nospam,
                                                m->friendlist[i].info,
                                                m->friendlist[i].info_size);

            if (fr >= 0) {
                set_friend_status(m, i, FRIEND_REQUESTED, userdata);
                m->friendlist[i].friendrequest_lastsent = temp_time;
            }
        }

        if (m->friendlist[i].status == FRIEND_REQUESTED
                || m->friendlist[i].status == FRIEND_CONFIRMED) { /* friend is not online. */
            if (m->friendlist[i].status == FRIEND_REQUESTED) {
                /* If we didn't connect to friend after successfully sending him a friend request the request is deemed
                 * unsuccessful so we set the status back to FRIEND_ADDED and try again.
                 */
                check_friend_request_timed_out(m, i, temp_time, userdata);
            }
        }

        if (m->friendlist[i].status == FRIEND_ONLINE) { /* friend is online. */
            if (m->friendlist[i].name_sent == 0) {
                if (m_sendname(m, i, m->name, m->name_length)) {
                    m->friendlist[i].name_sent = 1;
                }
            }

            if (m->friendlist[i].statusmessage_sent == 0) {
                if (send_statusmessage(m, i, m->statusmessage, m->statusmessage_length)) {
                    m->friendlist[i].statusmessage_sent = 1;
                }
            }

            if (m->friendlist[i].userstatus_sent == 0) {
                if (send_userstatus(m, i, m->userstatus)) {
                    m->friendlist[i].userstatus_sent = 1;
                }
            }

            if (m->friendlist[i].user_istyping_sent == 0) {
                if (send_user_istyping(m, i, m->friendlist[i].user_istyping)) {
                    m->friendlist[i].user_istyping_sent = 1;
                }
            }

            check_friend_tcp_udp(m, i, userdata);
            do_receipts(m, i, userdata);
            do_reqchunk_filecb(m, i, userdata);

            m->friendlist[i].last_seen_time = (uint64_t) time(nullptr);
        }
    }
}

static void connection_status_callback(Messenger *m, void *userdata)
{
    unsigned int conn_status = onion_connection_status(m->onion_c);

    if (conn_status != m->last_connection_status) {
        if (m->core_connection_change) {
            (*m->core_connection_change)(m, conn_status, userdata);
        }

        m->last_connection_status = conn_status;
    }
}


#define DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS 60UL

#define IDSTRING_LEN (CRYPTO_PUBLIC_KEY_SIZE * 2 + 1)
/* id_str should be of length at least IDSTRING_LEN */
static char *id_to_string(const uint8_t *pk, char *id_str, size_t length)
{
    if (length < IDSTRING_LEN) {
        snprintf(id_str, length, "Bad buf length");
        return id_str;
    }

    for (uint32_t i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        sprintf(&id_str[i * 2], "%02X", pk[i]);
    }

    id_str[CRYPTO_PUBLIC_KEY_SIZE * 2] = 0;
    return id_str;
}

/* Minimum messenger run interval in ms
 * TODO(mannol): A/V */
#define MIN_RUN_INTERVAL 50

/* Return the time in milliseconds before do_messenger() should be called again
 * for optimal performance.
 *
 * returns time (in ms) before the next do_messenger() needs to be run on success.
 */
uint32_t messenger_run_interval(const Messenger *m)
{
    uint32_t crypto_interval = crypto_run_interval(m->net_crypto);

    if (crypto_interval > MIN_RUN_INTERVAL) {
        return MIN_RUN_INTERVAL;
    }

    return crypto_interval;
}

/* The main loop that needs to be run at least 20 times per second. */
void do_messenger(Messenger *m, void *userdata)
{
    // Add the TCP relays, but only if this is the first time calling do_messenger
    if (!m->has_added_relays) {
        m->has_added_relays = true;

        for (uint16_t i = 0; i < m->num_loaded_relays; ++i) {
            add_tcp_relay(m->net_crypto, m->loaded_relays[i].ip_port, m->loaded_relays[i].public_key);
        }

        m->num_loaded_relays = 0;

        if (m->tcp_server) {
            /* Add self tcp server. */
            IP_Port local_ip_port;
            local_ip_port.port = m->options.tcp_server_port;
            local_ip_port.ip.family = net_family_ipv4;
            local_ip_port.ip.ip.v4 = get_ip4_loopback();
            add_tcp_relay(m->net_crypto, local_ip_port,
                          tcp_server_public_key(m->tcp_server));
        }
    }

    if (!m->options.udp_disabled) {
        networking_poll(m->net, userdata);
        do_dht(m->dht);
    }

    if (m->tcp_server) {
        do_TCP_server(m->tcp_server, m->mono_time);
    }

    do_net_crypto(m->net_crypto, userdata);
    do_onion_client(m->onion_c);
    do_friend_connections(m->fr_c, userdata);
    do_friends(m, userdata);
    connection_status_callback(m, userdata);

    if (mono_time_get(m->mono_time) > m->lastdump + DUMPING_CLIENTS_FRIENDS_EVERY_N_SECONDS) {
        m->lastdump = mono_time_get(m->mono_time);
        uint32_t last_pinged;

        for (uint32_t client = 0; client < LCLIENT_LIST; ++client) {
            const Client_data *cptr = dht_get_close_client(m->dht, client);
            const IPPTsPng *const assocs[] = { &cptr->assoc4, &cptr->assoc6, nullptr };

            for (const IPPTsPng * const *it = assocs; *it; ++it) {
                const IPPTsPng *const assoc = *it;

                if (ip_isset(&assoc->ip_port.ip)) {
                    last_pinged = m->lastdump - assoc->last_pinged;

                    if (last_pinged > 999) {
                        last_pinged = 999;
                    }

                    char ip_str[IP_NTOA_LEN];
                    char id_str[IDSTRING_LEN];
                    LOGGER_TRACE(m->log, "C[%2u] %s:%u [%3u] %s",
                                 client, ip_ntoa(&assoc->ip_port.ip, ip_str, sizeof(ip_str)),
                                 net_ntohs(assoc->ip_port.port), last_pinged,
                                 id_to_string(cptr->public_key, id_str, sizeof(id_str)));
                }
            }
        }


        /* dht contains additional "friends" (requests) */
        uint32_t num_dhtfriends = dht_get_num_friends(m->dht);
        VLA(int32_t, m2dht, num_dhtfriends);
        VLA(int32_t, dht2m, num_dhtfriends);

        for (uint32_t friend_idx = 0; friend_idx < num_dhtfriends; ++friend_idx) {
            m2dht[friend_idx] = -1;
            dht2m[friend_idx] = -1;

            if (friend_idx >= m->numfriends) {
                continue;
            }

            for (uint32_t dhtfriend = 0; dhtfriend < dht_get_num_friends(m->dht); ++dhtfriend) {
                if (id_equal(m->friendlist[friend_idx].real_pk, dht_get_friend_public_key(m->dht, dhtfriend))) {
                    m2dht[friend_idx] = dhtfriend;
                    break;
                }
            }
        }

        for (uint32_t friend_idx = 0; friend_idx < num_dhtfriends; ++friend_idx) {
            if (m2dht[friend_idx] >= 0) {
                dht2m[m2dht[friend_idx]] = friend_idx;
            }
        }

        if (m->numfriends != dht_get_num_friends(m->dht)) {
            LOGGER_TRACE(m->log, "Friend num in DHT %u != friend num in msger %u", dht_get_num_friends(m->dht), m->numfriends);
        }

        Friend *msgfptr;
        DHT_Friend *dhtfptr;

        for (uint32_t friend_idx = 0; friend_idx < num_dhtfriends; ++friend_idx) {
            if (dht2m[friend_idx] >= 0) {
                msgfptr = &m->friendlist[dht2m[friend_idx]];
            } else {
                msgfptr = nullptr;
            }

            dhtfptr = dht_get_friend(m->dht, friend_idx);

            if (msgfptr) {
                char id_str[IDSTRING_LEN];
                LOGGER_TRACE(m->log, "F[%2u:%2u] <%s> %s",
                             dht2m[friend_idx], friend_idx, msgfptr->name,
                             id_to_string(msgfptr->real_pk, id_str, sizeof(id_str)));
            } else {
                char id_str[IDSTRING_LEN];
                LOGGER_TRACE(m->log, "F[--:%2u] %s", friend_idx,
                             id_to_string(dht_friend_public_key(dhtfptr), id_str, sizeof(id_str)));
            }

            for (uint32_t client = 0; client < MAX_FRIEND_CLIENTS; ++client) {
                const Client_data *cptr = dht_friend_client(dhtfptr, client);
                const IPPTsPng *const assocs[] = {&cptr->assoc4, &cptr->assoc6};

                for (size_t a = 0; a < sizeof(assocs) / sizeof(assocs[0]); ++a) {
                    const IPPTsPng *const assoc = assocs[a];

                    if (ip_isset(&assoc->ip_port.ip)) {
                        last_pinged = m->lastdump - assoc->last_pinged;

                        if (last_pinged > 999) {
                            last_pinged = 999;
                        }

                        char ip_str[IP_NTOA_LEN];
                        char id_str[IDSTRING_LEN];
                        LOGGER_TRACE(m->log, "F[%2u] => C[%2u] %s:%u [%3u] %s",
                                     friend_idx, client, ip_ntoa(&assoc->ip_port.ip, ip_str, sizeof(ip_str)),
                                     net_ntohs(assoc->ip_port.port), last_pinged,
                                     id_to_string(cptr->public_key, id_str, sizeof(id_str)));
                    }
                }
            }
        }
    }
}

/* new messenger format for load/save, more robust and forward compatible */

#define SAVED_FRIEND_REQUEST_SIZE 1024
#define NUM_SAVED_PATH_NODES 8

struct Saved_Friend {
    uint8_t status;
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t info[SAVED_FRIEND_REQUEST_SIZE]; // the data that is sent during the friend requests we do.
    uint16_t info_size; // Length of the info.
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;
    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;
    uint8_t userstatus;
    uint32_t friendrequest_nospam;
    uint8_t last_seen_time[sizeof(uint64_t)];
};

static uint32_t friend_size(void)
{
    uint32_t data = 0;
    const struct Saved_Friend *const temp = nullptr;

#define VALUE_MEMBER(name) do { data += sizeof(temp->name); } while (0)
#define ARRAY_MEMBER(name) do { data += sizeof(temp->name); } while (0)

    // Exactly the same in friend_load, friend_save, and friend_size
    VALUE_MEMBER(status);
    ARRAY_MEMBER(real_pk);
    ARRAY_MEMBER(info);
    ++data; // padding
    VALUE_MEMBER(info_size);
    ARRAY_MEMBER(name);
    VALUE_MEMBER(name_length);
    ARRAY_MEMBER(statusmessage);
    ++data; // padding
    VALUE_MEMBER(statusmessage_length);
    VALUE_MEMBER(userstatus);
    data += 3; // padding
    VALUE_MEMBER(friendrequest_nospam);
    ARRAY_MEMBER(last_seen_time);

#undef VALUE_MEMBER
#undef ARRAY_MEMBER

    return data;
}

static uint8_t *friend_save(const struct Saved_Friend *temp, uint8_t *data)
{
#define VALUE_MEMBER(name) do {                     \
    memcpy(data, &temp->name, sizeof(temp->name));  \
    data += sizeof(temp->name);                     \
} while (0)

#define ARRAY_MEMBER(name) do {                     \
    memcpy(data, temp->name, sizeof(temp->name));   \
    data += sizeof(temp->name);                     \
} while (0)

    // Exactly the same in friend_load, friend_save, and friend_size
    VALUE_MEMBER(status);
    ARRAY_MEMBER(real_pk);
    ARRAY_MEMBER(info);
    ++data; // padding
    VALUE_MEMBER(info_size);
    ARRAY_MEMBER(name);
    VALUE_MEMBER(name_length);
    ARRAY_MEMBER(statusmessage);
    ++data; // padding
    VALUE_MEMBER(statusmessage_length);
    VALUE_MEMBER(userstatus);
    data += 3; // padding
    VALUE_MEMBER(friendrequest_nospam);
    ARRAY_MEMBER(last_seen_time);

#undef VALUE_MEMBER
#undef ARRAY_MEMBER

    return data;
}


static const uint8_t *friend_load(struct Saved_Friend *temp, const uint8_t *data)
{
#define VALUE_MEMBER(name) do {                     \
    memcpy(&temp->name, data, sizeof(temp->name));  \
    data += sizeof(temp->name);                     \
} while (0)

#define ARRAY_MEMBER(name) do {                     \
    memcpy(temp->name, data, sizeof(temp->name));   \
    data += sizeof(temp->name);                     \
} while (0)

    // Exactly the same in friend_load, friend_save, and friend_size
    VALUE_MEMBER(status);
    ARRAY_MEMBER(real_pk);
    ARRAY_MEMBER(info);
    ++data; // padding
    VALUE_MEMBER(info_size);
    ARRAY_MEMBER(name);
    VALUE_MEMBER(name_length);
    ARRAY_MEMBER(statusmessage);
    ++data; // padding
    VALUE_MEMBER(statusmessage_length);
    VALUE_MEMBER(userstatus);
    data += 3; // padding
    VALUE_MEMBER(friendrequest_nospam);
    ARRAY_MEMBER(last_seen_time);

#undef VALUE_MEMBER
#undef ARRAY_MEMBER

    return data;
}


static uint32_t m_state_plugins_size(const Messenger *m)
{
    const uint32_t size32 = sizeof(uint32_t);
    const uint32_t sizesubhead = size32 * 2;

    uint32_t size = 0;

    for (const Messenger_State_Plugin *plugin = m->options.state_plugins;
            plugin != m->options.state_plugins + m->options.state_plugins_length;
            ++plugin) {
        size += sizesubhead + plugin->size(m);
    }

    return size;
}

/*
 * Registers a state plugin with the messenger
 * returns true on success
 * returns false on failure
 */
bool m_register_state_plugin(Messenger *m, State_Type type, m_state_size_cb size_callback,
                             m_state_load_cb load_callback,
                             m_state_save_cb save_callback)
{
    Messenger_State_Plugin *temp = (Messenger_State_Plugin *)realloc(m->options.state_plugins,
                                   sizeof(Messenger_State_Plugin) * (m->options.state_plugins_length + 1));

    if (!temp) {
        return false;
    }

    m->options.state_plugins = temp;
    ++m->options.state_plugins_length;

    const uint8_t index = m->options.state_plugins_length - 1;
    m->options.state_plugins[index].type = type;
    m->options.state_plugins[index].size = size_callback;
    m->options.state_plugins[index].load = load_callback;
    m->options.state_plugins[index].save = save_callback;

    return true;
}

static uint32_t m_plugin_size(const Messenger *m, State_Type type)
{
    for (uint8_t i = 0; i < m->options.state_plugins_length; ++i) {
        const Messenger_State_Plugin plugin = m->options.state_plugins[i];

        if (plugin.type == type) {
            return plugin.size(m);
        }
    }

    LOGGER_ERROR(m->log, "Unknown type encountered: %u", type);

    return UINT32_MAX;
}

/*  return size of the messenger data (for saving) */
uint32_t messenger_size(const Messenger *m)
{
    return m_state_plugins_size(m);
}

/* Save the messenger in data of size messenger_size(). */
uint8_t *messenger_save(const Messenger *m, uint8_t *data)
{
    for (uint8_t i = 0; i < m->options.state_plugins_length; ++i) {
        const Messenger_State_Plugin plugin = m->options.state_plugins[i];
        data = plugin.save(m, data);
    }

    return data;
}

// nospam state plugin
static uint32_t nospam_keys_size(const Messenger *m)
{
    return sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE;
}

static State_Load_Status load_nospam_keys(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length != m_plugin_size(m, STATE_TYPE_NOSPAMKEYS)) {
        return STATE_LOAD_STATUS_ERROR;
    }

    uint32_t nospam;
    lendian_bytes_to_host32(&nospam, data);
    set_nospam(m->fr, nospam);
    load_secret_key(m->net_crypto, data + sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE);

    if (public_key_cmp(data + sizeof(uint32_t), nc_get_self_public_key(m->net_crypto)) != 0) {
        return STATE_LOAD_STATUS_ERROR;
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

static uint8_t *save_nospam_keys(const Messenger *m, uint8_t *data)
{
    const uint32_t len = m_plugin_size(m, STATE_TYPE_NOSPAMKEYS);
    assert(sizeof(get_nospam(m->fr)) == sizeof(uint32_t));
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_NOSPAMKEYS);
    uint32_t nospam = get_nospam(m->fr);
    host_to_lendian_bytes32(data, nospam);
    save_keys(m->net_crypto, data + sizeof(uint32_t));
    data += len;
    return data;
}

// DHT state plugin
static uint32_t m_dht_size(const Messenger *m)
{
    return dht_size(m->dht);
}

static uint8_t *save_dht(const Messenger *m, uint8_t *data)
{
    const uint32_t len = m_plugin_size(m, STATE_TYPE_DHT);
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_DHT);
    dht_save(m->dht, data);
    data += len;
    return data;
}

static State_Load_Status m_dht_load(Messenger *m, const uint8_t *data, uint32_t length)
{
    dht_load(m->dht, data, length); // TODO(endoffile78): Should we throw an error if dht_load fails?
    return STATE_LOAD_STATUS_CONTINUE;
}

// friendlist state plugin
static uint32_t saved_friendslist_size(const Messenger *m)
{
    return count_friendlist(m) * friend_size();
}

static uint8_t *friends_list_save(const Messenger *m, uint8_t *data)
{
    const uint32_t len = m_plugin_size(m, STATE_TYPE_FRIENDS);
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_FRIENDS);

    uint32_t num = 0;
    uint8_t *cur_data = data;

    for (uint32_t i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status > 0) {
            struct Saved_Friend temp = { 0 };
            temp.status = m->friendlist[i].status;
            memcpy(temp.real_pk, m->friendlist[i].real_pk, CRYPTO_PUBLIC_KEY_SIZE);

            if (temp.status < 3) {
                // TODO(iphydf): Use uint16_t and min_u16 here.
                const size_t friendrequest_length =
                    min_u32(m->friendlist[i].info_size,
                            min_u32(SAVED_FRIEND_REQUEST_SIZE, MAX_FRIEND_REQUEST_DATA_SIZE));
                memcpy(temp.info, m->friendlist[i].info, friendrequest_length);

                temp.info_size = net_htons(m->friendlist[i].info_size);
                temp.friendrequest_nospam = m->friendlist[i].friendrequest_nospam;
            } else {
                temp.status = 3;
                memcpy(temp.name, m->friendlist[i].name, m->friendlist[i].name_length);
                temp.name_length = net_htons(m->friendlist[i].name_length);
                memcpy(temp.statusmessage, m->friendlist[i].statusmessage, m->friendlist[i].statusmessage_length);
                temp.statusmessage_length = net_htons(m->friendlist[i].statusmessage_length);
                temp.userstatus = m->friendlist[i].userstatus;

                net_pack_u64(temp.last_seen_time, m->friendlist[i].last_seen_time);
            }

            uint8_t *next_data = friend_save(&temp, cur_data);
            assert(next_data - cur_data == friend_size());
#ifdef __LP64__
            assert(memcmp(cur_data, &temp, friend_size()) == 0);
#endif
            cur_data = next_data;
            ++num;
        }
    }

    assert(cur_data - data == num * friend_size());
    data += len;

    return data;
}

static State_Load_Status friends_list_load(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length % friend_size() != 0) {
        return STATE_LOAD_STATUS_ERROR; // TODO(endoffile78): error or continue?
    }

    uint32_t num = length / friend_size();
    uint32_t i;
    const uint8_t *cur_data = data;

    for (i = 0; i < num; ++i) {
        struct Saved_Friend temp = { 0 };
        const uint8_t *next_data = friend_load(&temp, cur_data);
        assert(next_data - cur_data == friend_size());
#ifdef __LP64__
        assert(memcmp(&temp, cur_data, friend_size()) == 0);
#endif
        cur_data = next_data;

        if (temp.status >= 3) {
            int fnum = m_addfriend_norequest(m, temp.real_pk);

            if (fnum < 0) {
                continue;
            }

            setfriendname(m, fnum, temp.name, net_ntohs(temp.name_length));
            set_friend_statusmessage(m, fnum, temp.statusmessage, net_ntohs(temp.statusmessage_length));
            set_friend_userstatus(m, fnum, temp.userstatus);
            net_unpack_u64(temp.last_seen_time, &m->friendlist[fnum].last_seen_time);
        } else if (temp.status != 0) {
            /* TODO(irungentoo): This is not a good way to do this. */
            uint8_t address[FRIEND_ADDRESS_SIZE];
            id_copy(address, temp.real_pk);
            memcpy(address + CRYPTO_PUBLIC_KEY_SIZE, &temp.friendrequest_nospam, sizeof(uint32_t));
            uint16_t checksum = address_checksum(address, FRIEND_ADDRESS_SIZE - sizeof(checksum));
            memcpy(address + CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t), &checksum, sizeof(checksum));
            m_addfriend(m, address, temp.info, net_ntohs(temp.info_size));
        }
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

// name state plugin
static uint32_t name_size(const Messenger *m)
{
    return m->name_length;
}

static uint8_t *save_name(const Messenger *m, uint8_t *data)
{
    const uint32_t len = m_plugin_size(m, STATE_TYPE_NAME);
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_NAME);
    memcpy(data, m->name, len);
    data += len;
    return data;
}

static State_Load_Status load_name(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length > 0 && length <= MAX_NAME_LENGTH) {
        setname(m, data, length);
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

// status message state plugin
static uint32_t status_message_size(const Messenger *m)
{
    return m->statusmessage_length;
}

static uint8_t *save_status_message(const Messenger *m, uint8_t *data)
{
    const uint32_t len = m_plugin_size(m, STATE_TYPE_STATUSMESSAGE);
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_STATUSMESSAGE);
    memcpy(data, m->statusmessage, len);
    data += len;
    return data;
}

static State_Load_Status load_status_message(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length > 0 && length <= MAX_STATUSMESSAGE_LENGTH) {
        m_set_statusmessage(m, data, length);
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

// status state plugin
static uint32_t status_size(const Messenger *m)
{
    return 1;
}

static uint8_t *save_status(const Messenger *m, uint8_t *data)
{
    const uint32_t len = m_plugin_size(m, STATE_TYPE_STATUS);
    data = state_write_section_header(data, STATE_COOKIE_TYPE, len, STATE_TYPE_STATUS);
    *data = m->userstatus;
    data += len;
    return data;
}

static State_Load_Status load_status(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length == 1) {
        m_set_userstatus(m, *data);
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

// TCP Relay state plugin
static uint32_t tcp_relay_size(const Messenger *m)
{
    return NUM_SAVED_TCP_RELAYS * packed_node_size(net_family_tcp_ipv6);
}

static uint8_t *save_tcp_relays(const Messenger *m, uint8_t *data)
{
    Node_format relays[NUM_SAVED_TCP_RELAYS];
    uint8_t *temp_data = data;
    data = state_write_section_header(temp_data, STATE_COOKIE_TYPE, 0, STATE_TYPE_TCP_RELAY);

    if (m->num_loaded_relays > 0) {
        memcpy(relays, m->loaded_relays, sizeof(Node_format) * m->num_loaded_relays);
    }

    uint32_t num = m->num_loaded_relays;
    num += copy_connected_tcp_relays(m->net_crypto, relays + num, NUM_SAVED_TCP_RELAYS - num);

    int l = pack_nodes(data, NUM_SAVED_TCP_RELAYS * packed_node_size(net_family_tcp_ipv6), relays, num);

    if (l > 0) {
        const uint32_t len = l;
        data = state_write_section_header(temp_data, STATE_COOKIE_TYPE, len, STATE_TYPE_TCP_RELAY);
        data += len;
    }

    return data;
}

static State_Load_Status load_tcp_relays(Messenger *m, const uint8_t *data, uint32_t length)
{
    if (length != 0) {
        const int num = unpack_nodes(m->loaded_relays, NUM_SAVED_TCP_RELAYS, nullptr, data, length, 1);

        if (num == -1) {
            m->num_loaded_relays = 0;
            return STATE_LOAD_STATUS_CONTINUE;
        }

        m->num_loaded_relays = num;
        m->has_added_relays = false;
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

// path node state plugin
static uint32_t path_node_size(const Messenger *m)
{
    return NUM_SAVED_PATH_NODES * packed_node_size(net_family_tcp_ipv6);
}

static uint8_t *save_path_nodes(const Messenger *m, uint8_t *data)
{
    Node_format nodes[NUM_SAVED_PATH_NODES];
    uint8_t *temp_data = data;
    data = state_write_section_header(data, STATE_COOKIE_TYPE, 0, STATE_TYPE_PATH_NODE);
    memset(nodes, 0, sizeof(nodes));
    const unsigned int num = onion_backup_nodes(m->onion_c, nodes, NUM_SAVED_PATH_NODES);
    const int l = pack_nodes(data, NUM_SAVED_PATH_NODES * packed_node_size(net_family_tcp_ipv6), nodes, num);

    if (l > 0) {
        const uint32_t len = l;
        data = state_write_section_header(temp_data, STATE_COOKIE_TYPE, len, STATE_TYPE_PATH_NODE);
        data += len;
    }

    return data;
}

static State_Load_Status load_path_nodes(Messenger *m, const uint8_t *data, uint32_t length)
{
    Node_format nodes[NUM_SAVED_PATH_NODES];

    if (length != 0) {
        const int num = unpack_nodes(nodes, NUM_SAVED_PATH_NODES, nullptr, data, length, 0);

        if (num == -1) {
            return STATE_LOAD_STATUS_CONTINUE;
        }

        for (int i = 0; i < num; ++i) {
            onion_add_bs_path_node(m->onion_c, nodes[i].ip_port, nodes[i].public_key);
        }
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

static void m_register_default_plugins(Messenger *m)
{
    m_register_state_plugin(m, STATE_TYPE_NOSPAMKEYS, nospam_keys_size, load_nospam_keys, save_nospam_keys);
    m_register_state_plugin(m, STATE_TYPE_DHT, m_dht_size, m_dht_load, save_dht);
    m_register_state_plugin(m, STATE_TYPE_FRIENDS, saved_friendslist_size, friends_list_load, friends_list_save);
    m_register_state_plugin(m, STATE_TYPE_NAME, name_size, load_name, save_name);
    m_register_state_plugin(m, STATE_TYPE_STATUSMESSAGE, status_message_size, load_status_message,
                            save_status_message);
    m_register_state_plugin(m, STATE_TYPE_STATUS, status_size, load_status, save_status);
    m_register_state_plugin(m, STATE_TYPE_TCP_RELAY, tcp_relay_size, load_tcp_relays, save_tcp_relays);
    m_register_state_plugin(m, STATE_TYPE_PATH_NODE, path_node_size, load_path_nodes, save_path_nodes);
}

bool messenger_load_state_section(Messenger *m, const uint8_t *data, uint32_t length, uint16_t type,
                                  State_Load_Status *status)
{
    for (uint8_t i = 0; i < m->options.state_plugins_length; ++i) {
        const Messenger_State_Plugin *const plugin = &m->options.state_plugins[i];

        if (plugin->type == type) {
            *status = plugin->load(m, data, length);
            return true;
        }
    }

    return false;
}

/* Return the number of friends in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_friendlist. */
uint32_t count_friendlist(const Messenger *m)
{
    uint32_t ret = 0;
    uint32_t i;

    for (i = 0; i < m->numfriends; ++i) {
        if (m->friendlist[i].status > 0) {
            ++ret;
        }
    }

    return ret;
}

/* Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t copy_friendlist(Messenger const *m, uint32_t *out_list, uint32_t list_size)
{
    if (!out_list) {
        return 0;
    }

    if (m->numfriends == 0) {
        return 0;
    }

    uint32_t i;
    uint32_t ret = 0;

    for (i = 0; i < m->numfriends; ++i) {
        if (ret >= list_size) {
            break; /* Abandon ship */
        }

        if (m->friendlist[i].status > 0) {
            out_list[ret] = i;
            ++ret;
        }
    }

    return ret;
}
