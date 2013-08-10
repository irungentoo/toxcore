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
#include "media_session_initiation.h" /* It contains Messenger.h by default
                                                 * so no need to include Messenger.h */
#define MIN(a,b) (((a)<(b))?(a):(b))

uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];

static uint8_t self_name[MAX_NAME_LENGTH];
static uint16_t self_name_length;

static uint8_t *self_userstatus;
static uint16_t self_userstatus_len;
static USERSTATUS_KIND self_userstatus_kind;

#define MAX_NUM_FRIENDS 256


typedef struct {
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    uint64_t friend_request_id; /* id of the friend request corresponding to the current friend request to the current friend. */
    uint8_t status; /* 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online. */
    uint8_t info[MAX_DATA_SIZE]; /* the data that is sent during the friend requests we do */
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t name_sent; /* 0 if we didn't send our name to this friend 1 if we have. */
    uint8_t *userstatus;
    uint16_t userstatus_length;
    uint8_t userstatus_sent;
    USERSTATUS_KIND userstatus_kind;
    uint16_t info_size; /* length of the info */
} Friend;

static Friend friendlist[MAX_NUM_FRIENDS];

static uint32_t numfriends;

/* This messenger's Media session descriptor */
static media_session_t* _media_session;
/**/

/* 1 if we are online
   0 if we are offline
   static uint8_t online; */

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

    uint32_t i;
    for (i = 0; i <= numfriends && i <= MAX_NUM_FRIENDS; ++i)  { /*TODO: dynamic memory allocation to allow for more than MAX_NUM_FRIENDS friends */
        if (friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            friendlist[i].status = FRIEND_ADDED;
            friendlist[i].crypt_connection_id = -1;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            friendlist[i].userstatus = calloc(1, 1);
            friendlist[i].userstatus_length = 1;
            friendlist[i].userstatus_kind = USERSTATUS_KIND_OFFLINE;
            memcpy(friendlist[i].info, data, length);
            friendlist[i].info_size = length;

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
    uint32_t i;
    for (i = 0; i <= numfriends && i <= MAX_NUM_FRIENDS; ++i) { /*TODO: dynamic memory allocation to allow for more than MAX_NUM_FRIENDS friends */
        if(friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            friendlist[i].status = FRIEND_REQUESTED;
            friendlist[i].crypt_connection_id = -1;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            friendlist[i].userstatus = calloc(1, 1);
            friendlist[i].userstatus_length = 1;
            numfriends++;
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
    free(friendlist[friendnumber].userstatus);
    memset(&friendlist[friendnumber], 0, sizeof(Friend));
    uint32_t i;

    for (i = numfriends; i != 0; --i) {
        if (friendlist[i-1].status != NOFRIEND)
            break;
    }
    numfriends = i;

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
   return 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendmessage(int friendnumber, uint8_t *message, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return 0;
    if (length >= MAX_DATA_SIZE || friendlist[friendnumber].status != FRIEND_ONLINE)
        /* this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less. */
        return 0;
    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = PACKET_ID_MESSAGE;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(friendlist[friendnumber].crypt_connection_id, temp, length + 1);
}

/* send an media_session_initiation packet to an online friend
    returns 1 if packet was successfully put into the send queue
    return 0 if it was not */
int m_sendmediainitcallback(int friendnumber, uint8_t *message, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return 0;
    if (length >= MAX_DATA_SIZE || friendlist[friendnumber].status != FRIEND_ONLINE)
        /* this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less. */
        return 0;
    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = PACKET_ID_MEDIA;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(friendlist[friendnumber].crypt_connection_id, temp, length + 1);
}

/* Starts the call flow.
   Returns if the thread started */
int m_startcall(int friendnumber)
{
    if ( !_media_session )
        return 0; /* Failed */

    int _status;
    _media_session->_friend_id = friendnumber;

    _status = pthread_create(&(_media_session->_thread_id), NULL, media_session_pool_stack, (void*) _media_session );

    if ( _status != 0 )
        return 0; /* Failed */

    _status = pthread_detach(_media_session->_thread_id);

    if ( _status != 0 )
        return 0; /* Failed */

    return 1;
}

/* send a name packet to friendnumber
   length is the length with the NULL terminator*/
static int m_sendname(int friendnumber, uint8_t * name, uint16_t length)
{
    if(length > MAX_NAME_LENGTH || length == 0)
        return 0;
    uint8_t temp[MAX_NAME_LENGTH + 1];
    memcpy(temp + 1, name, length);
    temp[0] = PACKET_ID_NICKNAME;
    return write_cryptpacket(friendlist[friendnumber].crypt_connection_id, temp, length + 1);
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

int m_set_userstatus(USERSTATUS_KIND kind, uint8_t *status, uint16_t length)
{
    if (length > MAX_USERSTATUS_LENGTH)
        return -1;
    if (kind != USERSTATUS_KIND_RETAIN) {
        self_userstatus_kind = kind;
    }
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(self_userstatus);
    self_userstatus = newstatus;
    self_userstatus_len = length;

    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].userstatus_sent = 0;
    return 0;
}

int m_set_userstatus_kind(USERSTATUS_KIND kind) {
    if (kind >= USERSTATUS_KIND_INVALID) {
        return -1;
    }
    if (kind == USERSTATUS_KIND_RETAIN) {
        return 0;
    }
    self_userstatus_kind = kind;
    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].userstatus_sent = 0;
    return 0;
}

/*  return the size of friendnumber's user status
    guaranteed to be at most MAX_USERSTATUS_LENGTH */
int m_get_userstatus_size(int friendnumber)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    return friendlist[friendnumber].userstatus_length;
}

/*  copy the user status of friendnumber into buf, truncating if needed to maxlen
    bytes, use m_get_userstatus_size to find out how much you need to allocate */
int m_copy_userstatus(int friendnumber, uint8_t * buf, uint32_t maxlen)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    memset(buf, 0, maxlen);
    memcpy(buf, friendlist[friendnumber].userstatus, MIN(maxlen, MAX_USERSTATUS_LENGTH) - 1);
    return 0;
}

int m_copy_self_userstatus(uint8_t * buf, uint32_t maxlen)
{
    memset(buf, 0, maxlen);
    memcpy(buf, self_userstatus, MIN(maxlen, MAX_USERSTATUS_LENGTH) - 1);
    return 0;
}

USERSTATUS_KIND m_get_userstatus_kind(int friendnumber) {
    if (friendnumber >= numfriends || friendnumber < 0)
        return USERSTATUS_KIND_INVALID;
    USERSTATUS_KIND uk = friendlist[friendnumber].userstatus_kind;
    if (uk >= USERSTATUS_KIND_INVALID) {
        uk = USERSTATUS_KIND_ONLINE;
    }
    return uk;
}

USERSTATUS_KIND m_get_self_userstatus_kind(void) {
    return self_userstatus_kind;
}

static int send_userstatus(int friendnumber, uint8_t * status, uint16_t length)
{
    uint8_t *thepacket = malloc(length + 2);
    memcpy(thepacket + 2, status, length);
    thepacket[0] = PACKET_ID_USERSTATUS;
    thepacket[1] = self_userstatus_kind;
    int written = write_cryptpacket(friendlist[friendnumber].crypt_connection_id, thepacket, length + 2);
    free(thepacket);
    return written;
}

static int set_friend_userstatus(int friendnumber, uint8_t * status, uint16_t length)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(friendlist[friendnumber].userstatus);
    friendlist[friendnumber].userstatus = newstatus;
    friendlist[friendnumber].userstatus_length = length;
    return 0;
}

static void set_friend_userstatus_kind(int friendnumber, USERSTATUS_KIND k)
{
    friendlist[friendnumber].userstatus_kind = k;
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

static void (*friend_namechange)(int, uint8_t *, uint16_t);
static uint8_t friend_namechange_isset = 0;
void m_callback_namechange(void (*function)(int, uint8_t *, uint16_t))
{
    friend_namechange = function;
    friend_namechange_isset = 1;
}

static void (*friend_statuschange)(int, USERSTATUS_KIND, uint8_t *, uint16_t);
static uint8_t friend_statuschange_isset = 0;
void m_callback_userstatus(void (*function)(int, USERSTATUS_KIND, uint8_t *, uint16_t))
{
    friend_statuschange = function;
    friend_statuschange_isset = 1;
}

#define PORT 33445

/* run this at startup */
int initMessenger(void)
{
    new_keys();
    m_set_userstatus(USERSTATUS_KIND_ONLINE, (uint8_t*)"Online", sizeof("Online"));
    initNetCrypto();
    IP ip;
    ip.i = 0;

    if(init_networking(ip,PORT) == -1)
        return -1;

    IP_Port ip_port = { ip, PORT, -1 };
    _media_session = media_init_session(ip_port);

    if ( _media_session == NULL )
        return -1;

    media_session_register_callback_send(m_sendmediainitcallback);

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
                friendlist[i].status = FRIEND_REQUESTED;
            else if (fr > 0)
                friendlist[i].status = FRIEND_REQUESTED;
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
                friendlist[i].status = FRIEND_ONLINE;
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
            if (friendlist[i].userstatus_sent == 0) {
                if (send_userstatus(i, self_userstatus, self_userstatus_len))
                    friendlist[i].userstatus_sent = 1;
            }
            len = read_cryptpacket(friendlist[i].crypt_connection_id, temp);
            if (len > 0) {
                switch (temp[0]) {
                case PACKET_ID_NICKNAME: {
                    if (len >= MAX_NAME_LENGTH + 1 || len == 1)
                        break;
                    if(friend_namechange_isset)
                        friend_namechange(i, temp + 1, len - 1);
                    memcpy(friendlist[i].name, temp + 1, len - 1);
                    friendlist[i].name[len - 2] = 0; /* make sure the NULL terminator is present. */
                    break;
                }
                case PACKET_ID_USERSTATUS: {
                    if (len > 2) {
                        uint8_t *status = calloc(MIN(len - 2, MAX_USERSTATUS_LENGTH), 1);
                        memcpy(status, temp + 2, MIN(len - 2, MAX_USERSTATUS_LENGTH));
                        if (friend_statuschange_isset)
                            friend_statuschange(i, temp[1], status, MIN(len - 2, MAX_USERSTATUS_LENGTH));
                        set_friend_userstatus(i, status, MIN(len - 2, MAX_USERSTATUS_LENGTH));
                        free(status);
                    } else if (friend_statuschange_isset) {
                        friend_statuschange(i, temp[1], friendlist[i].userstatus, friendlist[i].userstatus_length);
                    }
                    set_friend_userstatus_kind(i, temp[1]);
                    break;
                }
                case PACKET_ID_MESSAGE: {
                    if (friend_message_isset)
                        (*friend_message)(i, temp + 1, len - 1);
                    break;
                }
                }
            } else {
                if (is_cryptoconnected(friendlist[i].crypt_connection_id) == 4) { /* if the connection timed out, kill it */
                    crypto_kill(friendlist[i].crypt_connection_id);
                    friendlist[i].crypt_connection_id = -1;
                    friendlist[i].status = FRIEND_CONFIRMED;
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

            friendlist[friend_id].status = FRIEND_CONFIRMED;
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
        if      ( media_session_handlepacket( _media_session, data, length ) ) break;
        else if ( DHT_handlepacket(data, length, ip_port) ) break;
        else if ( LosslessUDP_handlepacket(data, length, ip_port) ) break;
        else if ( friendreq_handlepacket(data, length, ip_port) ) break;
        else if ( LANdiscovery_handlepacket(data, length, ip_port) ) break;
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
            /* set_friend_userstatus(fnum, temp[i].userstatus, temp[i].userstatus_length); */
        }
    }
    free(temp);
    return 0;
}
