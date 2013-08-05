/* Messenger.c
 *
 * An implementation of a simple (text chat only) messenger on the Tox network core.
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

typedef struct Friend Friend;
struct Friend {
    uint8_t client_id[CLIENT_ID_SIZE];
    int crypt_connection_id;
    uint64_t friend_request_id; /* id of the friend request corresponding to the current friend request to the current friend. */
    uint8_t status; /* 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online. */
    uint8_t info[MAX_DATA_SIZE]; /* the data that is sent during the friend requests we do */
    uint8_t name[MAX_NAME_LENGTH];
    uint8_t name_sent; /* 0 if we haven't sent our name to this friend, 1 if we have. */
    uint8_t *userstatus;
    uint16_t userstatus_length;
    uint8_t userstatus_sent;
    uint16_t info_size; /* length of the info */
    Friend *next; /* next friend in friend list */
};

uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];

static uint8_t self_name[MAX_NAME_LENGTH];
static uint16_t self_name_length;

static uint8_t *self_userstatus;
static uint16_t self_userstatus_len;

static Friend *friendlist;

static uint32_t numfriends = 0;

/* 1 if we are online
   0 if we are offline
   static uint8_t online; */

/* find friend #friendnumber in the friend list */
Friend *seektofriend(uint32_t friendnumber)
{
    uint32_t i;
    Friend *f;

    /* in most cases this should already be guaranteed */
    if (friendnumber >= numfriends || friendnumber < 0)
        return NULL;

    for (i = 0, f = friendlist; i < friendnumber; i++, f = f->next);
    return f;
}

/* return the friend id associated to that public key.
   return -1 if no such friend */
int getfriend_id(uint8_t *client_id)
{
    uint32_t i;
    Friend *f;

    for (i = 0, f = friendlist; f != NULL; f = f->next)
        if (memcmp(client_id, f->client_id, crypto_box_PUBLICKEYBYTES) == 0)
            return i;

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

    memcpy(client_id, seektofriend(friend_id)->client_id, CLIENT_ID_SIZE);
    return 0;

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
    Friend *f;

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

    /* create new friend */
    Friend *newfriend = malloc(sizeof(Friend));
    DHT_addfriend(client_id);
    newfriend->status = FRIEND_ADDED;
    newfriend->crypt_connection_id = -1;
    newfriend->friend_request_id = -1;
    memcpy(newfriend->client_id, client_id, CLIENT_ID_SIZE);
    newfriend->userstatus = calloc(1, 1);
    newfriend->userstatus_length = 1;
    memcpy(newfriend->info, data, length);
    newfriend->info_size = length;
    newfriend->next = NULL;

    /* append to end of friend list */
    if (friendlist == NULL)
        friendlist = newfriend;
    else {
        for (f = friendlist; f->next != NULL; f = f->next);
        f->next = newfriend;
    }

    ++numfriends;
    return numfriends;
}

int m_addfriend_norequest(uint8_t *client_id)
{
    Friend *f;

    if (getfriend_id(client_id) != -1)
        return -1;

    /* create new friend */
    Friend *newfriend = malloc(sizeof(Friend));
    DHT_addfriend(client_id);
    newfriend->status = FRIEND_REQUESTED;
    newfriend->crypt_connection_id = -1;
    newfriend->friend_request_id = -1;
    memcpy(newfriend->client_id, client_id, CLIENT_ID_SIZE);
    newfriend->userstatus = calloc(1, 1);
    newfriend->userstatus_length = 1;
    newfriend->next = NULL;

    /* append to end of friend list */
    if (friendlist == NULL)
        friendlist = newfriend;
    else {
        for (f = friendlist; f->next != NULL; f = f->next);
        f->next = newfriend;
    }

    ++numfriends;
    return numfriends;
}

/* remove a friend
   return 0 if success
   return -1 if failure */
int m_delfriend(int friendnumber)
{
    uint32_t i;
    Friend *f;
    Friend *deleteme;

    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;

    /* remove friend from linked list */
    if (friendnumber == 0) {
        deleteme = friendlist;
        friendlist = deleteme->next;
    }
    else {
        for (i = 0, f = friendlist; i < friendnumber - 1; i++, f = f->next);
        deleteme = f->next;
        f->next = deleteme->next;
    }

    DHT_delfriend(deleteme->client_id);
    crypto_kill(deleteme->crypt_connection_id);
    free(deleteme->userstatus);
    free(deleteme);
    
    --numfriends;
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

    return seektofriend(friendnumber)->status;
}

/* send a text chat message to an online friend
   return 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendmessage(int friendnumber, uint8_t *message, uint32_t length)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return 0;
    if (length >= MAX_DATA_SIZE || seektofriend(friendnumber)->status != FRIEND_ONLINE)
        /* this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less. */
        return 0;

    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = PACKET_ID_MESSAGE;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(seektofriend(friendnumber)->crypt_connection_id, temp, length + 1);
}

/* send a name packet to friendnumber 
   length is the length with the NULL terminator*/
static int m_sendname(Friend *f, uint8_t * name, uint16_t length)
{
    if(length > MAX_NAME_LENGTH || length == 0)
        return 0;

    uint8_t temp[MAX_NAME_LENGTH + 1];
    memcpy(temp + 1, name, length);
    temp[0] = PACKET_ID_NICKNAME;
    return write_cryptpacket(f->crypt_connection_id, temp, length + 1);
}

/* set the name of a friend
   return 0 if success
   return -1 if failure */
static int setfriendname(int friendnumber, uint8_t * name)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;

    memcpy(seektofriend(friendnumber)->name, name, MAX_NAME_LENGTH);
    return 0;
}

/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   length must be at least 1 byte
   length is the length of name with the NULL terminator
   return 0 if success
   return -1 if failure */
int setname(uint8_t *name, uint16_t length)
{
    Friend *f;

    if (length > MAX_NAME_LENGTH || length == 0)
        return -1;
    memcpy(self_name, name, length);
    self_name_length = length;
    for (f = friendlist; f != NULL; f = f->next)
        f->name_sent = 0;
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

    memcpy(name, seektofriend(friendnumber)->name, MAX_NAME_LENGTH);
    return 0;
}

int m_set_userstatus(uint8_t *status, uint16_t length)
{
    Friend *f;

    if (length > MAX_USERSTATUS_LENGTH)
        return -1;
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(self_userstatus);
    self_userstatus = newstatus;
    self_userstatus_len = length;

    for (f = friendlist; f != NULL; f = f->next)
        f->userstatus_sent = 0;
    return 0;
}

/*  return the size of friendnumber's user status
    guaranteed to be at most MAX_USERSTATUS_LENGTH */
int m_get_userstatus_size(int friendnumber)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;

    return seektofriend(friendnumber)->userstatus_length;
}

/*  copy the user status of friendnumber into buf, truncating if needed to maxlen
    bytes, use m_get_userstatus_size to find out how much you need to allocate */
int m_copy_userstatus(int friendnumber, uint8_t *buf, uint32_t maxlen)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;

    memset(buf, 0, maxlen);
    memcpy(buf, seektofriend(friendnumber)->userstatus, MIN(maxlen, MAX_USERSTATUS_LENGTH) - 1);
    return 0;
}

static int send_userstatus(Friend *f, uint8_t *status, uint16_t length)
{
    uint8_t *thepacket = malloc(length + 1);
    memcpy(thepacket + 1, status, length);
    thepacket[0] = PACKET_ID_USERSTATUS;
    int written = write_cryptpacket(f->crypt_connection_id, thepacket, length + 1);
    free(thepacket);
    return written;
}

static int set_friend_userstatus(Friend *f, uint8_t *status, uint16_t length)
{
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(f->userstatus);
    f->userstatus = newstatus;
    f->userstatus_length = length;
    return 0;
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

static void (*friend_statuschange)(int, uint8_t *, uint16_t);
static uint8_t friend_statuschange_isset = 0;
void m_callback_userstatus(void (*function)(int, uint8_t *, uint16_t))
{
    friend_statuschange = function;
    friend_statuschange_isset = 1;
}

#define PORT 33445
/* run this at startup */
int initMessenger(void)
{
    new_keys();
    m_set_userstatus((uint8_t*)"Online", sizeof("Online"));
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
    Friend *f;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    for (i = 0, f = friendlist; f != NULL; i++, f = f->next) {
        if (f->status == FRIEND_ADDED) {
            int fr = send_friendrequest(f->client_id, f->info, f->info_size);
            if (fr == 0) /* TODO: This needs to be fixed so that it sends the friend requests a couple of times in case of packet loss */
                f->status = FRIEND_REQUESTED;
            else if (fr > 0)
                f->status = FRIEND_REQUESTED;
        }
        if (f->status == FRIEND_REQUESTED || f->status == FRIEND_CONFIRMED) { /* friend is not online */
            if (f->status == FRIEND_REQUESTED) {
                if (f->friend_request_id + 10 < unix_time()) { /*I know this is hackish but it should work.*/
                    send_friendrequest(f->client_id, f->info, f->info_size);
                    f->friend_request_id = unix_time();
                }
            }
            IP_Port friendip = DHT_getfriendip(f->client_id);
            switch (is_cryptoconnected(f->crypt_connection_id)) {
            case 0:
                if (friendip.ip.i > 1)
                    f->crypt_connection_id = crypto_connect(f->client_id, friendip);
                break;
            case 3: /*  Connection is established */
                f->status = FRIEND_ONLINE;
                break;
            case 4:
                crypto_kill(f->crypt_connection_id);
                f->crypt_connection_id = -1;
                break;
            default:
                break;
            }
        }
        while (f->status == FRIEND_ONLINE) { /* friend is online */
            if (f->name_sent == 0) {
                if (m_sendname(f, self_name, self_name_length))
                    f->name_sent = 1;
            }
            if (f->userstatus_sent == 0) {
                if (send_userstatus(f, self_userstatus, self_userstatus_len))
                    f->userstatus_sent = 1;
            }
            len = read_cryptpacket(f->crypt_connection_id, temp);
            if (len > 0) {
                switch (temp[0]) {
                case PACKET_ID_NICKNAME: {
                    if (len >= MAX_NAME_LENGTH + 1 || len == 1)
                        break;
                    if(friend_namechange_isset)
                        friend_namechange(i, temp + 1, len - 1);
                    memcpy(f->name, temp + 1, len - 1);
                    f->name[len - 2] = 0; /* make sure the NULL terminator is present. */
                    break;
                }
                case PACKET_ID_USERSTATUS: {
                    uint8_t *status = calloc(MIN(len - 1, MAX_USERSTATUS_LENGTH), 1);
                    memcpy(status, temp + 1, MIN(len - 1, MAX_USERSTATUS_LENGTH));
                    if (friend_statuschange_isset)
                        friend_statuschange(i, status, MIN(len - 1, MAX_USERSTATUS_LENGTH));
                    set_friend_userstatus(f, status, MIN(len - 1, MAX_USERSTATUS_LENGTH));
                    free(status);
                    break;
                }
                case PACKET_ID_MESSAGE: {
                    if (friend_message_isset)
                        (*friend_message)(i, temp + 1, len - 1);
                    break;
                }
                }
            } else {
                if (is_cryptoconnected(f->crypt_connection_id) == 4) { /* if the connection timed out, kill it */
                    crypto_kill(f->crypt_connection_id);
                    f->crypt_connection_id = -1;
                    f->status = FRIEND_CONFIRMED;
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
        Friend *f = seektofriend(getfriend_id(public_key));
        if (f != NULL) {
            crypto_kill(f->crypt_connection_id);
            f->crypt_connection_id =
                accept_crypto_inbound(inconnection, public_key, secret_nonce, session_key);

            f->status = FRIEND_CONFIRMED;
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
        printf("Status: %u %u %u\n",friendlist->status,is_cryptoconnected(friendlist->crypt_connection_id),  friendlist->crypt_connection_id);
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
    Friend *f;
    for (f = friendlist; f != NULL; f = f->next) {
        memcpy(data, f, sizeof(Friend));
        data += sizeof(Friend);
    }
}

/* load the messenger from data of size length. */
int Messenger_load(uint8_t *data, uint32_t length)
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

    uint32_t i;
    uint16_t num = size / sizeof(Friend);
    Friend f;
    for (i = 0; i < num; i++) {
        memcpy(&f, data, sizeof(Friend));
        data += sizeof(Friend);
        int fnum = m_addfriend_norequest(f.client_id);
        setfriendname(fnum, f.name);
    }

    return 0;
}
