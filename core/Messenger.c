/* Messenger.c
*
* An implementation of a simple text chat only messenger on the tox network core.
*

    Copyright (C) 2013 Tox project All Rights Reserved.

    This file is part of Tox.

    Tox is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "Messenger.h"

/* 1 if we are online
   0 if we are offline
   static uint8_t online; */


/* return the friend id associated to that public key.
   return -1 if no such friend */
int getfriend_id(Messenger *m, uint8_t * client_id)
{
    uint32_t i;
    for(i = 0; i < m->numfriends; ++i)
    {
        if(m->friendlist[i].status > 0)
        {
            if(memcmp(client_id, m->friendlist[i].client_id, crypto_box_PUBLICKEYBYTES) == 0)
            {
                return i;
            }
        }
    }
    return -1;
}


/* copies the public key associated to that friend id into client_id buffer.
   make sure that client_id is of size CLIENT_ID_SIZE.
   return 0 if success
   return -1 if failure. */
int getclient_id(Messenger *m, int friend_id, uint8_t * client_id)
{
    if(friend_id >= m->numfriends || friend_id < 0)
    {
        return -1;
    }

    if(m->friendlist[friend_id].status > 0)
    {
        memcpy(client_id, m->friendlist[friend_id].client_id, CLIENT_ID_SIZE);
        return 0;
    }
    return -1;
}


/* add a friend
   set the data that will be sent along with friend request
   client_id is the client id of the friend
   data is the data and length is the length
   returns the friend number if success
   return -1 if failure. */
int m_addfriend(Messenger *m, uint8_t * client_id, uint8_t * data, uint16_t length)
{
    if(length == 0 || length >=
            (MAX_DATA_SIZE - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES))
    {
        return -1;
    }
    if(memcmp(client_id, self_public_key, crypto_box_PUBLICKEYBYTES) == 0)
    {
        return -1;
    }
    if(getfriend_id(m, client_id) != -1)
    {
        return -1;
    }
    uint32_t i;
    for(i = 0; i <= m->numfriends; ++i)
    {
        if(m->friendlist[i].status == NO_ADDED)
        {
            DHT_addfriend(client_id);
            m->friendlist[i].status = ADDED;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friend_request_id = -1;
            memcpy(m->friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            m->friendlist[i].userstatus = calloc(1, 1);
            m->friendlist[i].userstatus_length = 1;
            memcpy(m->friendlist[i].info, data, length);
            m->friendlist[i].info_size = length;

            ++m->numfriends;
            return i;
        }
    }
    return -1;
}

int m_addfriend_norequest(Messenger *m, uint8_t * client_id)
{
    if(getfriend_id(m, client_id) != -1)
    {
        return -1;
    }
    uint32_t i;
    for(i = 0; i <= m->numfriends; ++i)
    {
        if(m->friendlist[i].status == NO_ADDED)
        {
            DHT_addfriend(client_id);
            m->friendlist[i].status = REQUEST_SENT;
            m->friendlist[i].crypt_connection_id = -1;
            m->friendlist[i].friend_request_id = -1;
            memcpy(m->friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            m->friendlist[i].userstatus = calloc(1, 1);
            m->friendlist[i].userstatus_length = 1;
            ++m->numfriends;
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
    if(friendnumber >= m->numfriends || friendnumber < 0)
    {
        return -1;
    }

    DHT_delfriend(m->friendlist[friendnumber].client_id);
    crypto_kill(m->friendlist[friendnumber].crypt_connection_id);
    free(m->friendlist[friendnumber].userstatus);
    memset(&(m->friendlist[friendnumber]), 0, sizeof(Friend));
    uint32_t i;
    for(i = m->numfriends; i != 0; --i)
    {
        if(m->friendlist[i].status != NO_ADDED)
        {
            break;
        }
    }
    m->numfriends = i;
    return 0;
}


Friend_status m_friendstatus(Messenger *m, int friendnumber)
{
    if(friendnumber < 0 || friendnumber >= m->numfriends)
    {
        return 0;
    }
    return m->friendlist[friendnumber].status;
}


/* send a text chat message to an online friend
   return 1 if packet was successfully put into the send queue
   return 0 if it was not */
int m_sendmessage(Messenger *m, int friendnumber, uint8_t * message, uint32_t length)
{
    if(friendnumber < 0 || friendnumber >= m->numfriends)
    {
        return 0;
    }
    if(length >= MAX_DATA_SIZE || m->friendlist[friendnumber].status != ONLINE)
    /* this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less. */
    {
        return 0;
    }
    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = PACKET_ID_MESSAGE;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(m->friendlist[friendnumber].crypt_connection_id, temp, length + 1);
}

/* send a name packet to friendnumber */
static int m_sendname(Messenger *m, int friendnumber, uint8_t * name)
{
    uint8_t temp[MAX_NAME_LENGTH + 1];
    memcpy(temp + 1, name, MAX_NAME_LENGTH);
    temp[0] = PACKET_ID_NICKNAME;
    return write_cryptpacket(m->friendlist[friendnumber].crypt_connection_id, temp, MAX_NAME_LENGTH + 1);
}

/* set the name of a friend
   return 0 if success
   return -1 if failure */

static int setfriendname(Messenger *m, int friendnumber, uint8_t * name)
{
    if(friendnumber >= m->numfriends || friendnumber < 0)
    {
        return -1;
    }
    memcpy(m->friendlist[friendnumber].name, name, MAX_NAME_LENGTH);
    return 0;
}


/* Set our nickname
   name must be a string of maximum MAX_NAME_LENGTH length.
   return 0 if success
   return -1 if failure */
int setname(Messenger *m, uint8_t * name, uint16_t length)
{
    if(length > MAX_NAME_LENGTH)
    {
        return -1;
    }
    memcpy(m->self_name, name, length);
    uint32_t i;
    for(i = 0; i < m->numfriends; ++i)
    {
        m->friendlist[i].name_sent = 0;
    }
    return 0;
}

/* get name of friendnumber
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return 0 if success
   return -1 if failure */
int getname(Messenger *m, int friendnumber, uint8_t * name)
{
    if(friendnumber >= m->numfriends || friendnumber < 0)
    {
        return -1;
    }
    memcpy(name, m->friendlist[friendnumber].name, MAX_NAME_LENGTH);
    return 0;
}

int m_set_userstatus(Messenger *m, uint8_t *status, uint16_t length)
{
    if(length > MAX_USERSTATUS_LENGTH)
    {
        return -1;
    }
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(m->self_userstatus);
    m->self_userstatus = newstatus;
    m->self_userstatus_len = length;

    uint32_t i;
    for(i = 0; i < m->numfriends; ++i)
    {
        m->friendlist[i].userstatus_sent = 0;
    }
    return 0;
}

/*  return the size of friendnumber's user status
    guaranteed to be at most MAX_USERSTATUS_LENGTH */
int m_get_userstatus_size(Messenger *m, int friendnumber)
{
    if(friendnumber >= m->numfriends || friendnumber < 0)
    {
        return -1;
    }
    return m->friendlist[friendnumber].userstatus_length;
}

/*  copy the user status of friendnumber into buf, truncating if needed to maxlen
    bytes, use m_get_userstatus_size to find out how much you need to allocate */
int m_copy_userstatus(Messenger *m, int friendnumber, uint8_t * buf, uint32_t maxlen)
{
    if(friendnumber >= m->numfriends || friendnumber < 0)
    {
        return -1;
    }
    memset(buf, 0, maxlen);
    memcpy(buf, m->friendlist[friendnumber].userstatus, MIN(maxlen, MAX_USERSTATUS_LENGTH) - 1);
    return 0;
}

static int send_userstatus(Messenger *m, int friendnumber, uint8_t * status, uint16_t length)
{
    uint8_t *thepacket = malloc(length + 1);
    memcpy(thepacket + 1, status, length);
    thepacket[0] = PACKET_ID_USERSTATUS;
    int written = write_cryptpacket(m->friendlist[friendnumber].crypt_connection_id, thepacket, length + 1);
    free(thepacket);
    return written;
}

static int set_friend_userstatus(Messenger *m, int friendnumber, uint8_t * status, uint16_t length)
{
    if(friendnumber >= m->numfriends || friendnumber < 0)
    {
        return -1;
    }
    uint8_t *newstatus = calloc(length, 1);
    memcpy(newstatus, status, length);
    free(m->friendlist[friendnumber].userstatus);
    m->friendlist[friendnumber].userstatus = newstatus;
    m->friendlist[friendnumber].userstatus_length = length;
    return 0;
}

/* set the function that will be executed when a friend request is received. */
void m_callback_friendrequest(Messenger *m, void (*function)(Messenger *, uint8_t *, uint8_t *, uint16_t))
{
    m->friend_request = function;
    m->friend_request_isset = 1;
}

/* set the function that will be executed when a message from a friend is received. */
void m_callback_friendmessage(Messenger *m, void (*function)(Messenger *, int, uint8_t *, uint16_t))
{
    m->friend_message = function;
    m->friend_message_isset = 1;
}

void m_callback_namechange(Messenger *m, void (*function)(Messenger *, int, uint8_t *, uint16_t))
{
    m->friend_namechange = function;
    m->friend_namechange_isset = 1;
}

void m_callback_userstatus(Messenger *m, void (*function)(Messenger *, int, uint8_t *, uint16_t))
{
    m->friend_statuschange = function;
    m->friend_statuschange_isset = 1;
}

/* run this at startup */
Messenger * initMessenger()
{
	Messenger *m = calloc(1, sizeof(Messenger));
	if( !m ) /* FIXME panic */
		return 0;
	m->friendlist = calloc(256, sizeof(Friend));
	if( !m ) /* FIXME panic */
		return 0;
	m->size = 256; /* FIXME make dynamic later on, requires logic change */

    new_keys();
    m_set_userstatus(m, (uint8_t*)"Online", sizeof("Online"));
    initNetCrypto();
    IP ip;
    ip.i = 0;
    init_networking(ip, MESSENGER_PORT);

	return m;
}

static void doFriends(Messenger *m)
{/* TODO: add incoming connections and some other stuff. */
    uint32_t i;
    int len;
    uint8_t temp[MAX_DATA_SIZE];
    for(i = 0; i < m->numfriends; ++i)
    {
        if(m->friendlist[i].status == 1)
        {
             IP_Port friendip = DHT_getfriendip(m->friendlist[i].client_id);
             int request = check_friendrequest(m->friendlist[i].friend_request_id);
             /* printf("\n%u %u %u\n", friendip.ip.i, request, friendlist[i].friend_request_id); */
             if(friendip.ip.i > 1 && request == -1)
             {
                  m->friendlist[i].friend_request_id = send_friendrequest(m->friendlist[i].client_id,
                                               friendip, m->friendlist[i].info, m->friendlist[i].info_size);
                  m->friendlist[i].status = 2;
             }
        }
        if(m->friendlist[i].status == REQUEST_SENT || m->friendlist[i].status == CONFIRMED_FRIEND) /* friend is not online */
        {
            check_friendrequest(m->friendlist[i].friend_request_id); /* for now this is used to kill the friend request */
            IP_Port friendip = DHT_getfriendip(m->friendlist[i].client_id);
            switch(is_cryptoconnected(m->friendlist[i].crypt_connection_id))
            {
                case 0:
                    if (friendip.ip.i > 1)
                        m->friendlist[i].crypt_connection_id = crypto_connect(m->friendlist[i].client_id, friendip);
                    break;
                case 3: /*  Connection is established */
                    m->friendlist[i].status = 4;
                    break;
                case 4:
                    crypto_kill(m->friendlist[i].crypt_connection_id);
                    m->friendlist[i].crypt_connection_id = -1;
                    break;
                default:
                    break;
            }
        }
        while(m->friendlist[i].status == 4) /* friend is online */
        {
            if(m->friendlist[i].name_sent == 0)
            {
                if(m_sendname(m, i, m->self_name))
                {
                    m->friendlist[i].name_sent = 1;
                }
            }
            if(m->friendlist[i].userstatus_sent == 0)
            {
                if(send_userstatus(m, i, m->self_userstatus, m->self_userstatus_len))
                {
                    m->friendlist[i].userstatus_sent = 1;
                }
            }
            len = read_cryptpacket(m->friendlist[i].crypt_connection_id, temp);
            if(len > 0)
            {
                switch(temp[0]) {
                    case PACKET_ID_NICKNAME: {
                        if (len != MAX_NAME_LENGTH + 1) break;
                        if(m->friend_namechange_isset)
                        {
                            m->friend_namechange(m, i, temp + 1, MAX_NAME_LENGTH); /* TODO: use the actual length */
                        }
                        memcpy(m->friendlist[i].name, temp + 1, MAX_NAME_LENGTH);
                        m->friendlist[i].name[MAX_NAME_LENGTH - 1] = 0; /* make sure the NULL terminator is present. */
                        break;
                    }
                    case PACKET_ID_USERSTATUS: {
                        uint8_t *status = calloc(MIN(len - 1, MAX_USERSTATUS_LENGTH), 1);
                        memcpy(status, temp + 1, MIN(len - 1, MAX_USERSTATUS_LENGTH));
                        if(m->friend_statuschange_isset)
                        {
                            m->friend_statuschange(m, i, status, MIN(len - 1, MAX_USERSTATUS_LENGTH));
                        }
                        set_friend_userstatus(m, i, status, MIN(len - 1, MAX_USERSTATUS_LENGTH));
                        free(status);
                        break;
                    }
                    case PACKET_ID_MESSAGE: {
                        if(m->friend_message_isset)
                        {
                            (*m->friend_message)(m, i, temp + 1, len - 1);
                        }
                        break;
                    }
                }
            }
            else
            {
                 if(is_cryptoconnected(m->friendlist[i].crypt_connection_id) == 4) /* if the connection timed out, kill it */
                 {
                         crypto_kill(m->friendlist[i].crypt_connection_id);
                         m->friendlist[i].crypt_connection_id = -1;
                         m->friendlist[i].status = 3;
                 }
                 break;
            }
        }
    }
}

static void doFriendRequest(Messenger *m)
{
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t temp[MAX_DATA_SIZE];

    int len = handle_friendrequest(public_key, temp);
    if(len >= 0)
    {
        if(m->friend_request_isset)
        {
            (*(m->friend_request))(m, public_key, temp, len);
        }
    }
}



static void doInbound(Messenger *m)
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(public_key, secret_nonce, session_key);
    if(inconnection != -1)
    {
        int friend_id = getfriend_id(m, public_key);
        if(friend_id != -1)
        {
             crypto_kill(m->friendlist[friend_id].crypt_connection_id);
             m->friendlist[friend_id].crypt_connection_id =
             accept_crypto_inbound(inconnection, public_key, secret_nonce, session_key);

             m->friendlist[friend_id].status = 3;
        }
    }
}

/* the main loop that needs to be run at least 200 times per second. */
void doMessenger(Messenger *m)
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while(receivepacket(&ip_port, data, &length) != -1)
    {
#ifdef DEBUG
        /* if(rand() % 3 != 1) //simulate packet loss */
        /* { */
        if(DHT_handlepacket(data, length, ip_port) && LosslessUDP_handlepacket(data, length, ip_port))
        {
            /* if packet is discarded */
            printf("Received unhandled packet with length: %u\n", length);
        }
        else
        {
            printf("Received handled packet with length: %u\n", length);
        }
        /* } */
        printf("Status: %u %u %u\n",friendlist[0].status ,is_cryptoconnected(friendlist[0].crypt_connection_id),  friendlist[0].crypt_connection_id);
#else
        DHT_handlepacket(data, length, ip_port);
        LosslessUDP_handlepacket(data, length, ip_port);
#endif

    }
    doDHT();
    doLossless_UDP();
    doNetCrypto();
    doInbound(m);
    doFriendRequest(m);
    doFriends(m);
}

/* returns the size of the messenger data (for saving) */
uint32_t Messenger_size(Messenger *m)
{
    return crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
                                     + sizeof(uint32_t) + DHT_size() + sizeof(uint32_t) + sizeof(Friend) * m->numfriends;
}

/* save the messenger in data of size Messenger_size() */
void Messenger_save(Messenger *m, uint8_t * data)
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
    if(length == ~0)
    {
        return -1;
    }
    if(length < crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 2)
    {
        return -1;
    }
    length -= crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + sizeof(uint32_t) * 2;
    load_keys(data);
    data += crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    uint32_t size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);

    if(length < size)
    {
        return -1;
    }
    length -= size;
    if(DHT_load(data, size) == -1)
    {
        return -1;
    }
    data += size;
    memcpy(&size, data, sizeof(size));
    data += sizeof(size);
    if(length != size || length % sizeof(Friend) != 0)
    {
        return -1;
    }

    Friend * temp = malloc(size);
    memcpy(temp, data, size);

    uint16_t num = size / sizeof(Friend);

    uint32_t i;
    for(i = 0; i < num; ++i)
    {
        if(temp[i].status != 0)
        {
            int fnum = m_addfriend_norequest(m, temp[i].client_id);
            setfriendname(m, fnum, temp[i].name);
            /* set_friend_userstatus(fnum, temp[i].userstatus, temp[i].userstatus_length); */
        }
    }
    free(temp);
    return 0;
}
