#include "Friends.h"
#define MIN(a,b) (((a)<(b))?(a):(b))

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
    uint16_t info_size; /* length of the info */
} Friend;

uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];

#define MAX_NUM_FRIENDS 256

static Friend friendlist[MAX_NUM_FRIENDS];

static uint32_t numfriends;


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

static int send_userstatus(int friendnumber, uint8_t * status, uint16_t length)
{
    uint8_t *thepacket = malloc(length + 1);
    memcpy(thepacket + 1, status, length);
    thepacket[0] = PACKET_ID_USERSTATUS;
    int written = write_cryptpacket(friendlist[friendnumber].crypt_connection_id, thepacket, length + 1);
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

/* static void (*friend_request)(uint8_t *, uint8_t *, uint16_t);
static uint8_t friend_request_isset = 0; */
/* set the function that will be executed when a friend request is received. */
void friend_add_request_callback(void (*function)(uint8_t *, uint8_t *, uint16_t))
{
    callback_friendrequest(function);
}


static void (*friend_namechange)(int, uint8_t *, uint16_t);
static uint8_t friend_namechange_isset = 0;
void friend_name_change_callback(void (*function)(int, uint8_t *, uint16_t))
{
    friend_namechange = function;
    friend_namechange_isset = 1;
}

static void (*friend_statuschange)(int, uint8_t *, uint16_t);
static uint8_t friend_statuschange_isset = 0;
void friend_userstatus_change_callback(void (*function)(int, uint8_t *, uint16_t))
{
    friend_statuschange = function;
    friend_statuschange_isset = 1;
}

/* return friends count */
int get_friends_number()
{
    return numfriends;
}

/* return crypt connection id by friend id */
int get_friend_connection_id(int friendId)
{
    return friendlist[friendId].crypt_connection_id;
}

/* return 1 if online; 0 if ofline */
int is_friend_online(int friendId)
{
    return friendlist[friendId].status == FRIEND_ONLINE;
}

/* process incoming name change packet */
void friend_change_nickname(int friendId, uint8_t* data, uint16_t size)
{
    if (size >= MAX_NAME_LENGTH + 1 || size == 1)
        return;
    if(friend_namechange_isset)
        friend_namechange(friendId, data, size);
    memcpy(friendlist[friendId].name, data, size);
    friendlist[friendId].name[size - 1] = 0; /* make sure the NULL terminator is present. */
}

/* process incoming userstate change packet */
void friend_change_userstate(int friendId, uint8_t* data, uint16_t size)
{
    uint8_t *status = calloc(MIN(size, MAX_USERSTATUS_LENGTH), 1);
    memcpy(status, data, MIN(size, MAX_USERSTATUS_LENGTH));
    if (friend_statuschange_isset)
        friend_statuschange(friendId, status, MIN(size, MAX_USERSTATUS_LENGTH));
    set_friend_userstatus(friendId, status, MIN(size, MAX_USERSTATUS_LENGTH));
    free(status);
}

/* process friend connection timeout */
void friend_disconnect(int friendId)
{
    friendlist[friendId].crypt_connection_id = -1;
    friendlist[friendId].status = FRIEND_CONFIRMED;
}

/* tell friends that our name has changed */
void friends_selfname_updated()
{
    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].name_sent = 0;
}

/* tell friends that our status has changed */
void friends_selfstatus_updated()
{
    uint32_t i;
    for (i = 0; i < numfriends; ++i)
        friendlist[i].userstatus_sent = 0;
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
int add_friend(uint8_t *client_id, uint8_t *data, uint16_t length)
{
    if (length >= (MAX_DATA_SIZE - crypto_box_PUBLICKEYBYTES
                         - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES
                         + crypto_box_ZEROBYTES))
        return FAERR_TOOLONG;
    if (length < 1)
        return FAERR_NOMESSAGE;
    if (memcmp(client_id, self_public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return FAERR_OWNKEY;
    if (get_friend_id(client_id) != -1)
        return FAERR_ALREADYSENT;

    uint32_t i;
    for (i = 0; i <= numfriends; ++i) { /*TODO: dynamic memory allocation, this will segfault if there are more than MAX_NUM_FRIENDS*/
        if(friendlist[i].status == NOFRIEND) {
            DHT_addfriend(client_id);
            friendlist[i].status = FRIEND_ADDED;
            friendlist[i].crypt_connection_id = -1;
            friendlist[i].friend_request_id = -1;
            memcpy(friendlist[i].client_id, client_id, CLIENT_ID_SIZE);
            friendlist[i].userstatus = calloc(1, 1);
            friendlist[i].userstatus_length = 1;
            memcpy(friendlist[i].info, data, length);
            friendlist[i].info_size = length;

            ++numfriends;
            return i;
        }
    }
    return FAERR_UNKNOWN;
}

int add_friend_norequest(uint8_t *client_id)
{
    if (get_friend_id(client_id) != -1)
        return -1;
    uint32_t i;
    for (i = 0; i <= numfriends; ++i) {/*TODO: dynamic memory allocation, this will segfault if there are more than MAX_NUM_FRIENDS*/
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

/* return the friend id associated to that public key.
   return -1 if no such friend */
int get_friend_id(uint8_t *client_id)
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
int get_client_id(int friend_id, uint8_t *client_id)
{
    if (friend_id >= numfriends || friend_id < 0)
        return -1;

    if (friendlist[friend_id].status > 0) {
        memcpy(client_id, friendlist[friend_id].client_id, CLIENT_ID_SIZE);
        return 0;
    }

    return -1;
}

/* remove a friend
   return 0 if success
   return -1 if failure */
int del_friend(int friendnumber)
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
int get_friend_status(int friendnumber)
{
    if (friendnumber < 0 || friendnumber >= numfriends)
        return NOFRIEND;
    return friendlist[friendnumber].status;
}

/* get name of the friend
   put it in name
   name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
   return 0 if success
   return -1 if failure */
int get_friend_name(int friendnumber, uint8_t *name)
{
    if (friendnumber >= numfriends || friendnumber < 0)
        return -1;
    memcpy(name, friendlist[friendnumber].name, MAX_NAME_LENGTH);
    return 0;
}

//TODO: make this function not suck.
static void doProcessFriends(uint8_t *self_name,
                             uint16_t self_name_length,
                             uint8_t *self_userstatus,
                             uint16_t self_userstatus_len)
{
    /* TODO: add incoming connections and some other stuff. */
    uint32_t i;
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

            if (received_friend_packet(i, friendlist[i].crypt_connection_id)) {
                break;
            }
        }
    }
}

static void doInbound()
{
    uint8_t secret_nonce[crypto_box_NONCEBYTES];
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t session_key[crypto_box_PUBLICKEYBYTES];
    int inconnection = crypto_inbound(public_key, secret_nonce, session_key);
    if (inconnection != -1) {
        int friend_id = get_friend_id(public_key);
        if (friend_id != -1) {
            crypto_kill(friendlist[friend_id].crypt_connection_id);
            friendlist[friend_id].crypt_connection_id =
                accept_crypto_inbound(inconnection, public_key, secret_nonce, session_key);

            friendlist[friend_id].status = FRIEND_CONFIRMED;
        }
    }
}

void doFriends(uint8_t *self_name,
               uint16_t self_name_length,
               uint8_t *self_userstatus,
               uint16_t self_userstatus_len)
{
    doInbound();
    doProcessFriends(self_name, self_name_length, self_userstatus, self_userstatus_len);
}


/* returns size of friends data (for saving) */
uint32_t friends_data_size()
{
    return sizeof(Friend) * numfriends;
}

/* store friends in data */
void friends_data_save(uint8_t *data)
{
    memcpy(data, friendlist, sizeof(Friend) * numfriends);
}

/* loads friends from data */
int friends_data_load(uint8_t *data, uint32_t size)
{
    if (size % sizeof(Friend) != 0)
        return -1;

    Friend * temp = malloc(size);
    memcpy(temp, data, size);

    uint16_t num = size / sizeof(Friend);

    uint32_t i;
    for (i = 0; i < num; ++i) {
        if(temp[i].status != 0) {
            int fnum = add_friend_norequest(temp[i].client_id);
            setfriendname(fnum, temp[i].name);
            /* set_friend_userstatus(fnum, temp[i].userstatus, temp[i].userstatus_length); */
        }
    }
    free(temp);

    return 0;
}
