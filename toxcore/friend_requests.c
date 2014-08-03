/* friend_requests.c
 *
 * Handle friend requests.
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

#include "friend_requests.h"
#include "Messenger.h"
#include "util.h"

//The hashdata will include our pubkey ++ the receiver's pubkey ++ the receiver's nospam_num ++ nNonce
struct __attribute__((__packed__)) hashcash_s
{
    u8int sender_pubkey[crypto_box_PUBLICKEYBYTES];
    u8int receiver_pubkey[crypto_box_PUBLICKEYBYTES];
    u32int receiver_nospam_num;
    uint64 nNonce;
}; 

inline bool hash_meets_target(u8int hash[static crypto_hash_sha256_BYTES])
{
    return hash[0] == 0x00 && hash[1] == 0x00 && hash[2] <= 0x17;
}

/* Try to send a friend request to peer with public_key.
 * data is the data in the request and length is the length.
 *
 *  return -1 if failure.
 *  return  0 if it sent the friend request directly to the friend.
 *  return the number of peers it was routed through if it did not send it directly.
 */
int send_friendrequest(const Messenger *messenger, const Onion_Client *onion_c, const uint8_t *public_key, 
                       uint32_t nospam_num, const uint8_t *data, uint32_t length)
{
    if (length > MAX_FRIEND_REQUEST_DATA_SIZE || length == 0)
        return -1;

    int friend_num = onion_friend_num(onion_c, public_key);

    if (friend_num == -1)
        return -1;

    //The data to be hashed
    struct hashcash_s hashdata;

    //set the nonce to the last recorded and copy over the constant data
    // 0 if the friend is new
    hashdata.nNonce = onion_c->friends_list[friend_num].last_nNonce;

    id_copy(hashdata.sender_pubkey, messenger->net_crypto->self_public_key);
    id_copy(hashdata.receiver_pubkey, public_key);
    hashdata.receiver_nospam_num = nospam_num;

    //scan for a good hash
    u8int outhash[crypto_hash_sha256_BYTES];
    for(;; hashdata.nNonce++)
    {
        //hash the hashdata
        crypto_hash_sha256(outhash, (const u8int*)&hashdata, sizeof(struct hashcash_s));

        //did it meet the target
        if(hash_meets_target(outhash))
            break;

        //increment the nNonce if did not meet the target
        hashdata.nNonce++;
    }

    //Once a good hash has been found, record the god nNonce in the friend entry
    onion_c->friends_list[friend_num].last_nNonce = hashdata.nNonce;

    uint8_t temp[1 + sizeof(nospam_num) + sizeof(hashdata.nNonce) + length];
    temp[0] = CRYPTO_PACKET_FRIEND_REQ;
    memcpy(temp + 1, &nospam_num, sizeof(nospam_num));
    memcpy(temp + 1 + sizeof(nospam_num), &hashdata.nNonce, sizeof(hashdata.nNonce));
    memcpy(temp + 1 + sizeof(nospam_num) + sizeof(hashdata.nNonce), data, length);

    int num = send_onion_data(onion_c, friend_num, temp, sizeof(temp));

    if (num <= 0)
        return -1;

    return num;
}


/* Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(Friend_Requests *fr, uint32_t num)
{
    fr->nospam = num;
}

uint32_t get_nospam(const Friend_Requests *fr)
{
    return fr->nospam;
}


/* Set the function that will be executed when a friend request is received. */
void callback_friendrequest(Friend_Requests *fr, 
                            void (*function)(void *, const uint8_t *, const uint8_t *, uint16_t, void *), 
                            void *object, void *userdata)
{
    fr->handle_friendrequest = function;
    fr->handle_friendrequest_isset = 1;
    fr->handle_friendrequest_object = object;
    fr->handle_friendrequest_userdata = userdata;
}
/* Set the function used to check if a friend request should be displayed to the user or not. */
void set_filter_function(Friend_Requests *fr, int (*function)(const uint8_t *, void *), void *userdata)
{
    fr->filter_function = function;
    fr->filter_function_userdata = userdata;
}

/* Add to list of received friend requests. */
static void addto_receivedlist(Friend_Requests *fr, const uint8_t *client_id)
{
    if (fr->received_requests_index >= MAX_RECEIVED_STORED)
        fr->received_requests_index = 0;

    id_copy(fr->received_requests[fr->received_requests_index], client_id);
    ++fr->received_requests_index;
}

/* Check if a friend request was already received.
 *
 *  return 0 if it did not.
 *  return 1 if it did.
 */
static int request_received(Friend_Requests *fr, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < MAX_RECEIVED_STORED; ++i)
        if (id_equal(fr->received_requests[i], client_id))
            return 1;

    return 0;
}

/* Remove client id from received_requests list.
 *
 *  return 0 if it removed it successfully.
 *  return -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *fr, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received_requests[i], client_id)) {
            memset(fr->received_requests[i], 0, crypto_box_PUBLICKEYBYTES);
            return 0;
        }
    }

    return -1;
}

static int friendreq_handlepacket(void *object, const uint8_t *source_pubkey, 
                                  const uint8_t *packet, uint32_t length)
{
    Messenger *messenger = object;
    Friend_Requests *fr = &(messenger->fr);

    if (length <= 1 + sizeof(fr->nospam) || length > ONION_CLIENT_MAX_DATA_SIZE)
        return 1;

    //increment packet and decrement the length since the identifying byte in packet is no longer needed
    ++packet;
    --length;

    if (fr->handle_friendrequest_isset == 0)
        return 1;

    if (request_received(fr, source_pubkey))
        return 1;

    if (memcmp(packet, &fr->nospam, sizeof(fr->nospam)) != 0)
        return 1;

    //increment packet and decrement the length as the nospam in packet is no longer needed
    packet += sizeof(fr->nospam);
    length -= sizeof(fr->nospam);

    if (fr->filter_function)
        if ((*fr->filter_function)(source_pubkey, fr->filter_function_userdata) != 0)
            return 1;

    //Build the hash data
    struct hashcash_s hashdata;

    id_copy(hashdata.sender_pubkey, source_pubkey);
    id_copy(hashdata.receiver_pubkey, messenger->net_crypto->self_public_key);
    hashdata.receiver_nospam_num = fr->nospam;
    memcpy(&hashdata.nNonce, packet, sizeof(hashdata.nNonce));

    //increment packet and decrement the length as the hashdata.nNonce in packet is no longer needed
    packet += sizeof(hashdata.nNonce);
    length -= sizeof(hashdata.nNonce);

    //Hash and check if it meets the target
    u8int outhash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(outhash, (const u8int*)&hashdata, sizeof(struct hashcash_s));

    if(!hash_meets_target(outhash))
        return 1;

    addto_receivedlist(fr, source_pubkey);

    uint32_t message_len = length;
    uint8_t message[message_len + 1];
    memcpy(message, packet + sizeof(fr->nospam), message_len);
    message[sizeof(message) - 1] = 0; /* Be sure the message is null terminated. */

    (*fr->handle_friendrequest)(fr->handle_friendrequest_object, source_pubkey, message, message_len,
                                fr->handle_friendrequest_userdata);
    return 0;
}

void friendreq_init(Messenger *messenger, Onion_Client *onion_c)
{
    oniondata_registerhandler(onion_c, CRYPTO_PACKET_FRIEND_REQ, &friendreq_handlepacket, messenger);    
}
