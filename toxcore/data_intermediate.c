/**
 * data_intermediate.c: Functions for working with txd_intermediate_t
 * as an internal data structure.
 * Copyright (c) 2014 the Tox developers. All rights reserved.
 * Rest of copyright notice omitted; look at another file.
 */

#include "data.h"
#include "data_private.h"
#include "util.h"

const uint32_t TXD_ERR_BAD_BLOCK        = -2049;
const uint32_t TXD_ERR_SIZE_MISMATCH    = -2050;
const uint32_t TXD_ERR_NOT_IMPLEMENTED  = -2052;
const uint32_t TXD_ERR_SUCCESS          = 0;

const uint8_t TXD_BIT_NEEDS_FRIEND_REQUEST = 1; /* bit 1 */
const uint8_t TXD_BIT_SENDS_RECEIPTS = 1 << 1; /* bit 2 */

const uint8_t TXD_BIT_HAS_INET4 = 1; /* bit 1 */
const uint8_t TXD_BIT_HAS_INET6 = 1 << 1; /* bit 2 */

/* Intermediates */

/* TODO: save DHT stuff */
txd_intermediate_t txd_intermediate_from_tox(Tox *tox)
{
    Messenger *tox_ = (Messenger *)tox;
    txd_intermediate_t interm = malloc(sizeof(*interm));
    interm -> txd_name_length = tox_ -> name_length;
    /* interm -> txd_name_length = tox_get_self_name_size(tox); */
    interm -> txd_name = malloc(interm -> txd_name_length);
    /* tox.h: "it must be at least MAX_NAME_LENGTH"... but Messenger code
     * says otherwise */
    tox_get_self_name(tox, interm -> txd_name);

    /* interm -> txd_status_length = tox_get_self_status_message_size(tox); */
    interm -> txd_status_length = tox_ -> statusmessage_length;
    interm -> txd_status = malloc(interm -> txd_status_length);
    tox_get_self_status_message(tox, interm -> txd_status, interm -> txd_status_length);
    interm -> txd_status_troolean = tox_get_self_user_status(tox);

    memcpy(interm -> txd_public, tox_ -> net_crypto -> self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(interm -> txd_private, tox_ -> net_crypto -> self_secret_key, crypto_box_PUBLICKEYBYTES);
    memcpy(interm -> txd_nospam, &(tox_ -> fr.nospam), sizeof(uint32_t));

    uint32_t numfriends = tox_count_friendlist(tox);
    struct txd_friend *friends = malloc(numfriends * sizeof(struct txd_friend));
    int32_t toxfl[numfriends];
    uint32_t actual_number_of_friends = numfriends;
    tox_get_friendlist(tox, toxfl, numfriends);
    int i;

    for (i = 0; i < numfriends; ++i) {
        int32_t f_n = toxfl[i];
        uint8_t flag = 0;

        if (tox_ -> friendlist[f_n].status < FRIEND_CONFIRMED) {
            flag |= TXD_BIT_NEEDS_FRIEND_REQUEST;
            uint16_t info_len = tox_ -> friendlist[f_n].info_size;
            uint8_t *data = malloc(info_len);
            memcpy(data, tox_ -> friendlist[f_n].info, info_len);
            friends[i].txd_data = data;
            friends[i].txd_data_length = info_len;
        } else {
            friends[i].txd_data = NULL;
            friends[i].txd_data_length = 0;
        }

        if (tox_ -> friendlist[f_n].receives_read_receipts) {
            flag |= TXD_BIT_SENDS_RECEIPTS;
        }

        friends[i].txd_flags = flag;
        /* uint32_t friend_name_len = tox_get_name_size(tox, f_n); */
        uint32_t friend_name_len = tox_ -> friendlist[f_n].name_length;
        friends[i].txd_name_length = friend_name_len;
        friends[i].txd_name = malloc(friend_name_len);
        tox_get_name(tox, f_n, friends[i].txd_name);
        tox_get_client_id(tox, f_n, friends[i].txd_addr);
        memcpy(friends[i].txd_addr + TOX_CLIENT_ID_SIZE,
               &(tox_ -> friendlist[f_n].friendrequest_nospam), sizeof(uint32_t));
    }

    /* something to think about: can we prevent ourselves from allocating
     * more memory than we actually need here? */
    struct txd_dhtlite *dht_save = calloc(sizeof(struct txd_dhtlite), LCLIENT_LIST);
    /* copy out dht nodes (irungentoo said this was all i needed...) */
    Client_data *dht_close = tox_ -> dht -> close_clientlist;
    unix_time_update();
    uint32_t num_dhtlite = 0;
    int j;

    for (j = 0; j < LCLIENT_LIST; ++j) {
        uint8_t flags = 0;

        if (!is_timeout(dht_close[j].assoc4.timestamp, BAD_NODE_TIMEOUT)) {
            flags = (flags | TXD_BIT_HAS_INET4);
            IP_Port ipp4 = dht_close[j].assoc4.ip_port;

            if (ipp4.ip.family != AF_INET)
                continue; /* wtf?? */

            dht_save[num_dhtlite].txd_port4 = ipp4.port;
            memcpy(dht_save[num_dhtlite].txd_bytes_inet4, ipp4.ip.ip4.uint8, 4);
        }

        if (!is_timeout(dht_close[j].assoc6.timestamp, BAD_NODE_TIMEOUT)) {
            flags = (flags | TXD_BIT_HAS_INET6);
            IP_Port ipp6 = dht_close[j].assoc6.ip_port;

            if (ipp6.ip.family != AF_INET6)
                continue; /* wtf wtf wtf wtf?? */

            dht_save[num_dhtlite].txd_port6 = ipp6.port;
            memcpy(dht_save[num_dhtlite].txd_bytes_inet4, ipp6.ip.ip6.uint8, 16);
        }

        dht_save[num_dhtlite].txd_flags = flags;
        memcpy(dht_save[num_dhtlite].txd_dhtlite_onion_id,
               dht_close[num_dhtlite].client_id, TOX_CLIENT_ID_SIZE);

        if (flags)
            ++num_dhtlite;

    }

    interm -> txd_dhtlite = dht_save;
    interm -> txd_dhtlite_length = num_dhtlite;

    interm -> txd_friends_length = actual_number_of_friends;
    interm -> txd_friends = friends;
    return interm;
}

int txd_restore_intermediate(txd_intermediate_t interm, Tox *tox)
{
    tox_set_name(tox, interm -> txd_name, interm -> txd_name_length);
    tox_set_status_message(tox, interm -> txd_status, interm -> txd_status_length);
    tox_set_user_status(tox, interm -> txd_status_troolean);

    Messenger *tox_ = (Messenger *)tox;

    memcpy(tox_ -> net_crypto -> self_public_key,
           interm -> txd_public, crypto_box_PUBLICKEYBYTES);
    memcpy(tox_ -> net_crypto -> self_secret_key,
           interm -> txd_private, crypto_box_SECRETKEYBYTES);
    memcpy(&(tox_ -> fr.nospam),
           interm -> txd_nospam, sizeof(uint32_t));

    struct txd_friend *friend = NULL;
    int i;

    for (i = 0; i < interm -> txd_friends_length; ++i) {
        friend = &(interm -> txd_friends[i]);
        int32_t new_friendnum = -1;

        if (friend -> txd_flags & TXD_BIT_NEEDS_FRIEND_REQUEST) {
            /* probably doesn't work */
            new_friendnum = tox_add_friend(tox, friend -> txd_addr,
                                           friend -> txd_data,
                                           friend -> txd_data_length);
        } else {
            new_friendnum = tox_add_friend_norequest(tox, friend -> txd_addr);
        }

        if (friend -> txd_flags & TXD_BIT_SENDS_RECEIPTS)
            tox_set_sends_receipts(tox, new_friendnum, 1);
    }

    struct txd_dhtlite *server = NULL; /* lu stqism :^) */

    int j;

    for (j = 0; j < interm -> txd_dhtlite_length; ++j) {
        server = &(interm -> txd_dhtlite[j]);
        /* is it bad to DHT_bootstrap so many times? */
        IP_Port ippn;

        if (server -> txd_flags & TXD_BIT_HAS_INET4) {
            IP the_ip;
            the_ip.family = AF_INET;
            memset(the_ip.padding, 0, 3);
            IP4 ip4;
            memcpy(ip4.uint8, server -> txd_bytes_inet4, 4);
            the_ip.ip4 = ip4;
            ippn.ip = the_ip;
            ippn.port = server -> txd_port4;
            DHT_bootstrap(tox_ -> dht, ippn, server -> txd_dhtlite_onion_id);
        }

        if (server -> txd_flags & TXD_BIT_HAS_INET6) {
            IP the_ip;
            the_ip.family = AF_INET;
            IP6 ip6;
            memcpy(ip6.uint8, server -> txd_bytes_inet6, 16);
            the_ip.ip6 = ip6;
            ippn.ip = the_ip;
            ippn.port = server -> txd_port4;
            DHT_bootstrap(tox_ -> dht, ippn, server -> txd_dhtlite_onion_id);
        }
    }

    return TXD_ERR_SUCCESS;
}

void txd_intermediate_free(txd_intermediate_t interm)
{
    _txd_kill_memory(interm -> txd_name, interm -> txd_name_length);
    free(interm -> txd_name);

    _txd_kill_memory(interm -> txd_status, interm -> txd_status_length);
    free(interm -> txd_status);

    struct txd_friend *friend = NULL;
    int i;

    for (i = 0; i < interm -> txd_friends_length; ++i) {
        friend = &(interm -> txd_friends[i]);
        _txd_kill_memory(friend -> txd_data, friend -> txd_data_length);
        _txd_kill_memory(friend -> txd_name, friend -> txd_name_length);
        free(friend -> txd_data);
        free(friend -> txd_name);
    }

    _txd_kill_memory(interm -> txd_dhtlite,
                     sizeof(struct txd_dhtlite) * interm -> txd_dhtlite_length);
    free(interm -> txd_dhtlite);
    _txd_kill_memory(interm -> txd_friends, sizeof(struct txd_friend) * interm -> txd_friends_length);
    free(interm -> txd_friends);
    _txd_kill_memory(interm, sizeof(struct txd_intermediate));
    free(interm);
}

/* Intermediate getters
 * The intermediate is immutable. */

uint32_t txd_get_length_of_name(txd_intermediate_t interm)
{
    return interm -> txd_name_length;
}

void txd_copy_name(txd_intermediate_t interm, uint8_t *out, uint32_t max_len)
{
    uint32_t copy_len = interm -> txd_name_length;

    /* tfw C stdlib has no min/max macros */
    if (copy_len > max_len)
        copy_len = max_len;

    memcpy(out, interm -> txd_name, copy_len);
}

uint32_t txd_get_length_of_status_message(txd_intermediate_t interm)
{
    return interm -> txd_status_length;
}

void txd_copy_status_message(txd_intermediate_t interm, uint8_t *out, uint32_t max_len)
{
    uint32_t copy_len = interm -> txd_status_length;

    if (copy_len > max_len)
        copy_len = max_len;

    memcpy(out, interm -> txd_status, copy_len);
}

TOX_USERSTATUS txd_get_user_status(txd_intermediate_t interm)
{
    return (TOX_USERSTATUS)interm -> txd_status_troolean;
}

void txd_copy_public_key(txd_intermediate_t interm, uint8_t *out)
{
    memcpy(out, interm -> txd_public, crypto_box_PUBLICKEYBYTES);
}

void txd_copy_secret_key(txd_intermediate_t interm, uint8_t *out)
{
    memcpy(out, interm -> txd_private, crypto_box_SECRETKEYBYTES);
}

void txd_copy_nospam(txd_intermediate_t interm, uint8_t *out)
{
    memcpy(out, interm -> txd_nospam, 4);
}

uint32_t txd_get_number_of_friends(txd_intermediate_t interm)
{
    return interm -> txd_friends_length;
}

uint32_t txd_get_length_of_friend_name(txd_intermediate_t interm, uint32_t f_n)
{
    return interm -> txd_friends[f_n].txd_name_length;
}

void txd_copy_friend_name(txd_intermediate_t interm, uint32_t f_n, uint8_t *out, uint32_t max_len)
{
    uint32_t copy_len = interm -> txd_friends[f_n].txd_name_length;

    if (copy_len > max_len)
        copy_len = max_len;

    memcpy(out, interm -> txd_friends[f_n].txd_name, copy_len);
}

void txd_copy_friend_client_id(txd_intermediate_t interm, uint32_t f_n, uint8_t *out)
{
    memcpy(out, interm -> txd_friends[f_n].txd_addr, TOX_CLIENT_ID_SIZE);
}

void txd_copy_friend_address(txd_intermediate_t interm, uint32_t f_n, uint8_t *out)
{
    memcpy(out, interm -> txd_friends[f_n].txd_addr, TOX_FRIEND_ADDRESS_SIZE);
}

uint8_t txd_get_sends_receipts(txd_intermediate_t interm, uint32_t f_n)
{
    return (interm -> txd_friends[f_n].txd_flags & TXD_BIT_SENDS_RECEIPTS) == TXD_BIT_SENDS_RECEIPTS;
}

uint8_t txd_get_needs_requests(txd_intermediate_t interm, uint32_t f_n)
{
    return (interm -> txd_friends[f_n].txd_flags & TXD_BIT_NEEDS_FRIEND_REQUEST) == TXD_BIT_NEEDS_FRIEND_REQUEST;
}

uint16_t txd_get_length_of_request_data(txd_intermediate_t interm, uint32_t f_n)
{
    return interm -> txd_friends[f_n].txd_data_length;
}

void txd_copy_request_data(txd_intermediate_t interm, uint32_t f_n, uint8_t *out, uint32_t max_len)
{
    uint32_t copy_len = interm -> txd_friends[f_n].txd_data_length;

    if (copy_len > max_len)
        copy_len = max_len;

    memcpy(out, interm -> txd_friends[f_n].txd_data, copy_len);
}

uint32_t txd_get_number_of_dht_nodes(txd_intermediate_t interm)
{
    return interm -> txd_dhtlite_length;
}

void txd_copy_dht_client_id(txd_intermediate_t interm, uint32_t node, uint8_t *out)
{
    memcpy(out, interm -> txd_dhtlite[node].txd_dhtlite_onion_id, TOX_CLIENT_ID_SIZE);
}

uint8_t txd_get_dht_has_ip4(txd_intermediate_t interm, uint32_t node)
{
    return (interm -> txd_dhtlite[node].txd_flags & TXD_BIT_HAS_INET4)
           == TXD_BIT_HAS_INET4;
}

uint8_t txd_get_dht_has_ip6(txd_intermediate_t interm, uint32_t node)
{
    return (interm -> txd_dhtlite[node].txd_flags & TXD_BIT_HAS_INET6)
           == TXD_BIT_HAS_INET6;
}

uint16_t txd_get_dht_port4(txd_intermediate_t interm, uint32_t node)
{
    return ntohs(interm -> txd_dhtlite[node].txd_port4);
}

void txd_copy_dht_ip4(txd_intermediate_t interm, uint32_t node, uint8_t *out)
{
    memcpy(out, interm -> txd_dhtlite[node].txd_bytes_inet4, 4);
}

uint16_t txd_get_dht_port6(txd_intermediate_t interm, uint32_t node)
{
    return ntohs(interm -> txd_dhtlite[node].txd_port6);
}

void txd_copy_dht_ip6(txd_intermediate_t interm, uint32_t node, uint8_t *out)
{
    memcpy(out, interm -> txd_dhtlite[node].txd_bytes_inet6, 16);
}
