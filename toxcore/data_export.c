/**
 * data_export.c: Functions for working with txd_intermediate_t
 * in wire format.
 * Copyright (c) 2014 the Tox developers. All rights reserved.
 * Rest of copyright notice omitted; look at another file.
 * Documentation for functions in this file is located in the relevant
 * headers.
 */

#include <stdlib.h>
#include "data.h"
#include "data_private.h"
#pragma GCC diagnostic ignored "-Wmultichar"

/* you'll never guess which utf-8 character this is!
 * yep, you were right! it's [REDACTED] */
const txd_fourcc_t TXD_FORMAT_BINARY1 = 0xE6A19C00;
#define TXD_BLOCK_SELF    ((txd_fourcc_t)'SELf')
#define TXD_BLOCK_KEYS    ((txd_fourcc_t)'KEYs')
#define TXD_BLOCK_FRIENDS ((txd_fourcc_t)'FRNd')
#define TXD_BLOCK_DHT     ((txd_fourcc_t)'DHt*')

const uint32_t TXD_ARC_SELF_BLOCK = 1;
const uint32_t TXD_ARC_KEYS_BLOCK = 1 << 1;
const uint32_t TXD_ARC_FRIEND_BLOCK = 1 << 2;
const uint32_t TXD_ARC_DHT_BLOCK = 1 << 3;

const uint32_t TXD_ALL_BLOCKS = 0xFFFFFFFF;

#define TXD_KEYS_BLOCK_LEN (crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 4)

uint32_t _txd_load_self_block(uint8_t *buf, uint32_t block_size, txd_intermediate_t out)
{
    uint8_t *pos = buf;
    uint32_t adv, copy_len;
    /* name */
    adv = _txd_read_int_32(pos);
    pos += 4;

    if (adv > TOX_MAX_NAME_LENGTH)
        copy_len = 0;
    else
        copy_len = adv;

    out -> txd_name = copy_len ? malloc(copy_len) : NULL;
    memcpy(out -> txd_name, pos, copy_len);
    out -> txd_name_length = copy_len;
    pos += adv;

    /* status msg */
    adv = _txd_read_int_32(pos);
    pos += 4;

    if (adv > TOX_MAX_STATUSMESSAGE_LENGTH)
        copy_len = 0;
    else
        copy_len = adv;

    out -> txd_status = copy_len ? malloc(copy_len) : NULL;
    memcpy(out -> txd_status, pos, copy_len);
    out -> txd_status_length = copy_len;
    pos += adv;

    out -> txd_status_troolean = (TOX_USERSTATUS) * pos;
    return TXD_ERR_SUCCESS;
}

uint32_t _txd_load_keys_block(uint8_t *buf, uint32_t block_size, txd_intermediate_t out)
{
    if (block_size != crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES + 4)
        return TXD_ERR_SIZE_MISMATCH; /* the keys block is constant size */

    memcpy(out -> txd_public, buf, crypto_box_PUBLICKEYBYTES);
    buf += crypto_box_PUBLICKEYBYTES;
    memcpy(out -> txd_private, buf, crypto_box_SECRETKEYBYTES);
    buf += crypto_box_SECRETKEYBYTES;
    memcpy(out -> txd_nospam, buf, 4);
    return TXD_ERR_SUCCESS;
}

uint32_t _txd_load_friends_block(uint8_t *buf, uint32_t block_size, txd_intermediate_t out)
{
    uint8_t *pos = buf;

    if (block_size < 4)
        return TXD_ERR_SIZE_MISMATCH;

    uint32_t friend_count = _txd_read_int_32(buf);
    pos += 4;
    uint32_t guaranteed_size = (9 + TOX_FRIEND_ADDRESS_SIZE) * friend_count;

    /* i'm kinda paranoid about people jacking up the friend count
     * and making us alloc too much memory
     * this check helps but not really */
    if (guaranteed_size > block_size - 4)
        return TXD_ERR_SIZE_MISMATCH;

    struct txd_friend *friends = calloc(sizeof(struct txd_friend), friend_count);
    int i, j;

    for (i = 0; i < friend_count; ++i) {
        struct txd_friend *f = &(friends[i]);
        f -> txd_flags = *pos;
        pos += 1;
        memcpy(f -> txd_addr, pos, TOX_FRIEND_ADDRESS_SIZE);
        pos += TOX_FRIEND_ADDRESS_SIZE;
        uint32_t nl = _txd_read_int_32(pos);
        pos += 4;

        if (guaranteed_size + nl > block_size)
            goto kill;

        f -> txd_name_length = nl;
        f -> txd_name = malloc(nl);
        memcpy(f -> txd_name, pos, nl);
        pos += nl;
        uint32_t dl = 0;

        if (f -> txd_flags & TXD_BIT_NEEDS_FRIEND_REQUEST) {
            dl = _txd_read_int_32(pos);
            pos += 4;

            if (guaranteed_size + nl + dl > block_size)
                goto kill;

            f -> txd_data_length = dl;
            f -> txd_data = malloc(dl);
            memcpy(f -> txd_data, pos, dl);
            pos += dl;
        } else {
            f -> txd_data_length = 0;
            f -> txd_data = NULL;
        }

        uint32_t fex_count = _txd_read_int_32(pos);
        pos += 4;

        if (guaranteed_size + nl + dl + (fex_count * 6) > block_size)
            goto kill;

        int k;

        for (k = 0; k < fex_count; ++k) {
            /* read a twocc from buffer
             * this could be longer and clear but no */
            /* txd_twocc_t fex_key = ntohs(*(txd_twocc_t*)pos);
            uint32_t fex_data_length = _txd_read_int_32(pos + 2);
            pos += 6; */
            /* this is where we would switch on fex values
             * there aren't any, so continue */
            uint32_t fex_data_length = _txd_read_int_32(pos + 2);
            pos += 6 + fex_data_length;
        }

        uint32_t read_so_far = (uint32_t)(pos - buf);

        if (read_so_far > block_size)
            goto kill;
    }

    out -> txd_friends = friends;
    out -> txd_friends_length = friend_count;
    return TXD_ERR_SUCCESS;
kill: /* we need to release the friend structs here, all of it */

    for (j = 0; j < friend_count; ++j) {
        free(friends[j].txd_name);
        free(friends[j].txd_data);
    }

    _txd_kill_memory(friends, sizeof(struct txd_friend) * friend_count);
    free(friends);
    out -> txd_friends = NULL;
    out -> txd_friends_length = 0;
    return TXD_ERR_SIZE_MISMATCH;
}

uint32_t _txd_load_dht_block(uint8_t *buf, uint32_t block_size, txd_intermediate_t out)
{
    uint8_t *pos = buf;

    if (block_size < 4)
        return TXD_ERR_SIZE_MISMATCH;

    uint32_t dht_count = _txd_read_int_32(pos);
    pos += 4;

    if (dht_count > LCLIENT_LIST)
        dht_count = LCLIENT_LIST;

    if (block_size < 4 + ((crypto_box_PUBLICKEYBYTES + 25) * dht_count))
        return TXD_ERR_SIZE_MISMATCH;

    struct txd_dhtlite *dhtlites = calloc(sizeof(struct txd_dhtlite), dht_count);
    int i;

    for (i = 0; i < dht_count; ++i) {
        struct txd_dhtlite *cur = &(dhtlites[i]);
        memcpy(cur -> txd_dhtlite_onion_id, pos, crypto_box_PUBLICKEYBYTES);
        pos += crypto_box_PUBLICKEYBYTES;
        uint8_t flag = *pos;
        pos += 1;
        cur -> txd_flags = flag;

        if (flag & TXD_BIT_HAS_INET4) {
            memcpy(&(cur -> txd_bytes_inet4), pos, 4);
            memcpy(&(cur -> txd_port4), pos + 4, 2);
        }

        pos += 6;

        if (flag & TXD_BIT_HAS_INET6) {
            memcpy(&(cur -> txd_bytes_inet6), pos, 16);
            memcpy(&(cur -> txd_port6), pos + 16, 2);
        }

        pos += 18;
    }

    out -> txd_dhtlite = dhtlites;
    out -> txd_dhtlite_length = dht_count;
    return TXD_ERR_SUCCESS;
}

/* Operations on full intermediates. */

uint64_t txd_get_size_of_intermediate(txd_intermediate_t im)
{
    return txd_get_size_of_intermediate_ex(im, TXD_ALL_BLOCKS);
}

uint64_t txd_get_size_of_intermediate_ex(txd_intermediate_t im, uint32_t arc_blocks)
{
    uint64_t running_total = 12;

    /* the base length is ??? bytes.
     * 4 bytes for magic TXD_FORMAT_BINARY1
     * 8 bytes for the length of the rest of the file
     * + more for various magics */
    /* self block: magic, name&status lengths, troolean, keys & nospam
     * don't worry, the compiler will optimize it down to a constant :^) */
    if (arc_blocks & TXD_ARC_SELF_BLOCK) {
        running_total += 17;
        running_total += txd_get_length_of_name(im);
        running_total += txd_get_length_of_status_message(im);
    }

    if (arc_blocks & TXD_ARC_KEYS_BLOCK) {
        running_total += 12 + crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES;
    }

    if (arc_blocks & TXD_ARC_FRIEND_BLOCK) {
        running_total += 12; /* friend count */
        uint32_t friend_count = txd_get_number_of_friends(im);
        running_total += (9 + TOX_FRIEND_ADDRESS_SIZE) * friend_count;
        int i;

        for (i = 0; i < friend_count; ++i) {
            running_total += txd_get_length_of_friend_name(im, i);

            if (txd_get_needs_requests(im, i))
                running_total += 4 + txd_get_length_of_request_data(im, i);
        }
    }

    if (arc_blocks & TXD_ARC_DHT_BLOCK) {
        running_total += 12; /* dht count */
        uint32_t dhtlite_count = txd_get_number_of_dht_nodes(im);
        running_total += (crypto_box_PUBLICKEYBYTES + 25) * dhtlite_count;
    }

    return running_total;
}

uint32_t txd_export_to_buf(txd_intermediate_t im, uint8_t **buf,
                           uint64_t *size)
{
    return txd_export_to_buf_ex(im, buf, size, TXD_ALL_BLOCKS);
}

uint32_t txd_export_to_buf_ex(txd_intermediate_t im, uint8_t **buf,
                              uint64_t *size, uint32_t arc_blocks)
{
    uint64_t block_size = txd_get_size_of_intermediate_ex(im, arc_blocks);

    if (size)
        *size = block_size;

    if (!buf)
        return TXD_ERR_SUCCESS;

    uint8_t *rbuf = malloc(block_size);
    uint32_t save_ret = txd_export_to_buf_prealloc(im, rbuf, block_size, arc_blocks);

    if (save_ret != TXD_ERR_SUCCESS) {
        _txd_kill_memory(rbuf, block_size);
        free(rbuf);
        *buf = NULL;
    } else {
        *buf = rbuf;
    }

    return save_ret;
}

uint32_t txd_export_to_buf_prealloc(txd_intermediate_t im, uint8_t *buf,
                                    uint64_t block_size, uint32_t arc_blocks)
{
    uint8_t *pos = buf;
    _txd_write_int_32(TXD_FORMAT_BINARY1, pos);
    pos += 4;
    _txd_write_int_64(block_size - 12, pos);
    pos += 8;

    if (arc_blocks & TXD_ARC_SELF_BLOCK) {
        /* layout of self block:
         * [SELf:4][len:4]
         * [name len:4][name:nl]
         * [stat len:4][stat:sl]
         * [ustat:1]
         */
        _txd_write_int_32(TXD_BLOCK_SELF, pos);
        pos += 4;
        uint32_t nl = txd_get_length_of_name(im),
                 sl = txd_get_length_of_status_message(im);
        uint32_t sb_size = (9 + nl + sl);
        _txd_write_int_32(sb_size, pos);
        pos += 4;
        _txd_write_int_32(nl, pos);
        pos += 4;
        txd_copy_name(im, pos, nl);
        pos += nl;
        _txd_write_int_32(sl, pos);
        pos += 4;
        txd_copy_status_message(im, pos, sl);
        pos += sl;
        *pos = txd_get_user_status(im);
        pos += 1;
    }

    if (arc_blocks & TXD_ARC_KEYS_BLOCK) {
        _txd_write_int_32(TXD_BLOCK_KEYS, pos);
        pos += 4;
        _txd_write_int_32(TXD_KEYS_BLOCK_LEN, pos);
        pos += 4;
        txd_copy_public_key(im, pos);
        pos += crypto_box_PUBLICKEYBYTES;
        txd_copy_secret_key(im, pos);
        pos += crypto_box_SECRETKEYBYTES;
        txd_copy_nospam(im, pos);
        pos += 4;
    }

    if (arc_blocks & TXD_ARC_FRIEND_BLOCK) {
        _txd_write_int_32(TXD_BLOCK_FRIENDS, pos);
        pos += 4;
        uint8_t *lptr = pos;
        pos += 4;
        /* saves the position of the length so we can calculate
         * as we go along, then write at end */
        uint32_t block_total = 4;
        uint32_t friend_count = txd_get_number_of_friends(im);
        _txd_write_int_32(friend_count, pos);
        pos += 4;
        int i;

        for (i = 0; i < friend_count; ++i) {
            *pos = im -> txd_friends[i].txd_flags;
            pos += 1;
            txd_copy_friend_address(im, i, pos);
            pos += TOX_FRIEND_ADDRESS_SIZE;
            uint32_t nl = txd_get_length_of_friend_name(im, i);
            _txd_write_int_32(nl, pos);
            pos += 4;
            txd_copy_friend_name(im, i, pos, nl);
            pos += nl;

            if (txd_get_needs_requests(im, i)) {
                uint32_t dl = txd_get_length_of_request_data(im, i);
                _txd_write_int_32(dl, pos);
                pos += 4;
                txd_copy_request_data(im, i, pos, dl);
                pos += dl;
                block_total += 4 + dl;
            }

            _txd_write_int_32(0, pos);
            pos += 4;
            /* count of FrEx k/v pairs */
            block_total += 9 + TOX_FRIEND_ADDRESS_SIZE + nl;
        }

        _txd_write_int_32(block_total, lptr);
    }

    if (arc_blocks & TXD_ARC_DHT_BLOCK) {
        _txd_write_int_32(TXD_BLOCK_DHT, pos);
        pos += 4;
        uint8_t *lptr = pos;
        pos += 4;
        /* saves the position of the length so we can calculate
         * as we go along, then write at end */
        uint32_t block_total = 4;
        uint32_t node_count = txd_get_number_of_dht_nodes(im);
        _txd_write_int_32(node_count, pos);
        pos += 4;
        int i;

        for (i = 0; i < node_count; ++i) {
            txd_copy_dht_client_id(im, i, pos);
            pos += crypto_box_PUBLICKEYBYTES;
            *pos = im -> txd_dhtlite[i].txd_flags;
            pos += 1;

            if (txd_get_dht_has_ip4(im, i)) {
                txd_copy_dht_ip4(im, i, pos);
                pos += 4;
                uint16_t port4 = htons(txd_get_dht_port4(im, i));
                memcpy(pos, &port4, 2);
                pos += 2;
            } else {
                memset(pos, 0, 6);
                pos += 6;
            }

            if (txd_get_dht_has_ip6(im, i)) {
                txd_copy_dht_ip6(im, i, pos);
                pos += 16;
                uint16_t port6 = htons(txd_get_dht_port6(im, i));
                memcpy(pos, &port6, 2);
                pos += 2;
            } else {
                memset(pos, 0, 18);
                pos += 18;
            }

            block_total += crypto_box_PUBLICKEYBYTES + 25;
            /* we used padding here because i am a lazy shit */
        }

        _txd_write_int_32(block_total, lptr);
    }

    return TXD_ERR_SUCCESS;
}

uint32_t txd_intermediate_from_buf(uint8_t *buf, uint64_t size,
                                   txd_intermediate_t *out)
{
    if (size <= 12)
        return TXD_ERR_BAD_BLOCK;

    uint8_t *pos = buf + 4;
    uint32_t magic = _txd_read_int_32(buf);

    /* warning! below only works because TXD_FORMAT_BINARY1 has a null at the
     * end */
    /* note: above comment is deprecated, ignore */
    if (magic != TXD_FORMAT_BINARY1) {

        return TXD_ERR_BAD_BLOCK;
    }

    uint64_t vsize = _txd_read_int_64(pos);
    pos += 8;

    if (size - 12 != vsize)
        return TXD_ERR_SIZE_MISMATCH;

    size -= 12;
    txd_intermediate_t base = calloc(sizeof(*base), 1);

    while (size > 0) {
        uint32_t b_magic = _txd_read_int_32(pos);
        pos += 4;
        uint32_t b_size = _txd_read_int_32(pos);
        pos += 4;

        if (b_size == 0 || b_size > size) {
            /* a block size of 0 is illegal */
            txd_intermediate_free(base);
            return TXD_ERR_SIZE_MISMATCH;
        }

        uint32_t delegation_ret = 0;

        switch (b_magic) {
            case TXD_BLOCK_SELF:
                delegation_ret = _txd_load_self_block(pos, b_size, base);
                break;

            case TXD_BLOCK_KEYS:
                delegation_ret = _txd_load_keys_block(pos, b_size, base);
                break;

            case TXD_BLOCK_FRIENDS:
                delegation_ret = _txd_load_friends_block(pos, b_size, base);
                break;

            case TXD_BLOCK_DHT:
                delegation_ret = _txd_load_dht_block(pos, b_size, base);

            default:
                break;
        }

        if (delegation_ret != TXD_ERR_SUCCESS) {
            txd_intermediate_free(base);

            if (out)
                *out = NULL;

            return delegation_ret;
        }

        size -= b_size + 8;
        pos += b_size;
    }

    if (out)
        *out = base;
    else
        txd_intermediate_free(base);

    return TXD_ERR_SUCCESS;
}
