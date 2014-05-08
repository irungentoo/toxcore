/**
 * data_private.h: it's like data.h, but private, like bread
 * Copyright (c) 2014 the Tox developers. All rights reserved.
 * Rest of copyright notice omitted; look at another file.
 */

#ifndef TXD_PRIVATE_H
#define TXD_PRIVATE_H
#include <sys/types.h>
#include <sys/param.h>
#include "Messenger.h"

extern const uint8_t TXD_BIT_NEEDS_FRIEND_REQUEST;
extern const uint8_t TXD_BIT_SENDS_RECEIPTS;
extern const uint8_t TXD_BIT_HAS_INET4;
extern const uint8_t TXD_BIT_HAS_INET6;

/**
 * Endian-ness and stuff
 * probably only works on linux and BSD-like
 */

static inline void _txd_write_int_32_le(uint32_t the_int, uint8_t *buf)
{
    buf[0] = the_int >> 24;
    buf[1] = the_int >> 16;
    buf[2] = the_int >> 8;
    buf[3] = the_int;
}

static inline void _txd_write_int_64_le(uint64_t the_int, uint8_t *buf)
{
    buf[0] = the_int >> 56;
    buf[1] = the_int >> 48;
    buf[2] = the_int >> 40;
    buf[3] = the_int >> 32;
    buf[4] = the_int >> 24;
    buf[5] = the_int >> 16;
    buf[6] = the_int >> 8;
    buf[7] = the_int;
}
static inline uint32_t _txd_read_int_32_le(const uint8_t *buf)
{
    return (((uint32_t)buf[0] << 24) + ((uint32_t)buf[1] << 16) +
            ((uint32_t)buf[2] << 8) + (uint32_t)buf[3]);
}

static inline uint64_t _txd_read_int_64_le(const uint8_t *buf)
{
    return (((uint64_t)buf[0] << 56) + ((uint64_t)buf[1] << 48) +
            ((uint64_t)buf[2] << 40) + ((uint64_t)buf[3] << 32) +
            ((uint64_t)buf[4] << 24) + ((uint64_t)buf[5] << 16) +
            ((uint64_t)buf[6] << 8) + (uint64_t)buf[7]);
}
/* otherwise, we write them backwards.
 * It's like how the British drive on the wrong side of the road.
 */
static inline void _txd_write_int_32_be(uint32_t the_int, uint8_t *buf)
{
    buf[3] = the_int >> 24;
    buf[2] = the_int >> 16;
    buf[1] = the_int >> 8;
    buf[0] = the_int;
}

static inline void _txd_write_int_64_be(uint64_t the_int, uint8_t *buf)
{
    buf[7] = the_int >> 56;
    buf[6] = the_int >> 48;
    buf[5] = the_int >> 40;
    buf[4] = the_int >> 32;
    buf[3] = the_int >> 24;
    buf[2] = the_int >> 16;
    buf[1] = the_int >> 8;
    buf[0] = the_int;
}

static inline uint32_t _txd_read_int_32_be(const uint8_t *buf)
{
    return *((uint32_t *)buf);
}

static inline uint64_t _txd_read_int_64_be(const uint8_t *buf)
{
    return *((uint64_t *)buf);
}

static inline void _txd_write_int_64(uint64_t the_int, uint8_t *buf)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    _txd_write_int_64_le(the_int, buf);
#elif BYTE_ORDER == BIG_ENDIAN
    _txd_write_int_64_be(the_int, buf);
#else
#error u w0t m8
#endif
}

static inline void _txd_write_int_32(uint32_t the_int, uint8_t *buf)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    _txd_write_int_32_le(the_int, buf);;
#elif BYTE_ORDER == BIG_ENDIAN
    _txd_write_int_32_be(the_int, buf);;
#else
#error u w0t m8
#endif
}

static inline uint64_t _txd_read_int_64(const uint8_t *buf)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    return _txd_read_int_64_le(buf);
#elif BYTE_ORDER == BIG_ENDIAN
    return _txd_read_int_64_be(buf);
#else
#error u w0t m8
#endif
}

static inline uint32_t _txd_read_int_32(const uint8_t *buf)
{
#if BYTE_ORDER == LITTLE_ENDIAN
    return _txd_read_int_32_le(buf);
#elif BYTE_ORDER == BIG_ENDIAN
    return _txd_read_int_32_be(buf);
#else
#error u w0t m8
#endif
}

static inline void _txd_kill_memory(void *buf, size_t size)
{
    volatile char *p = buf;

    while (size--) {
        *p++ = 0;
    }
}

struct txd_friend {
    uint32_t txd_name_length;
    uint8_t *txd_name;
    uint8_t txd_addr[TOX_FRIEND_ADDRESS_SIZE];
    uint8_t txd_flags;

    uint32_t txd_data_length;
    uint8_t *txd_data;
    /* note: Status isn't saved because we're going to show
     * friends offline anyway while the connection resyncs. */
    uint64_t txd_lastseen;
};

struct txd_dhtlite {
    /* Associated IPs. They are only valid if the flags say they are. */
    /* the below members are in network order; you shouldn't [need] to care
     * because it is an implementation detail only (+ this entire struct) */
    /* The getters for ports return host-order - you're good. */
    uint8_t txd_bytes_inet4[4];
    uint16_t txd_port4;
    uint8_t txd_bytes_inet6[16];
    uint16_t txd_port6;
    /* use bitwise AND to check these. */
    uint8_t txd_flags;
    uint8_t txd_dhtlite_onion_id[crypto_box_PUBLICKEYBYTES];
};

struct txd_intermediate {
    uint32_t txd_name_length;
    uint8_t *txd_name;
    uint32_t txd_status_length;
    uint8_t *txd_status;
    uint8_t txd_status_troolean;

    uint8_t txd_public[crypto_box_PUBLICKEYBYTES];
    uint8_t txd_private[crypto_box_SECRETKEYBYTES];
    uint8_t txd_nospam[sizeof(uint32_t)];

    uint32_t txd_friends_length;
    struct txd_friend *txd_friends;

    uint32_t txd_dhtlite_length;
    struct txd_dhtlite *txd_dhtlite;
};

#endif
