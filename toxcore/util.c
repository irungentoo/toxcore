/*
 * util.c -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#include "DHT.h"
#include "packets.h"

uint64_t now()
{
    return time(NULL);
}

uint64_t random_64b()
{
    uint64_t r;

    // This is probably not random enough?
    r = random_int();
    r <<= 32;
    r |= random_int();

    return r;
}

bool ipp_eq(IP_Port a, IP_Port b)
{
    return (a.ip.i == b.ip.i) && (a.port == b.port);
}

bool id_eq(clientid_t *dest, clientid_t *src)
{
    return memcmp(dest, src, sizeof(clientid_t)) == 0;
}

void id_cpy(clientid_t *dest, clientid_t *src)
{
    memcpy(dest, src, sizeof(clientid_t));
}

bool system_big_endian()
{
    unsigned int x = 1;
    char *c = (char *)&x;
    return !*c;
}

uint8_t reverse_bits(uint8_t x)
{
    x = (x & 0xF0) >> 4 | (x & 0x0F) << 4;
    x = (x & 0xCC) >> 2 | (x & 0x33) << 2;
    x = (x & 0xAA) >> 1 | (x & 0x55) << 1;
    return x;
}
