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
    return (a.ip.uint32 == b.ip.uint32) && (a.port == b.port);
}

bool id_eq(uint8_t *dest, uint8_t *src)
{
    return memcmp(dest, src, CLIENT_ID_SIZE) == 0;
}

void id_cpy(uint8_t *dest, uint8_t *src)
{
    memcpy(dest, src, CLIENT_ID_SIZE);
}
