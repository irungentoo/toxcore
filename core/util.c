/*
 * util.c -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#include "network.h"

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

bool ipp_eq(tox_IP_Port a, tox_IP_Port b)
{
    return (a.ip.i == b.ip.i) && (a.port == b.port);
}
