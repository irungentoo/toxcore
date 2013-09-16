/*
 * util.c -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

/* for CLIENT_ID_SIZE */
#include "DHT.h"
#include "util.h"

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

bool id_eq(uint8_t *dest, uint8_t *src)
{
    return memcmp(dest, src, CLIENT_ID_SIZE) == 0;
}

void id_cpy(uint8_t *dest, uint8_t *src)
{
    memcpy(dest, src, CLIENT_ID_SIZE);
}

int load_state(load_state_callback_func load_state_callback, void *outer,
        uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (!load_state_callback || !data) {
        fprintf(stderr, "load_state() called with invalid args.\n");
        return -1;
    }


    uint16_t type;
    uint32_t length_sub, cookie_type;
    uint32_t size32 = sizeof(uint32_t), size_head = size32 * 2;
    while (length > size_head) {
        length_sub = *(uint32_t *)data;
        cookie_type = *(uint32_t *)(data + size32);
        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
            fprintf(stderr, "state file too short: %u < %u\n", length, length_sub);
            return -1;
        }

        if ((cookie_type >> 16) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
            fprintf(stderr, "state file garbeled: %04hx != %04hx\n", (cookie_type >> 16), cookie_inner);
            return -1;
        }

        type = cookie_type & 0xFFFF;
        if (-1 == load_state_callback(outer, data, length_sub, type))
            return -1;

        data += length_sub;
        length -= length_sub;
    }

    return length == 0 ? 0 : - 1;
};

#ifdef LOGGING
time_t starttime = 0;
char logbuffer[512];
static FILE *logfile = NULL;
void loginit(uint16_t port)
{
    if (logfile)
        fclose(logfile);

    sprintf(logbuffer, "%u-%u.log", ntohs(port), now());
    logfile = fopen(logbuffer, "w");
    starttime = now();
};
void loglog(char *text)
{
    if (logfile) {
        fprintf(logfile, "%4u ", now() - starttime);
        fprintf(logfile, text);
        fflush(logfile);
    }
};
void logexit()
{
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
};
#endif
