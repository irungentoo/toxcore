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
