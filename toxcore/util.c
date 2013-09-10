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

int cmdline_parsefor_ipv46(int argc, char **argv, uint8_t *ipv6enabled)
{
    int argvoffset = 0, argi;
    for(argi = 1; argi < argc; argi++)
        if (!strncasecmp(argv[argi], "--ipv", 5)) {
            if (argv[argi][5] && !argv[argi][6]) {
                char c = argv[argi][5];
                if (c == '4')
                    *ipv6enabled = 0;
                else if (c == '6')
                    *ipv6enabled = 1;
                else {
                    printf("Invalid argument: %s. Try --ipv4 or --ipv6!\n", argv[argi]);
                    return -1;
                }
            }
            else {
                printf("Invalid argument: %s. Try --ipv4 or --ipv6!\n", argv[argi]);
                return -1;
            }

            if (argvoffset != argi - 1) {
                printf("Argument must come first: %s.\n", argv[argi]);
                return -1;
            }

            argvoffset++;
        }

    return argvoffset;
};

#ifdef LOGGING
char logbuffer[512];
static FILE *logfile = NULL;
void loginit(uint16_t port)
{
    if (logfile)
        fclose(logfile);

    sprintf(logbuffer, "%u-%u.log", ntohs(port), now);
    logfile = fopen(logbuffer, "w");
};
void loglog(char *text)
{
    if (logfile) {
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
