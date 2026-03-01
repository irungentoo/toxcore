/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Miscellaneous functions and data structures for doing random things.
 */
#ifndef _POSIX_C_SOURCE
// For nanosleep().
#define _POSIX_C_SOURCE 200112L
#endif

#include "misc_tools.h"

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"

void c_sleep(uint32_t x)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    Sleep(x);
#else
    struct timespec req;
    req.tv_sec = x / 1000;
    req.tv_nsec = (long)x % 1000 * 1000 * 1000;
    nanosleep(&req, nullptr);
#endif
}

// You are responsible for freeing the return value!
uint8_t *hex_string_to_bin(const char *hex_string)
{
    // byte is represented by exactly 2 hex digits, so length of binary string
    // is half of that of the hex one. only hex string with even length
    // valid. the more proper implementation would be to check if strlen(hex_string)
    // is odd and return error code if it is. we assume strlen is even. if it's not
    // then the last byte just won't be written in 'ret'.
    size_t i, len = strlen(hex_string) / 2;
    uint8_t *ret = (uint8_t *)malloc(len);
    const char *pos = hex_string;

    if (ret == nullptr) {
        return nullptr;
    }

    for (i = 0; i < len; ++i, pos += 2) {
        unsigned int val;
        sscanf(pos, "%02x", &val);
        ret[i] = val;
    }

    return ret;
}

void to_hex(char *out, uint8_t *in, int size)
{
    while (size--) {
        if (*in >> 4 < 0xA) {
            *out++ = '0' + (*in >> 4);
        } else {
            *out++ = 'A' + (*in >> 4) - 0xA;
        }

        if ((*in & 0xf) < 0xA) {
            *out++ = '0' + (*in & 0xF);
        } else {
            *out++ = 'A' + (*in & 0xF) - 0xA;
        }

        in++;
    }
}

/* Reimplementation of strncasecmp() function from strings.h, as strings.h is
 * POSIX and not portable. Specifically it doesn't exist on MSVC.
 */
int tox_strncasecmp(const char *s1, const char *s2, size_t n)
{
    while (n--) {
        int c1 = tolower(*(s1++));
        int c2 = tolower(*(s2++));

        if (c1 == '\0' || c2 == '\0' || c1 != c2) {
            return c1 - c2;
        }
    }

    return 0;
}

int cmdline_parsefor_ipv46(int argc, char **argv, bool *ipv6enabled)
{
    int argvoffset = 0, argi;

    for (argi = 1; argi < argc; argi++) {
        if (!tox_strncasecmp(argv[argi], "--ipv", 5)) {
            if (argv[argi][5] && !argv[argi][6]) {
                char c = argv[argi][5];

                if (c == '4') {
                    *ipv6enabled = false;
                } else if (c == '6') {
                    *ipv6enabled = true;
                } else {
                    printf("Invalid argument: %s. Try --ipv4 or --ipv6!\n", argv[argi]);
                    return -1;
                }
            } else {
                printf("Invalid argument: %s. Try --ipv4 or --ipv6!\n", argv[argi]);
                return -1;
            }

            if (argvoffset != argi - 1) {
                printf("Argument must come first: %s.\n", argv[argi]);
                return -1;
            }

            argvoffset++;
        }
    }

    return argvoffset;
}
