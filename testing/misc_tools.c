/*
 * Miscellaneous functions and data structures for doing random things.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _POSIX_C_SOURCE
// For nanosleep().
#define _POSIX_C_SOURCE 199309L
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
    // byte is represented by exactly 2 hex digits, so lenth of binary string
    // is half of that of the hex one. only hex string with even length
    // valid. the more proper implementation would be to check if strlen(hex_string)
    // is odd and return error code if it is. we assume strlen is even. if it's not
    // then the last byte just won't be written in 'ret'.
    size_t i, len = strlen(hex_string) / 2;
    uint8_t *ret = (uint8_t *)malloc(len);
    const char *pos = hex_string;

    for (i = 0; i < len; ++i, pos += 2) {
        unsigned int val;
        sscanf(pos, "%02x", &val);
        ret[i] = val;
    }

    return ret;
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

int cmdline_parsefor_ipv46(int argc, char **argv, uint8_t *ipv6enabled)
{
    int argvoffset = 0, argi;

    for (argi = 1; argi < argc; argi++) {
        if (!tox_strncasecmp(argv[argi], "--ipv", 5)) {
            if (argv[argi][5] && !argv[argi][6]) {
                char c = argv[argi][5];

                if (c == '4') {
                    *ipv6enabled = 0;
                } else if (c == '6') {
                    *ipv6enabled = 1;
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

static const char *tox_log_level_name(TOX_LOG_LEVEL level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            return "TRACE";

        case TOX_LOG_LEVEL_DEBUG:
            return "DEBUG";

        case TOX_LOG_LEVEL_INFO:
            return "INFO";

        case TOX_LOG_LEVEL_WARNING:
            return "WARNING";

        case TOX_LOG_LEVEL_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

void print_debug_log(Tox *m, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
                     const char *message, void *user_data)
{
    if (level == TOX_LOG_LEVEL_TRACE) {
        return;
    }

    uint32_t index = user_data ? *(uint32_t *)user_data : 0;
    fprintf(stderr, "[#%u] %s %s:%u\t%s:\t%s\n", index, tox_log_level_name(level), file, line, func, message);
}

Tox *tox_new_log_lan(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data, bool lan_discovery)
{
    struct Tox_Options *log_options = options;

    if (log_options == nullptr) {
        log_options = tox_options_new(nullptr);
    }

    assert(log_options != nullptr);

    tox_options_set_local_discovery_enabled(log_options, lan_discovery);
    tox_options_set_start_port(log_options, 33445);
    tox_options_set_end_port(log_options, 33445 + 2000);
    tox_options_set_log_callback(log_options, &print_debug_log);
    tox_options_set_log_user_data(log_options, log_user_data);
    Tox *tox = tox_new(log_options, err);

    if (options == nullptr) {
        tox_options_free(log_options);
    }

    return tox;
}

Tox *tox_new_log(struct Tox_Options *options, TOX_ERR_NEW *err, void *log_user_data)
{
    return tox_new_log_lan(options, err, log_user_data, false);
}
