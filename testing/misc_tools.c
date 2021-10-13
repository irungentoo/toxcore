/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Miscellaneous functions and data structures for doing random things.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#ifndef VANILLA_NACL
#include <sodium.h>
#endif

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

static const char *tox_log_level_name(Tox_Log_Level level)
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

void print_debug_log(Tox *m, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
                     const char *message, void *user_data)
{
    if (level == TOX_LOG_LEVEL_TRACE) {
        return;
    }

    uint32_t index = user_data ? *(uint32_t *)user_data : 0;
    fprintf(stderr, "[#%u] %s %s:%u\t%s:\t%s\n", index, tox_log_level_name(level), file, line, func, message);
}

Tox *tox_new_log_lan(struct Tox_Options *options, Tox_Err_New *err, void *log_user_data, bool lan_discovery)
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

Tox *tox_new_log(struct Tox_Options *options, Tox_Err_New *err, void *log_user_data)
{
    return tox_new_log_lan(options, err, log_user_data, false);
}


#ifndef VANILLA_NACL
static const char *test_rng_name(void)
{
    return "test_rng";
}

static uint32_t rng_state;

static uint32_t test_rng_random(void)
{
    rng_state = 2624534371 * rng_state + 1;
    return rng_state;
}

static void test_rng_buf(void *const buf, const size_t size)
{
    uint8_t *p = (uint8_t *)buf;
    uint32_t r = 0;

    for (size_t i = 0; i < size; i++) {
        if ((i % 4) == 0) {
            r = test_rng_random();
        }

        *p = (r >> ((i % 4) * 8)) & 0xff;
        ++p;
    }
}

static uint32_t test_rng_uniform(const uint32_t upper_bound)
{
    // XXX: Not uniform! But that's ok for testing purposes.
    return test_rng_random() % upper_bound;
}

static void test_rng_stir(void) { }
static int test_rng_close(void)
{
    return 0;
}

static randombytes_implementation test_rng = {
    test_rng_name,
    test_rng_random,
    test_rng_stir,
    test_rng_uniform,
    test_rng_buf,
    test_rng_close
};

/* Simple insecure PRNG for testing purposes */
int use_test_rng(uint32_t seed)
{
    rng_state = seed;

    return randombytes_set_implementation(&test_rng);
}

#else

int use_test_rng(uint32_t seed)
{
    assert(!"libsodium required for use_test_rng");
}
#endif
