/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared functions of create_*.c programs.
 */
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "../../toxcore/ccompat.h"

static void init_sodium(void)
{
    if (sodium_init() < 0) {
        printf("Error: Failed to initialize sodium.\n");
        exit(1);
    }
}

static int tox_strcasecmp(const char *s1, const char *s2)
{
    while (true) {
        const int c1 = tolower(*(s1++));
        const int c2 = tolower(*(s2++));

        if (c1 == '\0' || c2 == '\0' || c1 != c2) {
            return c1 - c2;
        }
    }
}

static void print_usage(const char *const argv0, const char *const does_what)
{
    printf("%s for a given secret key, if provided, or a random key otherwise.\n", does_what);
    printf("The data is written to stderr, human-readable key info is written to stdout.\n");
    printf("\nUsage: %s [secret-key] 2>data\n", argv0);
}

static void handle_args(const int argc, const char *const argv[], const char *const does_what,
                        unsigned char *const public_key, unsigned char *const secret_key)
{
    if (argc == 2 && (!tox_strcasecmp(argv[1], "-h") || !tox_strcasecmp(argv[1], "--help"))) {
        print_usage(argv[0], does_what);
        exit(0);
    }

    if (argc == 1) {
        crypto_box_keypair(public_key, secret_key);
    } else if (argc == 2 && strlen(argv[1]) == crypto_box_SECRETKEYBYTES * 2) {
        size_t bin_len = 0;

        if (sodium_hex2bin(secret_key, crypto_box_SECRETKEYBYTES, argv[1], crypto_box_SECRETKEYBYTES * 2, nullptr, &bin_len,
                           nullptr) != 0 || bin_len != crypto_box_SECRETKEYBYTES) {
            printf("Error: Secret key must be a hex string.\n");
            exit(1);
        }

        crypto_scalarmult_base(public_key, secret_key);
    } else if (argc == 2) {
        printf("Error: Secret key must be a %u character hex string.\n", crypto_box_SECRETKEYBYTES * 2);
        exit(1);
    } else {
        print_usage(argv[0], does_what);
        exit(1);
    }
}

static void bin2hex_toupper(char *const hex, const size_t hex_maxlen, const unsigned char *const bin,
                            const size_t bin_len)
{
    sodium_bin2hex(hex, hex_maxlen, bin, bin_len);

    for (size_t i = 0; i < hex_maxlen; i ++) {
        hex[i] = (char)toupper(hex[i]);
    }
}

static void print_keys(const unsigned char *const public_key, const unsigned char *const secret_key)
{
    char public_key_str[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char secret_key_str[crypto_box_SECRETKEYBYTES * 2 + 1];
    bin2hex_toupper(public_key_str, sizeof(public_key_str), public_key, crypto_box_PUBLICKEYBYTES);
    bin2hex_toupper(secret_key_str, sizeof(secret_key_str), secret_key, crypto_box_SECRETKEYBYTES);
    fprintf(stdout, "Public key: %s\n", public_key_str);
    fprintf(stdout, "Secret key: %s\n", secret_key_str);
}
