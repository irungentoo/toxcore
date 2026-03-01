/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Creates bootstrap keys data for a given secret key, if provided, or a random key otherwise.
 * The data is written to stderr, human-readable key info is written to stdout.
 *
 * Build: gcc -o create_bootstrap_keys create_bootstrap_key.c -lsodium -std=c99
 *
 * Usage: ./create_bootstrap_key [secret-key] 2>data
 */
#include <stdio.h>

#include "create_common.h"

int main(const int argc, const char *const argv[])
{
    init_sodium();

    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    handle_args(argc, argv, "Creates bootstrap keys data", public_key, secret_key);

    print_keys(public_key, secret_key);

    fwrite(public_key, sizeof(public_key), 1, stderr);
    fwrite(secret_key, sizeof(secret_key), 1, stderr);

    return 0;
}
