/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Creates minimal Tox savedata for a given secret key, if provided, or a random key otherwise.
 * The data is written to stderr, human-readable key info is written to stdout.
 *
 * Build: gcc -o create_minimal_savedata create_minimal_savedata.c -lsodium -std=c99
 *
 * Usage: ./create_minimal_savedata [secret-key] 2>data
 */
#include <stdio.h>

#include <sodium.h>

#include "create_common.h"

int main(const int argc, const char *const argv[])
{
    init_sodium();

    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    handle_args(argc, argv, "Creates minimal Tox savedata", public_key, secret_key);

    print_keys(public_key, secret_key);

    // toxcore stores integers in savedata explicitly in little-endian, so this is indeed portable across architectures
    // 0x00000000 = (uint32_t) 0
    // 0x15ed1b1f = (uint32_t) STATE_COOKIE_GLOBAL
    // 0x00000044 = (uint32_t) (crypto_box_PUBLICKEYBYTES+crypto_box_SECRETKEYBYTES+sizeof(uint32_t))
    // 0x0001     = (uint16_t) STATE_TYPE_NOSPAMKEYS
    // 0x01ce     = (uint16_t) STATE_COOKIE_TYPE
    // 0x00000000 = (uint32_t) nospam
    // _          = uint8_t[crypto_box_PUBLICKEYBYTES] public key
    // _          = uint8_t[crypto_box_SECRETKEYBYTES] secret key
    const char tox_file[] = "\x00\x00\x00\x00" \
                            "\x1f\x1b\xed\x15" \
                            "\x44\x00\x00\x00" \
                            "\x01\x00" \
                            "\xce\x01" \
                            "\x00\x00\x00\x00";
    fwrite(tox_file, sizeof(tox_file) - 1, 1, stderr);
    fwrite(public_key, sizeof(public_key), 1, stderr);
    fwrite(secret_key, sizeof(secret_key), 1, stderr);

    unsigned char checksum[2] = {0};

    for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; i ++) {
        checksum[i % sizeof(checksum)] ^= public_key[i];
    }

    char checksum_str[sizeof(checksum) * 2 + 1];
    bin2hex_toupper(checksum_str, sizeof(checksum_str), checksum, sizeof(checksum));
    char public_key_str[crypto_box_PUBLICKEYBYTES * 2 + 1];
    bin2hex_toupper(public_key_str, sizeof(public_key_str), public_key, crypto_box_PUBLICKEYBYTES);
    fprintf(stdout, "Tox Id: %s00000000%s\n", public_key_str, checksum_str);

    return 0;
}
