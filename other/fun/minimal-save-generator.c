/* minimal-save-generator -- Minimal Save Generator
 *
 * Generates a minimal Tox savedata file that can be used in clients.
 * Prints the savedata file to stderr, prints information to stdout.
 *
 * Requires sodium library.
 *
 * Usage: minimal-save-generator 2> profile.tox
 *
 * Compile: gcc minimal-save-generator.c -o minimal-save-generator -lsodium
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sodium.h>

int main(void)
{
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(public_key, secret_key);

    // print new tox savedata to stderr
    char tox_file[] = "\x00\x00\x00\x00\x1f\x1b\xed\x15\x44\x00\x00\x00\x01\x00\xce\x01\x00\x00\x00\x00";
    fwrite(tox_file, sizeof(tox_file) - 1, 1, stderr);
    fwrite(public_key, sizeof(public_key), 1, stderr);
    fwrite(secret_key, sizeof(secret_key), 1, stderr);

    // print info on it to stdout
    char public_key_str[crypto_box_PUBLICKEYBYTES * 2 + 1];
    char secret_key_str[crypto_box_SECRETKEYBYTES * 2 + 1];
    sodium_bin2hex(public_key_str, sizeof(public_key_str), public_key, sizeof(public_key));
    sodium_bin2hex(secret_key_str, sizeof(secret_key_str), secret_key, sizeof(secret_key));

    for (size_t i = 0; i < sizeof(public_key_str); i ++) {
        public_key_str[i] = toupper(public_key_str[i]);
        secret_key_str[i] = toupper(secret_key_str[i]);
    }

    fprintf(stdout, "Public key: %s\n", public_key_str);
    fprintf(stdout, "Secret key: %s\n", secret_key_str);

    // calculate checksum for tox id printing
    unsigned char checksum[2] = {0};

    for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; i ++) {
        checksum[i % 2] ^= public_key[i];
    }

    char checksum_str[sizeof(checksum) * 2 + 1];
    sodium_bin2hex(checksum_str, sizeof(checksum_str), checksum, sizeof(checksum));

    for (size_t i = 0; i < sizeof(checksum_str); i ++) {
        checksum_str[i] = toupper(checksum_str[i]);
    }

    fprintf(stdout, "Tox Id: %s00000000%s\n", public_key_str, checksum_str);

    return 0;
}
