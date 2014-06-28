/* strkey -- String in Public Key
 *
 * Generates Tox's key pairs, checking if a certain string is in the public key.
 *
 * Requires sodium or nacl library.
 *
 * There seem to be some problems with the code working on Windows -- it works
 * when built in debug mode with MinGW 4.8, but it doesn't work correctly when
 * built in release.
 *
 * Usage: strkey <offset> <string>
 *
 * Offset - an integer specifying exact byte offset position of the string you
 * are looking for within a public key. When offset is negative, the program
 * just looks for the desired string being somewhere, doesn't matter where, in
 * the public key.
 *
 * String - a hex string that you want to have in your public key. It must have
 * an even number of letters, since every two hexes map to a single byte of
 * the public key.
 *
 * Examples:
 *   strkey 0 0123
 *   Looks for a public key that begins with "0123".
 *
 *   strkey 1 0123
 *   Looks for a public key that has "0123" starting at its second byte, i.e. "XX0123...".
 *
 *   strkey 2 0123
 *   Looks for a public key that has "0123" starting at its third byte, i.e. "XXXX0123...".
 *   (each two hexes represent a single byte of a public key)
 *
 *   strkey -1 AF57CC
 *   Looks for a public key that contains "AF57CC", regardless of its position.
 *
 * To compile with gcc and sodium: gcc strkey.c -o strkey -lsodium
*/

#include <stdio.h>
#include <string.h>

#include <sodium.h>

#define PRINT_TRIES_COUNT

void print_key(unsigned char *key)
{
    size_t i;
    for (i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
        if (key[i] < 16) {
            fprintf(stdout, "0");
        }

        fprintf(stdout, "%hhX", key[i]);
    }
}

int main(int argc, char *argv[])
{
    unsigned char public_key[crypto_box_PUBLICKEYBYTES]; // null terminator
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    int offset = 0;
    size_t len;
    unsigned char desired_bin[crypto_box_PUBLICKEYBYTES]; // null terminator

    if (argc == 3) {
        offset = atoi(argv[1]);
        char *desired_hex = argv[2];
        len = strlen(desired_hex);
        if (len % 2 != 0) {
            fprintf(stderr, "Desired key should have an even number of letters\n");
            exit(1);
        }
        size_t block_length = (offset < 0 ? 0 : offset) + len/2;
        if (block_length > crypto_box_PUBLICKEYBYTES) {
            fprintf(stderr, "The given key with the given offset exceed public key's length\n");
            exit(1);
        }

        // convert hex to bin
        char *pos = desired_hex;
        size_t i;
        for (i = 0; i < len; pos += 2) {
            sscanf(pos, "%2hhx", &desired_bin[i]);
            ++i;
        }
    } else {
        fprintf(stdout, "Usage: executable <byte offset> <desired hex string with even number of letters>\n");
        exit(1);
    }

    len /= 2;

#ifdef PRINT_TRIES_COUNT
    long long unsigned int tries = 0;
#endif

    if (offset < 0) {
        int found = 0;
        do {
#ifdef PRINT_TRIES_COUNT
            tries ++;
#endif
            crypto_box_keypair(public_key, secret_key);
            int i;
            for (i = 0; i <= crypto_box_PUBLICKEYBYTES - len; i ++) {
                if (memcmp(public_key + i, desired_bin, len) == 0) {
                    found = 1;
                    break;
                }
            }
        } while (!found);
    } else {
        unsigned char *p = public_key + offset;

        do {
#ifdef PRINT_TRIES_COUNT
	    tries ++;
#endif
            crypto_box_keypair(public_key, secret_key);
        } while (memcmp(p, desired_bin, len) != 0);
    }

    fprintf(stdout, "Public key:  ");
    print_key(public_key);
    fprintf(stdout, "\n");

    fprintf(stdout, "Private key: ");
    print_key(secret_key);
    fprintf(stdout, "\n");

#ifdef PRINT_TRIES_COUNT
	fprintf(stdout, "Found the key pair on %llu try.\n", tries);
#endif

    return 0;
}
