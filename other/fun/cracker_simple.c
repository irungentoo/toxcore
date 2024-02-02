/* Public key cracker.
 *
 * Can be used to find public keys starting with specific hex (ABCD) for example.
 *
 * NOTE: There's probably a way to make this faster.
 *
 * Usage: ./cracker ABCDEF
 *
 * Will try to find a public key starting with: ABCDEF
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Sodium includes*/
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/randombytes.h>

#include "../../testing/misc_tools.h"
#include "../../toxcore/ccompat.h"

// Secret key and public key length
#define KEY_LEN 32

static void print_key(const uint8_t *client_id)
{
    for (int j = 0; j < KEY_LEN; ++j) {
        printf("%02X", client_id[j]);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("usage: ./cracker public_key(or beginning of one in hex format)\n");
        return 0;
    }

    long long unsigned int num_tries = 0;

    size_t len = strlen(argv[1]) / 2;
    unsigned char *key = hex_string_to_bin(argv[1]);
    uint8_t pub_key[KEY_LEN], priv_key[KEY_LEN], c_key[KEY_LEN];

    if (len > KEY_LEN) {
        printf("%zu characters given, truncating to: %d\n", len * 2, KEY_LEN * 2);
        len = KEY_LEN;
    }

    memcpy(c_key, key, len);
    free(key);
    randombytes(priv_key, KEY_LEN);

    while (1) {
        crypto_scalarmult_curve25519_base(pub_key, priv_key);

        if (memcmp(c_key, pub_key, len) == 0) {
            break;
        }

        /*
         * We can't use the first and last bytes because they are masked in
         * curve25519. Using them would generate duplicate keys.
         */
        for (int i = (KEY_LEN - 1); i > 1; --i) {
            priv_key[i - 1] += 1;

            if (priv_key[i - 1] != 0) {
                break;
            }
        }

        ++num_tries;
    }

    printf("Public key:\n");
    print_key(pub_key);
    printf("\nPrivate key:\n");
    print_key(priv_key);
    printf("\n %llu keys tried\n", num_tries);
    return 0;
}
