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

#include "../../testing/misc_tools.c"
#include <time.h>

/* NaCl includes*/
#include <crypto_scalarmult_curve25519.h>
#include <randombytes.h>

/* Sodium include*/
//#include <sodium.h>

void print_key(uint8_t *client_id)
{
    uint32_t j;

    for (j = 0; j < 32; j++) {
        printf("%02hhX", client_id[j]);
    }
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("usage: ./cracker public_key(or beginning of one in hex format)\n");
        return 0;
    }

    long long unsigned int num_tries = 0;

    uint32_t len = strlen(argv[1]) / 2;
    unsigned char *key = hex_string_to_bin(argv[1]);
    uint8_t pub_key[32], priv_key[32], c_key[32];

    if (len > 32)
        len = 32;

    memcpy(c_key, key, len);
    free(key);
    randombytes(priv_key, 32);

    while (1) {
        crypto_scalarmult_curve25519_base(pub_key, priv_key);
        uint32_t i;

        if (memcmp(c_key, pub_key, len) == 0)
            break;

        for (i = 32; i != 0; --i) {
            priv_key[i - 1] += 1;

            if (priv_key[i - 1] != 0)
                break;
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
