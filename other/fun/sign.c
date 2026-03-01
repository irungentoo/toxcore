/* Binary signer/checker using ed25519
 *
 * Compile with:
 *  gcc -o sign sign.c -lsodium
 *
 * Generate a keypair:
 *  ./sign g
 *
 * Sign a file:
 *  ./sign s PRIVATEKEY file.bin signedfile.bin
 *
 * Check a file:
 *
 * ./sign c PUBKEY signedfile.bin
 *
 * NOTE: The signature is appended to the end of the file.
 */
#include <sodium.h>
#include <string.h>

#include "../../toxcore/ccompat.h"

static int load_file(const char *filename, unsigned char **result)
{
    int size = 0;
    FILE *f = fopen(filename, "rb");

    if (f == nullptr) {
        *result = nullptr;
        return -1; // -1 means file opening fail
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *result = (unsigned char *)malloc(size + 1);

    if ((size_t)size != fread(*result, sizeof(char), size, f)) {
        free(*result);
        fclose(f);
        return -2; // -2 means file reading fail
    }

    fclose(f);
    (*result)[size] = 0;
    return size;
}

int main(int argc, char *argv[])
{
    unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];

    if (argc == 2 && argv[1][0] == 'g') {
        crypto_sign_ed25519_keypair(pk, sk);
        printf("Public key:\n");

        for (uint32_t i = 0; i < crypto_sign_ed25519_PUBLICKEYBYTES; ++i) {
            printf("%02X", pk[i]);
        }

        printf("\nSecret key:\n");

        for (uint32_t i = 0; i < crypto_sign_ed25519_SECRETKEYBYTES; ++i) {
            printf("%02X", sk[i]);
        }

        printf("\n");
    }

    if (argc == 5 && argv[1][0] == 's') {
        const char *hex_end = nullptr;
        if (sodium_hex2bin(sk, sizeof(sk), argv[2], strlen(argv[2]), nullptr, nullptr, &hex_end) != 0
                || hex_end != argv[2] + strlen(argv[2])) {
            printf("Invalid secret key provided.\n");
            goto fail;
        }
        unsigned char *data = nullptr;
        int size = load_file(argv[3], &data);

        if (size < 0) {
            goto fail;
        }

        unsigned long long smlen;
        unsigned char *sm = (unsigned char *)malloc(size + crypto_sign_ed25519_BYTES * 2);
        crypto_sign_ed25519(sm, &smlen, data, size, sk);
        free(data);

        if (smlen - size != crypto_sign_ed25519_BYTES) {
            free(sm);
            goto fail;
        }

        FILE *f = fopen(argv[4], "wb");

        if (f == nullptr) {
            free(sm);
            goto fail;
        }

        memcpy(sm + smlen, sm, crypto_sign_ed25519_BYTES); // Move signature from beginning to end of file.

        if (fwrite(sm + (smlen - size), 1, smlen, f) != smlen) {
            fclose(f);
            free(sm);
            goto fail;
        }

        fclose(f);
        free(sm);
        printf("Signed successfully.\n");
    }

    if (argc == 4 && argv[1][0] == 'c') {
        const char *hex_end = nullptr;
        if (sodium_hex2bin(pk, sizeof(pk), argv[2], strlen(argv[2]), nullptr, nullptr, &hex_end) != 0
                || hex_end != argv[2] + strlen(argv[2])) {
            printf("Invalid public key provided.\n");
            goto fail;
        }
        unsigned char *data = nullptr;
        int size = load_file(argv[3], &data);

        if (size < 0) {
            goto fail;
        }

        unsigned char *signe = (unsigned char *)malloc(size + crypto_sign_ed25519_BYTES);
        memcpy(signe, data + size - crypto_sign_ed25519_BYTES,
               crypto_sign_ed25519_BYTES); // Move signature from end to beginning of file.
        memcpy(signe + crypto_sign_ed25519_BYTES, data, size - crypto_sign_ed25519_BYTES);
        free(data);

        unsigned char *m = (unsigned char *)malloc(size);
        unsigned long long mlen;

        if (crypto_sign_ed25519_open(m, &mlen, signe, size, pk) == -1) {
            printf("Failed checking sig.\n");
            free(m);
            free(signe);
            goto fail;
        }

        free(m);
        free(signe);
        printf("Checked successfully.\n");
    }

    return 0;

fail:
    printf("FAIL\n");
    return 1;
}
