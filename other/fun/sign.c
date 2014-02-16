/* Binary signer/checker using ed25519

 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
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
#include "../../testing/misc_tools.c" // hex_string_to_bin

int load_file(char *filename, char **result)
{
    int size = 0;
    FILE *f = fopen(filename, "rb");

    if (f == NULL) {
        *result = NULL;
        return -1; // -1 means file opening fail
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *result = (char *)malloc(size + 1);

    if (size != fread(*result, sizeof(char), size, f)) {
        free(*result);
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
        int i;

        for (i = 0; i < crypto_sign_ed25519_PUBLICKEYBYTES; i++) {
            printf("%02hhX", pk[i]);
        }

        printf("\nSecret key:\n");

        for (i = 0; i < crypto_sign_ed25519_SECRETKEYBYTES; i++) {
            printf("%02hhX", sk[i]);
        }

        printf("\n");
    }

    if (argc == 5 && argv[1][0] == 's') {
        unsigned char *secret_key = hex_string_to_bin(argv[2]);
        char *data;
        int size = load_file(argv[3], &data);

        if (size < 0)
            goto fail;

        unsigned long long smlen;
        char *sm = malloc(size + crypto_sign_ed25519_BYTES * 2);
        crypto_sign_ed25519(sm, &smlen, data, size, secret_key);
        free(secret_key);

        if (smlen - size != crypto_sign_ed25519_BYTES)
            goto fail;

        FILE *f = fopen(argv[4], "wb");

        if (f == NULL)
            goto fail;

        memcpy(sm + smlen, sm, crypto_sign_ed25519_BYTES); // Move signature from beginning to end of file.

        if (fwrite(sm + (smlen - size), 1, smlen, f) != smlen)
            goto fail;

        fclose(f);
        printf("Signed successfully.\n");
    }

    if (argc == 4 && argv[1][0] == 'c') {
        unsigned char *public_key = hex_string_to_bin(argv[2]);
        char *data;
        int size = load_file(argv[3], &data);

        if (size < 0)
            goto fail;

        char *signe = malloc(size + crypto_sign_ed25519_BYTES);
        memcpy(signe, data + size - crypto_sign_ed25519_BYTES,
               crypto_sign_ed25519_BYTES); // Move signature from end to beginning of file.
        memcpy(signe + crypto_sign_ed25519_BYTES, data, size - crypto_sign_ed25519_BYTES);
        unsigned long long smlen;
        char *m = malloc(size);
        unsigned long long mlen;

        if (crypto_sign_ed25519_open(m, &mlen, signe, size, public_key) == -1) {
            printf("Failed checking sig.\n");
            goto fail;
        }

        printf("Checked successfully.\n");
    }

    return 0;

fail:
    printf("FAIL\n");
    return 1;
}
