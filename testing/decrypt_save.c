/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025-2026 The TokTok team.
 */
#include "../toxencryptsave/toxencryptsave.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ./decrypt_save <password> <encrypted input> <decrypted output>
int main(int argc, char *argv[])
{
    if (argc != 4) {
        printf("Usage: %s <password> <encrypted input> <decrypted output>\n", argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[2], "rb");
    if (!fp) {
        printf("Could not open %s\n", argv[2]);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    size_t len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) {
        printf("Could not allocate memory\n");
        fclose(fp);
        return 1;
    }

    if (fread(data, 1, len, fp) != len) {
        printf("Could not read %s\n", argv[2]);
        free(data);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    uint8_t *plaintext = (uint8_t *)malloc(len);
    if (!plaintext) {
        printf("Could not allocate memory\n");
        free(data);
        return 1;
    }
    Tox_Err_Decryption error;
    if (!tox_pass_decrypt(data, len, (uint8_t *)argv[1], strlen(argv[1]), plaintext, &error)) {
        printf("Could not decrypt: %s\n", tox_err_decryption_to_string(error));
        free(data);
        free(plaintext);
        return 1;
    }
    fp = fopen(argv[3], "wb");
    if (!fp) {
        printf("Could not open %s\n", argv[3]);
        free(data);
        free(plaintext);
        return 1;
    }
    if (fwrite(plaintext, 1, len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, fp) != len - TOX_PASS_ENCRYPTION_EXTRA_LENGTH) {
        printf("Could not write %s\n", argv[3]);
        free(data);
        free(plaintext);
        fclose(fp);
        return 1;
    }
    free(data);
    free(plaintext);
    fclose(fp);

    return 0;
}
