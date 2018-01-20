/*
 * Small test for checking if obtaining savedata, saving it to disk and using
 * works correctly.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2016 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"

static const char *pphrase = "bar", *name = "foo", *savefile = "./save";

static void save_data_encrypted(void)
{
    struct Tox_Options *options = tox_options_new(NULL);
    Tox *t = tox_new(options, NULL);
    tox_options_free(options);

    tox_self_set_name(t, (const uint8_t *)name, strlen(name), NULL);

    FILE *f = fopen(savefile, "w");

    size_t size = tox_get_savedata_size(t);
    uint8_t *clear = (uint8_t *)malloc(size);

    /*this function does not write any data at all*/
    tox_get_savedata(t, clear);

    size += TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *cipher = (uint8_t *)malloc(size);

    TOX_ERR_ENCRYPTION eerr;

    if (!tox_pass_encrypt(clear, size - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)pphrase, strlen(pphrase), cipher,
                          &eerr)) {
        fprintf(stderr, "error: could not encrypt, error code %d\n", eerr);
        exit(4);
    }

    size_t written_value = fwrite(cipher, sizeof(*cipher), size, f);
    printf("written written_value = %li of %li\n", written_value, size);

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

static void load_data_decrypted(void)
{
    FILE *f = fopen(savefile, "r");
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *cipher = (uint8_t *)malloc(size);
    uint8_t *clear = (uint8_t *)malloc(size - TOX_PASS_ENCRYPTION_EXTRA_LENGTH);
    size_t read_value = fread(cipher, sizeof(*cipher), size, f);
    printf("read read_vavue = %li of %li\n", read_value, size);

    TOX_ERR_DECRYPTION derr;

    if (!tox_pass_decrypt(cipher, size, (const uint8_t *)pphrase, strlen(pphrase), clear, &derr)) {
        fprintf(stderr, "error: could not decrypt, error code %d\n", derr);
        exit(3);
    }

    struct Tox_Options *options = tox_options_new(NULL);

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    tox_options_set_savedata_data(options, clear, size);

    TOX_ERR_NEW err;

    Tox *t = tox_new(options, &err);

    tox_options_free(options);

    if (t == NULL) {
        fprintf(stderr, "error: tox_new returned the error value %d\n", err);
        return;
    }

    uint8_t readname[TOX_MAX_NAME_LENGTH];
    tox_self_get_name(t, readname);
    readname[tox_self_get_name_size(t)] = '\0';

    if (strcmp((const char *)readname, name)) {
        fprintf(stderr, "error: name returned by tox_self_get_name does not match expected result\n");
        exit(2);
    }

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

int main(void)
{
    save_data_encrypted();
    load_data_decrypted();

    int ret = remove(savefile);

    if (ret != 0) {
        fprintf(stderr, "error: could not remove savefile\n");
    }

    return 0;
}
