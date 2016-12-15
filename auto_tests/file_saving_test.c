/* file_saving_test.c
 *
 * Small test for checking if obtaining savedata, saving it to disk and using
 * works correctly.
 *
 *  Copyright (C) 2016 Tox project All Rights Reserved.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"

static const char *pphrase = "bar", *name = "foo";

static void tse(void)
{
    struct Tox_Options options;
    tox_options_default(&options);
    Tox *t = tox_new(&options, NULL);

    tox_self_set_name(t, (const uint8_t *)name, strlen(name), NULL);

    FILE *f = fopen("save", "w");

    off_t sz = tox_get_savedata_size(t);
    uint8_t *clear = (uint8_t *)malloc(sz);

    /*this function does not write any data at all*/
    tox_get_savedata(t, clear);

    sz += TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *cipher = (uint8_t *)malloc(sz);

    TOX_ERR_ENCRYPTION eerr;

    if (!tox_pass_encrypt(clear, sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)pphrase, strlen(pphrase), cipher,
                          &eerr)) {
        fprintf(stderr, "error: could not encrypt, error code %d\n", eerr);
        exit(4);
    }

    size_t wv = fwrite(cipher, sizeof(*cipher), sz, f);
    printf("written wv = %li of %li\n", wv, sz);

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

static void tsd(void)
{
    FILE *f = fopen("save", "r");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *cipher = (uint8_t *)malloc(sz);
    uint8_t *clear = (uint8_t *)malloc(sz - TOX_PASS_ENCRYPTION_EXTRA_LENGTH);
    size_t rv = fread(cipher, sizeof(*cipher), sz, f);
    printf("read rv = %li of %li\n", rv, sz);

    TOX_ERR_DECRYPTION derr;

    if (!tox_pass_decrypt(cipher, sz, (const uint8_t *)pphrase, strlen(pphrase), clear, &derr)) {
        fprintf(stderr, "error: could not decrypt, error code %d\n", derr);
        exit(3);
    }

    struct Tox_Options options;

    tox_options_default(&options);

    tox_options_set_savedata_type(&options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    tox_options_set_savedata_data(&options, clear, sz);

    TOX_ERR_NEW err;

    Tox *t = tox_new(&options, &err);

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
    tse();
    tsd();

    int ret = remove("./save");

    if (ret != 0) {
        fprintf(stderr, "error: could not remove savefile\n");
    }

    return 0;
}
