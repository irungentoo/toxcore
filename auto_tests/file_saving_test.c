/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2016 Tox project.
 */

/*
 * Small test for checking if obtaining savedata, saving it to disk and using
 * works correctly.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "check_compat.h"

#include "../toxencryptsave/toxencryptsave.h"

static const char *pphrase = "bar";
static const char *name = "foo";
static const char *savefile = "./save";

static void save_data_encrypted(void)
{
    struct Tox_Options *options = tox_options_new(nullptr);
    Tox *t = tox_new_log(options, nullptr, nullptr);
    tox_options_free(options);

    tox_self_set_name(t, (const uint8_t *)name, strlen(name), nullptr);

    FILE *f = fopen(savefile, "w");

    size_t size = tox_get_savedata_size(t);
    uint8_t *clear = (uint8_t *)malloc(size);

    /*this function does not write any data at all*/
    tox_get_savedata(t, clear);

    size += TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *cipher = (uint8_t *)malloc(size);

    Tox_Err_Encryption eerr;

    ck_assert_msg(tox_pass_encrypt(clear, size - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)pphrase,
                                   strlen(pphrase), cipher,
                                   &eerr), "Could not encrypt, error code %d.", eerr);

    size_t written_value = fwrite(cipher, sizeof(*cipher), size, f);
    printf("written written_value = %u of %u\n", (unsigned)written_value, (unsigned)size);

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

static void load_data_decrypted(void)
{
    FILE *f = fopen(savefile, "r");
    fseek(f, 0, SEEK_END);
    int64_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    ck_assert_msg(0 <= size && size <= UINT_MAX, "file size out of range");

    uint8_t *cipher = (uint8_t *)malloc(size);
    uint8_t *clear = (uint8_t *)malloc(size - TOX_PASS_ENCRYPTION_EXTRA_LENGTH);
    size_t read_value = fread(cipher, sizeof(*cipher), size, f);
    printf("Read read_value = %u of %u\n", (unsigned)read_value, (unsigned)size);

    Tox_Err_Decryption derr;

    ck_assert_msg(tox_pass_decrypt(cipher, size, (const uint8_t *)pphrase, strlen(pphrase), clear, &derr),
                  "Could not decrypt, error code %d.", derr);

    struct Tox_Options *options = tox_options_new(nullptr);

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    tox_options_set_savedata_data(options, clear, size);

    Tox_Err_New err;

    Tox *t = tox_new_log(options, &err, nullptr);

    tox_options_free(options);

    ck_assert_msg(t != nullptr, "tox_new returned the error value %d", err);

    uint8_t readname[TOX_MAX_NAME_LENGTH];
    tox_self_get_name(t, readname);
    readname[tox_self_get_name_size(t)] = '\0';

    ck_assert_msg(strcmp((const char *)readname, name) == 0,
                  "name returned by tox_self_get_name does not match expected result");

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    save_data_encrypted();
    load_data_decrypted();

    ck_assert_msg(remove(savefile) == 0, "Could not remove the savefile.");

    return 0;
}
