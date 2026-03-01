/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Creates Tox savedata for a given secret key, if provided, or a random key otherwise.
 * The data is written to stderr, human-readable key info is written to stdout.
 *
 * Build: gcc -o create_savedata create_savedata.c -lsodium -ltoxcore -std=c99
 *
 * Usage: ./create_savedata [secret-key] 2>data
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <sodium.h>

#include "../../toxcore/ccompat.h"
#include "../../toxcore/tox.h"
#include "create_common.h"

static bool create_tox(const unsigned char *const secret_key, Tox **const tox)
{
    Tox_Err_Options_New options_error;
    struct Tox_Options *const options = tox_options_new(&options_error);

    if (options_error != TOX_ERR_OPTIONS_NEW_OK) {
        tox_options_free(options);
        return false;
    }

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_SECRET_KEY);
    tox_options_set_savedata_data(options, secret_key, crypto_box_SECRETKEYBYTES);
    Tox_Err_New tox_error;
    *tox = tox_new(options, &tox_error);

    if (tox_error != TOX_ERR_NEW_OK) {
        tox_options_free(options);
        return false;
    }

    tox_options_free(options);
    return true;
}

static bool print_savedata(const Tox *const tox)
{
    const size_t savedata_size = tox_get_savedata_size(tox);
    uint8_t *const savedata = (uint8_t *)malloc(savedata_size);

    if (savedata == nullptr) {
        return false;
    }

    tox_get_savedata(tox, savedata);
    fwrite(savedata, savedata_size, 1, stderr);
    free(savedata);
    return true;
}

static bool print_tox_id(const Tox *const tox)
{
    uint8_t *const tox_id = (uint8_t *)malloc(tox_address_size());

    if (tox_id == nullptr) {
        return false;
    }

    tox_self_get_address(tox, tox_id);
    const size_t tox_id_str_size = tox_address_size() * 2 + 1;
    char *const tox_id_str = (char *)malloc(tox_id_str_size);

    if (tox_id_str == nullptr) {
        free(tox_id);
        return false;
    }

    bin2hex_toupper(tox_id_str, tox_id_str_size, tox_id, tox_address_size());
    fprintf(stdout, "Tox Id: %s\n", tox_id_str);
    free(tox_id_str);
    free(tox_id);
    return true;
}

int main(const int argc, const char *const argv[])
{
    init_sodium();

    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    handle_args(argc, argv, "Creates Tox savedata", public_key, secret_key);

    print_keys(public_key, secret_key);

    Tox *tox;

    if (!create_tox(secret_key, &tox)) {
        printf("Error: Failed to create a Tox instance.\n");
        return 1;
    }

    if (!print_savedata(tox)) {
        printf("Error: Failed to print savedata.\n");
        tox_kill(tox);
        return 1;
    }

    if (!print_tox_id(tox)) {
        printf("Error: Failed to print Tox ID.\n");
        tox_kill(tox);
        return 1;
    }

    tox_kill(tox);

    return 0;
}
