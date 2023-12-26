#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../testing/misc_tools.h"
#include "../../toxcore/ccompat.h"
#include "../../toxcore/tox.h"

#define GENERATED_SAVE_FILE "save.tox"
#define GENERATED_STATUS_MESSAGE "Hello World"
#define GENERATED_REQUEST_MESSAGE "Add me."
#define BOOTSTRAP_IP "185.14.30.213"
#define BOOTSTRAP_ADDRESS "2555763C8C460495B14157D234DD56B86300A2395554BCAE4621AC345B8C1B1B"
#define BOOTSTRAP_UDP_PORT 443

static bool write_save(const uint8_t *data, size_t length)
{
    FILE *fp = fopen(GENERATED_SAVE_FILE, "wb");

    if (!fp) {
        return false;
    }

    if (fwrite(data, length, 1, fp) != 1) {
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

static bool bootstrap_tox(Tox *tox)
{
    uint8_t *key = hex_string_to_bin(BOOTSTRAP_ADDRESS);

    if (!key) {
        printf("Could not allocate memory for tox address\n");
        return false;
    }

    Tox_Err_Bootstrap err;
    tox_bootstrap(tox, BOOTSTRAP_IP, BOOTSTRAP_UDP_PORT, key, &err);
    free(key);

    if (err != TOX_ERR_BOOTSTRAP_OK) {
        printf("Failed to bootstrap. Error number: %d", err);
        return false;
    }

    return true;
}

static void tox_connection_callback(Tox *tox, Tox_Connection connection, void *userdata)
{
    if (connection == TOX_CONNECTION_UDP) {
        printf("Connected to the tox network.\n");
        *(bool *)userdata = true;
    }
}

static void print_information(const Tox *tox)
{
    uint8_t tox_id[TOX_ADDRESS_SIZE];
    char tox_id_str[TOX_ADDRESS_SIZE * 2];
    tox_self_get_address(tox, tox_id);
    to_hex(tox_id_str, tox_id, TOX_ADDRESS_SIZE);

    char nospam_str[(TOX_NOSPAM_SIZE * 2) + 1];
    uint32_t nospam = tox_self_get_nospam(tox);
    int length = snprintf(nospam_str, sizeof(nospam_str), "%08X", nospam);
    nospam_str[length] = '\0';

    size_t name_size = tox_self_get_name_size(tox);
    uint8_t *name = (uint8_t *)malloc(name_size + 1);

    if (!name) {
        return;
    }

    tox_self_get_name(tox, name);
    name[name_size] = '\0';

    printf("INFORMATION\n");
    printf("----------------------------------\n");
    printf("Tox ID: %.*s.\n", (int)TOX_ADDRESS_SIZE * 2, tox_id_str);
    printf("Nospam: %s.\n", nospam_str);
    printf("Name: %s.\n", name);
    printf("Status message: %s.\n", GENERATED_STATUS_MESSAGE);
    printf("Number of friends: %zu.\n", tox_self_get_friend_list_size(tox));
    printf("----------------------------------\n");

    free(name);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: ./save-generator <name> <friend id> ...\n");
        return -1;
    }

    Tox *tox = tox_new(nullptr, nullptr);

    if (!tox) {
        printf("Failed to create tox.\n");
        return -1;
    }

    if (!bootstrap_tox(tox)) {
        tox_kill(tox);
        return -1;
    }

    tox_callback_self_connection_status(tox, tox_connection_callback);

    bool connected = false;

    while (!connected) {
        tox_iterate(tox, &connected);
        c_sleep(tox_iteration_interval(tox));
    }

    Tox_Err_Set_Info err;
    const uint8_t *name = (uint8_t *)argv[1];
    tox_self_set_name(tox, name, strlen((const char *)name), &err);

    if (err != TOX_ERR_SET_INFO_OK) {
        printf("Failed to set name. Error number %d\n", err);
    }

    tox_self_set_status_message(tox, (const uint8_t *)GENERATED_STATUS_MESSAGE, strlen(GENERATED_STATUS_MESSAGE), &err);

    if (err != TOX_ERR_SET_INFO_OK) {
        printf("Failed to set status. Error number: %d\n", err);
    }

    for (unsigned int i = 2; i < argc; i++) { //start at 2 because that is where the tox ids are
        uint8_t *address = hex_string_to_bin(argv[i]);
        Tox_Err_Friend_Add friend_err;
        tox_friend_add(tox, address, (const uint8_t *)GENERATED_REQUEST_MESSAGE, strlen(GENERATED_REQUEST_MESSAGE),
                       &friend_err);
        free(address);

        if (friend_err != TOX_ERR_FRIEND_ADD_OK) {
            printf("Failed to add friend number %u. Error number: %d\n", i - 1, friend_err);
        }
    }

    const size_t length = tox_get_savedata_size(tox);
    uint8_t *savedata = (uint8_t *)malloc(length);

    if (!savedata) {
        printf("Could not allocate memory for savedata.\n");
        tox_kill(tox);
        return -1;
    }

    tox_get_savedata(tox, savedata);

    bool ret = write_save(savedata, length);
    free(savedata);

    if (!ret) {
        printf("Failed to write save.\n");
        tox_kill(tox);
        return -1;
    }

    printf("Wrote tox save to %s\n", GENERATED_SAVE_FILE);

    print_information(tox);

    tox_kill(tox);

    return 0;
}
