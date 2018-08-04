//Tests to make sure new save code is compatible with old save files

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "check_compat.h"

#include <string.h>

#define SAVE_FILE "../auto_tests/data/save.tox"

// Information from the save file
#define NAME "name"
#define NAME_SIZE strlen(NAME)
#define STATUS_MESSAGE "Hello World"
#define STATUS_MESSAGE_SIZE strlen(STATUS_MESSAGE)
#define NUM_FRIENDS 1
#define NOSPAM "4C762C7D"
#define TOX_ID "B70E97D41F69B7F4C42A5BC7BD7A76B95B8030BE1B7C0E9E6FC19FC4ABEB195B4C762C7D800B"

static size_t get_file_size(void)
{
    size_t size = 0;

    FILE *fp = fopen(SAVE_FILE, "r");

    if (fp == nullptr) {
        return size;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);

    return size;
}

static uint8_t *read_save(size_t *length)
{
    const size_t size = get_file_size();

    if (size == 0) {
        return nullptr;
    }

    FILE *fp = fopen(SAVE_FILE, "r");

    if (!fp) {
        return nullptr;
    }

    uint8_t *data = (uint8_t *)malloc(size);

    if (!data) {
        fclose(fp);
        return nullptr;
    }

    if (fread(data, size, 1, fp) != 1) {
        free(data);
        fclose(fp);
        return nullptr;
    }

    *length = size;
    fclose(fp);

    return data;
}

static void test_save_compatibility(void)
{
    struct Tox_Options options = { 0 };
    tox_options_default(&options);

    size_t size = 0;
    uint8_t *save_data = read_save(&size);
    ck_assert_msg(save_data != nullptr, "Error while reading save file.");

    options.savedata_data = save_data;
    options.savedata_length = size;
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

    Tox *tox = tox_new(&options, nullptr);

    free(save_data);

    size_t name_size = tox_self_get_name_size(tox);
    ck_assert_msg(name_size == NAME_SIZE, "name sizes do not match expected %zu got %zu", NAME_SIZE, name_size);

    uint8_t name[TOX_MAX_NAME_LENGTH];
    tox_self_get_name(tox, name);
    ck_assert_msg(strncmp((const char *)name, NAME, name_size) == 0, "names do not match, expected %s got %s", NAME, name);

    size_t status_message_size = tox_self_get_status_message_size(tox);
    ck_assert_msg(status_message_size == STATUS_MESSAGE_SIZE, "status message sizes do not match, expected %zu got %zu",
                  STATUS_MESSAGE_SIZE, status_message_size);

    uint8_t status_message[TOX_MAX_STATUS_MESSAGE_LENGTH];
    tox_self_get_status_message(tox, status_message);
    ck_assert_msg(strncmp((const char *)status_message, STATUS_MESSAGE, status_message_size) == 0,
                  "status messages do not match, expected %s got %s",
                  STATUS_MESSAGE, status_message);

    size_t num_friends = tox_self_get_friend_list_size(tox);
    ck_assert_msg(num_friends == NUM_FRIENDS, "number of friends do not match, expected %d got %zu", NUM_FRIENDS,
                  num_friends);

    uint32_t nospam = tox_self_get_nospam(tox);
    char nospam_str[(TOX_NOSPAM_SIZE * 2) + 1];
    size_t length = snprintf(nospam_str, sizeof(nospam_str), "%08X", nospam);
    nospam_str[length] = '\0';
    ck_assert_msg(strcmp(nospam_str, NOSPAM) == 0, "nospam does not match, expected %s got %s", NOSPAM, nospam_str);

    uint8_t tox_id[TOX_ADDRESS_SIZE];
    char tox_id_str[TOX_ADDRESS_SIZE * 2];
    tox_self_get_address(tox, tox_id);
    to_hex(tox_id_str, tox_id, TOX_ADDRESS_SIZE);
    ck_assert_msg(strncmp(tox_id_str, TOX_ID, TOX_ADDRESS_SIZE * 2) == 0, "tox ids do not match, expected %s got %s",
                  TOX_ID, tox_id_str);

    tox_kill(tox);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_save_compatibility();

    return 0;
}
