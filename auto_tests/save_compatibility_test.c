// Tests to make sure new save code is compatible with old save files

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "auto_test_support.h"
#include "check_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOADED_SAVE_FILE_BIG    "../auto_tests/data/save.tox.big"
#define LOADED_SAVE_FILE_LITTLE "../auto_tests/data/save.tox.little"

// Information from the save file
#define EXPECTED_NAME "name"
#define EXPECTED_NAME_SIZE strlen(EXPECTED_NAME)
#define EXPECTED_STATUS_MESSAGE "Hello World"
#define EXPECTED_STATUS_MESSAGE_SIZE strlen(EXPECTED_STATUS_MESSAGE)
#define EXPECTED_NUM_FRIENDS 1
#define EXPECTED_NOSPAM "4C762C7D"
#define EXPECTED_TOX_ID "E776E9A993EE3CAE04F5946D9AC66FBBAA8C63A95A94B41942353C6DC1739B4B4C762C7DA7B9"

static size_t get_file_size(const char *save_path)
{
    FILE *const fp = fopen(save_path, "rb");

    if (fp == nullptr) {
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    const size_t size = ftell(fp);
    fclose(fp);

    return size;
}

static uint8_t *read_save(const char *save_path, size_t *length)
{
    const size_t size = get_file_size(save_path);

    if (size == 0) {
        return nullptr;
    }

    FILE *const fp = fopen(save_path, "rb");

    if (!fp) {
        return nullptr;
    }

    uint8_t *const data = (uint8_t *)malloc(size);

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

static void test_save_compatibility(const char *save_path)
{
    struct Tox_Options options = {0};
    tox_options_default(&options);

    size_t size = 0;
    uint8_t *save_data = read_save(save_path, &size);
    ck_assert_msg(save_data != nullptr, "error while reading save file '%s'", save_path);

    options.savedata_data = save_data;
    options.savedata_length = size;
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

    size_t index = 0;
    Tox_Err_New err;
    Tox *tox = tox_new_log(&options, &err, &index);
    ck_assert_msg(tox, "failed to create tox, error number: %d", err);

    free(save_data);

    const size_t name_size = tox_self_get_name_size(tox);
    ck_assert_msg(name_size == EXPECTED_NAME_SIZE, "name sizes do not match expected %zu got %zu", EXPECTED_NAME_SIZE,
                  name_size);

    uint8_t *name = (uint8_t *)malloc(tox_self_get_name_size(tox));
    ck_assert(name != nullptr);
    tox_self_get_name(tox, name);
    ck_assert_msg(strncmp((const char *)name, EXPECTED_NAME, name_size) == 0,
                  "names do not match, expected %s got %s", EXPECTED_NAME, name);

    const size_t status_message_size = tox_self_get_status_message_size(tox);
    ck_assert_msg(status_message_size == EXPECTED_STATUS_MESSAGE_SIZE,
                  "status message sizes do not match, expected %zu got %zu", EXPECTED_STATUS_MESSAGE_SIZE, status_message_size);

    uint8_t *status_message = (uint8_t *)malloc(tox_self_get_status_message_size(tox));
    ck_assert(status_message != nullptr);
    tox_self_get_status_message(tox, status_message);
    ck_assert_msg(strncmp((const char *)status_message, EXPECTED_STATUS_MESSAGE, status_message_size) == 0,
                  "status messages do not match, expected %s got %s",
                  EXPECTED_STATUS_MESSAGE, status_message);

    const size_t num_friends = tox_self_get_friend_list_size(tox);
    ck_assert_msg(num_friends == EXPECTED_NUM_FRIENDS,
                  "number of friends do not match, expected %d got %zu",  EXPECTED_NUM_FRIENDS, num_friends);

    const uint32_t nospam = tox_self_get_nospam(tox);
    char nospam_str[TOX_NOSPAM_SIZE * 2 + 1];
    const size_t length = snprintf(nospam_str, sizeof(nospam_str), "%08X", nospam);
    nospam_str[length] = '\0';
    ck_assert_msg(strcmp(nospam_str, EXPECTED_NOSPAM) == 0,
                  "nospam does not match, expected %s got %s", EXPECTED_NOSPAM, nospam_str);

    uint8_t tox_id[TOX_ADDRESS_SIZE];
    char tox_id_str[TOX_ADDRESS_SIZE * 2 + 1] = {0};
    tox_self_get_address(tox, tox_id);
    to_hex(tox_id_str, tox_id, TOX_ADDRESS_SIZE);
    ck_assert_msg(strncmp(tox_id_str, EXPECTED_TOX_ID, TOX_ADDRESS_SIZE * 2) == 0,
                  "tox ids do not match, expected %s got %s", EXPECTED_TOX_ID, tox_id_str);

    /* Giving the tox a chance to error on iterate due to corrupted loaded structures */
    tox_iterate(tox, nullptr);

    free(status_message);
    free(name);
    tox_kill(tox);
}

static bool is_little_endian(void)
{
    uint16_t x = 1;
    return ((uint8_t *)&x)[0] == 1;
}

// cppcheck-suppress constParameter
int main(int argc, char *argv[])
{
    char base_path[4096] = {0};

    if (argc <= 1) {
        const char *srcdir = getenv("srcdir");

        if (srcdir == nullptr) {
            srcdir = ".";
        }

        snprintf(base_path, sizeof(base_path), "%s", srcdir);
    } else {
        snprintf(base_path, sizeof(base_path), "%s", argv[1]);
        base_path[strrchr(base_path, '/') - base_path] = '\0';
    }

    if (is_little_endian()) {
        char save_path[4096 + sizeof(LOADED_SAVE_FILE_LITTLE)];
        snprintf(save_path, sizeof(save_path), "%s/%s", base_path, LOADED_SAVE_FILE_LITTLE);
        test_save_compatibility(save_path);
    } else {
        char save_path[4096 + sizeof(LOADED_SAVE_FILE_BIG)];
        snprintf(save_path, sizeof(save_path), "%s/%s", base_path, LOADED_SAVE_FILE_BIG);
        test_save_compatibility(save_path);
    }

    return 0;
}
