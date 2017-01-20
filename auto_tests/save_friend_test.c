/* Auto Tests: Save and load friends.
 */

#define _XOPEN_SOURCE 600

#include "helpers.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

struct test_data {
    uint8_t name[TOX_MAX_NAME_LENGTH];
    uint8_t status_message[TOX_MAX_STATUS_MESSAGE_LENGTH];
    bool received_name;
    bool received_status_message;
};

static void set_random(Tox *m, bool (*setter)(Tox *, const uint8_t *, size_t, TOX_ERR_SET_INFO *), size_t length)
{
    VLA(uint8_t, text, length);
    uint32_t i;

    for (i = 0; i < length; ++i) {
        text[i] = rand();
    }

    setter(m, text, SIZEOF_VLA(text), 0);
}

void namechange_callback(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data)
{
    struct test_data *to_compare = (struct test_data *)user_data;
    memcpy(to_compare->name, name, length);
    to_compare->received_name = true;
}

void statuschange_callback(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length, void *user_data)
{
    struct test_data *to_compare = (struct test_data *)user_data;
    memcpy(to_compare->status_message, message, length);
    to_compare->received_status_message = true;
}

int main(int argc, char *argv[])
{
    Tox *tox1 = tox_new_log(0, 0, 0);
    Tox *tox2 = tox_new_log(0, 0, 0);

    struct test_data to_compare = { { 0 } };

    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox1, public_key);
    tox_friend_add_norequest(tox2, public_key, NULL);
    tox_self_get_public_key(tox2, public_key);
    tox_friend_add_norequest(tox1, public_key, NULL);

    uint8_t reference_name[TOX_MAX_NAME_LENGTH] = { 0 };
    uint8_t reference_status[TOX_MAX_STATUS_MESSAGE_LENGTH] = { 0 };

    set_random(tox1, tox_self_set_name, TOX_MAX_NAME_LENGTH);
    set_random(tox2, tox_self_set_name, TOX_MAX_NAME_LENGTH);
    set_random(tox1, tox_self_set_status_message, TOX_MAX_STATUS_MESSAGE_LENGTH);
    set_random(tox2, tox_self_set_status_message, TOX_MAX_STATUS_MESSAGE_LENGTH);

    tox_self_get_name(tox2, reference_name);
    tox_self_get_status_message(tox2, reference_status);

    tox_callback_friend_name(tox1, namechange_callback);
    tox_callback_friend_status_message(tox1, statuschange_callback);

    while (true) {
        if (tox_self_get_connection_status(tox1) &&
                tox_self_get_connection_status(tox2) &&
                tox_friend_get_connection_status(tox1, 0, 0) == TOX_CONNECTION_UDP) {
            printf("Connected.\n");
            break;
        }

        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, NULL);

        c_sleep(tox_iteration_interval(tox1));
    }

    while (true) {
        if (to_compare.received_name && to_compare.received_status_message) {
            printf("Exchanged names and status messages.\n");
            break;
        }

        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, NULL);

        c_sleep(tox_iteration_interval(tox1));
    }

    size_t save_size = tox_get_savedata_size(tox1);
    VLA(uint8_t, savedata, save_size);
    tox_get_savedata(tox1, savedata);

    struct Tox_Options *options = tox_options_new(NULL);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, savedata, save_size);

    Tox *tox_to_compare = tox_new(options, 0);

    tox_friend_get_name(tox_to_compare, 0, to_compare.name, 0);
    tox_friend_get_status_message(tox_to_compare, 0, to_compare.status_message, 0);

    assert(memcmp(reference_name, to_compare.name, TOX_MAX_NAME_LENGTH) == 0);
    assert(memcmp(reference_status, to_compare.status_message, TOX_MAX_STATUS_MESSAGE_LENGTH) == 0);

    tox_options_free(options);
    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox_to_compare);

    return 0;
}
