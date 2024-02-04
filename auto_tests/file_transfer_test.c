/* File transfer test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

#ifdef TOX_LOCALHOST
#undef TOX_LOCALHOST
#endif
#if USE_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

static void accept_friend_request(const Tox_Event_Friend_Request *event, void *userdata)
{
    Tox *tox = (Tox *)userdata;

    const uint8_t *public_key = tox_event_friend_request_get_public_key(event);
    const uint8_t *data = tox_event_friend_request_get_message(event);
    const size_t length = tox_event_friend_request_get_message_length(event);

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(tox, public_key, nullptr);
    }
}

static uint64_t size_recv;
static uint64_t sending_pos;

static uint8_t file_cmp_id[TOX_FILE_ID_LENGTH];
static uint32_t file_accepted;
static uint64_t file_size;
static void tox_file_receive(const Tox_Event_File_Recv *event, void *userdata)
{
    Tox *state_tox = (Tox *)userdata;

    const uint32_t friend_number = tox_event_file_recv_get_friend_number(event);
    const uint32_t file_number = tox_event_file_recv_get_file_number(event);
    const uint32_t kind = tox_event_file_recv_get_kind(event);
    const uint64_t filesize = tox_event_file_recv_get_file_size(event);
    const uint8_t *filename = tox_event_file_recv_get_filename(event);
    const size_t filename_length = tox_event_file_recv_get_filename_length(event);

    ck_assert_msg(kind == TOX_FILE_KIND_DATA, "bad kind");

    ck_assert_msg(filename_length == sizeof("Gentoo.exe")
                  && memcmp(filename, "Gentoo.exe", sizeof("Gentoo.exe")) == 0, "bad filename");

    uint8_t file_id[TOX_FILE_ID_LENGTH];

    ck_assert_msg(tox_file_get_file_id(state_tox, friend_number, file_number, file_id, nullptr), "tox_file_get_file_id error");

    ck_assert_msg(memcmp(file_id, file_cmp_id, TOX_FILE_ID_LENGTH) == 0, "bad file_id");

    const uint8_t empty[TOX_FILE_ID_LENGTH] = {0};

    ck_assert_msg(memcmp(empty, file_cmp_id, TOX_FILE_ID_LENGTH) != 0, "empty file_id");

    file_size = filesize;

    if (filesize) {
        sending_pos = size_recv = 1337;

        Tox_Err_File_Seek err_s;

        ck_assert_msg(tox_file_seek(state_tox, friend_number, file_number, 1337, &err_s), "tox_file_seek error");

        ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_OK, "tox_file_seek wrong error");

    } else {
        sending_pos = size_recv = 0;
    }

    Tox_Err_File_Control error;

    ck_assert_msg(tox_file_control(state_tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, &error),
                  "tox_file_control failed. %i", error);
    ++file_accepted;

    Tox_Err_File_Seek err_s;

    ck_assert_msg(!tox_file_seek(state_tox, friend_number, file_number, 1234, &err_s), "tox_file_seek no error");

    ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_DENIED, "tox_file_seek wrong error");
}

static uint32_t sendf_ok;
static void file_print_control(const Tox_Event_File_Recv_Control *event,
                               void *userdata)
{
    const uint32_t file_number = tox_event_file_recv_control_get_file_number(event);
    const Tox_File_Control control = tox_event_file_recv_control_get_control(event);

    /* First send file num is 0.*/
    if (file_number == 0 && control == TOX_FILE_CONTROL_RESUME) {
        sendf_ok = 1;
    }
}

static uint64_t max_sending;
static bool m_send_reached;
static uint8_t sending_num;
static bool file_sending_done;
static void tox_file_chunk_request(const Tox_Event_File_Chunk_Request *event, void *user_data)
{
    Tox *state_tox = (Tox *)user_data;

    const uint32_t friend_number = tox_event_file_chunk_request_get_friend_number(event);
    const uint32_t file_number = tox_event_file_chunk_request_get_file_number(event);
    const uint64_t position = tox_event_file_chunk_request_get_position(event);
    size_t length = tox_event_file_chunk_request_get_length(event);

    ck_assert_msg(sendf_ok, "didn't get resume control");

    ck_assert_msg(sending_pos == position, "bad position %lu (should be %lu)", (unsigned long)position, (unsigned long)sending_pos);

    if (length == 0) {
        ck_assert_msg(!file_sending_done, "file sending already done");

        file_sending_done = 1;
        return;
    }

    if (position + length > max_sending) {
        ck_assert_msg(!m_send_reached, "requested done file transfer");

        length = max_sending - position;
        m_send_reached = 1;
    }

    VLA(uint8_t, f_data, length);
    memset(f_data, sending_num, length);

    Tox_Err_File_Send_Chunk error;
    tox_file_send_chunk(state_tox, friend_number, file_number, position, f_data, length, &error);

    ck_assert_msg(error == TOX_ERR_FILE_SEND_CHUNK_OK,
                  "could not send chunk, error num=%d pos=%d len=%d", (int)error, (int)position, (int)length);

    ++sending_num;
    sending_pos += length;
}

static uint8_t num;
static bool file_recv;
static void write_file(const Tox_Event_File_Recv_Chunk *event, void *user_data)
{
    const uint64_t position = tox_event_file_recv_chunk_get_position(event);
    const uint8_t *data = tox_event_file_recv_chunk_get_data(event);
    const size_t length = tox_event_file_recv_chunk_get_data_length(event);

    ck_assert_msg(size_recv == position, "bad position");

    if (length == 0) {
        file_recv = 1;
        return;
    }

    VLA(uint8_t, f_data, length);
    memset(f_data, num, length);
    ++num;

    ck_assert_msg(memcmp(f_data, data, length) == 0, "FILE_CORRUPTED");

    size_recv += length;
}

static void iterate_and_dispatch(const Tox_Dispatch *dispatch, Tox *tox)
{
    Tox_Err_Events_Iterate err;
    Tox_Events *events;

    events = tox_events_iterate(tox, true, &err);
    ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
    tox_dispatch_invoke(dispatch, events, tox);
    tox_events_free(events);
}

static void file_transfer_test(void)
{
    printf("Starting test: few_clients\n");
    uint32_t index[] = { 1, 2, 3 };
    long long unsigned int cur_time = time(nullptr);
    Tox_Err_New t_n_error;
    Tox *tox1 = tox_new_log(nullptr, &t_n_error, &index[0]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox2 = tox_new_log(nullptr, &t_n_error, &index[1]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox3 = tox_new_log(nullptr, &t_n_error, &index[2]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    tox_events_init(tox1);
    tox_events_init(tox2);
    tox_events_init(tox3);

    Tox_Dispatch *dispatch1 = tox_dispatch_new(nullptr);
    ck_assert(dispatch1 != nullptr);
    Tox_Dispatch *dispatch2 = tox_dispatch_new(nullptr);
    ck_assert(dispatch2 != nullptr);
    Tox_Dispatch *dispatch3 = tox_dispatch_new(nullptr);
    ck_assert(dispatch3 != nullptr);

    tox_events_callback_friend_request(dispatch2, accept_friend_request);

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %u", test);

    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, TOX_LOCALHOST, dht_port, dht_key, nullptr);
    tox_bootstrap(tox3, TOX_LOCALHOST, dht_port, dht_key, nullptr);

    printf("Waiting for toxes to come online\n");

    do {
        iterate_and_dispatch(dispatch1, tox1);
        iterate_and_dispatch(dispatch2, tox2);
        iterate_and_dispatch(dispatch3, tox3);

        printf("Connections: self (%d, %d, %d), friends (%d, %d)\n",
               tox_self_get_connection_status(tox1),
               tox_self_get_connection_status(tox2),
               tox_self_get_connection_status(tox3),
               tox_friend_get_connection_status(tox2, 0, nullptr),
               tox_friend_get_connection_status(tox3, 0, nullptr));
        c_sleep(ITERATION_INTERVAL);
    } while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
             tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE ||
             tox_self_get_connection_status(tox3) == TOX_CONNECTION_NONE ||
             tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_NONE ||
             tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_NONE);

    printf("Starting file transfer test: 100MiB file.\n");

    file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    max_sending = UINT64_MAX;
    uint64_t f_time = time(nullptr);
    tox_events_callback_file_recv_chunk(dispatch3, write_file);
    tox_events_callback_file_recv_control(dispatch2, file_print_control);
    tox_events_callback_file_chunk_request(dispatch2, tox_file_chunk_request);
    tox_events_callback_file_recv_control(dispatch3, file_print_control);
    tox_events_callback_file_recv(dispatch3, tox_file_receive);
    uint64_t totalf_size = 100 * 1024 * 1024;
    uint32_t fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, nullptr, (const uint8_t *)"Gentoo.exe",
                                  sizeof("Gentoo.exe"), nullptr);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    Tox_Err_File_Get gfierr;
    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    const size_t max_iterations = INT16_MAX;

    for (size_t i = 0; i < max_iterations; i++) {
        iterate_and_dispatch(dispatch1, tox1);
        iterate_and_dispatch(dispatch2, tox2);
        iterate_and_dispatch(dispatch3, tox3);

        if (file_sending_done) {
            ck_assert_msg(sendf_ok && file_recv && totalf_size == file_size && size_recv == file_size && sending_pos == size_recv
                          && file_accepted == 1,
                          "Something went wrong in file transfer %u %u %u %u %u %u %lu %lu %lu",
                          sendf_ok, file_recv, totalf_size == file_size, size_recv == file_size, sending_pos == size_recv,
                          file_accepted == 1, (unsigned long)totalf_size, (unsigned long)size_recv,
                          (unsigned long)sending_pos);
            break;
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        if ((i + 1) % 500 == 0) {
            printf("after %u iterations: %.2fMiB done\n", (unsigned int)i + 1, (double)size_recv / 1024 / 1024);
        }

        c_sleep(min_u32(tox1_interval, min_u32(tox2_interval, tox3_interval)));
    }

    ck_assert_msg(file_sending_done, "file sending did not complete after %u iterations: sendf_ok:%u file_recv:%u "
                  "totalf_size==file_size:%u size_recv==file_size:%u sending_pos==size_recv:%u file_accepted:%u "
                  "totalf_size:%lu size_recv:%lu sending_pos:%lu",
                  (unsigned int)max_iterations, sendf_ok, file_recv,
                  totalf_size == file_size, size_recv == file_size, sending_pos == size_recv, file_accepted == 1,
                  (unsigned long)totalf_size, (unsigned long)size_recv,
                  (unsigned long)sending_pos);

    printf("100MiB file sent in %lu seconds\n", (unsigned long)(time(nullptr) - f_time));

    printf("starting file 0 transfer test.\n");

    file_sending_done = 0;
    file_accepted = 0;
    file_size = 0;
    sendf_ok = 0;
    size_recv = 0;
    file_recv = 0;
    tox_events_callback_file_recv_chunk(dispatch3, write_file);
    tox_events_callback_file_recv_control(dispatch2, file_print_control);
    tox_events_callback_file_chunk_request(dispatch2, tox_file_chunk_request);
    tox_events_callback_file_recv_control(dispatch3, file_print_control);
    tox_events_callback_file_recv(dispatch3, tox_file_receive);
    totalf_size = 0;
    fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, nullptr,
                         (const uint8_t *)"Gentoo.exe", sizeof("Gentoo.exe"), nullptr);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    do {
        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(min_u32(tox1_interval, min_u32(tox2_interval, tox3_interval)));

        iterate_and_dispatch(dispatch1, tox1);
        iterate_and_dispatch(dispatch2, tox2);
        iterate_and_dispatch(dispatch3, tox3);
    } while (!file_sending_done);

    ck_assert_msg(sendf_ok && file_recv && totalf_size == file_size && size_recv == file_size
                  && sending_pos == size_recv && file_accepted == 1,
                  "something went wrong in file transfer %u %u %u %u %u %u %llu %llu %llu", sendf_ok, file_recv,
                  totalf_size == file_size, size_recv == file_size, sending_pos == size_recv, file_accepted == 1,
                  (unsigned long long)totalf_size, (unsigned long long)size_recv,
                  (unsigned long long)sending_pos);

    printf("file_transfer_test succeeded, took %llu seconds\n", time(nullptr) - cur_time);

    tox_dispatch_free(dispatch3);
    tox_dispatch_free(dispatch2);
    tox_dispatch_free(dispatch1);
    tox_kill(tox3);
    tox_kill(tox2);
    tox_kill(tox1);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    file_transfer_test();
    return 0;
}
