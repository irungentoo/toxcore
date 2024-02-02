/* File transfer test: streaming version (no known size).
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

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}

static uint64_t size_recv;
static uint64_t sending_pos;

static uint8_t file_cmp_id[TOX_FILE_ID_LENGTH];
static uint32_t file_accepted;
static uint64_t file_size;
static void tox_file_receive(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind, uint64_t filesize,
                             const uint8_t *filename, size_t filename_length, void *userdata)
{
    ck_assert_msg(kind == TOX_FILE_KIND_DATA, "bad kind");

    ck_assert_msg(filename_length == sizeof("Gentoo.exe")
                  && memcmp(filename, "Gentoo.exe", sizeof("Gentoo.exe")) == 0, "bad filename");

    uint8_t file_id[TOX_FILE_ID_LENGTH];

    ck_assert_msg(tox_file_get_file_id(tox, friend_number, file_number, file_id, nullptr), "tox_file_get_file_id error");

    ck_assert_msg(memcmp(file_id, file_cmp_id, TOX_FILE_ID_LENGTH) == 0, "bad file_id");

    const uint8_t empty[TOX_FILE_ID_LENGTH] = {0};

    ck_assert_msg(memcmp(empty, file_cmp_id, TOX_FILE_ID_LENGTH) != 0, "empty file_id");

    file_size = filesize;

    if (filesize) {
        sending_pos = size_recv = 1337;

        Tox_Err_File_Seek err_s;

        ck_assert_msg(tox_file_seek(tox, friend_number, file_number, 1337, &err_s), "tox_file_seek error");

        ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_OK, "tox_file_seek wrong error");

    } else {
        sending_pos = size_recv = 0;
    }

    Tox_Err_File_Control error;

    ck_assert_msg(tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, &error),
                  "tox_file_control failed. %i", error);
    ++file_accepted;

    Tox_Err_File_Seek err_s;

    ck_assert_msg(!tox_file_seek(tox, friend_number, file_number, 1234, &err_s), "tox_file_seek no error");

    ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_DENIED, "tox_file_seek wrong error");
}

static uint32_t sendf_ok;
static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, Tox_File_Control control,
                               void *userdata)
{
    /* First send file num is 0.*/
    if (file_number == 0 && control == TOX_FILE_CONTROL_RESUME) {
        sendf_ok = 1;
    }
}

static uint64_t max_sending;
static bool m_send_reached;
static uint8_t sending_num;
static bool file_sending_done;
static void tox_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                   size_t length, void *user_data)
{
    ck_assert_msg(sendf_ok, "didn't get resume control");

    ck_assert_msg(sending_pos == position, "bad position %lu", (unsigned long)position);

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
    tox_file_send_chunk(tox, friend_number, file_number, position, f_data, length, &error);

    ck_assert_msg(error == TOX_ERR_FILE_SEND_CHUNK_OK,
                  "could not send chunk, error num=%d pos=%d len=%d", (int)error, (int)position, (int)length);

    ++sending_num;
    sending_pos += length;
}

static uint8_t num;
static bool file_recv;
static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
                       size_t length, void *user_data)
{
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

    tox_callback_friend_request(tox2, accept_friend_request);
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
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

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

    printf("Starting file streaming transfer test.\n");

    file_sending_done = 0;
    file_accepted = 0;
    file_size = 0;
    sendf_ok = 0;
    size_recv = 0;
    file_recv = 0;
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    const uint64_t totalf_size = UINT64_MAX;
    Tox_File_Number fnum = tox_file_send(
                               tox2, 0, TOX_FILE_KIND_DATA, totalf_size, nullptr,
                               (const uint8_t *)"Gentoo.exe", sizeof("Gentoo.exe"), nullptr);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    Tox_Err_File_Get gfierr;
    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    max_sending = 100 * 1024;
    m_send_reached = 0;

    do {
        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(min_u32(tox1_interval, min_u32(tox2_interval, tox3_interval)));
    } while (!file_sending_done);

    ck_assert_msg(sendf_ok && file_recv && m_send_reached && totalf_size == file_size && size_recv == max_sending
                  && sending_pos == size_recv && file_accepted == 1,
                  "something went wrong in file transfer %u %u %u %u %u %u %u %lu %lu %lu %lu", sendf_ok, file_recv,
                  m_send_reached, totalf_size == file_size, size_recv == max_sending, sending_pos == size_recv, file_accepted == 1,
                  (unsigned long)totalf_size, (unsigned long)file_size,
                  (unsigned long)size_recv, (unsigned long)sending_pos);

    printf("file_transfer_test succeeded, took %llu seconds\n", time(nullptr) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    file_transfer_test();
    return 0;
}
