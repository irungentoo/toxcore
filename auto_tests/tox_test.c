/* Auto Tests
 *
 * Tox Tests
 *
 * The following tests were written with a small Tox network in mind. Therefore,
 * each test timeout was set to one for a small Tox Network. If connected to the
 * 'Global' Tox Network, traversing the DHT would take MUCH longer than the
 * timeouts allow. Because of this running these tests require NO other Tox
 * clients running or accessible on/to localhost.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#include <windows.h>
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, 0);
    }
}
static uint32_t messages_received;

static void print_message(Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type, const uint8_t *string, size_t length,
                          void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (type != TOX_MESSAGE_TYPE_NORMAL) {
        ck_abort_msg("Bad type");
    }

    uint8_t cmp_msg[TOX_MAX_MESSAGE_LENGTH];
    memset(cmp_msg, 'G', sizeof(cmp_msg));

    if (length == TOX_MAX_MESSAGE_LENGTH && memcmp(string, cmp_msg, sizeof(cmp_msg)) == 0) {
        ++messages_received;
    }
}

static uint32_t name_changes;

static void print_nickchange(Tox *m, uint32_t friendnumber, const uint8_t *string, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == sizeof("Gentoo") && memcmp(string, "Gentoo", sizeof("Gentoo")) == 0) {
        ++name_changes;
    }
}

static uint32_t status_m_changes;
static void print_status_m_change(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length,
                                  void *user_data)
{
    if (*((uint32_t *)user_data) != 974536) {
        return;
    }

    if (length == sizeof("Installing Gentoo") &&
            memcmp(message, "Installing Gentoo", sizeof("Installing Gentoo")) == 0) {
        ++status_m_changes;
    }
}

static uint32_t typing_changes;

static void print_typingchange(Tox *m, uint32_t friendnumber, bool typing, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (!typing) {
        typing_changes = 1;
    } else {
        typing_changes = 2;
    }
}

static uint32_t custom_packet;

static void handle_custom_packet(Tox *m, uint32_t friend_num, const uint8_t *data, size_t len, void *object)
{
    uint8_t number = *((uint32_t *)object);

    if (len != TOX_MAX_CUSTOM_PACKET_SIZE) {
        return;
    }

    uint8_t f_data[len];
    memset(f_data, number, len);

    if (memcmp(f_data, data, len) == 0) {
        ++custom_packet;
    } else {
        ck_abort_msg("Custom packet fail. %u", number);
    }

    return;
}

static uint64_t size_recv;
static uint64_t sending_pos;

static uint8_t file_cmp_id[TOX_FILE_ID_LENGTH];
static uint32_t file_accepted;
static uint64_t file_size;
static void tox_file_receive(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind, uint64_t filesize,
                             const uint8_t *filename, size_t filename_length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (kind != TOX_FILE_KIND_DATA) {
        ck_abort_msg("Bad kind");
    }

    if (!(filename_length == sizeof("Gentoo.exe") && memcmp(filename, "Gentoo.exe", sizeof("Gentoo.exe")) == 0)) {
        ck_abort_msg("Bad filename");
    }

    uint8_t file_id[TOX_FILE_ID_LENGTH];

    if (!tox_file_get_file_id(tox, friend_number, file_number, file_id, 0)) {
        ck_abort_msg("tox_file_get_file_id error");
    }

    if (memcmp(file_id, file_cmp_id, TOX_FILE_ID_LENGTH) != 0) {
        ck_abort_msg("bad file_id");
    }

    uint8_t empty[TOX_FILE_ID_LENGTH] = {0};

    if (memcmp(empty, file_cmp_id, TOX_FILE_ID_LENGTH) == 0) {
        ck_abort_msg("empty file_id");
    }

    file_size = filesize;

    if (filesize) {
        sending_pos = size_recv = 1337;

        TOX_ERR_FILE_SEEK err_s;

        if (!tox_file_seek(tox, friend_number, file_number, 1337, &err_s)) {
            ck_abort_msg("tox_file_seek error");
        }

        ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_OK, "tox_file_seek wrong error");
    } else {
        sending_pos = size_recv = 0;
    }

    TOX_ERR_FILE_CONTROL error;

    if (tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, &error)) {
        ++file_accepted;
    } else {
        ck_abort_msg("tox_file_control failed. %i", error);
    }

    TOX_ERR_FILE_SEEK err_s;

    if (tox_file_seek(tox, friend_number, file_number, 1234, &err_s)) {
        ck_abort_msg("tox_file_seek no error");
    }

    ck_assert_msg(err_s == TOX_ERR_FILE_SEEK_DENIED, "tox_file_seek wrong error");
}

static uint32_t sendf_ok;
static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                               void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

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
                                   size_t length,
                                   void *user_data)
{
    if (*((uint32_t *)user_data) != 974536) {
        return;
    }

    if (!sendf_ok) {
        ck_abort_msg("Didn't get resume control");
    }

    if (sending_pos != position) {
        ck_abort_msg("Bad position %llu", position);
    }

    if (length == 0) {
        if (file_sending_done) {
            ck_abort_msg("File sending already done.");
        }

        file_sending_done = 1;
        return;
    }

    if (position + length > max_sending) {
        if (m_send_reached) {
            ck_abort_msg("Requested done file tranfer.");
        }

        length = max_sending - position;
        m_send_reached = 1;
    }

    TOX_ERR_FILE_SEND_CHUNK error;
    uint8_t f_data[length];
    memset(f_data, sending_num, length);

    if (tox_file_send_chunk(tox, friend_number, file_number, position, f_data, length, &error)) {
        ++sending_num;
        sending_pos += length;
    } else {
        ck_abort_msg("Could not send chunk %i", error);
    }

    if (error != TOX_ERR_FILE_SEND_CHUNK_OK) {
        ck_abort_msg("Wrong error code");
    }
}


static uint8_t num;
static bool file_recv;
static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data,
                       size_t length, void *user_data)
{
    if (*((uint32_t *)user_data) != 974536) {
        return;
    }

    if (size_recv != position) {
        ck_abort_msg("Bad position");
    }

    if (length == 0) {
        file_recv = 1;
        return;
    }

    uint8_t f_data[length];
    memset(f_data, num, length);
    ++num;

    if (memcmp(f_data, data, length) == 0) {
        size_recv += length;
    } else {
        ck_abort_msg("FILE_CORRUPTED");
    }
}

static unsigned int connected_t1;
static void tox_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    if (*((uint32_t *)user_data) != 974536) {
        return;
    }

    if (connected_t1 && !connection_status) {
        ck_abort_msg("Tox went offline");
    }

    ck_assert_msg(connection_status == TOX_CONNECTION_UDP, "wrong status %u", connection_status);

    connected_t1 = connection_status;
}

START_TEST(test_few_clients)
{
    uint32_t index[] = { 1, 2, 3 };
    long long unsigned int con_time = 0, cur_time = time(NULL);
    TOX_ERR_NEW t_n_error;
    Tox *tox1 = tox_new_log(0, &t_n_error, &index[0]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox2 = tox_new_log(0, &t_n_error, &index[1]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox3 = tox_new_log(0, &t_n_error, &index[2]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(tox1, &error) == 33445, "First Tox instance did not bind to udp port 33445.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(tox2, &error) == 33446, "Second Tox instance did not bind to udp port 33446.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    {
        TOX_ERR_GET_PORT error;
        ck_assert_msg(tox_self_get_udp_port(tox3, &error) == 33447, "Third Tox instance did not bind to udp port 33447.\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    uint32_t to_compare = 974536;
    connected_t1 = 0;
    tox_callback_self_connection_status(tox1, tox_connection_status);
    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, 0);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t off = 1;

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
                con_time = time(NULL);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, 0) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, 0) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(50);
    }

    ck_assert_msg(connected_t1, "Tox1 isn't connected. %u", connected_t1);
    printf("tox clients connected took %llu seconds\n", time(NULL) - con_time);
    to_compare = 974536;
    tox_callback_friend_message(tox3, print_message);
    uint8_t msgs[TOX_MAX_MESSAGE_LENGTH + 1];
    memset(msgs, 'G', sizeof(msgs));
    TOX_ERR_FRIEND_SEND_MESSAGE errm;
    tox_friend_send_message(tox2, 0, TOX_MESSAGE_TYPE_NORMAL, msgs, TOX_MAX_MESSAGE_LENGTH + 1, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG, "TOX_MAX_MESSAGE_LENGTH is too small\n");
    tox_friend_send_message(tox2, 0, TOX_MESSAGE_TYPE_NORMAL, msgs, TOX_MAX_MESSAGE_LENGTH, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_OK, "TOX_MAX_MESSAGE_LENGTH is too big\n");

    while (1) {
        messages_received = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (messages_received) {
            break;
        }

        c_sleep(50);
    }

    printf("tox clients messaging succeeded\n");

    unsigned int save_size1 = tox_get_savedata_size(tox2);
    ck_assert_msg(save_size1 != 0 && save_size1 < 4096, "save is invalid size %u", save_size1);
    printf("%u\n", save_size1);
    uint8_t save1[save_size1];
    tox_get_savedata(tox2, save1);
    tox_kill(tox2);

    struct Tox_Options options;
    tox_options_default(&options);
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options.savedata_data = save1;
    options.savedata_length = save_size1;
    tox2 = tox_new_log(&options, NULL, &index[1]);
    cur_time = time(NULL);
    off = 1;

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online again after reloading, took %llu seconds\n", time(NULL) - cur_time);
                con_time = time(NULL);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, 0) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, 0) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(50);
    }

    printf("tox clients connected took %llu seconds\n", time(NULL) - con_time);
    tox_callback_friend_name(tox3, print_nickchange);
    TOX_ERR_SET_INFO err_n;
    bool succ = tox_self_set_name(tox2, (const uint8_t *)"Gentoo", sizeof("Gentoo"), &err_n);
    ck_assert_msg(succ && err_n == TOX_ERR_SET_INFO_OK, "tox_self_set_name failed because %u\n", err_n);

    while (1) {
        name_changes = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (name_changes) {
            break;
        }

        c_sleep(50);
    }

    ck_assert_msg(tox_friend_get_name_size(tox3, 0, 0) == sizeof("Gentoo"), "Name length not correct");
    uint8_t temp_name[sizeof("Gentoo")];
    tox_friend_get_name(tox3, 0, temp_name, 0);
    ck_assert_msg(memcmp(temp_name, "Gentoo", sizeof("Gentoo")) == 0, "Name not correct");

    tox_callback_friend_status_message(tox3, print_status_m_change);
    succ = tox_self_set_status_message(tox2, (const uint8_t *)"Installing Gentoo", sizeof("Installing Gentoo"), &err_n);
    ck_assert_msg(succ && err_n == TOX_ERR_SET_INFO_OK, "tox_self_set_status_message failed because %u\n", err_n);

    while (1) {
        status_m_changes = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (status_m_changes) {
            break;
        }

        c_sleep(50);
    }

    ck_assert_msg(tox_friend_get_status_message_size(tox3, 0, 0) == sizeof("Installing Gentoo"),
                  "status message length not correct");
    uint8_t temp_status_m[sizeof("Installing Gentoo")];
    tox_friend_get_status_message(tox3, 0, temp_status_m, 0);
    ck_assert_msg(memcmp(temp_status_m, "Installing Gentoo", sizeof("Installing Gentoo")) == 0,
                  "status message not correct");

    tox_callback_friend_typing(tox2, &print_typingchange);
    tox_self_set_typing(tox3, 0, 1, 0);

    while (1) {
        typing_changes = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (typing_changes == 2) {
            break;
        }

        ck_assert_msg(typing_changes == 0, "Typing fail");

        c_sleep(50);
    }

    ck_assert_msg(tox_friend_get_typing(tox2, 0, 0) == 1, "Typing fail");
    tox_self_set_typing(tox3, 0, 0, 0);

    while (1) {
        typing_changes = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (typing_changes == 1) {
            break;
        }

        ck_assert_msg(typing_changes == 0, "Typing fail");

        c_sleep(50);
    }

    TOX_ERR_FRIEND_QUERY err_t;
    ck_assert_msg(tox_friend_get_typing(tox2, 0, &err_t) == 0, "Typing fail");
    ck_assert_msg(err_t == TOX_ERR_FRIEND_QUERY_OK, "Typing fail");

    uint32_t packet_number = 160;
    tox_callback_friend_lossless_packet(tox3, &handle_custom_packet);
    uint8_t data_c[TOX_MAX_CUSTOM_PACKET_SIZE + 1];
    memset(data_c, ((uint8_t)packet_number), sizeof(data_c));
    int ret = tox_friend_send_lossless_packet(tox2, 0, data_c, sizeof(data_c), 0);
    ck_assert_msg(ret == 0, "tox_friend_send_lossless_packet bigger fail %i", ret);
    ret = tox_friend_send_lossless_packet(tox2, 0, data_c, TOX_MAX_CUSTOM_PACKET_SIZE, 0);
    ck_assert_msg(ret == 1, "tox_friend_send_lossless_packet fail %i", ret);

    while (1) {
        custom_packet = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &packet_number);

        if (custom_packet == 1) {
            break;
        }

        ck_assert_msg(custom_packet == 0, "Lossless packet fail");

        c_sleep(50);
    }

    packet_number = 200;
    tox_callback_friend_lossy_packet(tox3, &handle_custom_packet);
    memset(data_c, ((uint8_t)packet_number), sizeof(data_c));
    ret = tox_friend_send_lossy_packet(tox2, 0, data_c, sizeof(data_c), 0);
    ck_assert_msg(ret == 0, "tox_friend_send_lossy_packet bigger fail %i", ret);
    ret = tox_friend_send_lossy_packet(tox2, 0, data_c, TOX_MAX_CUSTOM_PACKET_SIZE, 0);
    ck_assert_msg(ret == 1, "tox_friend_send_lossy_packet fail %i", ret);

    while (1) {
        custom_packet = 0;
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &packet_number);

        if (custom_packet == 1) {
            break;
        }

        ck_assert_msg(custom_packet == 0, "lossy packet fail");

        c_sleep(50);
    }

    printf("Starting file transfer test.\n");

    file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    max_sending = UINT64_MAX;
    long long unsigned int f_time = time(NULL);
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    uint64_t totalf_size = 100 * 1024 * 1024;
    uint32_t fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, 0, (const uint8_t *)"Gentoo.exe",
                                  sizeof("Gentoo.exe"), 0);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    TOX_ERR_FILE_GET gfierr;
    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (file_sending_done) {
            if (sendf_ok && file_recv && totalf_size == file_size && size_recv == file_size && sending_pos == size_recv
                    && file_accepted == 1) {
                break;
            }

            ck_abort_msg("Something went wrong in file transfer %u %u %u %u %u %u %llu %llu %llu", sendf_ok, file_recv,
                         totalf_size == file_size, size_recv == file_size, sending_pos == size_recv, file_accepted == 1, totalf_size, size_recv,
                         sending_pos);
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(MIN(tox1_interval, MIN(tox2_interval, tox3_interval)));
    }

    printf("100MB file sent in %llu seconds\n", time(NULL) - f_time);

    printf("Starting file streaming transfer test.\n");

    file_sending_done = file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    totalf_size = UINT64_MAX;
    fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, 0, (const uint8_t *)"Gentoo.exe", sizeof("Gentoo.exe"),
                         0);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    max_sending = 100 * 1024;
    m_send_reached = 0;

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (file_sending_done) {
            if (sendf_ok && file_recv && m_send_reached && totalf_size == file_size && size_recv == max_sending
                    && sending_pos == size_recv && file_accepted == 1) {
                break;
            }

            ck_abort_msg("Something went wrong in file transfer %u %u %u %u %u %u %u %llu %llu %llu %llu", sendf_ok, file_recv,
                         m_send_reached, totalf_size == file_size, size_recv == max_sending, sending_pos == size_recv, file_accepted == 1,
                         totalf_size, file_size,
                         size_recv, sending_pos);
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(MIN(tox1_interval, MIN(tox2_interval, tox3_interval)));
    }

    printf("Starting file 0 transfer test.\n");

    file_sending_done = file_accepted = file_size = sendf_ok = size_recv = 0;
    file_recv = 0;
    tox_callback_file_recv_chunk(tox3, write_file);
    tox_callback_file_recv_control(tox2, file_print_control);
    tox_callback_file_chunk_request(tox2, tox_file_chunk_request);
    tox_callback_file_recv_control(tox3, file_print_control);
    tox_callback_file_recv(tox3, tox_file_receive);
    totalf_size = 0;
    fnum = tox_file_send(tox2, 0, TOX_FILE_KIND_DATA, totalf_size, 0, (const uint8_t *)"Gentoo.exe", sizeof("Gentoo.exe"),
                         0);
    ck_assert_msg(fnum != UINT32_MAX, "tox_new_file_sender fail");

    ck_assert_msg(!tox_file_get_file_id(tox2, 1, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_FRIEND_NOT_FOUND, "wrong error");
    ck_assert_msg(!tox_file_get_file_id(tox2, 0, fnum + 1, file_cmp_id, &gfierr), "tox_file_get_file_id didn't fail");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_NOT_FOUND, "wrong error");
    ck_assert_msg(tox_file_get_file_id(tox2, 0, fnum, file_cmp_id, &gfierr), "tox_file_get_file_id failed");
    ck_assert_msg(gfierr == TOX_ERR_FILE_GET_OK, "wrong error");

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (file_sending_done) {
            if (sendf_ok && file_recv && totalf_size == file_size && size_recv == file_size && sending_pos == size_recv
                    && file_accepted == 1) {
                break;
            }

            ck_abort_msg("Something went wrong in file transfer %u %u %u %u %u %u %llu %llu %llu", sendf_ok, file_recv,
                         totalf_size == file_size, size_recv == file_size, sending_pos == size_recv, file_accepted == 1, totalf_size, size_recv,
                         sending_pos);
        }

        uint32_t tox1_interval = tox_iteration_interval(tox1);
        uint32_t tox2_interval = tox_iteration_interval(tox2);
        uint32_t tox3_interval = tox_iteration_interval(tox3);

        c_sleep(MIN(tox1_interval, MIN(tox2_interval, tox3_interval)));
    }

    printf("test_few_clients succeeded, took %llu seconds\n", time(NULL) - cur_time);

    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
}
END_TEST

#ifdef TRAVIS_ENV
static const uint8_t timeout_mux = 20;
#else
static const uint8_t timeout_mux = 10;
#endif

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox few clients");

    DEFTESTCASE_SLOW(few_clients, 8 * timeout_mux);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
