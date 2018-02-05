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

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "check_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#include "helpers.h"

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
        tox_friend_add_norequest(m, public_key, nullptr);
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

    VLA(uint8_t, f_data, len);
    memset(f_data, number, len);

    if (memcmp(f_data, data, len) == 0) {
        ++custom_packet;
    } else {
        ck_abort_msg("Custom packet fail. %u", number);
    }

    return;
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
    long long unsigned int con_time = 0, cur_time = time(nullptr);
    TOX_ERR_NEW t_n_error;
    Tox *tox1 = tox_new_log(nullptr, &t_n_error, &index[0]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox2 = tox_new_log(nullptr, &t_n_error, &index[1]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");
    Tox *tox3 = tox_new_log(nullptr, &t_n_error, &index[2]);
    ck_assert_msg(t_n_error == TOX_ERR_NEW_OK, "wrong error");

    ck_assert_msg(tox1 && tox2 && tox3, "Failed to create 3 tox instances");

    {
        TOX_ERR_GET_PORT error;
        uint16_t first_port = tox_self_get_udp_port(tox1, &error);
        ck_assert_msg(33445 <= first_port && first_port <= 33545 - 2,
                      "First Tox instance did not bind to udp port inside [33445, 33543].\n");
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");

        ck_assert_msg(tox_self_get_udp_port(tox2, &error) == first_port + 1,
                      "Second Tox instance did not bind to udp port %d.\n", first_port + 1);
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");

        ck_assert_msg(tox_self_get_udp_port(tox3, &error) == first_port + 2,
                      "Third Tox instance did not bind to udp port %d.\n", first_port + 2);
        ck_assert_msg(error == TOX_ERR_GET_PORT_OK, "wrong error");
    }

    uint32_t to_compare = 974536;
    connected_t1 = 0;
    tox_callback_self_connection_status(tox1, tox_connection_status);
    tox_callback_friend_request(tox2, accept_friend_request);
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);
    uint32_t test = tox_friend_add(tox3, address, (const uint8_t *)"Gentoo", 7, nullptr);
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);

    uint8_t off = 1;

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online, took %llu seconds\n", time(nullptr) - cur_time);
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(50);
    }

    ck_assert_msg(connected_t1, "Tox1 isn't connected. %u", connected_t1);
    printf("tox clients connected took %llu seconds\n", time(nullptr) - con_time);
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
    ck_assert_msg(save_size1 != 0, "save is invalid size %u", save_size1);
    printf("%u\n", save_size1);
    VLA(uint8_t, save1, save_size1);
    tox_get_savedata(tox2, save1);
    tox_kill(tox2);

    struct Tox_Options *options = tox_options_new(nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, save1, save_size1);
    tox2 = tox_new_log(options, nullptr, &index[1]);
    cur_time = time(nullptr);
    off = 1;

    while (1) {
        tox_iterate(tox1, &to_compare);
        tox_iterate(tox2, &to_compare);
        tox_iterate(tox3, &to_compare);

        if (tox_self_get_connection_status(tox1) && tox_self_get_connection_status(tox2)
                && tox_self_get_connection_status(tox3)) {
            if (off) {
                printf("Toxes are online again after reloading, took %llu seconds\n", time(nullptr) - cur_time);
                con_time = time(nullptr);
                off = 0;
            }

            if (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_UDP
                    && tox_friend_get_connection_status(tox3, 0, nullptr) == TOX_CONNECTION_UDP) {
                break;
            }
        }

        c_sleep(50);
    }

    printf("tox clients connected took %llu seconds\n", time(nullptr) - con_time);
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

    ck_assert_msg(tox_friend_get_name_size(tox3, 0, nullptr) == sizeof("Gentoo"), "Name length not correct");
    uint8_t temp_name[sizeof("Gentoo")];
    tox_friend_get_name(tox3, 0, temp_name, nullptr);
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

    ck_assert_msg(tox_friend_get_status_message_size(tox3, 0, nullptr) == sizeof("Installing Gentoo"),
                  "status message length not correct");
    uint8_t temp_status_m[sizeof("Installing Gentoo")];
    tox_friend_get_status_message(tox3, 0, temp_status_m, nullptr);
    ck_assert_msg(memcmp(temp_status_m, "Installing Gentoo", sizeof("Installing Gentoo")) == 0,
                  "status message not correct");

    tox_callback_friend_typing(tox2, &print_typingchange);
    tox_self_set_typing(tox3, 0, 1, nullptr);

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

    ck_assert_msg(tox_friend_get_typing(tox2, 0, nullptr) == 1, "Typing fail");
    tox_self_set_typing(tox3, 0, 0, nullptr);

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
    int ret = tox_friend_send_lossless_packet(tox2, 0, data_c, sizeof(data_c), nullptr);
    ck_assert_msg(ret == 0, "tox_friend_send_lossless_packet bigger fail %i", ret);
    ret = tox_friend_send_lossless_packet(tox2, 0, data_c, TOX_MAX_CUSTOM_PACKET_SIZE, nullptr);
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
    ret = tox_friend_send_lossy_packet(tox2, 0, data_c, sizeof(data_c), nullptr);
    ck_assert_msg(ret == 0, "tox_friend_send_lossy_packet bigger fail %i", ret);
    ret = tox_friend_send_lossy_packet(tox2, 0, data_c, TOX_MAX_CUSTOM_PACKET_SIZE, nullptr);
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

    printf("test_few_clients succeeded, took %llu seconds\n", time(nullptr) - cur_time);

    tox_options_free(options);
    tox_kill(tox1);
    tox_kill(tox2);
    tox_kill(tox3);
}
END_TEST

static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox few clients");

    DEFTESTCASE(few_clients);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(nullptr));

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
