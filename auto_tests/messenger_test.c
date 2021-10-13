/* unit tests for /core/Messenger.c
 *  Design:
 *      Just call every non-static function in Messenger.c, checking that
 *      they return as they should with check calls. "Bad" calls of the type
 *      function(bad_data, good_length) are _not_ checked for, this type
 *      of call is the fault of the client code.
 *
 *  Note:
 *      None of the functions here test things that rely on the network, i.e.
 *      checking that status changes are received, messages can be sent, etc.
 *      All of that is done in a separate test, with two local clients running. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#ifdef VANILLA_NACL
#include <crypto_box.h> // crypto_box_PUBLICKEYBYTES and other defines.
#else
#include <sodium.h>
#endif

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"

#define REALLY_BIG_NUMBER ((1) << (sizeof(uint16_t) * 7))

static bool enable_broken_tests = false;

static const char *friend_id_str = "e4b3d5030bc99494605aecc33ceec8875640c1d74aa32790e821b17e98771c4a00000000f1db";
static const char *good_id_str   = "d3f14b6d384d8f5f2a66cff637e69f28f539c5de61bc29744785291fa4ef4d64";
static const char *bad_id_str    = "9B569D14ff637e69f2";

static uint8_t *friend_id = nullptr;
static uint8_t *good_id   = nullptr;
static uint8_t *bad_id    = nullptr;

static int friend_id_num = 0;

static Messenger *m;

START_TEST(test_m_sendmesage)
{
    const char *message = "h-hi :3";
    int good_len = strlen(message);
    int bad_len = MAX_CRYPTO_PACKET_SIZE;


    ck_assert(m_send_message_generic(
                  m, -1, MESSAGE_NORMAL, (const uint8_t *)message, good_len, nullptr) == -1);
    ck_assert(m_send_message_generic(
                  m, REALLY_BIG_NUMBER, MESSAGE_NORMAL, (const uint8_t *)message, good_len, nullptr) == -1);
    ck_assert(m_send_message_generic(
                  m, 17, MESSAGE_NORMAL, (const uint8_t *)message, good_len, nullptr) == -1);
    ck_assert(m_send_message_generic(
                  m, friend_id_num, MESSAGE_NORMAL, (const uint8_t *)message, bad_len, nullptr) == -2);
}
END_TEST

START_TEST(test_m_get_userstatus_size)
{
    int rc = 0;
    ck_assert_msg((m_get_statusmessage_size(m, -1) == -1),
                  "m_get_statusmessage_size did NOT catch an argument of -1");
    ck_assert_msg((m_get_statusmessage_size(m, REALLY_BIG_NUMBER) == -1),
                  "m_get_statusmessage_size did NOT catch the following argument: %d\n",
                  REALLY_BIG_NUMBER);
    rc = m_get_statusmessage_size(m, friend_id_num);

    /* this WILL error if the original m_addfriend_norequest() failed */
    ck_assert_msg((rc >= 0 && rc <= MAX_STATUSMESSAGE_LENGTH),
                  "m_get_statusmessage_size is returning out of range values! (%i)\n"
                  "(this can be caused by the error of m_addfriend_norequest"
                  " in the beginning of the suite)\n", rc);
}
END_TEST

START_TEST(test_m_set_userstatus)
{
    const char *status = "online!";
    uint16_t good_length = strlen(status);
    uint16_t bad_length = REALLY_BIG_NUMBER;

    ck_assert_msg((m_set_statusmessage(m, (const uint8_t *)status, bad_length) == -1),
                  "m_set_userstatus did NOT catch the following length: %d\n",
                  REALLY_BIG_NUMBER);

    ck_assert_msg((m_set_statusmessage(m, (const uint8_t *)status, good_length) == 0),
                  "m_set_userstatus did NOT return 0 on the following length: %d\n"
                  "MAX_STATUSMESSAGE_LENGTH: %d\n", good_length, MAX_STATUSMESSAGE_LENGTH);
}
END_TEST

START_TEST(test_m_get_friend_connectionstatus)
{
    ck_assert_msg((m_get_friend_connectionstatus(m, -1) == -1),
                  "m_get_friend_connectionstatus did NOT catch an argument of -1.\n");
    ck_assert_msg((m_get_friend_connectionstatus(m, REALLY_BIG_NUMBER) == -1),
                  "m_get_friend_connectionstatus did NOT catch an argument of %d.\n",
                  REALLY_BIG_NUMBER);
}
END_TEST

START_TEST(test_m_friend_exists)
{
    ck_assert_msg((m_friend_exists(m, -1) == 0),
                  "m_friend_exists did NOT catch an argument of -1.\n");
    ck_assert_msg((m_friend_exists(m, REALLY_BIG_NUMBER) == 0),
                  "m_friend_exists did NOT catch an argument of %d.\n",
                  REALLY_BIG_NUMBER);
}
END_TEST

START_TEST(test_m_delfriend)
{
    ck_assert_msg((m_delfriend(m, -1) == -1),
                  "m_delfriend did NOT catch an argument of -1\n");
    ck_assert_msg((m_delfriend(m, REALLY_BIG_NUMBER) == -1),
                  "m_delfriend did NOT catch the following number: %d\n",
                  REALLY_BIG_NUMBER);
}
END_TEST

START_TEST(test_m_addfriend)
{
    const char *good_data = "test";
    const char *bad_data = "";

    int good_len = strlen(good_data);
    int bad_len = strlen(bad_data);
    int really_bad_len = (MAX_CRYPTO_PACKET_SIZE - crypto_box_PUBLICKEYBYTES
                          - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES
                          + crypto_box_ZEROBYTES + 100);

    /* TODO(irungentoo): Update this properly to latest master */
    if (m_addfriend(m, friend_id, (const uint8_t *)good_data, really_bad_len) != FAERR_TOOLONG) {
        ck_abort_msg("m_addfriend did NOT catch the following length: %d\n", really_bad_len);
    }

    /* this will return an error if the original m_addfriend_norequest() failed */
    if (m_addfriend(m, friend_id, (const uint8_t *)good_data, good_len) != FAERR_ALREADYSENT) {
        ck_abort_msg("m_addfriend did NOT catch adding a friend we already have.\n"
                     "(this can be caused by the error of m_addfriend_norequest in"
                     " the beginning of the suite)\n");
    }

    if (m_addfriend(m, good_id, (const uint8_t *)bad_data, bad_len) != FAERR_NOMESSAGE) {
        ck_abort_msg("m_addfriend did NOT catch the following length: %d\n", bad_len);
    }

    /* this should REALLY return an error */
    /* TODO(irungentoo): validate client_id in m_addfriend? */
    if (m_addfriend(m, bad_id, (const uint8_t *)good_data, good_len) >= 0) {
        ck_abort_msg("The following ID passed through "
                     "m_addfriend without an error:\n'%s'\n", bad_id_str);
    }
}
END_TEST

START_TEST(test_setname)
{
    const char *good_name = "consensualCorn";
    int good_length = strlen(good_name);
    int bad_length = REALLY_BIG_NUMBER;

    ck_assert_msg((setname(m, (const uint8_t *)good_name, bad_length) == -1),
                  "setname() did NOT error on %d as a length argument!\n", bad_length);

    ck_assert_msg((setname(m, (const uint8_t *)good_name, good_length) == 0),
                  "setname() did NOT return 0 on good arguments!\n");
}
END_TEST

START_TEST(test_getself_name)
{
    const char *nickname = "testGallop";
    size_t len = strlen(nickname);
    char *nick_check = (char *)calloc(len + 1, 1);

    setname(m, (const uint8_t *)nickname, len);
    getself_name(m, (uint8_t *)nick_check);

    ck_assert_msg((memcmp(nickname, nick_check, len) == 0),
                  "getself_name failed to return the known name!\n"
                  "known name: %s\nreturned: %s\n", nickname, nick_check);
    free(nick_check);
}
END_TEST

/* this test is excluded for now, due to lack of a way
 *  to set a friend's status for now.
 *  ideas:
 *      if we have access to the friends list, we could
 *      just add a status manually ourselves. */
#if 0
START_TEST(test_m_copy_userstatus)
{
    assert(m_copy_userstatus(-1, buf, MAX_USERSTATUS_LENGTH) == -1);
    assert(m_copy_userstatus(REALLY_BIG_NUMBER, buf, MAX_USERSTATUS_LENGTH) == -1);
    m_copy_userstatus(friend_id_num, buf, MAX_USERSTATUS_LENGTH + 6);

    assert(strcmp(name_buf, friend_id_status) == 0);
}
END_TEST
#endif

START_TEST(test_getname)
{
    uint8_t name_buf[MAX_NAME_LENGTH];
    uint8_t test_name[] = {'f', 'o', 'o'};

    ck_assert(getname(m, -1, name_buf) == -1);
    ck_assert(getname(m, REALLY_BIG_NUMBER, name_buf) == -1);

    memcpy(m->friendlist[0].name, &test_name[0], 3);
    m->friendlist[0].name_length = 4;
    ck_assert(getname(m, 0, &name_buf[0]) == 4);

    ck_assert(strcmp((char *)&name_buf[0], "foo") == 0);
}
END_TEST

START_TEST(test_dht_state_saveloadsave)
{
    /* validate that:
     * a) saving stays within the confined space
     * b) a save()d state can be load()ed back successfully
     * c) a second save() is of equal size
     * d) the second save() is of equal content */
    const size_t extra = 64;
    const size_t size = dht_size(m->dht);
    VLA(uint8_t, buffer, size + 2 * extra);
    memset(buffer, 0xCD, extra);
    memset(buffer + extra + size, 0xCD, extra);
    dht_save(m->dht, buffer + extra);

    for (size_t i = 0; i < extra; i++) {
        ck_assert_msg(buffer[i] == 0xCD, "Buffer underwritten from dht_save() @%u", (unsigned)i);
        ck_assert_msg(buffer[extra + size + i] == 0xCD, "Buffer overwritten from dht_save() @%u", (unsigned)i);
    }

    const int res = dht_load(m->dht, buffer + extra, size);

    if (res == -1) {
        ck_assert_msg(res == 0, "Failed to load back stored buffer: res == -1");
    } else {
        const size_t offset = res >> 4;
        const uint8_t *ptr = buffer + extra + offset;
        ck_assert_msg(res == 0, "Failed to load back stored buffer: 0x%02x%02x%02x%02x%02x%02x%02x%02x @%u/%u, code %d",
                      ptr[-2], ptr[-1], ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5],
                      (unsigned)offset, (unsigned)size, res & 0x0F);
    }

    const size_t size2 = dht_size(m->dht);
    ck_assert_msg(size == size2, "Messenger \"grew\" in size from a store/load cycle: %u -> %u", (unsigned)size,
                  (unsigned)size2);

    VLA(uint8_t, buffer2, size2);
    dht_save(m->dht, buffer2);

    ck_assert_msg(!memcmp(buffer + extra, buffer2, size), "DHT state changed by store/load/store cycle");
}
END_TEST

static Suite *messenger_suite(void)
{
    Suite *s = suite_create("Messenger");

    DEFTESTCASE(dht_state_saveloadsave);

    DEFTESTCASE(getself_name);
    DEFTESTCASE(m_get_userstatus_size);
    DEFTESTCASE(m_set_userstatus);

    if (enable_broken_tests) {
        DEFTESTCASE(m_addfriend);
    }

    DEFTESTCASE(m_friend_exists);
    DEFTESTCASE(m_get_friend_connectionstatus);
    DEFTESTCASE(m_delfriend);

    DEFTESTCASE(setname);
    DEFTESTCASE(getname);
    DEFTESTCASE(m_sendmesage);

    return s;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    friend_id = hex_string_to_bin(friend_id_str);
    good_id   = hex_string_to_bin(good_id_str);
    bad_id    = hex_string_to_bin(bad_id_str);

    Mono_Time *mono_time = mono_time_new();

    /* IPv6 status from global define */
    Messenger_Options options = {0};
    options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    options.port_range[0] = 41234;
    options.port_range[1] = 44234;
    options.log_callback = (logger_cb *)print_debug_log;
    m = new_messenger(mono_time, &options, nullptr);

    /* setup a default friend and friendnum */
    if (m_addfriend_norequest(m, friend_id) < 0) {
        fputs("m_addfriend_norequest() failed on a valid ID!\n"
              "this was CRITICAL to the test, and the build WILL fail.\n"
              "the tests will continue now...\n\n", stderr);
    }

    if ((friend_id_num = getfriend_id(m, friend_id)) < 0) {
        fputs("getfriend_id() failed on a valid ID!\n"
              "this was CRITICAL to the test, and the build WILL fail.\n"
              "the tests will continue now...\n\n", stderr);
    }

    Suite *messenger = messenger_suite();
    SRunner *test_runner = srunner_create(messenger);
    int number_failed = 0;

    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);
    free(friend_id);
    free(good_id);
    free(bad_id);

    kill_messenger(m);
    mono_time_free(mono_time);

    return number_failed;
}
