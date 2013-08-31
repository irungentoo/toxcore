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

#include "../toxcore/Messenger.h"
#include "../toxcore/Lossless_UDP.h"
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>

#define REALLY_BIG_NUMBER ((1) << (sizeof(uint16_t) * 7))
#define STRINGS_EQUAL(X, Y) (strcmp(X, Y) == 0)

char *friend_id_str = "e4b3d5030bc99494605aecc33ceec8875640c1d74aa32790e821b17e98771c4a00000000f1db";

/* in case we need more than one ID for a test */
char *good_id_a_str = "DB9B569D14850ED8364C3744CAC2C8FF78985D213E980C7C508D0E91E8E45441";
char *good_id_b_str = "d3f14b6d384d8f5f2a66cff637e69f28f539c5de61bc29744785291fa4ef4d64";

char *bad_id_str =    "9B569D14ff637e69f2";

unsigned char *friend_id = NULL;
unsigned char *good_id_a = NULL;
unsigned char *good_id_b = NULL;
unsigned char *bad_id    = NULL;

int friend_id_num = 0;

Messenger *m;

unsigned char *hex_string_to_bin(char hex_string[])
{
    size_t len = strlen(hex_string);
    unsigned char *val = calloc(1, len);
    char *pos = hex_string;
    int i = 0;

    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &val[i]);

    return val;
}

START_TEST(test_m_sendmesage)
{
    char *message = "h-hi :3";
    int good_len = strlen(message);
    int bad_len = MAX_DATA_SIZE;


    ck_assert(m_sendmessage(m, -1, (uint8_t *)message, good_len) == 0);
    ck_assert(m_sendmessage(m, REALLY_BIG_NUMBER, (uint8_t *)message, good_len) == 0);
    ck_assert(m_sendmessage(m, 17, (uint8_t *)message, good_len) == 0);
    ck_assert(m_sendmessage(m, friend_id_num, (uint8_t *)message, bad_len) == 0);
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
    ck_assert_msg((rc > 0 && rc <= MAX_STATUSMESSAGE_LENGTH),
                  "m_get_statusmessage_size is returning out of range values!\n"
                  "(this can be caused by the error of m_addfriend_norequest"
                  " in the beginning of the suite)\n");
}
END_TEST

START_TEST(test_m_set_userstatus)
{
    char *status = "online!";
    uint16_t good_length = strlen(status);
    uint16_t bad_length = REALLY_BIG_NUMBER;

    ck_assert_msg((m_set_statusmessage(m, (uint8_t *)status, bad_length) == -1),
                  "m_set_userstatus did NOT catch the following length: %d\n",
                  REALLY_BIG_NUMBER);

    ck_assert_msg((m_set_statusmessage(m, (uint8_t *)status, good_length) == 0),
                  "m_set_userstatus did NOT return 0 on the following length: %d\n"
                  "MAX_STATUSMESSAGE_LENGTH: %d\n", good_length, MAX_STATUSMESSAGE_LENGTH);
}
END_TEST

START_TEST(test_m_friendstatus)
{
    ck_assert_msg((m_friendstatus(m, -1) == NOFRIEND),
                  "m_friendstatus did NOT catch an argument of -1.\n");
    ck_assert_msg((m_friendstatus(m, REALLY_BIG_NUMBER) == NOFRIEND),
                  "m_friendstatus did NOT catch an argument of %d.\n",
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
/*
START_TEST(test_m_addfriend)
{
    char *good_data = "test";
    char *bad_data = "";

    int good_len = strlen(good_data);
    int bad_len = strlen(bad_data);
    int really_bad_len = (MAX_DATA_SIZE - crypto_box_PUBLICKEYBYTES
                     - crypto_box_NONCEBYTES - crypto_box_BOXZEROBYTES
                                      + crypto_box_ZEROBYTES + 100); */
/* TODO: Update this properly to latest master
    if(m_addfriend(m, (uint8_t *)friend_id, (uint8_t *)good_data, really_bad_len) != FAERR_TOOLONG)
        ck_abort_msg("m_addfriend did NOT catch the following length: %d\n", really_bad_len);
*/
/* this will error if the original m_addfriend_norequest() failed */
/*    if(m_addfriend(m, (uint8_t *)friend_id, (uint8_t *)good_data, good_len) != FAERR_ALREADYSENT)
        ck_abort_msg("m_addfriend did NOT catch adding a friend we already have.\n"
                     "(this can be caused by the error of m_addfriend_norequest in"
                     " the beginning of the suite)\n");

    if(m_addfriend(m, (uint8_t *)good_id_b, (uint8_t *)bad_data, bad_len) != FAERR_NOMESSAGE)
        ck_abort_msg("m_addfriend did NOT catch the following length: %d\n", bad_len);
*/
/* this should REALLY error */
/*
 * TODO: validate client_id in m_addfriend?
if(m_addfriend((uint8_t *)bad_id, (uint8_t *)good_data, good_len) >= 0)
    ck_abort_msg("The following ID passed through "
          "m_addfriend without an error:\n'%s'\n", bad_id_str);

}
END_TEST */

START_TEST(test_setname)
{
    char *good_name = "consensualCorn";
    int good_length = strlen(good_name);
    int bad_length = REALLY_BIG_NUMBER;

    ck_assert_msg((setname(m, (uint8_t *)good_name, bad_length) == -1),
                  "setname() did NOT error on %d as a length argument!\n", bad_length);

    ck_assert_msg((setname(m, (uint8_t *)good_name, good_length) == 0),
                  "setname() did NOT return 0 on good arguments!\n");
}
END_TEST

START_TEST(test_getself_name)
{
    char *nickname = "testGallop";
    int len = strlen(nickname);
    char nick_check[len];

    setname(m, (uint8_t *)nickname, len);
    getself_name(m, (uint8_t *)nick_check, len);

    ck_assert_msg((memcmp(nickname, nick_check, len) == 0),
                  "getself_name failed to return the known name!\n"
                  "known name: %s\nreturned: %s\n", nickname, nick_check);
}
END_TEST

/* this test is excluded for now, due to lack of a way
 *  to set a friend's status for now.
 *  ideas:
 *      if we have access to the friends list, we could
 *      just add a status manually ourselves. */
/*
START_TEST(test_m_copy_userstatus)
{
    assert(m_copy_userstatus(-1, buf, MAX_USERSTATUS_LENGTH) == -1);
    assert(m_copy_userstatus(REALLY_BIG_NUMBER, buf, MAX_USERSTATUS_LENGTH) == -1);
    m_copy_userstatus(friend_id_num, buf, MAX_USERSTATUS_LENGTH + 6);

    assert(STRINGS_EQUAL(name_buf, friend_id_status));
}
END_TEST
*/

START_TEST(test_getname)
{
    uint8_t name_buf[MAX_NAME_LENGTH];
    uint8_t test_name[] = {'f', 'o', 'o'};

    ck_assert(getname(m, -1, name_buf) == -1);
    ck_assert(getname(m, REALLY_BIG_NUMBER, name_buf) == -1);

    memcpy(m->friendlist[0].name, &test_name[0], 3);
    getname(m, 0, &name_buf[0]);

    ck_assert(strcmp((char *)&name_buf[0], "foo") == 0);
}
END_TEST

Suite *messenger_suite(void)
{
    Suite *s = suite_create("Messenger");

    TCase *userstatus_size = tcase_create("userstatus_size");
    TCase *set_userstatus = tcase_create("set_userstatus");
    TCase *send_message = tcase_create("send_message");
    TCase *friendstatus = tcase_create("friendstatus");
    TCase *getself_name = tcase_create("getself_name");
    TCase *delfriend = tcase_create("delfriend");
    //TCase *addfriend = tcase_create("addfriend");
    TCase *setname = tcase_create("setname");
    TCase *getname = tcase_create("getname");

    tcase_add_test(userstatus_size, test_m_get_userstatus_size);
    tcase_add_test(set_userstatus, test_m_set_userstatus);
    tcase_add_test(friendstatus, test_m_friendstatus);
    tcase_add_test(getself_name, test_getself_name);
    tcase_add_test(send_message, test_m_sendmesage);
    tcase_add_test(delfriend, test_m_delfriend);
    //tcase_add_test(addfriend, test_m_addfriend);
    tcase_add_test(setname, test_getname);
    tcase_add_test(setname, test_setname);

    suite_add_tcase(s, userstatus_size);
    suite_add_tcase(s, set_userstatus);
    suite_add_tcase(s, friendstatus);
    suite_add_tcase(s, send_message);
    suite_add_tcase(s, getself_name);
    suite_add_tcase(s, delfriend);
    //suite_add_tcase(s, addfriend);
    suite_add_tcase(s, getname);
    suite_add_tcase(s, setname);

    return s;
}

int main(int argc, char *argv[])
{
    Suite *messenger = messenger_suite();
    SRunner *test_runner = srunner_create(messenger);
    int number_failed = 0;

    friend_id = hex_string_to_bin(friend_id_str);
    good_id_a = hex_string_to_bin(good_id_a_str);
    good_id_b = hex_string_to_bin(good_id_b_str);
    bad_id    = hex_string_to_bin(bad_id_str);

    m = initMessenger();

    /* setup a default friend and friendnum */
    if (m_addfriend_norequest(m, (uint8_t *)friend_id) < 0)
        fputs("m_addfriend_norequest() failed on a valid ID!\n"
              "this was CRITICAL to the test, and the build WILL fail.\n"
              "the tests will continue now...\n\n", stderr);

    if ((friend_id_num = getfriend_id(m, (uint8_t *)friend_id)) < 0)
        fputs("getfriend_id() failed on a valid ID!\n"
              "this was CRITICAL to the test, and the build WILL fail.\n"
              "the tests will continue now...\n\n", stderr);

    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);
    free(friend_id);
    free(good_id_a);
    free(good_id_b);
    free(bad_id);

    cleanupMessenger(m);

    return number_failed;
}
