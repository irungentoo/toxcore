
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "helpers.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

START_TEST(test_text_all)
{
    long long unsigned int cur_time = time(NULL);
    struct Tox_Options tox_opts;
    tox_options_default(&tox_opts);

    TOX_ERR_NEW error1, error2, error3;
    Tox *bootstrap_node = tox_new(&tox_opts, &error1);
    Tox *Alice = tox_new(&tox_opts, &error2);
    Tox *Bob = tox_new(&tox_opts, &error3);

    ck_assert_msg(error1 == TOX_ERR_NEW_OK && error2 == TOX_ERR_NEW_OK && error3 == TOX_ERR_NEW_OK,
                  "tox_new failed (%d %d %d %d)", error1, error2, error3);
    while (1) {
        tox_iterate(bootstrap_node);
        tox_iterate(Alice);
        tox_iterate(Bob);

        if (tox_self_get_connection_status(bootstrap_node)
            && tox_self_get_connection_status(Alice)
            && tox_self_get_connection_status(Bob)) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            break;
        }

        c_sleep(20);
    }

    printf("All set after %llu seconds!\n", time(NULL) - cur_time);

    /* Alice creates a group and is a founder of a newly created group */
    TOX_ERR_GROUP_NEW new_err;
    uint32_t alice_groupnum = tox_group_new(Alice, TOX_GROUP_PRIVACY_STATE_PUBLIC, "test", 4, &new_err);

    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed %d", new_err);

    tox_iterate(bootstrap_node);
    tox_iterate(Alice);
    tox_iterate(Bob);

    /* Alice gets the Chat ID and implicitly shares it with Bob */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(Alice, alice_groupnum, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* Bob and chad join the group using the Chat ID */
    TOX_ERR_GROUP_JOIN join_err;

    uint32_t bob_groupnum = tox_group_join(Bob, chat_id, NULL, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed for Bob %d", join_err);

    /* Keep checking if both instances have connected to the group until test times out */
    while (1) {
        tox_iterate(bootstrap_node);
        tox_iterate(Alice);
        tox_iterate(Bob);

        if (tox_group_get_number_peers(Alice, alice_groupnum, NULL) == 2
            && tox_group_get_number_peers(Bob, bob_groupnum, NULL) == 2)
            break;

        c_sleep(20);
    }
}
END_TEST

Suite *text_groupchats_suite(void)
{
    Suite *s = suite_create("text_groupchats");

    DEFTESTCASE_SLOW(text_all, 50);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *text_groupchats = text_groupchats_suite();
    SRunner *test_runner = srunner_create(text_groupchats);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
