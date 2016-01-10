#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"

#include "helpers.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define NUM_TOXES 15
#define TOPIC_NAME "test"

START_TEST(test_text_all)
{
    long long unsigned int cur_time = time(NULL);
    Tox *toxes[NUM_TOXES];

    ck_assert_msg(NUM_TOXES >= 3, "NUM_TOXES is too small: %d", NUM_TOXES);

    /* Init tox instances */
    TOX_ERR_NEW error;
    struct Tox_Options tox_opts;
    tox_options_default(&tox_opts);
    toxes[0] = tox_new(&tox_opts, &error);

    ck_assert_msg(error == TOX_ERR_GROUP_NEW_OK, "tox_new failed to bootstrap: %s\n", error);

    size_t i;

    for (i = 1; i < NUM_TOXES; ++i) {
        toxes[i] = tox_new(&tox_opts, &error);
        ck_assert_msg(error == TOX_ERR_GROUP_NEW_OK, "tox_new failed: %s\n", error);

        char name[16];
        snprintf(name, sizeof(name), "test-%d", i);
        tox_self_set_name(toxes[i], name, strlen(name), NULL);
    }

    while (1) {
        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i]);
        }

        size_t count = 0;

        for (i = 0 ; i < NUM_TOXES; ++i) {
            if (tox_self_get_connection_status(toxes[i]))
                ++count;
        }

        if (count == NUM_TOXES)
            break;

        c_sleep(20);
    }

    printf("All set after %llu seconds!\n", time(NULL) - cur_time);

    /* Tox1 creates a group and is a founder of a newly created group */
    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnum = tox_group_new(toxes[1], TOX_GROUP_PRIVACY_STATE_PUBLIC, "test", 4, &new_err);

    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed %d", new_err);

    /* Tox1 sets topic */
    TOX_ERR_GROUP_TOPIC_SET topic_err;
    tox_group_set_topic(toxes[1], groupnum, TOPIC_NAME, strlen(TOPIC_NAME), &topic_err);
    ck_assert_msg(topic_err == TOX_ERR_GROUP_TOPIC_SET_OK, "failed to set topic %d", topic_err);

    for (i = 0; i < NUM_TOXES; ++i) {
        tox_iterate(toxes[i]);
    }

    /* Tox1 gets the Chat ID and implicitly shares it with Bob */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[1], groupnum, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID */

    for (i = 2; i < NUM_TOXES; ++i) {
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, NULL, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);
    }

    /* Keep checking if both instances have connected to the group until test times out */
    while (1) {
        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i]);
        }

        size_t count = 0;

        /* Skip bootstrap and group creator */
        for (i = 2; i < NUM_TOXES; ++i) {
            uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];
            tox_group_get_topic(toxes[i], 0, topic, NULL);

            if (memcmp(topic, TOPIC_NAME, strlen(TOPIC_NAME)) == 0)
                ++count;
        }

        if (count == (NUM_TOXES - 2))
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

int main(int argc, char **argv)
{
    (void) argc;
    (void) argv;

    srand((unsigned int) time(NULL));

    Suite *tox = text_groupchats_suite();
    SRunner *test_runner = srunner_create(tox);

    srunner_run_all(test_runner, CK_NORMAL);
    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
