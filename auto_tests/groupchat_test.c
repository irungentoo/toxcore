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

#define NUM_TOXES 4

#define PEER_LIMIT_1 (NUM_TOXES)
#define PEER_LIMIT_2 1

#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)

#define TOPIC1 "This kills the skype"
#define TOPIC1_LEN (sizeof(TOPIC1) - 1)

#define TOPIC2 "The interjection zone"
#define TOPIC2_LEN (sizeof(TOPIC2) - 1)

#define GROUP_NAME "The Gas Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

/* Returns 0 if group state is equal to the state passed to this function.
 * Returns negative integer if state is invalid.
 */
static int check_group_state(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, TOX_GROUP_PRIVACY_STATE priv_state,
                             const uint8_t *password, size_t pass_len, const uint8_t *topic, size_t topic_len)
{
    TOX_ERR_GROUP_STATE_QUERIES query_err;

    TOX_GROUP_PRIVACY_STATE my_priv_state = tox_group_get_privacy_state(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get privacy state: %d", query_err);

    if (my_priv_state != priv_state) {
        return -1;
    }

    uint32_t my_peer_limit = tox_group_get_peer_limit(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get peer limit: %d", query_err);

    if (my_peer_limit != peer_limit) {
        return -2;
    }

    size_t my_topic_len = tox_group_get_topic_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get topic size: %d", query_err);

    if (my_topic_len != topic_len) {
        return -3;
    }

    uint8_t my_topic[my_topic_len + 1];
    tox_group_get_topic(tox, groupnumber, my_topic, &query_err);
    my_topic[my_topic_len] = 0;
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get topic: %d", query_err);

    if (memcmp(my_topic, topic, my_topic_len) != 0) {
        return -4;
    }

    size_t my_pass_len = tox_group_get_password_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get password size: %d", query_err);

    if (my_pass_len != pass_len) {
        return -5;
    }

    if (my_pass_len) {
        uint8_t my_pass[my_pass_len + 1];
        tox_group_get_password(tox, groupnumber, my_pass, &query_err);
        my_pass[my_pass_len] = 0;
        ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get password: %d", query_err);

        if (memcmp(my_pass, password, my_pass_len) != 0) {
            return -6;
        }
    }

    /* Group name should never change */
    size_t my_gname_len = tox_group_get_name_size(tox, groupnumber, &query_err);
    ck_assert_msg(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get group name size: %d", query_err);

    if (my_gname_len != GROUP_NAME_LEN) {
        return -7;
    }

    uint8_t my_gname[my_gname_len + 1];
    tox_group_get_name(tox, groupnumber, my_gname, &query_err);
    my_gname[my_gname_len] = 0;

    if (memcmp(my_gname, GROUP_NAME, my_gname_len) != 0) {
        return -8;
    }

    return 0;
}

static void set_group_state(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, TOX_GROUP_PRIVACY_STATE priv_state,
                            const uint8_t *password, size_t pass_len, const uint8_t *topic, size_t topic_len)
{

    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT limit_set_err;
    tox_group_founder_set_peer_limit(tox, groupnumber, peer_limit, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK, "failed to set peer limit: %d", limit_set_err);

    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE priv_err;
    tox_group_founder_set_privacy_state(tox, groupnumber, priv_state, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK, "failed to set privacy state: %d", priv_err);

    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD pass_set_err;
    tox_group_founder_set_password(tox, groupnumber, password, pass_len, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK, "failed to set password: %d", pass_set_err);

    TOX_ERR_GROUP_TOPIC_SET topic_set_err;
    tox_group_set_topic(tox, groupnumber, topic, topic_len, &topic_set_err);
    ck_assert_msg(topic_set_err == TOX_ERR_GROUP_TOPIC_SET_OK, "failed to set topic: %d", topic_set_err);
}

START_TEST(test_text_all)
{
    long long unsigned int cur_time = time(NULL);
    Tox *toxes[NUM_TOXES];

    ck_assert_msg(NUM_TOXES >= 3, "NUM_TOXES is too small: %d", NUM_TOXES);

    /* Init tox instances */
    TOX_ERR_NEW error;
    struct Tox_Options tox_opts;
    tox_options_default(&tox_opts);

    /* Tox0 is the bootstrap node */
    toxes[0] = tox_new(&tox_opts, &error);

    ck_assert_msg(error == TOX_ERR_GROUP_NEW_OK, "tox_new failed to bootstrap: %d\n", error);

    size_t i, count = 0;

    for (i = 1; i < NUM_TOXES; ++i) {
        toxes[i] = tox_new(&tox_opts, &error);
        ck_assert_msg(error == TOX_ERR_GROUP_NEW_OK, "tox_new failed: %d\n", error);

        char name[16];
        snprintf(name, sizeof(name), "test-%zu", i);
        tox_self_set_name(toxes[i], name, strlen(name), NULL);
    }

    while (1) {
        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i]);
        }

        count = 0;

        for (i = 0; i < NUM_TOXES; ++i) {
            if (tox_self_get_connection_status(toxes[i])) {
                ++count;
            }
        }

        if (count == NUM_TOXES) {
            break;
        }

        c_sleep(20);
    }

    printf("%zu Tox instances connected after %llu seconds!\n", count, time(NULL) - cur_time);

    /* Tox1 creates a group and is a founder of a newly created group */
    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnum = tox_group_new(toxes[1], TOX_GROUP_PRIVACY_STATE_PUBLIC, GROUP_NAME, GROUP_NAME_LEN, &new_err);
    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    /* Set default group state */
    set_group_state(toxes[1], 0, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, PASSWORD, PASS_LEN, TOPIC1, TOPIC1_LEN);

    for (i = 0; i < NUM_TOXES; ++i) {
        tox_iterate(toxes[i]);
    }

    /* Tox1 gets the Chat ID and implicitly shares it publicly */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[1], groupnum, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID and password */
    for (i = 2; i < NUM_TOXES; ++i) {
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, PASSWORD, PASS_LEN, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);
        sleep(1);
    }

    /* Keep checking if all instances have connected to the group until test times out */
    while (1) {
        for (i = 0; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i]);
        }

        size_t count = 0;

        for (i = 1; i < NUM_TOXES; ++i) {
            if (tox_group_get_peer_limit(toxes[i], 0, NULL) == PEER_LIMIT_1) {
                ++count;
            }
        }

        if (count == NUM_TOXES - 1) {
            break;
        }

        c_sleep(20);
    }

    /* Check that all peers have the correct group state */
    for (i = 1; i < NUM_TOXES; ++i) {
        tox_iterate(toxes[i]);
        int ret = check_group_state(toxes[i], 0, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, PASSWORD,
                                    PASS_LEN, TOPIC1, TOPIC1_LEN);
        ck_assert_msg(ret == 0, "Invalid group state: %d", ret);
        c_sleep(20);
    }

    /* Change group state and check that all peers received the changes */
    set_group_state(toxes[1], 0, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, NULL, 0, TOPIC2, TOPIC2_LEN);

    while (1) {
        size_t count = 0;

        for (i = 1; i < NUM_TOXES; ++i) {
            tox_iterate(toxes[i]);

            if (check_group_state(toxes[i], 0, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, NULL, 0,
                                  TOPIC2, TOPIC2_LEN) == 0) {
                ++count;
            }
        }

        if (count == NUM_TOXES - 1) {
            break;
        }

        c_sleep(20);
    }
}
END_TEST

Suite *text_groupchats_suite(void)
{
    Suite *s = suite_create("text_groupchats");

    DEFTESTCASE_SLOW(text_all, 80);
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
