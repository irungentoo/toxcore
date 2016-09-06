#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "check_compat.h"

#define NUM_GROUP_TOXES 5

#define PEER_LIMIT_1 NUM_GROUP_TOXES
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

    VLA(uint8_t, my_topic, my_topic_len + 1);
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
        VLA(uint8_t, my_pass, my_pass_len + 1);
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

    VLA(uint8_t, my_gname, my_gname_len + 1);
    tox_group_get_name(tox, groupnumber, my_gname, &query_err);
    my_gname[my_gname_len] = 0;

    if (memcmp(my_gname, (const uint8_t *)GROUP_NAME, my_gname_len) != 0) {
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
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK, "failed to set password: %d", pass_set_err);

    TOX_ERR_GROUP_TOPIC_SET topic_set_err;
    tox_group_set_topic(tox, groupnumber, topic, topic_len, &topic_set_err);
    ck_assert_msg(topic_set_err == TOX_ERR_GROUP_TOPIC_SET_OK, "failed to set topic: %d", topic_set_err);
}

START_TEST(test_text_all)
{
#ifndef VANILLA_NACL
    time_t cur_time = time(nullptr);
    uint32_t index[NUM_GROUP_TOXES] = {1};
    Tox *toxes[NUM_GROUP_TOXES];

    ck_assert_msg(NUM_GROUP_TOXES >= 3, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    /* Init tox instances */
    TOX_ERR_NEW error;
    struct Tox_Options tox_opts;
    tox_options_default(&tox_opts);

    /* Tox0 is the bootstrap node */
    toxes[0] = tox_new_log(&tox_opts, &error, &index[0]);

    ck_assert_msg(error == TOX_ERR_NEW_OK, "tox_new failed to bootstrap: %d\n", error);

    size_t i, count = 0;

    for (i = 1; i < NUM_GROUP_TOXES; ++i) {
        index[i] = i + 1;
        toxes[i] = tox_new_log(&tox_opts, &error, &index[i]);
        ck_assert_msg(error == TOX_ERR_NEW_OK, "tox_new failed: %d\n", error);

        char name[16];
        snprintf(name, sizeof(name), "test-%zu", i);
        tox_self_set_name(toxes[i], (const uint8_t *)name, strlen(name), nullptr);

        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0], dht_key);
        const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);
        tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, nullptr);
    }

    while (1) {
        for (i = 0; i < NUM_GROUP_TOXES; ++i) {
            tox_iterate(toxes[i], nullptr);
        }

        count = 0;

        for (i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (tox_self_get_connection_status(toxes[i])) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            break;
        }

        c_sleep(20);
    }

    printf("%zu Tox instances connected after %u seconds!\n", count, (unsigned)(time(nullptr) - cur_time));

    /* Tox1 creates a group and is a founder of a newly created group */
    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnum = tox_group_new(toxes[1], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN,
                                      &new_err);
    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    /* Set default group state */
    set_group_state(toxes[1], 0, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)PASSWORD, PASS_LEN,
                    (const uint8_t *)TOPIC1, TOPIC1_LEN);

    for (i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_iterate(toxes[i], nullptr);
    }

    /* Tox1 gets the Chat ID and implicitly shares it publicly */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[1], groupnum, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID and password */
    for (i = 2; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, (const uint8_t *)PASSWORD, PASS_LEN, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);
        c_sleep(1000);
    }

    /* Keep checking if all instances have connected to the group until test times out */
    while (1) {
        for (i = 0; i < NUM_GROUP_TOXES; ++i) {
            tox_iterate(toxes[i], nullptr);
        }

        count = 0;

        for (i = 1; i < NUM_GROUP_TOXES; ++i) {
            if (tox_group_get_peer_limit(toxes[i], 0, nullptr) == PEER_LIMIT_1) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES - 1) {
            break;
        }

        c_sleep(20);
    }

    /* Check that all peers have the correct group state */
    for (i = 1; i < NUM_GROUP_TOXES; ++i) {
        tox_iterate(toxes[i], nullptr);
        int ret = check_group_state(toxes[i], 0, PEER_LIMIT_1, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)PASSWORD,
                                    PASS_LEN, (const uint8_t *)TOPIC1, TOPIC1_LEN);
        ck_assert_msg(ret == 0, "Invalid group state: %d", ret);
        c_sleep(20);
    }

    /* Change group state and check that all peers received the changes */
    set_group_state(toxes[1], 0, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, nullptr, 0, (const uint8_t *)TOPIC2,
                    TOPIC2_LEN);

    while (1) {
        count = 0;

        for (i = 1; i < NUM_GROUP_TOXES; ++i) {
            tox_iterate(toxes[i], nullptr);

            if (check_group_state(toxes[i], 0, PEER_LIMIT_2, TOX_GROUP_PRIVACY_STATE_PRIVATE, nullptr, 0,
                                  (const uint8_t *)TOPIC2, TOPIC2_LEN) == 0) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES - 1) {
            break;
        }

        c_sleep(20);
    }

    for (i = 0; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], groupnum, nullptr, 0, &err_exit);
        // TODO(JFreegman): Fix?
        // ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    for (i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_kill(toxes[i]);
    }

#endif /* VANILLA_NACL */
}
END_TEST

static Suite *text_groupchats_suite(void)
{
    Suite *s = suite_create("text_groupchats");

    DEFTESTCASE_SLOW(text_all, 80);
    return s;
}

int main(void)
{
    srand((unsigned int) time(nullptr));

    Suite *tox = text_groupchats_suite();
    SRunner *test_runner = srunner_create(tox);

    srunner_run_all(test_runner, CK_NORMAL);
    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
