#include "../toxcore/tox.h"

#include <stdio.h>

START_TEST(text_all)
{
    long long unsigned int cur_time = time(NULL);
    Tox *bootstrap_node = tox_new(0);
    Tox *Alice = tox_new(0);
    Tox *Bob = tox_new(0);
    
    ck_assert_msg(bootstrap_node || Alice || Bob, "Failed to create 3 tox instances");
    
    uint32_t to_compare = 974536;
    tox_callback_friend_request(Alice, accept_friend_request, &to_compare);
    uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(Alice, address);
    int test = tox_add_friend(Bob, address, (uint8_t *)"gentoo", 6);
    
    ck_assert_msg(test == 0, "Failed to add friend error code: %i", test);
    
    uint8_t off = 1;
    
    while (1) {
        tox_do(bootstrap_node);
        tox_do(Alice);
        tox_do(Bob);
        
        if (tox_isconnected(bootstrap_node) && tox_isconnected(Alice) && tox_isconnected(Bob) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }
        
        if (tox_get_friend_connection_status(Alice, 0) == 1 && tox_get_friend_connection_status(Bob, 0) == 1)
            break;
        
        c_sleep(20);
    }
    
    printf("All set after %llu seconds!\n", time(NULL) - cur_time);
    
    /* Alice creates a group and is a founder of a newly created group */
    int groupnumber = tox_group_new(Alice);
    ck_assert_msg(groupnumber == 0, "Ayy faildo");
    
    /* Alice now shares group chat id on any way */
    uint8_t chat_id[64];
    tox_group_get_invite_key(Alice, groupnumber, chat_id); /* Assume success */
    
    /* Bob gets her key somehow and joins a chat */
    tox_group_new_join(Bob, chat_id);
}
END_TEST

Suite *text_groupchats_suite(void)
{
    Suite *s = suite_create("text_groupchats");
    
    DEFTESTCASE(text_all);
    
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
