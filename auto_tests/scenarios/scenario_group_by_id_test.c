#include "framework/framework.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define GROUP_NAME "NASA Headquarters"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define PEER_NICK "Test Nick"
#define PEER_NICK_LEN (sizeof(PEER_NICK) - 1)

typedef struct {
    Tox_Group_Number group_number;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
} GroupState;

static void script(ToxNode *self, void *ctx)
{
    GroupState *state = (GroupState *)ctx;
    Tox *tox = tox_node_get_tox(self);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME, GROUP_NAME_LEN, (const uint8_t *)PEER_NICK, PEER_NICK_LEN, &err_new);
    ck_assert_int_eq(err_new, TOX_ERR_GROUP_NEW_OK);
    tox_node_log(self, "Group created: %u", state->group_number);

    Tox_Err_Group_State_Query err_query;
    ck_assert(tox_group_get_chat_id(tox, state->group_number, state->chat_id, &err_query));
    ck_assert_int_eq(err_query, TOX_ERR_GROUP_STATE_QUERY_OK);

    {
        // Test tox_group_get_group_list
        uint32_t num_groups = tox_group_get_group_list_size(tox);
        ck_assert_uint_eq(num_groups, 1);

        Tox_Group_Number group_list[1];
        tox_group_get_group_list(tox, group_list);
        ck_assert_uint_eq(group_list[0], state->group_number);

        // Test with NULL (should not crash)
        tox_group_get_group_list(tox, NULL);
    }

    {
        // Test tox_group_by_id
        Tox_Err_Group_By_Id err_by_id;
        uint32_t group_number = tox_group_by_id(tox, state->chat_id, &err_by_id);
        ck_assert_int_eq(err_by_id, TOX_ERR_GROUP_BY_ID_OK);
        ck_assert_uint_eq(group_number, state->group_number);

        // Test tox_group_by_id with invalid ID
        uint8_t invalid_chat_id[TOX_GROUP_CHAT_ID_SIZE];
        memset(invalid_chat_id, 0xAA, TOX_GROUP_CHAT_ID_SIZE);
        group_number = tox_group_by_id(tox, invalid_chat_id, &err_by_id);
        ck_assert_int_eq(err_by_id, TOX_ERR_GROUP_BY_ID_NOT_FOUND);
        ck_assert_uint_eq(group_number, UINT32_MAX);
    }

    // Create another group to ensure it works with multiple groups
    Tox_Group_Number group2 = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"Group 2", 7, (const uint8_t *)PEER_NICK, PEER_NICK_LEN, &err_new);
    ck_assert_int_eq(err_new, TOX_ERR_GROUP_NEW_OK);
    uint8_t chat_id2[TOX_GROUP_CHAT_ID_SIZE];
    ck_assert(tox_group_get_chat_id(tox, group2, chat_id2, &err_query));
    ck_assert_int_eq(err_query, TOX_ERR_GROUP_STATE_QUERY_OK);

    {
        uint32_t num_groups = tox_group_get_group_list_size(tox);
        ck_assert_uint_eq(num_groups, 2);

        Tox_Group_Number group_list[2];
        tox_group_get_group_list(tox, group_list);
        // Groups are added in order of their index in the array
        ck_assert_uint_eq(group_list[0], state->group_number);
        ck_assert_uint_eq(group_list[1], group2);
    }

    {
        Tox_Err_Group_By_Id err_by_id;
        ck_assert_uint_eq(tox_group_by_id(tox, state->chat_id, &err_by_id), state->group_number);
        ck_assert_int_eq(err_by_id, TOX_ERR_GROUP_BY_ID_OK);

        ck_assert_uint_eq(tox_group_by_id(tox, chat_id2, &err_by_id), group2);
        ck_assert_int_eq(err_by_id, TOX_ERR_GROUP_BY_ID_OK);
    }

    Tox_Err_Group_Leave err_leave;
    ck_assert(tox_group_leave(tox, state->group_number, nullptr, 0, &err_leave));
    ck_assert_int_eq(err_leave, TOX_ERR_GROUP_LEAVE_OK);

    // Yield to allow the group to be actually deleted
    tox_scenario_yield(self);

    {
        uint32_t num_groups = tox_group_get_group_list_size(tox);
        ck_assert_uint_eq(num_groups, 1);

        Tox_Group_Number group_list[1];
        tox_group_get_group_list(tox, group_list);
        ck_assert_uint_eq(group_list[0], group2);
    }

    {
        // After leaving, it should not be found
        Tox_Err_Group_By_Id err_by_id;
        uint32_t group_number = tox_group_by_id(tox, state->chat_id, &err_by_id);
        ck_assert_int_eq(err_by_id, TOX_ERR_GROUP_BY_ID_NOT_FOUND);
        ck_assert_uint_eq(group_number, UINT32_MAX);
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    GroupState state = {0};

    tox_scenario_add_node(s, "Node", script, &state, sizeof(GroupState));

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
