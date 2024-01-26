#include "list.h"

#include <gtest/gtest.h>

namespace {

TEST(List, CreateAndDestroyWithNonZeroSize)
{
    BS_List list;
    bs_list_init(&list, sizeof(int), 10, memcmp);
    bs_list_free(&list);
}

TEST(List, CreateAndDestroyWithZeroSize)
{
    BS_List list;
    bs_list_init(&list, sizeof(int), 0, memcmp);
    bs_list_free(&list);
}

TEST(List, DeleteFromEmptyList)
{
    BS_List list;
    bs_list_init(&list, sizeof(int), 0, memcmp);
    const uint8_t data[sizeof(int)] = {0};
    bs_list_remove(&list, data, 0);
    bs_list_free(&list);
}

}  // namespace
