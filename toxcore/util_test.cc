/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 */
#include "util.h"

#include <gtest/gtest.h>

#include <climits>

namespace {

TEST(Cmp, OrdersNumbersCorrectly)
{
    EXPECT_EQ(cmp_uint(1, 2), -1);
    EXPECT_EQ(cmp_uint(0, UINT32_MAX), -1);
    EXPECT_EQ(cmp_uint(UINT32_MAX, 0), 1);
    EXPECT_EQ(cmp_uint(UINT32_MAX, UINT32_MAX), 0);
    EXPECT_EQ(cmp_uint(0, UINT64_MAX), -1);
    EXPECT_EQ(cmp_uint(UINT64_MAX, 0), 1);
    EXPECT_EQ(cmp_uint(UINT64_MAX, UINT64_MAX), 0);
}

}  // namespace
