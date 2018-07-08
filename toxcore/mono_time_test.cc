#include "mono_time.h"

#include <gtest/gtest.h>

namespace {

TEST(Util, UnixTimeIncreasesOverTime) {
  unix_time_update();
  uint64_t const start = unix_time();

  while (start == unix_time()) {
    unix_time_update();
  }

  uint64_t const end = unix_time();
  EXPECT_GT(end, start);
}

TEST(Util, IsTimeout) {
  uint64_t const start = unix_time();
  EXPECT_FALSE(is_timeout(start, 1));

  while (start == unix_time()) {
    unix_time_update();
  }

  EXPECT_TRUE(is_timeout(start, 1));
}

}  // namespace
