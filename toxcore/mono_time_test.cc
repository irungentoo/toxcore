#include "mono_time.h"

#include <gtest/gtest.h>

namespace {

TEST(Util, UnixTimeIncreasesOverTime) {
  Mono_Time *mono_time = mono_time_new();

  mono_time_update(mono_time);
  uint64_t const start = mono_time_get(mono_time);

  while (start == mono_time_get(mono_time)) {
    mono_time_update(mono_time);
  }

  uint64_t const end = mono_time_get(mono_time);
  EXPECT_GT(end, start);

  mono_time_free(mono_time);
}

TEST(Util, IsTimeout) {
  Mono_Time *mono_time = mono_time_new();

  uint64_t const start = mono_time_get(mono_time);
  EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 1));

  while (start == mono_time_get(mono_time)) {
    mono_time_update(mono_time);
  }

  EXPECT_TRUE(mono_time_is_timeout(mono_time, start, 1));

  mono_time_free(mono_time);
}

}  // namespace
