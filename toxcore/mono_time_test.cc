#include "mono_time.h"

#include <gtest/gtest.h>

namespace {

TEST(MonoTime, UnixTimeIncreasesOverTime) {
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

TEST(MonoTime, IsTimeout) {
  Mono_Time *mono_time = mono_time_new();

  uint64_t const start = mono_time_get(mono_time);
  EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 1));

  while (start == mono_time_get(mono_time)) {
    mono_time_update(mono_time);
  }

  EXPECT_TRUE(mono_time_is_timeout(mono_time, start, 1));

  mono_time_free(mono_time);
}

uint64_t test_current_time_callback(Mono_Time *mono_time, void *user_data) {
  return *static_cast<uint64_t *>(user_data);
}

TEST(MonoTime, CustomTime) {
  Mono_Time *mono_time = mono_time_new();

  uint64_t test_time = current_time_monotonic(mono_time) + 42137;

  mono_time_set_current_time_callback(mono_time, test_current_time_callback, &test_time);
  mono_time_update(mono_time);

  EXPECT_EQ(current_time_monotonic(mono_time), test_time);

  uint64_t const start = mono_time_get(mono_time);

  test_time += 7000;

  mono_time_update(mono_time);
  EXPECT_EQ(mono_time_get(mono_time) - start, 7);

  EXPECT_EQ(current_time_monotonic(mono_time), test_time);

  mono_time_free(mono_time);
}

}  // namespace
