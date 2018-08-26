#include "ping_array.h"

#include <memory>

#include <gtest/gtest.h>
#include "mono_time.h"

namespace {

struct Ping_Array_Deleter {
  void operator()(Ping_Array *arr) { ping_array_kill(arr); }
};

using Ping_Array_Ptr = std::unique_ptr<Ping_Array, Ping_Array_Deleter>;

struct Mono_Time_Deleter {
  void operator()(Mono_Time *arr) { mono_time_free(arr); }
};

using Mono_Time_Ptr = std::unique_ptr<Mono_Time, Mono_Time_Deleter>;

TEST(PingArray, MinimumTimeoutIsOne) {
  EXPECT_EQ(ping_array_new(1, 0), nullptr);
  EXPECT_NE(Ping_Array_Ptr(ping_array_new(1, 1)), nullptr);
}

TEST(PingArray, MinimumArraySizeIsOne) {
  EXPECT_EQ(ping_array_new(0, 1), nullptr);
  EXPECT_NE(Ping_Array_Ptr(ping_array_new(1, 1)), nullptr);
}

TEST(PingArray, ArraySizeMustBePowerOfTwo) {
  Ping_Array_Ptr arr;
  arr.reset(ping_array_new(2, 1));
  EXPECT_NE(arr, nullptr);
  arr.reset(ping_array_new(4, 1));
  EXPECT_NE(arr, nullptr);
  arr.reset(ping_array_new(1024, 1));
  EXPECT_NE(arr, nullptr);

  EXPECT_EQ(ping_array_new(1023, 1), nullptr);
  EXPECT_EQ(ping_array_new(1234, 1), nullptr);
}

TEST(PingArray, StoredDataCanBeRetrieved) {
  Ping_Array_Ptr const arr(ping_array_new(2, 1));
  Mono_Time_Ptr const mono_time(mono_time_new());

  uint64_t const ping_id =
      ping_array_add(arr.get(), mono_time.get(), std::vector<uint8_t>{1, 2, 3, 4}.data(), 4);
  EXPECT_NE(ping_id, 0);

  std::vector<uint8_t> data(4);
  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), data.data(), data.size(), ping_id), 4);
  EXPECT_EQ(data, std::vector<uint8_t>({1, 2, 3, 4}));
}

TEST(PingArray, RetrievingDataWithTooSmallOutputBufferHasNoEffect) {
  Ping_Array_Ptr const arr(ping_array_new(2, 1));
  Mono_Time_Ptr const mono_time(mono_time_new());

  uint64_t const ping_id =
      ping_array_add(arr.get(), mono_time.get(), (std::vector<uint8_t>{1, 2, 3, 4}).data(), 4);
  EXPECT_NE(ping_id, 0);

  std::vector<uint8_t> data(4);
  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), data.data(), 3, ping_id), -1);
  // It doesn't write anything to the data array.
  EXPECT_EQ(data, std::vector<uint8_t>({0, 0, 0, 0}));
  // Afterwards, we can still read it.
  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), data.data(), 4, ping_id), 4);
  EXPECT_EQ(data, std::vector<uint8_t>({1, 2, 3, 4}));
}

TEST(PingArray, ZeroLengthDataCanBeAdded) {
  Ping_Array_Ptr const arr(ping_array_new(2, 1));
  Mono_Time_Ptr const mono_time(mono_time_new());

  uint64_t const ping_id = ping_array_add(arr.get(), mono_time.get(), nullptr, 0);
  EXPECT_NE(ping_id, 0);

  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), nullptr, 0, ping_id), 0);
}

TEST(PingArray, PingId0IsInvalid) {
  Ping_Array_Ptr const arr(ping_array_new(2, 1));
  Mono_Time_Ptr const mono_time(mono_time_new());

  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), nullptr, 0, 0), -1);
}

// Protection against replay attacks.
TEST(PingArray, DataCanOnlyBeRetrievedOnce) {
  Ping_Array_Ptr const arr(ping_array_new(2, 1));
  Mono_Time_Ptr const mono_time(mono_time_new());

  uint64_t const ping_id = ping_array_add(arr.get(), mono_time.get(), nullptr, 0);
  EXPECT_NE(ping_id, 0);

  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), nullptr, 0, ping_id), 0);
  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), nullptr, 0, ping_id), -1);
}

TEST(PingArray, PingIdMustMatchOnCheck) {
  Ping_Array_Ptr const arr(ping_array_new(1, 1));
  Mono_Time_Ptr const mono_time(mono_time_new());

  uint64_t const ping_id = ping_array_add(arr.get(), mono_time.get(), nullptr, 0);
  EXPECT_NE(ping_id, 0);

  uint64_t const bad_ping_id = ping_id == 1 ? 2 : 1;

  // bad_ping_id will also be pointing at the same element, but won't match the
  // actual ping_id.
  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), nullptr, 0, bad_ping_id), -1);
  EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), nullptr, 0, ping_id), 0);
}

}  // namespace
