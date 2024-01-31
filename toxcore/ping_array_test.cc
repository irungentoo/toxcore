#include "ping_array.h"

#include <gtest/gtest.h>

#include <memory>

#include "crypto_core_test_util.hh"
#include "mem_test_util.hh"
#include "mono_time.h"

namespace {

struct Ping_Array_Deleter {
    void operator()(Ping_Array *arr) { ping_array_kill(arr); }
};

using Ping_Array_Ptr = std::unique_ptr<Ping_Array, Ping_Array_Deleter>;

struct Mono_Time_Deleter {
    Mono_Time_Deleter(const Test_Memory &mem)
        : mem_(mem)
    {
    }
    void operator()(Mono_Time *arr) { mono_time_free(mem_, arr); }

private:
    const Test_Memory &mem_;
};

using Mono_Time_Ptr = std::unique_ptr<Mono_Time, Mono_Time_Deleter>;

TEST(PingArray, MinimumTimeoutIsOne)
{
    Test_Memory mem;
    EXPECT_EQ(ping_array_new(mem, 1, 0), nullptr);
    EXPECT_NE(Ping_Array_Ptr(ping_array_new(mem, 1, 1)), nullptr);
}

TEST(PingArray, MinimumArraySizeIsOne)
{
    Test_Memory mem;
    EXPECT_EQ(ping_array_new(mem, 0, 1), nullptr);
    EXPECT_NE(Ping_Array_Ptr(ping_array_new(mem, 1, 1)), nullptr);
}

TEST(PingArray, ArraySizeMustBePowerOfTwo)
{
    Test_Memory mem;

    Ping_Array_Ptr arr;
    arr.reset(ping_array_new(mem, 2, 1));
    EXPECT_NE(arr, nullptr);
    arr.reset(ping_array_new(mem, 4, 1));
    EXPECT_NE(arr, nullptr);
    arr.reset(ping_array_new(mem, 1024, 1));
    EXPECT_NE(arr, nullptr);

    EXPECT_EQ(ping_array_new(mem, 1023, 1), nullptr);
    EXPECT_EQ(ping_array_new(mem, 1234, 1), nullptr);
}

TEST(PingArray, StoredDataCanBeRetrieved)
{
    Test_Memory mem;
    Test_Random rng;

    Ping_Array_Ptr const arr(ping_array_new(mem, 2, 1));
    Mono_Time_Ptr const mono_time(mono_time_new(mem, nullptr, nullptr), mem);
    ASSERT_NE(mono_time, nullptr);

    uint64_t const ping_id = ping_array_add(
        arr.get(), mono_time.get(), rng, std::vector<uint8_t>{1, 2, 3, 4}.data(), 4);
    EXPECT_NE(ping_id, 0);

    std::vector<uint8_t> data(4);
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), data.data(), data.size(), ping_id), 4);
    EXPECT_EQ(data, std::vector<uint8_t>({1, 2, 3, 4}));
}

TEST(PingArray, RetrievingDataWithTooSmallOutputBufferHasNoEffect)
{
    Test_Memory mem;
    Test_Random rng;

    Ping_Array_Ptr const arr(ping_array_new(mem, 2, 1));
    Mono_Time_Ptr const mono_time(mono_time_new(mem, nullptr, nullptr), mem);
    ASSERT_NE(mono_time, nullptr);

    uint64_t const ping_id = ping_array_add(
        arr.get(), mono_time.get(), rng, (std::vector<uint8_t>{1, 2, 3, 4}).data(), 4);
    EXPECT_NE(ping_id, 0);

    std::vector<uint8_t> data(4);
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), data.data(), 3, ping_id), -1);
    // It doesn't write anything to the data array.
    EXPECT_EQ(data, std::vector<uint8_t>({0, 0, 0, 0}));
    // Afterwards, we can still read it.
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), data.data(), 4, ping_id), 4);
    EXPECT_EQ(data, std::vector<uint8_t>({1, 2, 3, 4}));
}

TEST(PingArray, ZeroLengthDataCanBeAdded)
{
    Test_Memory mem;
    Test_Random rng;

    Ping_Array_Ptr const arr(ping_array_new(mem, 2, 1));
    Mono_Time_Ptr const mono_time(mono_time_new(mem, nullptr, nullptr), mem);
    ASSERT_NE(mono_time, nullptr);

    uint8_t c = 0;
    uint64_t const ping_id = ping_array_add(arr.get(), mono_time.get(), rng, &c, sizeof(c));
    EXPECT_NE(ping_id, 0);

    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), &c, sizeof(c), ping_id), 1);
}

TEST(PingArray, PingId0IsInvalid)
{
    Test_Memory mem;

    Ping_Array_Ptr const arr(ping_array_new(mem, 2, 1));
    Mono_Time_Ptr const mono_time(mono_time_new(mem, nullptr, nullptr), mem);
    ASSERT_NE(mono_time, nullptr);

    uint8_t c = 0;
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), &c, sizeof(c), 0), -1);
}

// Protection against replay attacks.
TEST(PingArray, DataCanOnlyBeRetrievedOnce)
{
    Test_Memory mem;
    Test_Random rng;

    Ping_Array_Ptr const arr(ping_array_new(mem, 2, 1));
    Mono_Time_Ptr const mono_time(mono_time_new(mem, nullptr, nullptr), mem);
    ASSERT_NE(mono_time, nullptr);

    uint8_t c = 0;
    uint64_t const ping_id = ping_array_add(arr.get(), mono_time.get(), rng, &c, sizeof(c));
    EXPECT_NE(ping_id, 0);

    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), &c, sizeof(c), ping_id), 1);
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), &c, sizeof(c), ping_id), -1);
}

TEST(PingArray, PingIdMustMatchOnCheck)
{
    Test_Memory mem;
    Test_Random rng;

    Ping_Array_Ptr const arr(ping_array_new(mem, 1, 1));
    Mono_Time_Ptr const mono_time(mono_time_new(mem, nullptr, nullptr), mem);
    ASSERT_NE(mono_time, nullptr);

    uint8_t c = 0;
    uint64_t const ping_id = ping_array_add(arr.get(), mono_time.get(), rng, &c, sizeof(c));
    EXPECT_NE(ping_id, 0);

    uint64_t const bad_ping_id = ping_id == 1 ? 2 : 1;

    // bad_ping_id will also be pointing at the same element, but won't match the
    // actual ping_id.
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), &c, sizeof(c), bad_ping_id), -1);
    EXPECT_EQ(ping_array_check(arr.get(), mono_time.get(), &c, sizeof(c), ping_id), 1);
}

}  // namespace
