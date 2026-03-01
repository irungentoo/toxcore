// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "mono_time.h"
// clang-format on

#include <gtest/gtest.h>

#include "attributes.h"
#include "mono_time_test_util.hh"

namespace {

using tox::test::FakeClock;
using tox::test::SimulatedEnvironment;

TEST(MonoTime, TimeIncreasesWhenAdvanced)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Mono_Time *mono_time = mono_time_new(&c_mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);
    setup_fake_clock(mono_time, env.fake_clock());

    mono_time_update(mono_time);
    std::uint64_t const start = mono_time_get(mono_time);

    // Advance 10 seconds to ensure we definitely cross second boundaries and see an increase
    env.fake_clock().advance(10000);
    mono_time_update(mono_time);

    std::uint64_t const end = mono_time_get(mono_time);
    EXPECT_GT(end, start);
    EXPECT_EQ(end, start + 10);

    mono_time_free(&c_mem, mono_time);
}

TEST(MonoTime, IsTimeout)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Mono_Time *mono_time = mono_time_new(&c_mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);
    setup_fake_clock(mono_time, env.fake_clock());

    mono_time_update(mono_time);  // Ensure start is consistent with fake clock
    std::uint64_t const start = mono_time_get(mono_time);
    EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 1));

    env.fake_clock().advance(2000);  // 2 seconds
    mono_time_update(mono_time);

    EXPECT_TRUE(mono_time_is_timeout(mono_time, start, 1));

    mono_time_free(&c_mem, mono_time);
}

TEST(MonoTime, IsTimeoutWithIntermediateUpdates)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Mono_Time *mono_time = mono_time_new(&c_mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);
    setup_fake_clock(mono_time, env.fake_clock());

    mono_time_update(mono_time);
    std::uint64_t const start = mono_time_get(mono_time);
    EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 5));

    env.fake_clock().advance(100);
    mono_time_update(mono_time);

    // Should not have timed out (5sec) after 100ms
    EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 5));

    env.fake_clock().advance(5000);
    mono_time_update(mono_time);
    EXPECT_TRUE(mono_time_is_timeout(mono_time, start, 5));

    mono_time_free(&c_mem, mono_time);
}

TEST(MonoTime, CustomTime)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Mono_Time *mono_time = mono_time_new(&c_mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);

    std::uint64_t test_time = 123456;
    mono_time_set_current_time_callback(
        mono_time,
        [](void *_Nullable user_data) { return *static_cast<std::uint64_t *>(user_data); },
        &test_time);
    mono_time_update(mono_time);

    EXPECT_EQ(current_time_monotonic(mono_time), test_time);

    std::uint64_t const start = mono_time_get(mono_time);

    test_time += 7000;
    mono_time_update(mono_time);

    EXPECT_EQ(mono_time_get(mono_time) - start, 7);
    EXPECT_EQ(current_time_monotonic(mono_time), test_time);

    mono_time_free(&c_mem, mono_time);
}

}  // namespace
