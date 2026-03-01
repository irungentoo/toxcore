#include "test_util.hh"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <array>

#include "../testing/support/public/simulated_environment.hh"
#include "crypto_core.h"

namespace {

using ::testing::Each;
using ::testing::Eq;
using tox::test::SimulatedEnvironment;

TEST(CryptoCoreTestUtil, RandomBytesDoesNotTouchZeroSizeArray)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();

    std::array<std::uint8_t, 32> bytes{};
    for (std::uint32_t i = 0; i < 100; ++i) {
        random_bytes(&c_rng, bytes.data(), 0);
        ASSERT_THAT(bytes, Each(Eq(0x00)));
    }
}

TEST(CryptoCoreTestUtil, RandomBytesFillsEntireArray)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();

    std::array<std::uint8_t, 32> bytes{};

    for (std::uint32_t size = 1; size < bytes.size(); ++size) {
        bool const success = [&]() {
            // Try a few times. There ought to be a non-zero byte in our randomness at
            // some point.
            for (std::uint32_t i = 0; i < 100; ++i) {
                random_bytes(&c_rng, bytes.data(), bytes.size());
                if (bytes[size - 1] != 0x00) {
                    return true;
                }
            }
            return false;
        }();
        ASSERT_TRUE(success);
    }
}

TEST(CryptoCoreTestUtil, RandomBytesDoesNotBufferOverrun)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();

    std::array<std::uint8_t, 32> bytes{};

    // Try a few times. It should never overrun.
    for (std::uint32_t i = 0; i < 100; ++i) {
        for (std::uint32_t diff = 1; diff < sizeof(std::uint64_t); ++diff) {
            bytes = {};
            random_bytes(&c_rng, bytes.data(), bytes.size() - diff);
            // All bytes not in the range we want to write should be 0.
            ASSERT_THAT(
                std::vector<std::uint8_t>(bytes.begin() + (bytes.size() - diff), bytes.end()),
                Each(Eq(0x00)));
        }
    }
}

}  // namespace
