#include "tox_events.h"

#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "crypto_core.h"

namespace {

TEST(ToxEvents, UnpackRandomDataDoesntCrash)
{
    std::array<uint8_t, 128> data;
    random_bytes(data.data(), data.size());
    tox_events_free(tox_events_load(data.data(), data.size()));
}

TEST(ToxEvents, UnpackEmptyDataFails)
{
    std::array<uint8_t, 1> data;
    Tox_Events *events = tox_events_load(data.end(), 0);
    EXPECT_EQ(events, nullptr);
}

TEST(ToxEvents, UnpackEmptyArrayCreatesEmptyEvents)
{
    std::array<uint8_t, 1> data{0x90};  // empty msgpack array
    Tox_Events *events = tox_events_load(data.data(), data.size());
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(tox_events_get_conference_connected_size(events), 0);
    tox_events_free(events);
}

// TODO(iphydf): Enable this test once we've fully moved away from msgpack-c.
#if 0
TEST(ToxEvents, DealsWithHugeMsgpackArrays)
{
    std::vector<uint8_t> data{0xdd, 0xff, 0xff, 0xff, 0xff};
    EXPECT_EQ(tox_events_load(data.data(), data.size()), nullptr);
}
#endif

}  // namespace
