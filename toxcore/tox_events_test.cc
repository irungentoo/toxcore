#include "tox_events.h"

#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "crypto_core.h"
#include "tox_private.h"

namespace {

TEST(ToxEvents, UnpackRandomDataDoesntCrash)
{
    const Tox_System sys = tox_default_system();
    ASSERT_NE(sys.rng, nullptr);
    std::array<uint8_t, 128> data;
    random_bytes(sys.rng, data.data(), data.size());
    tox_events_free(tox_events_load(&sys, data.data(), data.size()));
}

TEST(ToxEvents, UnpackEmptyDataFails)
{
    const Tox_System sys = tox_default_system();
    std::array<uint8_t, 1> data;
    Tox_Events *events = tox_events_load(&sys, data.end(), 0);
    EXPECT_EQ(events, nullptr);
}

TEST(ToxEvents, UnpackEmptyArrayCreatesEmptyEvents)
{
    const Tox_System sys = tox_default_system();
    std::array<uint8_t, 1> data{0x90};  // empty msgpack array
    Tox_Events *events = tox_events_load(&sys, data.data(), data.size());
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(tox_events_get_size(events), 0);
    tox_events_free(events);
}

TEST(ToxEvents, NullEventsPacksToEmptyArray)
{
    std::array<uint8_t, 1> bytes;
    ASSERT_EQ(tox_events_bytes_size(nullptr), bytes.size());
    tox_events_get_bytes(nullptr, bytes.data());
    EXPECT_EQ(bytes, (std::array<uint8_t, 1>{0x90}));
}

TEST(ToxEvents, PackedEventsCanBeUnpacked)
{
    const Tox_System sys = tox_default_system();
    // [[0, 1]] == Tox_Self_Connection_Status { .connection_status = TOX_CONNECTION_TCP }
    std::array<uint8_t, 6> packed{0x91, 0x92, 0xcc, 0x00, 0xcc, 0x01};
    Tox_Events *events = tox_events_load(&sys, packed.data(), packed.size());
    ASSERT_NE(events, nullptr);
    std::array<uint8_t, 4> bytes;
    ASSERT_EQ(tox_events_bytes_size(events), bytes.size());
    tox_events_get_bytes(events, bytes.data());
    EXPECT_EQ(bytes, (std::array<uint8_t, 4>{0x91, 0x92, 0x00, 0x01}));
    tox_events_free(events);
}

TEST(ToxEvents, DealsWithHugeMsgpackArrays)
{
    const Tox_System sys = tox_default_system();
    std::vector<uint8_t> data{0xdd, 0xff, 0xff, 0xff, 0xff};
    EXPECT_EQ(tox_events_load(&sys, data.data(), data.size()), nullptr);
}

}  // namespace
