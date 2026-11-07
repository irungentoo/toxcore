// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "tox_events.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

#include "crypto_core.h"
#include "events/events_alloc.h"
#include "mem.h"
#include "tox_event.h"
#include "tox_private.h"

namespace {

using tox::test::SimulatedEnvironment;

TEST(ToxEvents, UnpackRandomDataDoesntCrash)
{
    SimulatedEnvironment env{12345};
    auto node = env.create_node(33445);
    ASSERT_NE(node->system.rng, nullptr);
    std::array<std::uint8_t, 128> data;
    random_bytes(node->system.rng, data.data(), data.size());
    tox_events_free(tox_events_load(&node->system, data.data(), data.size()));
}

TEST(ToxEvents, UnpackEmptyDataFails)
{
    SimulatedEnvironment env{12345};
    auto node = env.create_node(33445);
    std::array<std::uint8_t, 1> data;
    Tox_Events *events = tox_events_load(&node->system, data.data(), 0);
    EXPECT_EQ(events, nullptr);
}

TEST(ToxEvents, UnpackEmptyArrayCreatesEmptyEvents)
{
    SimulatedEnvironment env{12345};
    auto node = env.create_node(33445);
    std::array<std::uint8_t, 1> data{0x90};  // empty msgpack array
    Tox_Events *events = tox_events_load(&node->system, data.data(), data.size());
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(tox_events_get_size(events), 0);
    tox_events_free(events);
}

TEST(ToxEvents, NullEventsPacksToEmptyArray)
{
    std::array<std::uint8_t, 1> bytes;
    ASSERT_EQ(tox_events_bytes_size(nullptr), bytes.size());
    tox_events_get_bytes(nullptr, bytes.data());
    EXPECT_EQ(bytes, (std::array<std::uint8_t, 1>{0x90}));
}

TEST(ToxEvents, PackedEventsCanBeUnpacked)
{
    SimulatedEnvironment env{12345};
    auto node = env.create_node(33445);
    // [[0, 1]] == Tox_Self_Connection_Status { .connection_status = TOX_CONNECTION_TCP }
    std::array<std::uint8_t, 6> packed{0x91, 0x92, 0xcc, 0x00, 0xcc, 0x01};
    Tox_Events *events = tox_events_load(&node->system, packed.data(), packed.size());
    ASSERT_NE(events, nullptr);
    std::array<std::uint8_t, 4> bytes;
    ASSERT_EQ(tox_events_bytes_size(events), bytes.size());
    tox_events_get_bytes(events, bytes.data());
    EXPECT_EQ(bytes, (std::array<std::uint8_t, 4>{0x91, 0x92, 0x00, 0x01}));
    tox_events_free(events);
}

TEST(ToxEvents, DealsWithHugeMsgpackArrays)
{
    SimulatedEnvironment env{12345};
    auto node = env.create_node(33445);
    std::vector<std::uint8_t> data{0xdd, 0xff, 0xff, 0xff, 0xff};
    EXPECT_EQ(tox_events_load(&node->system, data.data(), data.size()), nullptr);
}

// A failed copy of a message leaves no half-made event in the list.
TEST(ToxEvents, FailedFieldCopyAddsNoEvent)
{
    SimulatedEnvironment env{12345};
    constexpr std::size_t kLength = 101;
    env.fake_memory().set_failure_injector([](std::size_t size) { return size == kLength; });
    const Memory mem = env.fake_memory().c_memory();
    Tox_Events_State state = {TOX_ERR_EVENTS_ITERATE_OK, &mem, nullptr};

    const std::array<std::uint8_t, kLength> message{};
    tox_events_handle_friend_message(0, TOX_MESSAGE_TYPE_NORMAL, message.data(), 1, &state);
    ASSERT_EQ(state.error, TOX_ERR_EVENTS_ITERATE_OK);
    ASSERT_EQ(tox_events_get_size(state.events), 1);

    tox_events_handle_friend_message(
        0, TOX_MESSAGE_TYPE_NORMAL, message.data(), message.size(), &state);
    EXPECT_EQ(state.error, TOX_ERR_EVENTS_ITERATE_MALLOC);
    EXPECT_EQ(tox_events_get_size(state.events), 1);

    tox_events_free(state.events);
}

}  // namespace
