#include "bwcontroller.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/os_memory.h"

namespace {

struct BwcTimeMock {
    std::uint64_t t;
};

std::uint64_t bwc_mock_time_cb(void *ud) { return static_cast<BwcTimeMock *>(ud)->t; }

struct MockBwcData {
    std::vector<std::vector<std::uint8_t>> sent_packets;
    std::vector<float> reported_losses;
    std::uint32_t friend_number = 0;

    static int send_packet(
        void *_Nullable user_data, const std::uint8_t *_Nonnull data, std::uint16_t length)
    {
        auto *sd = static_cast<MockBwcData *>(user_data);
        if (sd->fail_send) {
            return -1;
        }
        sd->sent_packets.emplace_back(data, data + length);
        return 0;
    }

    static void loss_report(BWController *_Nonnull /*bwc*/, std::uint32_t friend_number, float loss,
        void *_Nullable user_data)
    {
        auto *sd = static_cast<MockBwcData *>(user_data);
        sd->friend_number = friend_number;
        sd->reported_losses.push_back(loss);
    }

    bool fail_send = false;
};

class BwcTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        const Memory *mem = os_memory();
        log = logger_new(mem);
        tm.t = 1000;
        mono_time = mono_time_new(mem, bwc_mock_time_cb, &tm);
        mono_time_update(mono_time);
    }

    void TearDown() override
    {
        const Memory *_Nonnull mem = os_memory();
        mono_time_free(mem, mono_time);
        logger_kill(log);
    }

    Logger *_Nullable log;
    Mono_Time *_Nullable mono_time;
    BwcTimeMock tm;
};

TEST_F(BwcTest, BasicNewKill)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);
    ASSERT_NE(bwc, nullptr);
    bwc_kill(bwc);
}

TEST_F(BwcTest, SendUpdate)
{
    MockBwcData sd;
    std::uint32_t friend_number = 123;
    BWController *bwc = bwc_new(log, friend_number, MockBwcData::loss_report, &sd,
        MockBwcData::send_packet, &sd, mono_time);
    ASSERT_NE(bwc, nullptr);

    // BWC_AVG_LOSS_OVER_CYCLES_COUNT is 30
    // BWC_SEND_INTERVAL_MS is 950

    // Add some received and lost bytes
    for (int i = 0; i < 30; ++i) {
        bwc_add_recv(bwc, 1000);
    }
    bwc_add_lost(bwc, 500);

    // Should not have sent anything yet because interval not reached
    EXPECT_EQ(sd.sent_packets.size(), 0);

    // Advance time
    tm.t += 1000;
    mono_time_update(mono_time);

    // Trigger another update
    bwc_add_recv(bwc, 1000);

    ASSERT_EQ(sd.sent_packets.size(), 1);
    EXPECT_EQ(sd.sent_packets[0][0], BWC_PACKET_ID);

    // Packet contains lost (4 bytes) and recv (4 bytes)
    std::uint32_t lost, recv;
    net_unpack_u32(sd.sent_packets[0].data() + 1, &lost);
    net_unpack_u32(sd.sent_packets[0].data() + 5, &recv);

    EXPECT_EQ(lost, 500);
    EXPECT_EQ(recv, 30 * 1000 + 1000);

    bwc_kill(bwc);
}

TEST_F(BwcTest, HandlePacket)
{
    MockBwcData sd;
    std::uint32_t friend_number = 123;
    BWController *bwc = bwc_new(log, friend_number, MockBwcData::loss_report, &sd,
        MockBwcData::send_packet, &sd, mono_time);
    ASSERT_NE(bwc, nullptr);

    std::uint8_t packet[9];
    packet[0] = BWC_PACKET_ID;
    net_pack_u32(packet + 1, 100);  // lost
    net_pack_u32(packet + 5, 900);  // recv

    bwc_handle_packet(bwc, packet, sizeof(packet));

    ASSERT_EQ(sd.reported_losses.size(), 1);
    EXPECT_EQ(sd.friend_number, friend_number);
    EXPECT_FLOAT_EQ(sd.reported_losses[0], 100.0f / (100.0f + 900.0f));

    // Try sending another update too soon
    bwc_handle_packet(bwc, packet, sizeof(packet));
    EXPECT_EQ(sd.reported_losses.size(), 1);

    // Advance time
    tm.t += 1000;
    mono_time_update(mono_time);

    bwc_handle_packet(bwc, packet, sizeof(packet));
    EXPECT_EQ(sd.reported_losses.size(), 2);

    bwc_kill(bwc);
}

TEST_F(BwcTest, InvalidPacketSize)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);
    std::uint8_t packet[10] = {0};

    // Correct size is 9
    bwc_handle_packet(bwc, packet, 8);
    bwc_handle_packet(bwc, packet, 10);
    EXPECT_EQ(sd.reported_losses.size(), 0);

    bwc_kill(bwc);
}

TEST_F(BwcTest, SendFailure)
{
    MockBwcData sd;
    sd.fail_send = true;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);

    for (int i = 0; i < 31; ++i) {
        bwc_add_recv(bwc, 1000);
    }
    bwc_add_lost(bwc, 500);
    tm.t += 1000;
    mono_time_update(mono_time);
    bwc_add_recv(bwc, 1000);

    // Send should have failed (logged, but doesn't crash)
    EXPECT_EQ(sd.sent_packets.size(), 0);

    bwc_kill(bwc);
}

TEST_F(BwcTest, NullCallback)
{
    MockBwcData sd;
    // Pass NULL for the loss report callback
    BWController *bwc
        = bwc_new(log, 123, nullptr, nullptr, MockBwcData::send_packet, &sd, mono_time);

    std::uint8_t packet[9];
    packet[0] = BWC_PACKET_ID;
    net_pack_u32(packet + 1, 100);  // lost
    net_pack_u32(packet + 5, 900);  // recv

    bwc_handle_packet(bwc, packet, sizeof(packet));

    // Should not crash, and no loss should be reported
    EXPECT_EQ(sd.reported_losses.size(), 0);

    bwc_kill(bwc);
}

TEST_F(BwcTest, ZeroLoss)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);

    // 1. Peer sends update with zero loss
    std::uint8_t packet[9];
    packet[0] = BWC_PACKET_ID;
    net_pack_u32(packet + 1, 0);  // lost
    net_pack_u32(packet + 5, 1000);  // recv

    bwc_handle_packet(bwc, packet, sizeof(packet));
    EXPECT_EQ(sd.reported_losses.size(), 0);

    // 2. We have zero loss to report
    for (int i = 0; i < 31; ++i) {
        bwc_add_recv(bwc, 1000);
    }
    // No bwc_add_lost called
    tm.t += 1000;
    mono_time_update(mono_time);
    bwc_add_recv(bwc, 1000);

    // Should NOT send update if loss is 0
    EXPECT_EQ(sd.sent_packets.size(), 0);

    bwc_kill(bwc);
}

TEST_F(BwcTest, Overflow)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);

    // Set lost/recv to near max to check for overflow (though they are just added)
    bwc_add_lost(bwc, 0xFFFFFFFF);
    bwc_add_recv(bwc, 0xFFFFFFFF);

    // Trigger update
    for (int i = 0; i < 32; ++i) {
        bwc_add_recv(bwc, 1);
    }
    tm.t += 1000;
    mono_time_update(mono_time);
    bwc_add_recv(bwc, 1);

    ASSERT_EQ(sd.sent_packets.size(), 1);
    std::uint32_t lost, recv;
    net_unpack_u32(sd.sent_packets[0].data() + 1, &lost);
    net_unpack_u32(sd.sent_packets[0].data() + 5, &recv);

    // 0xFFFFFFFF + 32 + 1 should wrap to 32
    EXPECT_EQ(lost, 0xFFFFFFFF);
    EXPECT_EQ(recv, 32);

    bwc_kill(bwc);
}

TEST_F(BwcTest, CycleCountThreshold)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);

    // BWC_AVG_LOSS_OVER_CYCLES_COUNT is 30.
    // We need more than 30 cycles AND the time interval to pass.

    tm.t += 2000;  // Time is sufficient
    mono_time_update(mono_time);

    for (int i = 0; i < 30; ++i) {
        bwc_add_recv(bwc, 100);
        bwc_add_lost(bwc, 1);
        ASSERT_EQ(sd.sent_packets.size(), 0) << "Should not send at cycle " << i;
    }

    // 31st call to bwc_add_recv (or bwc_add_lost)
    bwc_add_recv(bwc, 100);
    EXPECT_EQ(sd.sent_packets.size(), 1);

    bwc_kill(bwc);
}

TEST_F(BwcTest, TimeIntervalStrict)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);

    // Enough cycles
    for (int i = 0; i < 40; ++i) {
        bwc_add_recv(bwc, 100);
    }
    bwc_add_lost(bwc, 10);
    EXPECT_EQ(sd.sent_packets.size(), 0);  // Time not advanced

    // Advance just below 950ms
    tm.t += 949;
    mono_time_update(mono_time);
    bwc_add_recv(bwc, 100);
    EXPECT_EQ(sd.sent_packets.size(), 0);

    // Advance to 951ms (Total > 950)
    tm.t += 2;
    mono_time_update(mono_time);
    bwc_add_recv(bwc, 100);
    EXPECT_EQ(sd.sent_packets.size(), 1);

    bwc_kill(bwc);
}

TEST_F(BwcTest, RecvPlusLostOverflowBug)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);
    std::uint8_t packet[9];
    packet[0] = BWC_PACKET_ID;
    net_pack_u32(packet + 1, 1);
    net_pack_u32(packet + 5, 0xFFFFFFFF);
    bwc_handle_packet(bwc, packet, sizeof(packet));
    ASSERT_EQ(sd.reported_losses.size(), 1);
    // Loss should be very small, but if it's inf or > 1.0, it's a bug
    EXPECT_LE(sd.reported_losses[0], 1.0f);
    bwc_kill(bwc);
}

TEST_F(BwcTest, RateLimitBypassBug)
{
    MockBwcData sd;
    BWController *bwc = bwc_new(
        log, 123, MockBwcData::loss_report, &sd, MockBwcData::send_packet, &sd, mono_time);
    tm.t = 0xFFFFFFF0;
    mono_time_update(mono_time);
    std::uint8_t packet[9];
    packet[0] = BWC_PACKET_ID;
    net_pack_u32(packet + 1, 1);
    net_pack_u32(packet + 5, 100);
    bwc_handle_packet(bwc, packet, sizeof(packet));
    EXPECT_EQ(sd.reported_losses.size(), 1);

    // Only 5ms passed, should be rejected
    tm.t = 0xFFFFFFF5;
    mono_time_update(mono_time);
    bwc_handle_packet(bwc, packet, sizeof(packet));
    EXPECT_EQ(sd.reported_losses.size(), 1);
    bwc_kill(bwc);
}

TEST_F(BwcTest, NoCrashOnNullSendPacket)
{
    BWController *bwc = bwc_new(log, 123, nullptr, nullptr, nullptr, nullptr, mono_time);
    for (int i = 0; i < 31; ++i) {
        bwc_add_recv(bwc, 100);
    }
    bwc_add_lost(bwc, 10);
    tm.t += 1000;
    mono_time_update(mono_time);
    // This should no longer crash
    bwc_add_recv(bwc, 100);
    bwc_kill(bwc);
}

}  // namespace
