#include "rtp.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/os_memory.h"

namespace {

struct MockSessionData {
    MockSessionData();
    ~MockSessionData();

    std::vector<std::vector<std::uint8_t>> sent_packets;
    std::vector<std::vector<std::uint8_t>> received_frames;
    std::vector<std::uint16_t> received_frame_lengths;
    std::vector<std::uint32_t> received_32bit_lengths;
    std::vector<std::uint32_t> received_full_lengths;
    std::vector<std::uint16_t> received_sequnums;
    std::vector<std::uint8_t> received_pts;
    std::vector<std::uint64_t> received_flags;

    std::uint32_t total_bytes_received = 0;
    std::uint32_t total_bytes_lost = 0;
};

MockSessionData::MockSessionData() = default;
MockSessionData::~MockSessionData() = default;

static int mock_send_packet(
    void *_Nullable user_data, const std::uint8_t *_Nonnull data, std::uint16_t length)
{
    auto *sd = static_cast<MockSessionData *>(user_data);
    sd->sent_packets.emplace_back(data, data + length);
    return 0;
}

static int mock_m_cb(
    const Mono_Time *_Nonnull /*mono_time*/, void *_Nullable cs, RTPMessage *_Nonnull msg)
{
    auto *sd = static_cast<MockSessionData *>(cs);

    sd->received_pts.push_back(rtp_message_pt(msg));
    sd->received_flags.push_back(rtp_message_flags(msg));

    const std::uint8_t *_Nonnull data = rtp_message_data(msg);
    std::uint32_t len = rtp_message_len(msg);
    std::uint32_t full_len = rtp_message_data_length_full(msg);

    // If full_len is not set (old protocol), use len
    std::uint32_t actual_len = (full_len > 0) ? full_len : len;

    sd->received_frames.emplace_back(data, data + actual_len);
    sd->received_frame_lengths.push_back(static_cast<std::uint16_t>(len));
    sd->received_32bit_lengths.push_back(len);
    sd->received_full_lengths.push_back(full_len);
    sd->received_sequnums.push_back(rtp_message_sequnum(msg));

    std::free(msg);
    return 0;
}

static void mock_add_recv(void *_Nullable user_data, std::uint32_t bytes)
{
    auto *sd = static_cast<MockSessionData *>(user_data);
    sd->total_bytes_received += bytes;
}

static void mock_add_lost(void *_Nullable user_data, std::uint32_t bytes)
{
    auto *sd = static_cast<MockSessionData *>(user_data);
    sd->total_bytes_lost += bytes;
}

class RtpPublicTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        const Memory *mem = os_memory();
        log = logger_new(mem);
        mono_time = mono_time_new(mem, nullptr, nullptr);
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
};

TEST_F(RtpPublicTest, BasicAudioSendReceive)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);
    ASSERT_NE(session, nullptr);

    std::uint8_t data[] = "Hello RTP";
    rtp_send_data(log, session, data, sizeof(data), false);

    ASSERT_EQ(sd.sent_packets.size(), 1);
    EXPECT_EQ(sd.sent_packets[0][0], RTP_TYPE_AUDIO);

    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());

    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0].size(), sizeof(data));
    EXPECT_STREQ(reinterpret_cast<const char *>(sd.received_frames[0].data()), "Hello RTP");
    EXPECT_EQ(sd.received_pts[0], RTP_TYPE_AUDIO % 128);
    EXPECT_EQ(sd.received_flags[0], 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, LargeVideoFrameFragmentation)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    // Frame larger than MAX_CRYPTO_DATA_SIZE
    const std::uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 500;
    std::vector<std::uint8_t> data(frame_size);
    for (std::uint32_t i = 0; i < frame_size; ++i)
        data[i] = i & 0xFF;

    rtp_send_data(log, session, data.data(), frame_size, true);

    // Should be at least 2 packets
    ASSERT_GE(sd.sent_packets.size(), 2);

    // Receive packets in order
    for (const auto &pkt : sd.sent_packets) {
        rtp_receive_packet(session, pkt.data(), pkt.size());
    }

    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0], data);
    EXPECT_EQ(sd.received_pts[0], RTP_TYPE_VIDEO % 128);
    EXPECT_TRUE(sd.received_flags[0] & RTP_KEY_FRAME);
    EXPECT_TRUE(sd.received_flags[0] & RTP_LARGE_FRAME);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, OutOfOrderVideoPackets)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    const std::uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 100;
    std::vector<std::uint8_t> data(frame_size, 0x55);
    rtp_send_data(log, session, data.data(), frame_size, false);

    ASSERT_EQ(sd.sent_packets.size(), 2);

    // Receive last packet first
    rtp_receive_packet(session, sd.sent_packets[1].data(), sd.sent_packets[1].size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // Receive first packet
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0].size(), frame_size);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HandlingInvalidPackets)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    // Packet too short to even contain the Tox packet ID
    std::uint8_t empty[1];
    rtp_receive_packet(session, empty, 0);

    // Packet too short (less than RTP_HEADER_SIZE + 1)
    std::uint8_t short_pkt[10] = {RTP_TYPE_AUDIO};
    rtp_receive_packet(session, short_pkt, sizeof(short_pkt));

    // Wrong packet ID (Tox level)
    std::uint8_t wrong_id[RTP_HEADER_SIZE + 10];
    std::memset(wrong_id, 0, sizeof(wrong_id));
    wrong_id[0] = RTP_TYPE_VIDEO;  // Session expects AUDIO
    rtp_receive_packet(session, wrong_id, sizeof(wrong_id));

    EXPECT_EQ(sd.received_frames.size(), 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, ReceiveActiveToggle)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    EXPECT_TRUE(rtp_session_is_receiving_active(session));

    rtp_stop_receiving_mark(session);
    EXPECT_FALSE(rtp_session_is_receiving_active(session));

    rtp_allow_receiving_mark(session);
    EXPECT_TRUE(rtp_session_is_receiving_active(session));

    EXPECT_FALSE(rtp_session_is_receiving_active(nullptr));

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, SsrcAccessors)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    rtp_session_set_ssrc(session, 0x12345678);
    EXPECT_EQ(rtp_session_get_ssrc(session), 0x12345678);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, LargeAudioFragmentationOldProtocol)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    // Audio doesn't use RTP_LARGE_FRAME, so it uses the old 16-bit offset/length fields
    const std::uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 500;
    std::vector<std::uint8_t> data(frame_size, 0x44);

    rtp_send_data(log, session, data.data(), frame_size, false);

    ASSERT_GE(sd.sent_packets.size(), 2);

    for (const auto &pkt : sd.sent_packets) {
        rtp_receive_packet(session, pkt.data(), pkt.size());
    }

    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0].size(), frame_size);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, WorkBufferEvictionAndKeyframePreservation)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    struct TimeMock {
        std::uint64_t t;
    } tm = {1000};

    auto time_cb = [](void *ud) -> std::uint64_t { return static_cast<TimeMock *>(ud)->t; };
    mono_time_set_current_time_callback(mono_time, time_cb, &tm);
    mono_time_update(mono_time);

    // USED_RTP_WORKBUFFER_COUNT is 3.
    // 1. Start a keyframe (frame 0) but don't finish it.
    const std::uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 100;
    std::vector<std::uint8_t> kf_data(frame_size, 0x11);
    rtp_send_data(log, session, kf_data.data(), frame_size, true);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    sd.sent_packets.clear();

    // 2. Start two interframes (frames 1 and 2) but don't finish them.
    for (int i = 0; i < 2; ++i) {
        tm.t += 1;
        mono_time_update(mono_time);
        std::vector<std::uint8_t> if_data(frame_size, 0x20 + i);
        rtp_send_data(log, session, if_data.data(), frame_size, false);
        rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
        sd.sent_packets.clear();
    }

    // Now work buffer has 3 slots: [KF(part), IF1(part), IF2(part)]
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 3. Start another interframe (frame 3).
    // Since slot 0 is a KEYFRAME and it's not old yet (tm.t=1002, KF.t=1000, age=2ms < 15ms),
    // and it's not finished, it should be kept.
    // The new IF should be DROPPED because there's no space and slot 0 is a protected KF.
    tm.t += 1;
    mono_time_update(mono_time);
    std::vector<std::uint8_t> if3_data(frame_size, 0x33);
    rtp_send_data(log, session, if3_data.data(), frame_size, false);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    sd.sent_packets.clear();

    EXPECT_EQ(sd.received_frames.size(), 0);

    // 4. Advance time by 20ms (> VIDEO_KEEP_KEYFRAME_IN_BUFFER_FOR_MS = 15).
    // Now slot 0 (the KF) is old relative to the new incoming frame's timestamp.
    tm.t += 20;
    mono_time_update(mono_time);

    // 5. Start another frame (frame 4).
    // Now the old KF should be evicted and processed (sent to callback), making room.
    std::vector<std::uint8_t> if4_data(frame_size, 0x44);
    rtp_send_data(log, session, if4_data.data(), frame_size, false);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());

    // We expect the KF to have been delivered now.
    ASSERT_GE(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0][0], 0x11);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, BwcReporting)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    std::uint8_t data[] = "test";
    // DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT is 10.
    // Packets 1-9 are dismissed. Packet 10 is reported.
    for (int i = 0; i < 10; ++i) {
        sd.sent_packets.clear();
        rtp_send_data(log, session, data, sizeof(data), false);
        rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    }

    // Packet 10 should have been the first one reported.
    EXPECT_EQ(sd.total_bytes_received, sizeof(data));
    EXPECT_EQ(sd.total_bytes_lost, 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, OldProtocolEdgeCases)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // 1. Multipart message interrupted by a newer message.
    const std::uint32_t large_size = 5000;
    std::vector<std::uint8_t> data(large_size, 0xAA);
    rtp_send_data(log, session, data.data(), large_size, false);

    ASSERT_GE(sd.sent_packets.size(), 2);
    // Receive only the first part of the first message
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // Send a second message (newer)
    std::vector<std::uint8_t> data2 = {0x1, 0x2, 0x3};
    rtp_send_data(log, session, data2.data(), data2.size(), false);
    // The second message is the last one in sent_packets.
    rtp_receive_packet(session, sd.sent_packets.back().data(), sd.sent_packets.back().size());

    // The first (incomplete) message should have been pushed to mcb when the second one arrived.
    ASSERT_EQ(sd.received_frames.size(), 2);
    EXPECT_LT(sd.received_frame_lengths[0], large_size);
    EXPECT_EQ(sd.received_pts[0], RTP_TYPE_AUDIO % 128);
    EXPECT_EQ(sd.received_frame_lengths[1], static_cast<std::uint16_t>(data2.size()));

    // 2. Discarding old message part
    sd.received_frames.clear();
    sd.received_frame_lengths.clear();
    sd.received_full_lengths.clear();
    sd.received_pts.clear();

    // Send a very new message.
    std::vector<std::uint8_t> data3 = {0xDE, 0xAD};
    rtp_send_data(log, session, data3.data(), data3.size(), false);
    rtp_receive_packet(session, sd.sent_packets.back().data(), sd.sent_packets.back().size());
    EXPECT_EQ(sd.received_frames.size(), 1);

    // Now try to "receive" an old part of message 1 (Index 1)
    rtp_receive_packet(session, sd.sent_packets[1].data(), sd.sent_packets[1].size());
    // It should be discarded because it's older than the current session state.
    EXPECT_EQ(sd.received_frames.size(), 1);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, MoreInvalidPackets)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Get a valid packet to start with
    std::uint8_t data[] = "test";
    rtp_send_data(log, session, data, sizeof(data), false);
    ASSERT_FALSE(sd.sent_packets.empty());
    if (sd.sent_packets.empty())
        return;
    const std::vector<std::uint8_t> &src_pkt = sd.sent_packets[0];
    if (src_pkt.size() > 65536)
        return;
    std::vector<std::uint8_t> valid_pkt(src_pkt.begin(), src_pkt.end());
    sd.sent_packets.clear();

    // 1. RTPHeader packet type and Tox protocol packet type do not agree
    std::vector<std::uint8_t> bad_pkt_1 = valid_pkt;
    bad_pkt_1[0] = RTP_TYPE_AUDIO;  // Tox ID says AUDIO, but header (byte 2) still says VIDEO
    rtp_receive_packet(session, bad_pkt_1.data(), bad_pkt_1.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 2. RTPHeader packet type does not match session payload type
    // Create an AUDIO session and send it the valid VIDEO packet
    RTPSession *session_audio = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        nullptr, nullptr, nullptr, &sd, mock_m_cb);
    rtp_receive_packet(session_audio, valid_pkt.data(), valid_pkt.size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    rtp_kill(log, session_audio);

    // 3. Invalid video packet: offset >= length
    // From rtp.c, offset_full is at byte 20 and data_length_full at byte 24 of the RTP header.
    // The RTP header starts at index 1 of the packet.
    std::vector<std::uint8_t> bad_pkt_3 = valid_pkt;
    // Set offset (bytes 21-24) to be equal to length (bytes 25-28)
    // For a small packet, both are usually 0 and sizeof(data) respectively.
    // Let's just make offset very large.
    bad_pkt_3[1 + 20] = 0xFF;
    bad_pkt_3[1 + 21] = 0xFF;

    rtp_receive_packet(session, bad_pkt_3.data(), bad_pkt_3.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 4. Invalid old protocol packet: offset >= length
    // offset_lower is at byte 76, data_length_lower at byte 78 of the RTP header.
    RTPSession *session_audio2 = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        nullptr, nullptr, nullptr, &sd, mock_m_cb);

    rtp_send_data(log, session_audio2, data, sizeof(data), false);
    ASSERT_FALSE(sd.sent_packets.empty());
    if (sd.sent_packets.empty())
        return;
    const std::vector<std::uint8_t> &src_audio = sd.sent_packets[0];
    if (src_audio.size() > 65536)
        return;
    std::vector<std::uint8_t> audio_pkt(src_audio.begin(), src_audio.end());
    sd.sent_packets.clear();

    std::vector<std::uint8_t> bad_pkt_4 = audio_pkt;
    // Set offset_lower (byte 1 + 76) > data_length_lower (byte 1 + 78)
    bad_pkt_4[1 + 76] = 0x01;  // offset = 256
    bad_pkt_4[1 + 77] = 0x00;
    bad_pkt_4[1 + 78] = 0x00;  // length = 10
    bad_pkt_4[1 + 79] = 0x0A;

    rtp_receive_packet(session_audio2, bad_pkt_4.data(), bad_pkt_4.size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    rtp_kill(log, session_audio2);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, VideoJitterBufferEdgeCases)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Use a large frame size to force fragmentation and keep slots occupied
    const std::uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 100;
    std::vector<std::uint8_t> data(frame_size, 0);

    // Advancing time for subsequent frames
    struct TimeMock {
        std::uint64_t t;
    } tm = {1000};
    auto time_cb = [](void *ud) -> std::uint64_t { return static_cast<TimeMock *>(ud)->t; };
    mono_time_set_current_time_callback(mono_time, time_cb, &tm);
    mono_time_update(mono_time);

    // 1. Packet too old for work buffer
    rtp_send_data(log, session, data.data(), frame_size, false);  // Time 1000ms
    std::vector<std::uint8_t> old_pkt = sd.sent_packets[0];
    // Receive only first part to keep slot occupied
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    sd.sent_packets.clear();

    // Send a newer frame by advancing time
    tm.t = 2000;
    mono_time_update(mono_time);
    rtp_send_data(log, session, data.data(), frame_size, false);  // Time 2000ms
    // Receive first part of this one too. Now we have two slots occupied.
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    sd.sent_packets.clear();

    // Now try to send the old packet again. It should be rejected because
    // it's older than the most recent frame in the buffer.
    rtp_receive_packet(session, old_pkt.data(), old_pkt.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 2. Interframe waiting for keyframe in slot 0
    rtp_kill(log, session);
    sd.received_frames.clear();
    session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr, nullptr,
        nullptr, &sd, mock_m_cb);

    // Fill slot 0 with an incomplete Keyframe
    std::vector<std::uint8_t> kf_data(frame_size, 0x11);
    tm.t = 3000;
    mono_time_update(mono_time);
    rtp_send_data(log, session, kf_data.data(), frame_size, true);
    // Receive only first part
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    sd.sent_packets.clear();

    // Now send a complete Interframe
    std::vector<std::uint8_t> if_data(10, 0x22);
    tm.t += 1;
    mono_time_update(mono_time);
    rtp_send_data(log, session, if_data.data(), if_data.size(), false);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());

    // The interframe should be in slot 1, but NOT processed because slot 0 is an incomplete KF
    EXPECT_EQ(sd.received_frames.size(), 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, OldProtocolCorruption)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // 1. Packet claiming a smaller length than its payload.
    // This triggers the condition that previously caused a DoS crash via
    // an assertion failure in new_message().
    std::uint8_t data[10] = {0};
    rtp_send_data(log, session, data, sizeof(data), false);
    std::vector<std::uint8_t> pkt = sd.sent_packets[0];
    sd.sent_packets.clear();

    // Modify data_length_lower (byte 1 + 78) to be 2, while payload is 10.
    pkt[1 + 78] = 0x00;
    pkt[1 + 79] = 0x02;

    // This used to trigger an assertion failure (crash). Now it should return nullptr.
    rtp_receive_packet(session, pkt.data(), pkt.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 2. Corruption check for an EXISTING multipart message.
    const std::uint32_t multipart_size = 5000;
    std::vector<std::uint8_t> multipart_data(multipart_size, 0xBB);
    rtp_send_data(log, session, multipart_data.data(), multipart_size, false);

    // Receive the first part
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // Now receive a corrupted second part that claims a weird offset
    std::vector<std::uint8_t> corrupted_part = sd.sent_packets[1];
    // offset_lower is at byte 76. Set it beyond data_length_lower.
    corrupted_part[1 + 76] = 0xFF;
    corrupted_part[1 + 77] = 0xFF;

    rtp_receive_packet(session, corrupted_part.data(), corrupted_part.size());
    // It should return early without pushing the message.
    EXPECT_EQ(sd.received_frames.size(), 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HugeVideoFrameInternalLength)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Frame larger than 64KB (std::uint16_t max)
    const std::uint32_t huge_frame_size = 65540;
    std::vector<std::uint8_t> data(huge_frame_size);
    for (std::uint32_t i = 0; i < huge_frame_size; ++i) {
        data[i] = static_cast<std::uint8_t>(i & 0xFF);
    }

    rtp_send_data(log, session, data.data(), huge_frame_size, false);

    // Should be fragmented into many packets
    ASSERT_GT(sd.sent_packets.size(), 1);

    // Receive all packets
    for (const auto &pkt : sd.sent_packets) {
        rtp_receive_packet(session, pkt.data(), pkt.size());
    }

    ASSERT_EQ(sd.received_frames.size(), 1);
    // This verifies that the internal 32-bit length is working correctly.
    // We cast huge_frame_size to 16-bit to show what it would have been if it truncated.
    EXPECT_NE(static_cast<std::uint16_t>(sd.received_32bit_lengths[0]), huge_frame_size);
    EXPECT_EQ(sd.received_32bit_lengths[0], huge_frame_size);
    EXPECT_EQ(sd.received_full_lengths[0], huge_frame_size);
    EXPECT_EQ(sd.received_frames[0].size(), huge_frame_size);
    EXPECT_EQ(sd.received_frames[0], data);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HeapBufferOverflowRaw)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Manually construct a malicious packet.
    // 1 byte ID + 80 bytes Header + 200 bytes Payload
    const std::size_t header_size = 80;
    const std::size_t payload_size = 200;
    const std::size_t total_size = 1 + header_size + payload_size;
    std::vector<std::uint8_t> pkt(total_size, 0);

    // 0: Packet ID
    pkt[0] = RTP_TYPE_VIDEO;

    // 1: VE=2 (10xxxxxx) -> 0x80
    pkt[1] = 0x80;

    // 2: PT = RTP_TYPE_VIDEO % 128 (193 % 128 = 65 -> 0x41)
    // MA=0
    pkt[2] = 0x41;

    // 13-20: Flags (64-bit)
    // We need RTP_LARGE_FRAME (1<<0) and RTP_KEY_FRAME (1<<1) -> 0x03
    // Stored in Big Endian. Last byte is 0x03.
    pkt[20] = 0x03;

    // 25-28: Data Length Full (32-bit Big Endian)
    // We set this to 50 (0x32) to trick the allocator.
    pkt[28] = 50;

    // 81...: Payload
    // Fill with 0x41 ('A')
    std::fill(pkt.begin() + 81, pkt.end(), 0x41);

    // Inject the malicious packet
    rtp_receive_packet(session, pkt.data(), pkt.size());

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HeapBufferOverflow)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Common parameters
    std::uint16_t sequnum = 100;
    std::uint32_t timestamp = 12345;
    std::uint32_t ssrc = 0x11223344;

    // --- Packet 1: Small allocation ---
    // data_length_full = 10
    // offset_full = 0
    // payload_len = 5
    {
        std::uint8_t packet[100];
        std::memset(packet, 0, sizeof(packet));
        packet[0] = RTP_TYPE_VIDEO;  // Tox Packet ID

        // RTP Header
        std::uint8_t *h = &packet[1];
        // Byte 0: VE=2 (0x80)
        h[0] = 0x80;
        // Byte 1: PT=0x41
        h[1] = 0x41;  // 65
        // Bytes 2-3: Sequnum
        h[2] = (sequnum >> 8) & 0xFF;
        h[3] = sequnum & 0xFF;
        // Bytes 4-7: Timestamp
        h[4] = (timestamp >> 24) & 0xFF;
        h[5] = (timestamp >> 16) & 0xFF;
        h[6] = (timestamp >> 8) & 0xFF;
        h[7] = timestamp & 0xFF;
        // Bytes 8-11: SSRC
        h[8] = (ssrc >> 24) & 0xFF;
        h[9] = (ssrc >> 16) & 0xFF;
        h[10] = (ssrc >> 8) & 0xFF;
        h[11] = ssrc & 0xFF;
        // Bytes 12-19: Flags (RTP_LARGE_FRAME = 1)
        h[19] = 1;

        // Bytes 20-23: Offset Full (0)
        // 0

        // Bytes 24-27: Data Length Full (10)
        h[27] = 10;

        // Bytes 28-31: Received Length Full (0)

        // Offset Lower (at 76)
        h[76] = 0;
        h[77] = 0;
        // Data Length Lower (at 78) -> 10
        h[78] = 0;
        h[79] = 10;

        // Payload starts at 1 + RTP_HEADER_SIZE (80) = 81
        // We set payload length to 5.
        // Total packet size = 81 + 5 = 86

        rtp_receive_packet(session, packet, 81 + 5);
    }

    // --- Packet 2: Exploit ---
    // Same sequnum/timestamp -> same slot
    // data_length_full = 1000 (Larger!)
    // offset_full = 10
    // payload_len = 100
    //
    // Logic check:
    //   data_length_full (1000) - offset_full (10) < payload_len (100) -> 990 < 100 -> False.
    //   Check passes.
    //
    // Memcpy to buf->data + 10. Buf was allocated with size 10. Writing 100
    // bytes to offset 10 -> Overflow.
    {
        std::uint8_t packet[200];
        std::memset(packet, 0, sizeof(packet));
        packet[0] = RTP_TYPE_VIDEO;

        std::uint8_t *h = &packet[1];
        h[0] = 0x80;
        h[1] = 0x41;
        h[2] = (sequnum >> 8) & 0xFF;
        h[3] = sequnum & 0xFF;
        h[4] = (timestamp >> 24) & 0xFF;
        h[5] = (timestamp >> 16) & 0xFF;
        h[6] = (timestamp >> 8) & 0xFF;
        h[7] = timestamp & 0xFF;
        h[8] = (ssrc >> 24) & 0xFF;
        h[9] = (ssrc >> 16) & 0xFF;
        h[10] = (ssrc >> 8) & 0xFF;
        h[11] = ssrc & 0xFF;
        h[19] = 1;  // Large frame

        // Offset Full = 10
        h[23] = 10;

        // Data Length Full = 1000
        h[26] = (1000 >> 8) & 0xFF;
        h[27] = 1000 & 0xFF;

        // Offset Lower (at 76) -> 10
        h[76] = 0;
        h[77] = 10;
        // Data Length Lower (at 78) -> 1000
        h[78] = (1000 >> 8) & 0xFF;
        h[79] = 1000 & 0xFF;

        // Payload starts at 81. Length 100.
        // We fill it with 'A' to make the overflow obvious if inspected.
        std::memset(&packet[81], 'A', 100);

        rtp_receive_packet(session, packet, 81 + 100);
    }

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, AudioHeapBufferOverflow)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    std::uint16_t sequnum = 100;
    std::uint32_t timestamp = 12345;
    std::uint32_t ssrc = 0x11223344;

    std::uint8_t packet[200];
    std::memset(packet, 0, sizeof(packet));
    packet[0] = RTP_TYPE_AUDIO;

    std::uint8_t *h = &packet[1];
    h[0] = 0x80;
    h[1] = 0x40;  // 64 (Audio)
    h[2] = (sequnum >> 8) & 0xFF;
    h[3] = sequnum & 0xFF;
    h[4] = (timestamp >> 24) & 0xFF;
    h[5] = (timestamp >> 16) & 0xFF;
    h[6] = (timestamp >> 8) & 0xFF;
    h[7] = timestamp & 0xFF;
    h[8] = (ssrc >> 24) & 0xFF;
    h[9] = (ssrc >> 16) & 0xFF;
    h[10] = (ssrc >> 8) & 0xFF;
    h[11] = ssrc & 0xFF;
    h[19] = 0;  // Small frame (Audio)

    // Offset Lower (at 76) -> 90
    h[76] = 0;
    h[77] = 90;
    // Data Length Lower (at 78) -> 100
    h[78] = 0;
    h[79] = 100;

    // Payload starts at 81. Length 20.
    // Total size required = 90 + 20 = 110.
    // Allocated size = 100.
    // Overflow by 10 bytes.
    std::memset(&packet[81], 'A', 20);

    rtp_receive_packet(session, packet, 81 + 20);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HeapBufferOverflowMultipartAudio)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    std::uint16_t sequnum = 200;
    std::uint32_t timestamp = 67890;
    std::uint32_t ssrc = 0x55667788;
    std::uint16_t total_len = 100;

    // --- Packet 1: Allocate buffer ---
    // data_length_lower = 100
    // offset_lower = 0
    // payload_len = 10
    {
        std::uint8_t packet[200];
        std::memset(packet, 0, sizeof(packet));
        packet[0] = RTP_TYPE_AUDIO;

        std::uint8_t *h = &packet[1];
        h[0] = 0x80;
        h[1] = 0x40;  // Audio
        h[2] = (sequnum >> 8) & 0xFF;
        h[3] = sequnum & 0xFF;
        h[4] = (timestamp >> 24) & 0xFF;
        h[5] = (timestamp >> 16) & 0xFF;
        h[6] = (timestamp >> 8) & 0xFF;
        h[7] = timestamp & 0xFF;
        h[8] = (ssrc >> 24) & 0xFF;
        h[9] = (ssrc >> 16) & 0xFF;
        h[10] = (ssrc >> 8) & 0xFF;
        h[11] = ssrc & 0xFF;
        h[19] = 0;

        // Offset Lower (at 76) -> 0
        h[76] = 0;
        h[77] = 0;
        // Data Length Lower (at 78) -> 100
        h[78] = (total_len >> 8) & 0xFF;
        h[79] = total_len & 0xFF;

        // Payload len 10
        std::memset(&packet[81], 'A', 10);
        rtp_receive_packet(session, packet, 81 + 10);
    }

    // --- Packet 2: Overflow ---
    // offset_lower = 95
    // payload_len = 10
    //
    // Check 1: total (100) - received (10) = 90. 90 >= 10. Safe.
    // Check 2: total (100) > offset (95). Safe.
    // Write: 95 + 10 = 105. Overflow.
    {
        std::uint8_t packet[200];
        std::memset(packet, 0, sizeof(packet));
        packet[0] = RTP_TYPE_AUDIO;

        std::uint8_t *h = &packet[1];
        h[0] = 0x80;
        h[1] = 0x40;
        h[2] = (sequnum >> 8) & 0xFF;
        h[3] = sequnum & 0xFF;
        h[4] = (timestamp >> 24) & 0xFF;
        h[5] = (timestamp >> 16) & 0xFF;
        h[6] = (timestamp >> 8) & 0xFF;
        h[7] = timestamp & 0xFF;
        h[8] = (ssrc >> 24) & 0xFF;
        h[9] = (ssrc >> 16) & 0xFF;
        h[10] = (ssrc >> 8) & 0xFF;
        h[11] = ssrc & 0xFF;
        h[19] = 0;

        // Offset Lower (at 76) -> 95
        h[76] = 0;
        h[77] = 95;
        // Data Length Lower (at 78) -> 100
        h[78] = (total_len >> 8) & 0xFF;
        h[79] = total_len & 0xFF;

        // Payload len 10
        std::memset(&packet[81], 'B', 10);
        rtp_receive_packet(session, packet, 81 + 10);
    }

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HeapBufferOverflowLogRead)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    std::uint16_t sequnum = 123;
    std::uint32_t timestamp = 99999;
    std::uint32_t ssrc = 0x88776655;

    // Packet with data_length_full = 1.
    // The logger tries to read data[0] and data[1].
    // data[1] will be out of bounds if only 1 byte is allocated.
    std::uint8_t packet[100];
    std::memset(packet, 0, sizeof(packet));
    packet[0] = RTP_TYPE_VIDEO;

    std::uint8_t *h = &packet[1];
    h[0] = 0x80;
    h[1] = 0x41;  // Video
    h[2] = (sequnum >> 8) & 0xFF;
    h[3] = sequnum & 0xFF;
    h[4] = (timestamp >> 24) & 0xFF;
    h[5] = (timestamp >> 16) & 0xFF;
    h[6] = (timestamp >> 8) & 0xFF;
    h[7] = timestamp & 0xFF;
    h[8] = (ssrc >> 24) & 0xFF;
    h[9] = (ssrc >> 16) & 0xFF;
    h[10] = (ssrc >> 8) & 0xFF;
    h[11] = ssrc & 0xFF;
    h[19] = 1;  // Large frame

    // Offset Full = 0
    h[23] = 0;

    // Data Length Full = 1
    h[26] = 0;
    h[27] = 1;

    // Offset Lower (at 76) -> 0
    h[76] = 0;
    h[77] = 0;
    // Data Length Lower (at 78) -> 1
    h[78] = 0;
    h[79] = 1;

    // Payload starts at 81. Length 1.
    packet[81] = 0xCC;

    rtp_receive_packet(session, packet, 81 + 1);

    rtp_kill(log, session);
}

}  // namespace
