#include "video.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/os_memory.h"
#include "av_test_support.hh"
#include "rtp.h"

namespace {

using VideoTest = AvTest;

TEST_F(VideoTest, BasicNewKill)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);
    vc_kill(vc);
}

TEST_F(VideoTest, EncodeDecodeLoop)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    RtpMock rtp_mock;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = recv_rtp;

    std::uint16_t width = 320;
    std::uint16_t height = 240;
    std::uint32_t bitrate = 500;

    ASSERT_EQ(vc_reconfigure_encoder(vc, bitrate, width, height, -1), 0);

    std::vector<std::uint8_t> y(width * height, 128);
    std::vector<std::uint8_t> u((width / 2) * (height / 2), 64);
    std::vector<std::uint8_t> v((width / 2) * (height / 2), 192);

    ASSERT_EQ(vc_encode(vc, width, height, y.data(), u.data(), v.data(), VC_EFLAG_FORCE_KF), 0);
    vc_increment_frame_counter(vc);

    std::uint8_t *pkt_data;
    std::uint32_t pkt_size;
    bool is_keyframe;

    while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_keyframe)) {
        int rc = rtp_send_data(log, send_rtp, pkt_data, pkt_size, is_keyframe);
        ASSERT_EQ(rc, 0);
    }

    vc_iterate(vc);

    ASSERT_EQ(data.friend_number, 123u);
    ASSERT_EQ(data.width, width);
    ASSERT_EQ(data.height, height);
    ASSERT_FALSE(data.y.empty());

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    vc_kill(vc);
}

TEST_F(VideoTest, EncodeDecodeSequence)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    RtpMock rtp_mock;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = recv_rtp;

    std::uint16_t width = 320;
    std::uint16_t height = 240;
    std::uint32_t bitrate = 2000;

    ASSERT_EQ(vc_reconfigure_encoder(vc, bitrate, width, height, -1), 0);

    for (int i = 0; i < 20; ++i) {
        std::vector<std::uint8_t> y(width * height);
        std::vector<std::uint8_t> u((width / 2) * (height / 2));
        std::vector<std::uint8_t> v((width / 2) * (height / 2));

        // Background
        std::fill(y.begin(), y.end(), 16);
        std::fill(u.begin(), u.end(), 128);
        std::fill(v.begin(), v.end(), 128);

        // Moving square
        int sq_size = 64;
        int x0 = (i * 8) % (width - sq_size);
        int y0 = (i * 4) % (height - sq_size);
        for (int r = 0; r < sq_size; ++r) {
            for (int c = 0; c < sq_size; ++c) {
                y[(y0 + r) * width + (x0 + c)] = 200;
            }
        }

        ASSERT_EQ(vc_encode(vc, width, height, y.data(), u.data(), v.data(),
                      i == 0 ? VC_EFLAG_FORCE_KF : VC_EFLAG_NONE),
            0);
        vc_increment_frame_counter(vc);

        std::uint8_t *pkt_data;
        std::uint32_t pkt_size;
        bool is_keyframe;

        while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_keyframe)) {
            rtp_send_data(log, send_rtp, pkt_data, pkt_size, is_keyframe);
        }

        vc_iterate(vc);

        ASSERT_EQ(data.width, width);
        ASSERT_EQ(data.height, height);

        double mse = data.calculate_mse(y);
        // Expect MSE to be reasonably low for high bitrate
        EXPECT_LT(mse, 100.0) << "Frame " << i << " MSE too high: " << mse;
    }

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    vc_kill(vc);
}

TEST_F(VideoTest, EncodeDecodeResolutionChange)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    RtpMock rtp_mock;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = recv_rtp;

    std::uint16_t widths[] = {320, 160, 480};
    std::uint16_t heights[] = {240, 120, 360};

    for (int res = 0; res < 3; ++res) {
        std::uint16_t width = widths[res];
        std::uint16_t height = heights[res];
        ASSERT_EQ(vc_reconfigure_encoder(vc, 2000, width, height, -1), 0);

        for (int i = 0; i < 5; ++i) {
            std::vector<std::uint8_t> y(width * height);
            std::vector<std::uint8_t> u((width / 2) * (height / 2));
            std::vector<std::uint8_t> v((width / 2) * (height / 2));

            std::fill(y.begin(), y.end(), static_cast<std::uint8_t>((res * 50 + i * 10) % 256));
            std::fill(u.begin(), u.end(), 128);
            std::fill(v.begin(), v.end(), 128);

            ASSERT_EQ(vc_encode(vc, width, height, y.data(), u.data(), v.data(),
                          i == 0 ? VC_EFLAG_FORCE_KF : VC_EFLAG_NONE),
                0);
            vc_increment_frame_counter(vc);

            std::uint8_t *pkt_data;
            std::uint32_t pkt_size;
            bool is_keyframe;

            while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_keyframe)) {
                rtp_send_data(log, send_rtp, pkt_data, pkt_size, is_keyframe);
            }

            vc_iterate(vc);

            ASSERT_EQ(data.width, width);
            ASSERT_EQ(data.height, height);

            double mse = data.calculate_mse(y);
            EXPECT_LT(mse, 100.0) << "Res " << res << " Frame " << i << " MSE too high: " << mse;
        }
    }

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    vc_kill(vc);
}

TEST_F(VideoTest, EncodeDecodeBitrateImpact)
{
    std::uint32_t bitrates[] = {100, 500, 2000};
    double mses[3];

    std::uint16_t width = 320;
    std::uint16_t height = 240;

    for (int b = 0; b < 3; ++b) {
        VideoTestData data;
        VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
        ASSERT_NE(vc, nullptr);

        RtpMock rtp_mock;
        RTPSession *send_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet,
            &rtp_mock, nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
        RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet,
            &rtp_mock, nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
        rtp_mock.recv_session = recv_rtp;

        ASSERT_EQ(vc_reconfigure_encoder(vc, bitrates[b], width, height, -1), 0);

        double total_mse = 0;
        int frames = 10;
        for (int i = 0; i < frames; ++i) {
            std::vector<std::uint8_t> y(width * height);
            std::vector<std::uint8_t> u((width / 2) * (height / 2));
            std::vector<std::uint8_t> v((width / 2) * (height / 2));

            for (std::size_t j = 0; j < y.size(); ++j)
                y[j] = static_cast<std::uint8_t>((j + i * 10) % 256);
            std::fill(u.begin(), u.end(), 128);
            std::fill(v.begin(), v.end(), 128);

            ASSERT_EQ(vc_encode(vc, width, height, y.data(), u.data(), v.data(),
                          i == 0 ? VC_EFLAG_FORCE_KF : VC_EFLAG_NONE),
                0);
            vc_increment_frame_counter(vc);

            std::uint8_t *pkt_data;
            std::uint32_t pkt_size;
            bool is_keyframe;

            while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_keyframe)) {
                rtp_send_data(log, send_rtp, pkt_data, pkt_size, is_keyframe);
            }

            vc_iterate(vc);
            total_mse += data.calculate_mse(y);
        }

        mses[b] = total_mse / frames;

        rtp_kill(log, send_rtp);
        rtp_kill(log, recv_rtp);
        vc_kill(vc);
    }

    // Quality should generally improve (MSE decrease) as bitrate increases.
    // 100kbps should have significantly higher MSE than 2000kbps for this complex pattern.
    EXPECT_GT(mses[0], mses[1]);
    EXPECT_GT(mses[1], mses[2]);

    std::printf("MSE results: 100kbps: %f, 500kbps: %f, 2000kbps: %f\n", mses[0], mses[1], mses[2]);
}

TEST_F(VideoTest, ReconfigureEncoder)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    // Initial reconfigure
    ASSERT_EQ(vc_reconfigure_encoder(vc, 500, 320, 240, -1), 0);

    // Change bitrate and resolution
    ASSERT_EQ(vc_reconfigure_encoder(vc, 1000, 640, 480, -1), 0);

    std::vector<std::uint8_t> y(640 * 480, 128);
    std::vector<std::uint8_t> u(320 * 240, 64);
    std::vector<std::uint8_t> v(320 * 240, 192);

    ASSERT_EQ(vc_encode(vc, 640, 480, y.data(), u.data(), v.data(), VC_EFLAG_NONE), 0);

    vc_kill(vc);
}

TEST_F(VideoTest, GetLcfd)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    // Default lcfd is 60 in video.c
    EXPECT_EQ(vc_get_lcfd(vc), 60u);

    vc_kill(vc);
}

TEST_F(VideoTest, QueueInvalidMessage)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    RtpMock rtp_mock;
    // Create an audio RTP session but try to queue to video session
    RTPSession *audio_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    RTPSession *video_recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet,
        &rtp_mock, nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = video_recv_rtp;

    std::vector<std::uint8_t> dummy_audio(100, 0);
    int rc = rtp_send_data(
        log, audio_rtp, dummy_audio.data(), static_cast<std::uint32_t>(dummy_audio.size()), false);
    ASSERT_EQ(rc, 0);

    // Iterate should NOT trigger callback because payload type was wrong
    vc_iterate(vc);
    EXPECT_EQ(data.width, 0u);

    rtp_kill(log, audio_rtp);
    rtp_kill(log, video_recv_rtp);
    vc_kill(vc);
}

TEST_F(VideoTest, ReconfigureOptimizations)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    // 1. Reconfigure with same values (should do nothing)
    // vc_new initializes encoder with 800x600 and 5000 bitrate.
    EXPECT_EQ(vc_reconfigure_encoder(vc, 5000, 800, 600, -1), 0);

    // 2. Reconfigure with only bitrate change
    EXPECT_EQ(vc_reconfigure_encoder(vc, 2000, 800, 600, -1), 0);

    // 3. Reconfigure with kf_max_dist > 1 (triggers re-init and kf_max_dist branch)
    EXPECT_EQ(vc_reconfigure_encoder(vc, 2000, 800, 600, 60), 0);

    vc_kill(vc);
}

TEST_F(VideoTest, LcfdAndSpecialPackets)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    RtpMock rtp_mock;
    RTPSession *video_recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet,
        &rtp_mock, nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = video_recv_rtp;

    // 1. Test lcfd update
    tm.t += 50;  // Advance time by 50ms
    mono_time_update(mono_time);
    std::vector<std::uint8_t> dummy_frame(10, 0);
    rtp_send_data(log, video_recv_rtp, dummy_frame.data(),
        static_cast<std::uint32_t>(dummy_frame.size()), true);

    // lcfd should be updated. Initial linfts was set at vc_new (tm.t=1000).
    // Now tm.t is 1050. t_lcfd = 1050 - 1000 = 50.
    EXPECT_EQ(vc_get_lcfd(vc), 50u);

    // 2. Test lcfd threshold (t_lcfd > 100 should be ignored)
    tm.t += 200;
    mono_time_update(mono_time);
    rtp_send_data(log, video_recv_rtp, dummy_frame.data(),
        static_cast<std::uint32_t>(dummy_frame.size()), true);
    EXPECT_EQ(vc_get_lcfd(vc), 50u);  // Should still be 50

    // 3. Test dummy packet PT = (RTP_TYPE_VIDEO + 2) % 128
    RTPSession *dummy_rtp = rtp_new(log, (RTP_TYPE_VIDEO + 2), mono_time, RtpMock::send_packet,
        &rtp_mock, nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = dummy_rtp;
    rtp_send_data(
        log, dummy_rtp, dummy_frame.data(), static_cast<std::uint32_t>(dummy_frame.size()), false);
    // Should return 0 but do nothing (logged as "Got dummy!")

    // 4. Test GetQueueMutex
    EXPECT_NE(vc_get_queue_mutex(vc), nullptr);

    rtp_kill(log, video_recv_rtp);
    rtp_kill(log, dummy_rtp);
    vc_kill(vc);
}

TEST_F(VideoTest, MultiReconfigureEncode)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    for (int i = 0; i < 5; ++i) {
        std::uint16_t w = static_cast<std::uint16_t>(160 + (i * 16));
        std::uint16_t h = static_cast<std::uint16_t>(120 + (i * 16));
        std::vector<std::uint8_t> y(static_cast<std::size_t>(w) * h, 128);
        std::vector<std::uint8_t> u((static_cast<std::size_t>(w) / 2) * (h / 2), 64);
        std::vector<std::uint8_t> v((static_cast<std::size_t>(w) / 2) * (h / 2), 192);

        ASSERT_EQ(vc_reconfigure_encoder(vc, 1000, w, h, -1), 0);
        ASSERT_EQ(vc_encode(vc, w, h, y.data(), u.data(), v.data(), VC_EFLAG_NONE), 0);
    }

    vc_kill(vc);
}

TEST_F(VideoTest, ReconfigureFailDoS)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    // Trigger failure by passing invalid resolution (0)
    // This currently destroys the encoder.
    ASSERT_EQ(vc_reconfigure_encoder(vc, 1000, 0, 0, -1), -1);

    // Attempt to encode. This is expected to crash because vc->encoder is destroyed.
    std::vector<std::uint8_t> y(320 * 240, 128);
    std::vector<std::uint8_t> u(160 * 120, 64);
    std::vector<std::uint8_t> v(160 * 120, 192);
    // This call will crash in the current unfixed code.
    vc_encode(vc, 320, 240, y.data(), u.data(), v.data(), VC_EFLAG_NONE);

    vc_kill(vc);
}

TEST_F(VideoTest, LyingLengthOOB)
{
    VideoTestData data;
    VCSession *vc = vc_new(mem, log, mono_time, 123, VideoTestData::receive_frame, &data);
    ASSERT_NE(vc, nullptr);

    RtpMock rtp_mock;
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    rtp_mock.recv_session = recv_rtp;

    // Craft a malicious RTP packet
    std::uint16_t payload_len = 10;
    std::uint8_t packet[RTP_HEADER_SIZE + 11];  // +1 for Tox ID
    std::memset(packet, 0, sizeof(packet));

    // Tox ID
    packet[0] = static_cast<std::uint8_t>(RTP_TYPE_VIDEO);

    auto pack_u16 = [](std::uint8_t *p, std::uint16_t v) {
        p[0] = static_cast<std::uint8_t>(v >> 8);
        p[1] = static_cast<std::uint8_t>(v & 0xff);
    };
    auto pack_u32 = [](std::uint8_t *p, std::uint32_t v) {
        p[0] = static_cast<std::uint8_t>(v >> 24);
        p[1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
        p[2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
        p[3] = static_cast<std::uint8_t>(v & 0xff);
    };
    auto pack_u64 = [&](std::uint8_t *p, std::uint64_t v) {
        pack_u32(p, static_cast<std::uint32_t>(v >> 32));
        pack_u32(p + 4, static_cast<std::uint32_t>(v & 0xffffffff));
    };

    // RTP Header starts at packet[1]
    packet[1] = 2 << 6;  // ve = 2
    packet[2] = static_cast<std::uint8_t>(RTP_TYPE_VIDEO % 128);

    pack_u16(packet + 3, 1);  // sequnum
    pack_u32(packet + 5, 1000);  // timestamp
    pack_u32(packet + 9, 0x12345678);  // ssrc
    pack_u64(packet + 13, RTP_LARGE_FRAME);  // flags
    pack_u32(packet + 21, 0);  // offset_full
    pack_u32(packet + 25, 1000);  // data_length_full (LYING! Actual is 10)
    pack_u32(packet + 29, 0);  // received_length_full

    // Skip padding fields (11 * 4 = 44 bytes)
    pack_u16(packet + 77, 0);  // offset_lower
    pack_u16(packet + 79, payload_len);  // data_length_lower

    // Send the malicious packet
    rtp_receive_packet(recv_rtp, packet, sizeof(packet));

    // Trigger vc_iterate. This will call vpx_codec_decode with length 1000.
    // This is expected to cause OOB read.
    vc_iterate(vc);

    rtp_kill(log, recv_rtp);
    vc_kill(vc);
}

}  // namespace
