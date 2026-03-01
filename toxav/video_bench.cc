/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025-2026 The TokTok team.
 */

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/os_memory.h"
#include "av_test_support.hh"
#include "rtp.h"
#include "video.h"

namespace {

class VideoBench : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state) override
    {
        const Memory *_Nonnull mem = os_memory();
        log = logger_new(mem);
        tm.t = 1000;
        mono_time = mono_time_new(mem, mock_time_cb, &tm);
        vc = vc_new(mem, log, mono_time, 123, nullptr, nullptr);

        width = static_cast<std::uint16_t>(state.range(0));
        height = static_cast<std::uint16_t>(state.range(1));
        // Use a standard bitrate for benchmarks
        vc_reconfigure_encoder(vc, 2000, width, height, -1);

        y.resize(static_cast<std::size_t>(width) * height);
        u.resize((static_cast<std::size_t>(width) / 2) * (static_cast<std::size_t>(height) / 2));
        v.resize((static_cast<std::size_t>(width) / 2) * (static_cast<std::size_t>(height) / 2));

        rtp_mock.capture_packets = false;  // Disable capturing for benchmarks
        rtp_mock.auto_forward = true;

        rtp_mock.recv_session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet,
            &rtp_mock, nullptr, nullptr, nullptr, vc, RtpMock::video_cb);
    }

    void TearDown(const ::benchmark::State &state) override
    {
        const Memory *mem = os_memory();
        if (rtp_mock.recv_session) {
            rtp_kill(log, rtp_mock.recv_session);
        }
        if (vc) {
            vc_kill(vc);
        }
        if (mono_time) {
            mono_time_free(mem, mono_time);
        }
        if (log) {
            logger_kill(log);
        }
    }

    Logger *_Nullable log = nullptr;
    Mono_Time *_Nullable mono_time = nullptr;
    MockTime tm;
    VCSession *_Nullable vc = nullptr;
    RtpMock rtp_mock;
    std::uint16_t width = 0, height = 0;
    std::vector<std::uint8_t> y, u, v;
};

// Benchmark encoding a sequence of frames.
// Measures how the encoder performs as it builds up temporal state.
BENCHMARK_DEFINE_F(VideoBench, EncodeSequence)(benchmark::State &state)
{
    int frame_index = 0;
    // Pre-fill frames to avoid measuring fill_frame time
    const int num_prefilled = 100;
    std::vector<std::vector<std::uint8_t>> ys(
        num_prefilled, std::vector<std::uint8_t>(width * height));
    std::vector<std::vector<std::uint8_t>> us(
        num_prefilled, std::vector<std::uint8_t>((width / 2) * (height / 2)));
    std::vector<std::vector<std::uint8_t>> vs(
        num_prefilled, std::vector<std::uint8_t>((width / 2) * (height / 2)));
    for (int i = 0; i < num_prefilled; ++i) {
        fill_video_frame(width, height, i, ys[i], us[i], vs[i]);
    }

    for (auto _ : state) {
        int idx = frame_index % num_prefilled;
        // Force a keyframe every 100 frames to simulate real-world periodic keyframes
        int flags = (frame_index % 100 == 0) ? VC_EFLAG_FORCE_KF : VC_EFLAG_NONE;
        vc_encode(vc, width, height, ys[idx].data(), us[idx].data(), vs[idx].data(), flags);
        vc_increment_frame_counter(vc);

        std::uint8_t *pkt_data;
        std::uint32_t pkt_size;
        bool is_keyframe;
        while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_keyframe)) {
            benchmark::DoNotOptimize(pkt_data);
            benchmark::DoNotOptimize(pkt_size);
        }
        frame_index++;
    }
}

BENCHMARK_REGISTER_F(VideoBench, EncodeSequence)
    ->Args({320, 240})
    ->Args({640, 480})
    ->Args({1280, 720})
    ->Args({1920, 1080});

// Benchmark decoding a sequence of frames.
// First pre-encodes a sequence, then measures decoding performance.
BENCHMARK_DEFINE_F(VideoBench, DecodeSequence)(benchmark::State &state)
{
    const int num_frames = 100;
    std::vector<std::vector<std::uint8_t>> encoded_frames(num_frames);
    std::vector<bool> is_keyframe_list(num_frames);

    // Pre-encode
    for (int i = 0; i < num_frames; ++i) {
        fill_video_frame(width, height, i, y, u, v);
        int flags = (i == 0) ? VC_EFLAG_FORCE_KF : VC_EFLAG_NONE;
        vc_encode(vc, width, height, y.data(), u.data(), v.data(), flags);
        vc_increment_frame_counter(vc);

        std::uint8_t *pkt_data;
        std::uint32_t pkt_size;
        bool is_kf;
        while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_kf)) {
            encoded_frames[i].insert(encoded_frames[i].end(), pkt_data, pkt_data + pkt_size);
            is_keyframe_list[i] = is_kf;
        }
    }

    int frame_index = 0;
    for (auto _ : state) {
        int idx = frame_index % num_frames;
        const auto &encoded_data = encoded_frames[idx];
        rtp_send_data(log, rtp_mock.recv_session, encoded_data.data(),
            static_cast<std::uint32_t>(encoded_data.size()), is_keyframe_list[idx]);
        vc_iterate(vc);
        frame_index++;
    }
}

BENCHMARK_REGISTER_F(VideoBench, DecodeSequence)
    ->Args({320, 240})
    ->Args({640, 480})
    ->Args({1280, 720})
    ->Args({1920, 1080});

// Full end-to-end sequence benchmark (Encode -> RTP -> Decode)
BENCHMARK_DEFINE_F(VideoBench, FullSequence)(benchmark::State &state)
{
    int frame_index = 0;
    const int num_prefilled = 100;
    std::vector<std::vector<std::uint8_t>> ys(
        num_prefilled, std::vector<std::uint8_t>(width * height));
    std::vector<std::vector<std::uint8_t>> us(
        num_prefilled, std::vector<std::uint8_t>((width / 2) * (height / 2)));
    std::vector<std::vector<std::uint8_t>> vs(
        num_prefilled, std::vector<std::uint8_t>((width / 2) * (height / 2)));
    for (int i = 0; i < num_prefilled; ++i) {
        fill_video_frame(width, height, i, ys[i], us[i], vs[i]);
    }

    for (auto _ : state) {
        int idx = frame_index % num_prefilled;
        int flags = (frame_index % 100 == 0) ? VC_EFLAG_FORCE_KF : VC_EFLAG_NONE;
        vc_encode(vc, width, height, ys[idx].data(), us[idx].data(), vs[idx].data(), flags);
        vc_increment_frame_counter(vc);

        std::uint8_t *pkt_data;
        std::uint32_t pkt_size;
        bool is_keyframe = false;
        // We need to collect all packets for the frame before sending to decoder
        std::vector<std::uint8_t> frame_data;
        while (vc_get_cx_data(vc, &pkt_data, &pkt_size, &is_keyframe)) {
            frame_data.insert(frame_data.end(), pkt_data, pkt_data + pkt_size);
        }

        rtp_send_data(log, rtp_mock.recv_session, frame_data.data(),
            static_cast<std::uint32_t>(frame_data.size()), is_keyframe);
        vc_iterate(vc);

        frame_index++;
    }
}

BENCHMARK_REGISTER_F(VideoBench, FullSequence)
    ->Args({320, 240})
    ->Args({640, 480})
    ->Args({1280, 720})
    ->Args({1920, 1080});

}

BENCHMARK_MAIN();
