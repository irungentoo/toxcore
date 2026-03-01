/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025-2026 The TokTok team.
 */

#include <benchmark/benchmark.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/os_memory.h"
#include "audio.h"
#include "av_test_support.hh"
#include "rtp.h"

namespace {

class AudioBench : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state) override
    {
        const Memory *_Nonnull mem = os_memory();
        log = logger_new(mem);
        tm.t = 1000;
        mono_time = mono_time_new(mem, mock_time_cb, &tm);
        ac = ac_new(mono_time, log, 123, nullptr, nullptr);

        sampling_rate = static_cast<std::uint32_t>(state.range(0));
        channels = static_cast<std::uint8_t>(state.range(1));
        std::uint32_t bitrate = (channels == 1) ? 32000 : 64000;

        ac_reconfigure_encoder(ac, bitrate, sampling_rate, channels);

        sample_count = sampling_rate / 50;  // 20ms frames
        pcm.resize(sample_count * channels);

        rtp_mock.capture_packets = false;  // Disable capturing for benchmarks
        rtp_mock.auto_forward = true;

        rtp_mock.recv_session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet,
            &rtp_mock, nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    }

    void TearDown(const ::benchmark::State &state) override
    {
        const Memory *mem = os_memory();
        if (rtp_mock.recv_session) {
            rtp_kill(log, rtp_mock.recv_session);
        }
        if (ac) {
            ac_kill(ac);
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
    ACSession *_Nullable ac = nullptr;
    RtpMock rtp_mock;
    std::uint32_t sampling_rate = 0;
    std::uint8_t channels = 0;
    std::size_t sample_count = 0;
    std::vector<std::int16_t> pcm;
};

// Benchmark encoding a sequence of silent audio frames.
BENCHMARK_DEFINE_F(AudioBench, EncodeSilentSequence)(benchmark::State &state)
{
    std::vector<std::int16_t> silent_pcm(sample_count * channels);
    fill_silent_frame(channels, sample_count, silent_pcm);

    std::vector<std::uint8_t> encoded(2000);

    for (auto _ : state) {
        int encoded_size
            = ac_encode(ac, silent_pcm.data(), sample_count, encoded.data(), encoded.size());
        benchmark::DoNotOptimize(encoded_size);
    }
}

BENCHMARK_REGISTER_F(AudioBench, EncodeSilentSequence)
    ->Args({8000, 1})
    ->Args({48000, 1})
    ->Args({48000, 2});

// Benchmark encoding a sequence of audio frames.
BENCHMARK_DEFINE_F(AudioBench, EncodeSequence)(benchmark::State &state)
{
    int frame_index = 0;
    const int num_prefilled = 50;
    std::vector<std::vector<std::int16_t>> pcms(
        num_prefilled, std::vector<std::int16_t>(sample_count * channels));
    for (int i = 0; i < num_prefilled; ++i) {
        fill_audio_frame(sampling_rate, channels, i, sample_count, pcms[i]);
    }

    std::vector<std::uint8_t> encoded(2000);

    for (auto _ : state) {
        int idx = frame_index % num_prefilled;
        int encoded_size
            = ac_encode(ac, pcms[idx].data(), sample_count, encoded.data(), encoded.size());
        benchmark::DoNotOptimize(encoded_size);
        frame_index++;
    }
}

BENCHMARK_REGISTER_F(AudioBench, EncodeSequence)
    ->Args({8000, 1})
    ->Args({16000, 1})
    ->Args({24000, 1})
    ->Args({48000, 1})
    ->Args({48000, 2});

// Benchmark decoding a sequence of audio frames.
BENCHMARK_DEFINE_F(AudioBench, DecodeSequence)(benchmark::State &state)
{
    const int num_frames = 50;
    std::vector<std::vector<std::uint8_t>> encoded_frames(num_frames);

    // Pre-encode
    std::vector<std::uint8_t> encoded_tmp(2000);
    for (int i = 0; i < num_frames; ++i) {
        fill_audio_frame(sampling_rate, channels, i, sample_count, pcm);
        int size = ac_encode(ac, pcm.data(), sample_count, encoded_tmp.data(), encoded_tmp.size());

        encoded_frames[i].resize(4 + size);
        std::uint32_t net_sr = net_htonl(sampling_rate);
        std::memcpy(encoded_frames[i].data(), &net_sr, 4);
        std::memcpy(encoded_frames[i].data() + 4, encoded_tmp.data(), size);
    }

    int frame_index = 0;
    for (auto _ : state) {
        int idx = frame_index % num_frames;
        rtp_send_data(log, rtp_mock.recv_session, encoded_frames[idx].data(),
            static_cast<std::uint32_t>(encoded_frames[idx].size()), false);
        ac_iterate(ac);
        frame_index++;
    }
}

BENCHMARK_REGISTER_F(AudioBench, DecodeSequence)
    ->Args({8000, 1})
    ->Args({16000, 1})
    ->Args({24000, 1})
    ->Args({48000, 1})
    ->Args({48000, 2});

// Full end-to-end sequence benchmark (Encode -> RTP -> Decode)
BENCHMARK_DEFINE_F(AudioBench, FullSequence)(benchmark::State &state)
{
    int frame_index = 0;
    const int num_prefilled = 50;
    std::vector<std::vector<std::int16_t>> pcms(
        num_prefilled, std::vector<std::int16_t>(sample_count * channels));
    for (int i = 0; i < num_prefilled; ++i) {
        fill_audio_frame(sampling_rate, channels, i, sample_count, pcms[i]);
    }

    std::vector<std::uint8_t> encoded_tmp(2000);

    for (auto _ : state) {
        int idx = frame_index % num_prefilled;
        int size
            = ac_encode(ac, pcms[idx].data(), sample_count, encoded_tmp.data(), encoded_tmp.size());

        std::vector<std::uint8_t> payload(4 + size);
        std::uint32_t net_sr = net_htonl(sampling_rate);
        std::memcpy(payload.data(), &net_sr, 4);
        std::memcpy(payload.data() + 4, encoded_tmp.data(), size);

        rtp_send_data(log, rtp_mock.recv_session, payload.data(),
            static_cast<std::uint32_t>(payload.size()), false);
        ac_iterate(ac);

        frame_index++;
    }
}

BENCHMARK_REGISTER_F(AudioBench, FullSequence)
    ->Args({8000, 1})
    ->Args({16000, 1})
    ->Args({24000, 1})
    ->Args({48000, 1})
    ->Args({48000, 2});

}

BENCHMARK_MAIN();
