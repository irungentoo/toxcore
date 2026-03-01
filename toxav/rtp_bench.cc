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

namespace {

class RtpBench : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &) override
    {
        const Memory *_Nonnull mem = os_memory();
        log = logger_new(mem);
        mono_time = mono_time_new(mem, nullptr, nullptr);

        mock.store_last_packet_only = true;

        session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &mock, nullptr,
            nullptr, nullptr, &mock, RtpMock::noop_cb);
    }

    void TearDown(const ::benchmark::State &) override
    {
        const Memory *mem = os_memory();
        rtp_kill(log, session);
        mono_time_free(mem, mono_time);
        logger_kill(log);
    }

    Logger *_Nullable log = nullptr;
    Mono_Time *_Nullable mono_time = nullptr;
    RTPSession *_Nullable session = nullptr;
    RtpMock mock;
};

BENCHMARK_DEFINE_F(RtpBench, SendData)(benchmark::State &state)
{
    std::size_t data_size = static_cast<std::size_t>(state.range(0));
    std::vector<std::uint8_t> data(data_size, 0xAA);

    for (auto _ : state) {
        rtp_send_data(log, session, data.data(), static_cast<std::uint32_t>(data.size()), false);
        benchmark::DoNotOptimize(mock.captured_packets.back());
    }
}
BENCHMARK_REGISTER_F(RtpBench, SendData)->Arg(100)->Arg(1000)->Arg(5000);

BENCHMARK_DEFINE_F(RtpBench, ReceivePacket)(benchmark::State &state)
{
    std::size_t data_size = static_cast<std::size_t>(state.range(0));
    std::vector<std::uint8_t> data(data_size, 0xAA);
    rtp_send_data(log, session, data.data(), static_cast<std::uint32_t>(data.size()), false);
    std::vector<std::uint8_t> packet = mock.captured_packets.back();

    for (auto _ : state) {
        rtp_receive_packet(session, packet.data(), packet.size());
    }
}
BENCHMARK_REGISTER_F(RtpBench, ReceivePacket)->Arg(100)->Arg(1000);

}  // namespace

BENCHMARK_MAIN();
