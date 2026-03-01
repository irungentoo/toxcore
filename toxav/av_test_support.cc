#include "av_test_support.hh"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "../toxcore/os_memory.h"

static void test_log_cb(void *context, Logger_Level level, const char *file, uint32_t line,
    const char *func, const char *message, void *userdata)
{
    const char *level_str = "UNKNOWN";

    switch (level) {
    case LOGGER_LEVEL_TRACE:
        level_str = "TRACE";
        break;

    case LOGGER_LEVEL_DEBUG:
        level_str = "DEBUG";
        break;

    case LOGGER_LEVEL_INFO:
        level_str = "INFO";
        break;

    case LOGGER_LEVEL_WARNING:
        level_str = "WARNING";
        break;

    case LOGGER_LEVEL_ERROR:
        level_str = "ERROR";
        break;
    }

    std::cerr << "[" << level_str << "] " << file << ":" << line << " " << func << ": " << message
              << "\n";
}

// Mock Time
std::uint64_t mock_time_cb(void *_Nullable ud) { return static_cast<MockTime *>(ud)->t; }

// RTP Mock
int RtpMock::send_packet(
    void *_Nullable user_data, const std::uint8_t *_Nonnull data, std::uint16_t length)
{
    auto *self = static_cast<RtpMock *>(user_data);
    if (self->capture_packets) {
        if (self->store_last_packet_only) {
            if (self->captured_packets.empty()) {
                self->captured_packets.emplace_back(data, data + length);
            } else {
                self->captured_packets[0].assign(data, data + length);
            }
        } else {
            self->captured_packets.push_back(std::vector<std::uint8_t>(data, data + length));
        }
    }
    if (self->auto_forward && self->recv_session) {
        rtp_receive_packet(self->recv_session, data, length);
    }
    return 0;
}

int RtpMock::audio_cb(
    const Mono_Time *_Nonnull mono_time, void *_Nullable cs, RTPMessage *_Nonnull msg)
{
    return ac_queue_message(mono_time, cs, msg);
}

int RtpMock::video_cb(
    const Mono_Time *_Nonnull mono_time, void *_Nullable cs, RTPMessage *_Nonnull msg)
{
    return vc_queue_message(mono_time, cs, msg);
}

int RtpMock::noop_cb(
    const Mono_Time *_Nonnull /*mono_time*/, void *_Nullable /*cs*/, RTPMessage *_Nonnull msg)
{
    std::free(msg);
    return 0;
}

// Audio Helpers
void fill_audio_frame(std::uint32_t sampling_rate, std::uint8_t channels, int frame_index,
    std::size_t sample_count, std::vector<std::int16_t> &pcm)
{
    const double pi = std::acos(-1.0);
    double amplitude = 10000.0;

    for (std::size_t i = 0; i < sample_count; ++i) {
        double t = static_cast<double>(frame_index * sample_count + i) / sampling_rate;
        // Linear frequency sweep from 50Hz to 440Hz over 1 second (50 frames)
        // f(t) = 50 + 390t
        // phi(t) = 2*pi * (50t + 195t^2)
        double phi = 2.0 * pi * (50.0 * t + 195.0 * t * t);
        std::int16_t val = static_cast<std::int16_t>(std::sin(phi) * amplitude);
        for (std::uint8_t c = 0; c < channels; ++c) {
            pcm[i * channels + c] = val;
        }
    }
}

void fill_silent_frame(
    std::uint8_t channels, std::size_t sample_count, std::vector<std::int16_t> &pcm)
{
    for (std::size_t i = 0; i < sample_count * channels; ++i) {
        // Very low amplitude white noise (simulating silence with background hiss)
        pcm[i] = (std::rand() % 21) - 10;
    }
}

AudioTestData::AudioTestData() = default;
AudioTestData::~AudioTestData() = default;

void AudioTestData::receive_frame(std::uint32_t friend_number, const std::int16_t *_Nonnull pcm,
    std::size_t sample_count, std::uint8_t channels, std::uint32_t sampling_rate,
    void *_Nullable user_data)
{
    auto *self = static_cast<AudioTestData *>(user_data);
    self->friend_number = friend_number;
    self->last_pcm.assign(pcm, pcm + sample_count * channels);
    self->sample_count = sample_count;
    self->channels = channels;
    self->sampling_rate = sampling_rate;
}

// Video Helpers
void fill_video_frame(std::uint16_t width, std::uint16_t height, int frame_index,
    std::vector<std::uint8_t> &y, std::vector<std::uint8_t> &u, std::vector<std::uint8_t> &v)
{
    // Background (dark gray)
    std::fill(y.begin(), y.end(), 32);
    std::fill(u.begin(), u.end(), 128);
    std::fill(v.begin(), v.end(), 128);

    // Moving square (light gray)
    int sq_size = height / 4;
    if (sq_size < 16)
        sq_size = 16;
    int x0 = (frame_index * 8) % (width - sq_size);
    int y0 = (frame_index * 4) % (height - sq_size);
    for (int r = 0; r < sq_size; ++r) {
        for (int c = 0; c < sq_size; ++c) {
            y[(y0 + r) * width + (x0 + c)] = 200;
        }
    }
}

double calculate_video_mse(std::uint16_t width, std::uint16_t height, std::int32_t ystride,
    const std::vector<std::uint8_t> &y_recv, const std::vector<std::uint8_t> &y_orig)
{
    if (y_recv.empty() || y_orig.size() != static_cast<std::size_t>(width) * height) {
        return 1e10;
    }

    double mse = 0;
    for (int r = 0; r < height; ++r) {
        for (int c = 0; c < width; ++c) {
            int diff = static_cast<int>(y_orig[r * width + c]) - y_recv[r * std::abs(ystride) + c];
            mse += diff * diff;
        }
    }
    return mse / (static_cast<std::size_t>(width) * height);
}

// Video Test Data Helper
VideoTestData::VideoTestData() = default;
VideoTestData::~VideoTestData() = default;

void VideoTestData::receive_frame(std::uint32_t friend_number, std::uint16_t width,
    std::uint16_t height, const std::uint8_t *_Nonnull y, const std::uint8_t *_Nonnull u,
    const std::uint8_t *_Nonnull v, std::int32_t ystride, std::int32_t ustride,
    std::int32_t vstride, void *_Nullable user_data)
{
    auto *self = static_cast<VideoTestData *>(user_data);
    self->friend_number = friend_number;
    self->width = width;
    self->height = height;
    self->ystride = ystride;
    self->ustride = ustride;
    self->vstride = vstride;

    self->y.assign(y, y + static_cast<std::size_t>(std::abs(ystride)) * height);
    self->u.assign(u, u + static_cast<std::size_t>(std::abs(ustride)) * (height / 2));
    self->v.assign(v, v + static_cast<std::size_t>(std::abs(vstride)) * (height / 2));
}

double VideoTestData::calculate_mse(const std::vector<std::uint8_t> &y_orig) const
{
    return calculate_video_mse(width, height, ystride, y, y_orig);
}

// Common Test Fixture
void AvTest::SetUp()
{
    mem = os_memory();
    log = logger_new(mem);
    logger_callback_log(log, test_log_cb, nullptr, nullptr);
    tm.t = 1000;
    mono_time = mono_time_new(mem, mock_time_cb, &tm);
    mono_time_update(mono_time);
}

void AvTest::TearDown()
{
    mono_time_free(mem, mono_time);
    logger_kill(log);
}
