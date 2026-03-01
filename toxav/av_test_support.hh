#ifndef TOXAV_AV_TEST_SUPPORT_H
#define TOXAV_AV_TEST_SUPPORT_H

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "audio.h"
#include "rtp.h"
#include "video.h"

// Mock Time
struct MockTime {
    std::uint64_t t = 1000;
};
std::uint64_t mock_time_cb(void *_Nullable ud);

// RTP Mock
struct RtpMock {
    RTPSession *_Nullable recv_session = nullptr;
    std::vector<std::vector<std::uint8_t>> captured_packets;
    bool auto_forward = true;
    bool capture_packets = true;
    bool store_last_packet_only = false;

    static int send_packet(
        void *_Nullable user_data, const std::uint8_t *_Nonnull data, std::uint16_t length);
    static int audio_cb(
        const Mono_Time *_Nonnull mono_time, void *_Nullable cs, RTPMessage *_Nonnull msg);
    static int video_cb(
        const Mono_Time *_Nonnull mono_time, void *_Nullable cs, RTPMessage *_Nonnull msg);
    static int noop_cb(
        const Mono_Time *_Nonnull mono_time, void *_Nullable cs, RTPMessage *_Nonnull msg);
};

// Audio Helpers
void fill_audio_frame(std::uint32_t sampling_rate, std::uint8_t channels, int frame_index,
    std::size_t sample_count, std::vector<std::int16_t> &pcm);
void fill_silent_frame(
    std::uint8_t channels, std::size_t sample_count, std::vector<std::int16_t> &pcm);

struct AudioTestData {
    std::uint32_t friend_number = 0;
    std::vector<std::int16_t> last_pcm;
    std::size_t sample_count = 0;
    std::uint8_t channels = 0;
    std::uint32_t sampling_rate = 0;

    AudioTestData();
    ~AudioTestData();

    static void receive_frame(std::uint32_t friend_number, const std::int16_t *_Nonnull pcm,
        std::size_t sample_count, std::uint8_t channels, std::uint32_t sampling_rate,
        void *_Nullable user_data);
};

// Video Helpers
void fill_video_frame(std::uint16_t width, std::uint16_t height, int frame_index,
    std::vector<std::uint8_t> &y, std::vector<std::uint8_t> &u, std::vector<std::uint8_t> &v);
double calculate_video_mse(std::uint16_t width, std::uint16_t height, std::int32_t ystride,
    const std::vector<std::uint8_t> &y_recv, const std::vector<std::uint8_t> &y_orig);

// Video Test Data Helper
struct VideoTestData {
    std::uint32_t friend_number = 0;
    std::uint16_t width = 0;
    std::uint16_t height = 0;
    std::vector<std::uint8_t> y, u, v;
    std::int32_t ystride = 0, ustride = 0, vstride = 0;

    VideoTestData();
    ~VideoTestData();

    static void receive_frame(std::uint32_t friend_number, std::uint16_t width,
        std::uint16_t height, const std::uint8_t *_Nonnull y, const std::uint8_t *_Nonnull u,
        const std::uint8_t *_Nonnull v, std::int32_t ystride, std::int32_t ustride,
        std::int32_t vstride, void *_Nullable user_data);

    double calculate_mse(const std::vector<std::uint8_t> &y_orig) const;
};

// Common Test Fixture
class AvTest : public ::testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;

    Logger *_Nullable log = nullptr;
    Mono_Time *_Nullable mono_time = nullptr;
    const Memory *_Nullable mem = nullptr;
    MockTime tm;
};

#endif  // TOXAV_AV_TEST_SUPPORT_H
