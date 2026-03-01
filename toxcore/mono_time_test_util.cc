#include "mono_time_test_util.hh"

using tox::test::FakeClock;

void setup_fake_clock(Mono_Time *_Nonnull mono_time, FakeClock &clock)
{
    mono_time_set_current_time_callback(
        mono_time,
        [](void *_Nullable user_data) -> std::uint64_t {
            return static_cast<FakeClock *>(user_data)->current_time_ms();
        },
        &clock);
}
