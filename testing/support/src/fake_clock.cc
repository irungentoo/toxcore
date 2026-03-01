#include "../doubles/fake_clock.hh"

namespace tox::test {

FakeClock::FakeClock(uint64_t start_time_ms)
    : now_ms_(start_time_ms)
{
}

uint64_t FakeClock::current_time_ms() const { return now_ms_; }

uint64_t FakeClock::current_time_s() const { return now_ms_ / 1000; }

void FakeClock::advance(uint64_t ms) { now_ms_ += ms; }

}  // namespace tox::test
