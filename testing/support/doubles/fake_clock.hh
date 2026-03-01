#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_CLOCK_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_CLOCK_H

#include <atomic>
#include <cstdint>

#include "../public/clock.hh"

namespace tox::test {

class FakeClock : public ClockSystem {
public:
    explicit FakeClock(uint64_t start_time_ms = 1000);

    uint64_t current_time_ms() const override;
    uint64_t current_time_s() const override;

    void advance(uint64_t ms);

private:
    std::atomic<uint64_t> now_ms_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_CLOCK_H
