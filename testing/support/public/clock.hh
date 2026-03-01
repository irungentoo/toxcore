#ifndef C_TOXCORE_TESTING_SUPPORT_CLOCK_H
#define C_TOXCORE_TESTING_SUPPORT_CLOCK_H

#include <cstdint>

namespace tox::test {

/**
 * @brief Abstraction over the system's monotonic clock.
 */
class ClockSystem {
public:
    virtual ~ClockSystem();

    /**
     * @brief Returns current monotonic time in milliseconds.
     */
    virtual uint64_t current_time_ms() const = 0;

    /**
     * @brief Returns current monotonic time in seconds.
     */
    virtual uint64_t current_time_s() const = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_CLOCK_H
