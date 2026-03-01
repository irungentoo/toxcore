#ifndef C_TOXCORE_TESTING_SUPPORT_ENVIRONMENT_H
#define C_TOXCORE_TESTING_SUPPORT_ENVIRONMENT_H

#include <memory>

namespace tox::test {

class NetworkSystem;
class ClockSystem;
class RandomSystem;
class MemorySystem;

/**
 * @brief Service locator for system resources in tests.
 *
 * This interface allows tests to access system resources (Network, Time, RNG,
 * memory) in a way that can be swapped between real implementations (for
 * integration tests) and simulated ones (for unit/fuzz tests).
 */
class Environment {
public:
    virtual ~Environment();

    /**
     * @brief Access the network subsystem.
     */
    virtual NetworkSystem &network() = 0;

    /**
     * @brief Access the monotonic clock and timer subsystem.
     */
    virtual ClockSystem &clock() = 0;

    /**
     * @brief Access the random number generator.
     */
    virtual RandomSystem &random() = 0;

    /**
     * @brief Access the memory allocator.
     */
    virtual MemorySystem &memory() = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_ENVIRONMENT_H
