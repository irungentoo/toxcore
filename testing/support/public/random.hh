#ifndef C_TOXCORE_TESTING_SUPPORT_RANDOM_H
#define C_TOXCORE_TESTING_SUPPORT_RANDOM_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../../../toxcore/attributes.h"

// Forward declaration
struct Random;

namespace tox::test {

/**
 * @brief Abstraction over the random number generator.
 */
class RandomSystem {
public:
    virtual ~RandomSystem();

    virtual uint32_t uniform(uint32_t upper_bound) = 0;
    virtual void bytes(uint8_t *_Nonnull out, std::size_t count) = 0;

    /**
     * @brief Returns C-compatible Random struct.
     */
    virtual struct Random c_random() = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_RANDOM_H
