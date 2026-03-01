#ifndef C_TOXCORE_TESTING_SUPPORT_PUBLIC_MEMORY_H
#define C_TOXCORE_TESTING_SUPPORT_PUBLIC_MEMORY_H

#include <cstddef>
#include <cstdint>

#include "../../../toxcore/attributes.h"

// Forward declaration
struct Memory;

namespace tox::test {

/**
 * @brief Abstraction over the memory allocator.
 */
class MemorySystem {
public:
    virtual ~MemorySystem();

    virtual void *_Nullable malloc(std::size_t size) = 0;
    virtual void *_Nullable realloc(void *_Nullable ptr, std::size_t size) = 0;
    virtual void free(void *_Nullable ptr) = 0;

    /**
     * @brief Returns C-compatible Memory struct.
     */
    virtual struct Memory c_memory() = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_PUBLIC_MEMORY_H
