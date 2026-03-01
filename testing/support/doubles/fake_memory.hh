#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_MEMORY_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_MEMORY_H

#include <atomic>
#include <cstddef>
#include <functional>

#include "../public/memory.hh"

// Forward declaration
struct Memory;

namespace tox::test {

class FakeMemory : public MemorySystem {
public:
    using FailureInjector = std::function<bool(std::size_t size)>;  // Return true to fail
    using Observer = std::function<void(bool success)>;

    FakeMemory();
    ~FakeMemory() override;

    void *_Nullable malloc(std::size_t size) override;
    void *_Nullable realloc(void *_Nullable ptr, std::size_t size) override;
    void free(void *_Nullable ptr) override;

    // Configure failure injection
    void set_failure_injector(FailureInjector injector);

    // Configure observer
    void set_observer(Observer observer);

    /**
     * @brief Returns C-compatible Memory struct.
     */
    struct Memory c_memory() override;

    std::size_t current_allocation() const;
    std::size_t max_allocation() const;

private:
    void on_allocation(std::size_t size);
    void on_deallocation(std::size_t size);

    struct Header {
        std::size_t size;
        std::size_t magic;
    };
    static constexpr std::size_t kMagic = 0xDEADC0DE;
    static constexpr std::size_t kFreeMagic = 0xBAADF00D;

    std::atomic<std::size_t> current_allocation_{0};
    std::atomic<std::size_t> max_allocation_{0};

    FailureInjector failure_injector_;
    Observer observer_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_MEMORY_H
