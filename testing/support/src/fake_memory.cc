#include "../doubles/fake_memory.hh"

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <new>

#include "../../../toxcore/mem.h"

namespace tox::test {

// --- Trampolines ---

static const Memory_Funcs kFakeMemoryVtable = {
    .malloc_callback = [](void *_Nonnull obj,
                           uint32_t size) { return static_cast<FakeMemory *>(obj)->malloc(size); },
    .realloc_callback
    = [](void *_Nonnull obj, void *_Nullable ptr,
          uint32_t size) { return static_cast<FakeMemory *>(obj)->realloc(ptr, size); },
    .dealloc_callback
    = [](void *_Nonnull obj, void *_Nullable ptr) { static_cast<FakeMemory *>(obj)->free(ptr); },
};

// --- Implementation ---

FakeMemory::FakeMemory() = default;
FakeMemory::~FakeMemory() = default;

void *_Nullable FakeMemory::malloc(std::size_t size)
{
    bool fail = failure_injector_ && failure_injector_(size);

    if (observer_) {
        observer_(!fail);
    }

    if (fail) {
        return nullptr;
    }

    void *ptr = std::malloc(size + sizeof(Header));
    if (!ptr) {
        return nullptr;
    }

    Header *header = static_cast<Header *>(ptr);
    header->size = size;
    header->magic = kMagic;

    on_allocation(size);

    return header + 1;
}

void *_Nullable FakeMemory::realloc(void *_Nullable ptr, std::size_t size)
{
    if (!ptr) {
        return malloc(size);
    }

    Header *old_header = static_cast<Header *>(ptr) - 1;
    if (old_header->magic != kMagic) {
        if (old_header->magic == kFreeMagic) {
            std::cerr << "[FakeMemory] realloc: Double realloc/free detected at " << ptr
                      << " (header=" << old_header << ")" << std::endl;
        } else {
            std::cerr << "[FakeMemory] realloc: Invalid pointer (wrong magic 0x" << std::hex
                      << old_header->magic << ") at " << ptr << " (header=" << old_header << ")"
                      << std::endl;
        }
        std::abort();
    }

    bool fail = failure_injector_ && failure_injector_(size);

    if (observer_) {
        observer_(!fail);
    }

    if (fail) {
        return nullptr;
    }

    std::size_t old_size = old_header->size;
    void *new_ptr = std::realloc(old_header, size + sizeof(Header));
    if (!new_ptr) {
        return nullptr;
    }

    on_deallocation(old_size);
    on_allocation(size);

    Header *header = static_cast<Header *>(new_ptr);
    header->size = size;
    header->magic = kMagic;

    return header + 1;
}

void FakeMemory::free(void *_Nullable ptr)
{
    if (!ptr) {
        return;
    }

    Header *header = static_cast<Header *>(ptr) - 1;
    if (header->magic != kMagic) {
        if (header->magic == kFreeMagic) {
            std::cerr << "[FakeMemory] free: Double free detected at " << ptr
                      << " (header=" << header << ")" << std::endl;
        } else {
            std::cerr << "[FakeMemory] free: Invalid pointer (wrong magic 0x" << std::hex
                      << header->magic << ") at " << ptr << " (header=" << header << ")"
                      << std::endl;
        }
        std::abort();
    }

    std::size_t size = header->size;
    on_deallocation(size);
    header->magic = kFreeMagic;  // Mark as free
    std::free(header);
}

void FakeMemory::set_failure_injector(FailureInjector injector)
{
    failure_injector_ = std::move(injector);
}

void FakeMemory::set_observer(Observer observer) { observer_ = std::move(observer); }

struct Memory FakeMemory::c_memory() { return Memory{&kFakeMemoryVtable, this}; }

std::size_t FakeMemory::current_allocation() const { return current_allocation_.load(); }

std::size_t FakeMemory::max_allocation() const { return max_allocation_.load(); }

void FakeMemory::on_allocation(std::size_t size)
{
    std::size_t current = current_allocation_.fetch_add(size) + size;
    std::size_t max = max_allocation_.load(std::memory_order_relaxed);
    while (current > max && !max_allocation_.compare_exchange_weak(max, current)) { }
}

void FakeMemory::on_deallocation(std::size_t size) { current_allocation_.fetch_sub(size); }

}  // namespace tox::test
