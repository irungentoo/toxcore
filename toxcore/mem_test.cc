#include "mem.h"

#include <gtest/gtest.h>

namespace {

TEST(Mem, AllocLarge)
{
    // Mebi prefix: https://en.wikipedia.org/wiki/Binary_prefix.
    constexpr uint32_t MI = 1024 * 1024;

    const Memory *mem = os_memory();

    void *ptr = mem_valloc(mem, 4, MI);
    EXPECT_NE(ptr, nullptr);

    mem_delete(mem, ptr);
}

TEST(Mem, AllocOverflow)
{
    // Gibi prefix.
    constexpr uint32_t GI = 1024 * 1024 * 1024;

    const Memory *mem = os_memory();

    // 1 gibi-elements of 100 bytes each.
    void *ptr = mem_valloc(mem, GI, 100);
    EXPECT_EQ(ptr, nullptr);

    // 100 elements of 1 gibibyte each.
    ptr = mem_valloc(mem, 100, GI);
    EXPECT_EQ(ptr, nullptr);

    // 128 (a multiple of 2) elements of 1 gibibyte each.
    ptr = mem_valloc(mem, 128, GI);
    EXPECT_EQ(ptr, nullptr);
}

}  // namespace
