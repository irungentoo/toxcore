/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_SORT_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_SORT_TEST_UTIL_H

#include <array>
#include <cstdint>

#include "attributes.h"
#include "sort.h"

struct Memory;

template <typename T>
constexpr Sort_Funcs sort_funcs()
{
    return {[](const void *_Nonnull object, const void *_Nonnull va, const void *_Nonnull vb) {
                const T *a = static_cast<const T *>(va);
                const T *b = static_cast<const T *>(vb);

                return *a < *b;
            },
        [](const void *_Nonnull arr, std::uint32_t index) -> const void *_Nonnull {const T * vec
                                                              = static_cast<const T *>(arr);
    return &vec[index];
}
,
    [](void *_Nonnull arr, std::uint32_t index, const void *_Nonnull val) {
        T *vec = static_cast<T *>(arr);
        const T *value = static_cast<const T *>(val);
        vec[index] = *value;
    },
    [](void *_Nonnull arr, std::uint32_t index, std::uint32_t size) -> void *_Nonnull
{
    T *vec = static_cast<T *>(arr);
    return &vec[index];
}
, [](const void *_Nonnull object, std::uint32_t size) -> void *_Nonnull { return new T[size]; }
, [](const void *_Nonnull object, void *_Nonnull arr, std::uint32_t size) {
    delete[] static_cast<T *>(arr);
},
}
;
}

// A realistic test case where we have a struct with some stuff and an expensive value we compare.
struct Some_Type {
    const Memory *_Nullable mem;
    std::array<std::uint32_t, 8> compare_value;
    const char *_Nullable name;

    static const Sort_Funcs funcs;
};

int my_type_cmp(const void *_Nonnull va, const void *_Nonnull vb);
bool operator<(const Some_Type &a, const Some_Type &b);

#endif  // C_TOXCORE_TOXCORE_SORT_TEST_UTIL_H
