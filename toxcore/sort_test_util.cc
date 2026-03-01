#include "sort_test_util.hh"

#include <array>
#include <cstddef>

#include "sort.h"
#include "util.h"

namespace {
template <typename T, std::size_t N>
int cmp_uint_array(const std::array<T, N> &a, const std::array<T, N> &b)
{
    for (std::size_t i = 0; i < a.size(); ++i) {
        const int cmp = cmp_uint(a[i], b[i]);
        if (cmp != 0) {
            return cmp;
        }
    }
    return 0;
}
}

const Sort_Funcs Some_Type::funcs = sort_funcs<Some_Type>();

int my_type_cmp(const void *_Nonnull va, const void *_Nonnull vb)
{
    const auto *a = static_cast<const Some_Type *>(va);
    const auto *b = static_cast<const Some_Type *>(vb);
    return cmp_uint_array(a->compare_value, b->compare_value);
}

bool operator<(const Some_Type &a, const Some_Type &b) { return a.compare_value < b.compare_value; }
