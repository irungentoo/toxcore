/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "sort.h"

#include <gtest/gtest.h>

#include <algorithm>  // generate, sort
#include <limits>
#include <random>

#include "sort_test_util.hh"

namespace {

TEST(MergeSort, BehavesLikeStdSort)
{
    std::minstd_rand rng;
    // INT_MAX-1 so later we have room to add 1 larger element if needed.
    std::uniform_int_distribution<int> dist{
        std::numeric_limits<int>::min(), std::numeric_limits<int>::max() - 1};

    constexpr auto int_funcs = sort_funcs<int>();

    // Test with int arrays.
    for (std::uint32_t i = 1; i < 500; ++i) {
        std::vector<int> vec(i);
        std::generate(std::begin(vec), std::end(vec), [&]() { return dist(rng); });

        auto sorted = vec;
        std::sort(sorted.begin(), sorted.end(), std::less<int>());

        // If vec was accidentally sorted, add another larger element that almost definitely makes
        // it not sorted.
        if (vec == sorted) {
            int const largest = sorted.empty() ? 0 : sorted.back() + 1;
            sorted.push_back(largest);
            vec.insert(vec.begin(), largest);
        }
        ASSERT_NE(vec, sorted);

        // Just pass some arbitrary "self" to make sure the callbacks pass it through.
        ASSERT_TRUE(merge_sort(vec.data(), vec.size(), &i, &int_funcs));
        ASSERT_EQ(vec, sorted);
    }
}

TEST(MergeSort, WorksWithNonTrivialTypes)
{
    std::minstd_rand rng;
    std::uniform_int_distribution<int> dist{
        std::numeric_limits<int>::min(), std::numeric_limits<int>::max()};

    constexpr auto string_funcs = sort_funcs<std::string>();

    // Test with std::string arrays.
    for (std::uint32_t i = 1; i < 500; ++i) {
        std::vector<std::string> vec(i);
        std::generate(std::begin(vec), std::end(vec), [&]() { return std::to_string(dist(rng)); });

        auto sorted = vec;
        std::sort(sorted.begin(), sorted.end(), std::less<std::string>());

        // If vec was accidentally sorted, add another larger element that almost definitely makes
        // it not sorted.
        if (vec == sorted) {
            std::string const largest = "larger than largest int";
            sorted.push_back(largest);
            vec.push_back(largest);
            // Swap the last two elements. Since i >= 1, vec has at least 2 elements now.
            // This guarantees the vector is not sorted because 'largest' is now before the last
            // element (which is smaller than 'largest').
            std::iter_swap(vec.end() - 2, vec.end() - 1);
        }
        ASSERT_NE(vec, sorted);

        // Just pass some arbitrary "self" to make sure the callbacks pass it through.
        ASSERT_TRUE(merge_sort(vec.data(), vec.size(), &i, &string_funcs));
        ASSERT_EQ(vec, sorted);
    }
}

}  // namespace
