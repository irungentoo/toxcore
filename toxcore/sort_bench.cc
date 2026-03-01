/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include <benchmark/benchmark.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>

#include "attributes.h"
#include "mem.h"
#include "sort.h"
#include "sort_test_util.hh"

namespace {

std::pair<std::vector<Some_Type>, std::minstd_rand> random_vec(benchmark::State &state)
{
    std::minstd_rand rng;
    // INT_MAX-1 so later we have room to add 1 larger element if needed.
    std::uniform_int_distribution<std::uint32_t> dist{
        std::numeric_limits<std::uint32_t>::min(), std::numeric_limits<std::uint32_t>::max() - 1};

    std::vector<Some_Type> vec(state.range(0));
    std::generate(std::begin(vec), std::end(vec), [&]() {
        std::array<std::uint32_t, 8> compare_value;
        std::generate(
            std::begin(compare_value), std::end(compare_value), [&]() { return dist(rng); });
        return Some_Type{nullptr, compare_value, "hello there"};
    });

    return {vec, rng};
}

std::vector<Some_Type> mostly_sorted_vec(benchmark::State &state)
{
    auto [vec, rng] = random_vec(state);
    std::sort(vec.begin(), vec.end());

    // Randomly swap 5% of the vector.
    std::uniform_int_distribution<std::size_t> dist{0, vec.size() - 1};
    for (std::size_t i = 0; i < vec.size() / 20; ++i) {
        const auto a = dist(rng);
        const auto b = dist(rng);
        std::swap(vec[a], vec[b]);
    }

    return vec;
}

void BM_merge_sort(benchmark::State &state)
{
    const auto vec = random_vec(state).first;

    for (auto _ : state) {
        auto unsorted = vec;
        merge_sort(unsorted.data(), unsorted.size(), &state, &Some_Type::funcs);
    }
}

BENCHMARK(BM_merge_sort)->RangeMultiplier(2)->Range(8, 8 << 8);

void BM_merge_sort_with_buf(benchmark::State &state)
{
    const auto vec = random_vec(state).first;
    std::vector<Some_Type> buf(vec.size());

    for (auto _ : state) {
        auto unsorted = vec;
        merge_sort_with_buf(
            unsorted.data(), unsorted.size(), buf.data(), buf.size(), &state, &Some_Type::funcs);
    }
}

BENCHMARK(BM_merge_sort_with_buf)->RangeMultiplier(2)->Range(8, 8 << 8);

void BM_merge_sort_mostly_sorted(benchmark::State &state)
{
    auto vec = mostly_sorted_vec(state);

    for (auto _ : state) {
        auto unsorted = vec;
        merge_sort(unsorted.data(), unsorted.size(), &state, &Some_Type::funcs);
    }
}

BENCHMARK(BM_merge_sort_mostly_sorted)->RangeMultiplier(2)->Range(8, 8 << 8);

void BM_qsort(benchmark::State &state)
{
    const auto vec = random_vec(state).first;

    for (auto _ : state) {
        auto unsorted = vec;
        qsort(unsorted.data(), unsorted.size(), sizeof(unsorted[0]), my_type_cmp);
    }
}

BENCHMARK(BM_qsort)->RangeMultiplier(2)->Range(8, 8 << 8);

void BM_qsort_mostly_sorted(benchmark::State &state)
{
    auto vec = mostly_sorted_vec(state);

    for (auto _ : state) {
        auto unsorted = vec;
        qsort(unsorted.data(), unsorted.size(), sizeof(unsorted[0]), my_type_cmp);
    }
}

BENCHMARK(BM_qsort_mostly_sorted)->RangeMultiplier(2)->Range(8, 8 << 8);

void BM_std_sort(benchmark::State &state)
{
    const auto vec = random_vec(state).first;

    for (auto _ : state) {
        auto unsorted = vec;
        std::sort(unsorted.begin(), unsorted.end());
    }
}

BENCHMARK(BM_std_sort)->RangeMultiplier(2)->Range(8, 8 << 8);

void BM_std_sort_mostly_sorted(benchmark::State &state)
{
    auto vec = mostly_sorted_vec(state);

    for (auto _ : state) {
        auto unsorted = vec;
        std::sort(unsorted.begin(), unsorted.end());
    }
}

BENCHMARK(BM_std_sort_mostly_sorted)->RangeMultiplier(2)->Range(8, 8 << 8);

}

BENCHMARK_MAIN();
