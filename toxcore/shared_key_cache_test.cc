/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "shared_key_cache.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>

#include "../testing/support/public/simulation.hh"
#include "attributes.h"
#include "mono_time.h"

namespace {

using tox::test::SimulatedNode;
using tox::test::Simulation;

class SharedKeyCacheTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        sim = std::make_unique<Simulation>(12345);
        node = sim->create_node();
        crypto_new_keypair(&node->c_random, alice_pk, alice_sk);

        sim->advance_time(1000);  // Ensure mono_time > 0

        mono_time = mono_time_new(
            &node->c_memory,
            [](void *_Nullable user_data) -> std::uint64_t {
                return static_cast<Simulation *>(user_data)->clock().current_time_ms();
            },
            sim.get());
        mono_time_update(mono_time);

        logger = logger_new(&node->c_memory);

        cache = shared_key_cache_new(logger, mono_time, &node->c_memory, alice_sk, 10000, 4);
        ASSERT_NE(cache, nullptr);
    }

    void TearDown() override
    {
        shared_key_cache_free(cache);
        logger_kill(logger);
        mono_time_free(&node->c_memory, mono_time);
    }

    std::unique_ptr<Simulation> sim;
    std::unique_ptr<SimulatedNode> node;
    std::uint8_t alice_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t alice_sk[CRYPTO_SECRET_KEY_SIZE];
    Mono_Time *_Nullable mono_time = nullptr;
    Logger *_Nullable logger = nullptr;
    Shared_Key_Cache *_Nullable cache = nullptr;
};

TEST_F(SharedKeyCacheTest, BasicLookup)
{
    std::uint8_t bob_pk[CRYPTO_PUBLIC_KEY_SIZE], bob_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(&node->c_random, bob_pk, bob_sk);

    const std::uint8_t *shared1 = shared_key_cache_lookup(cache, bob_pk);
    ASSERT_NE(shared1, nullptr);

    // Second lookup should return cached pointer
    const std::uint8_t *shared2 = shared_key_cache_lookup(cache, bob_pk);
    EXPECT_EQ(shared1, shared2);

    // Verify key correctness
    std::uint8_t expected[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(bob_pk, alice_sk, expected);
    EXPECT_EQ(std::memcmp(shared1, expected, CRYPTO_SHARED_KEY_SIZE), 0);
}

TEST_F(SharedKeyCacheTest, TimeoutEviction)
{
    std::uint8_t bob_pk[CRYPTO_PUBLIC_KEY_SIZE], bob_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(&node->c_random, bob_pk, bob_sk);

    shared_key_cache_lookup(cache, bob_pk);
    sim->advance_time(11000);  // Past 10s timeout
    mono_time_update(mono_time);

    // Should re-compute/re-insert after timeout
    const std::uint8_t *shared = shared_key_cache_lookup(cache, bob_pk);
    ASSERT_NE(shared, nullptr);
}

TEST_F(SharedKeyCacheTest, SlotExhaustionAndLRU)
{
    // Fill one bucket (4 slots)
    std::vector<std::vector<std::uint8_t>> pks;
    // Store pointers to verify cache hits (stable memory addresses)
    std::vector<const std::uint8_t *> pointers;
    std::uint8_t target_hash = 0x42;

    for (int i = 0; i < 5; ++i) {
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE], sk[CRYPTO_SECRET_KEY_SIZE];
        while (true) {
            crypto_new_keypair(&node->c_random, pk, sk);
            if (pk[8] == target_hash)
                break;
        }
        pks.push_back(std::vector<std::uint8_t>(pk, pk + CRYPTO_PUBLIC_KEY_SIZE));
        sim->advance_time(100);
        mono_time_update(mono_time);
        pointers.push_back(shared_key_cache_lookup(cache, pk));
    }

    // 5th lookup should have evicted the oldest (LRU)
    bool reused = false;
    for (int i = 0; i < 4; ++i) {
        if (pointers[4] == pointers[i])
            reused = true;
    }
    EXPECT_TRUE(reused);

    // Most recent should still be cached
    EXPECT_EQ(shared_key_cache_lookup(cache, pks[1].data()), pointers[1]);
}

TEST_F(SharedKeyCacheTest, HashDistribution)
{
    const int total_keys = 256;
    std::vector<std::vector<std::uint8_t>> pks;
    // Store pointers to verify cache hits (stable memory addresses)
    std::vector<const std::uint8_t *> pointers;

    // Fill cache with keys having unique hashes
    for (int i = 0; i < total_keys; ++i) {
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE], sk[CRYPTO_SECRET_KEY_SIZE];
        while (true) {
            crypto_new_keypair(&node->c_random, pk, sk);
            std::uint8_t h = pk[8];
            bool duplicate = false;
            for (const auto &existing : pks) {
                if (existing[8] == h) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate)
                break;
        }
        pks.push_back(std::vector<std::uint8_t>(pk, pk + CRYPTO_PUBLIC_KEY_SIZE));
        pointers.push_back(shared_key_cache_lookup(cache, pk));
    }

    // Verify high hit rate (low collisions)
    int hits = 0;
    for (int i = 0; i < total_keys; ++i) {
        if (shared_key_cache_lookup(cache, pks[i].data()) == pointers[i])
            hits++;
    }
    EXPECT_EQ(hits, total_keys);
}

}  // namespace
