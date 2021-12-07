#include "crypto_core.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

namespace {

enum {
  /**
   * The size of the arrays to compare. This was chosen to take around 2000
   * CPU clocks on x86_64.
   *
   * This is 1MiB.
   */
  CRYPTO_TEST_MEMCMP_SIZE = 1024 * 1024,
  /**
   * The number of times we run memcmp in the test.
   *
   * We compute the median time taken to reduce error margins.
   */
  CRYPTO_TEST_MEMCMP_ITERATIONS = 500,
  /**
   * The margin of error (in clocks) we allow for this test.
   *
   * Should be within 0.5% of ~2000 CPU clocks. In reality, the code is much
   * more precise and is usually within 1 CPU clock.
   */
  CRYPTO_TEST_MEMCMP_EPS = 10,
};

clock_t memcmp_time(uint8_t const *a, uint8_t const *b, size_t len) {
  clock_t start = clock();
  volatile int result = crypto_memcmp(a, b, len);
  (void)result;
  return clock() - start;
}

/**
 * This function performs the actual timing. It interleaves comparison of
 * equal and non-equal arrays to reduce the influence of external effects
 * such as the machine being a little more busy 1 second later.
 */
std::pair<clock_t, clock_t> memcmp_median(uint8_t const *src, uint8_t const *same,
                                          uint8_t const *not_same, size_t len) {
  clock_t same_results[CRYPTO_TEST_MEMCMP_ITERATIONS];
  clock_t not_same_results[CRYPTO_TEST_MEMCMP_ITERATIONS];

  for (size_t i = 0; i < CRYPTO_TEST_MEMCMP_ITERATIONS; i++) {
    same_results[i] = memcmp_time(src, same, len);
    not_same_results[i] = memcmp_time(src, not_same, len);
  }

  std::sort(same_results, same_results + CRYPTO_TEST_MEMCMP_ITERATIONS);
  clock_t const same_median = same_results[CRYPTO_TEST_MEMCMP_ITERATIONS / 2];
  std::sort(not_same_results, not_same_results + CRYPTO_TEST_MEMCMP_ITERATIONS);
  clock_t const not_same_median = not_same_results[CRYPTO_TEST_MEMCMP_ITERATIONS / 2];
  return {same_median, not_same_median};
}

/**
 * This test checks whether crypto_memcmp takes the same time for equal and
 * non-equal chunks of memory.
 */
TEST(CryptoCore, MemcmpTimingIsDataIndependent) {
  // A random piece of memory.
  std::array<uint8_t, CRYPTO_TEST_MEMCMP_SIZE> src;
  random_bytes(src.data(), CRYPTO_TEST_MEMCMP_SIZE);

  // A separate piece of memory containing the same data.
  std::array<uint8_t, CRYPTO_TEST_MEMCMP_SIZE> same = src;

  // Another piece of memory containing different data.
  std::array<uint8_t, CRYPTO_TEST_MEMCMP_SIZE> not_same;
  random_bytes(not_same.data(), CRYPTO_TEST_MEMCMP_SIZE);

  // Once we have C++17:
  // auto const [same_median, not_same_median] =
  auto const result =
      memcmp_median(src.data(), same.data(), not_same.data(), CRYPTO_TEST_MEMCMP_SIZE);

  clock_t const delta =
      std::max(result.first, result.second) - std::min(result.first, result.second);

  EXPECT_LT(delta, CRYPTO_TEST_MEMCMP_EPS)
      << "Delta time is too long (" << delta << " >= " << CRYPTO_TEST_MEMCMP_EPS << ")\n"
      << "Time of the same data comparison: " << result.first << " clocks\n"
      << "Time of the different data comparison: " << result.second << " clocks";
}

TEST(CryptoCore, IncrementNonce) {
  using Nonce = std::array<uint8_t, CRYPTO_NONCE_SIZE>;
  Nonce nonce{};
  increment_nonce(nonce.data());
  EXPECT_EQ(nonce,
            (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}));

  for (int i = 0; i < 0x1F4; ++i) {
    increment_nonce(nonce.data());
  }

  EXPECT_EQ(
      nonce,
      (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xF5}}));
}

TEST(CryptoCore, IncrementNonceNumber) {
  using Nonce = std::array<uint8_t, CRYPTO_NONCE_SIZE>;
  Nonce nonce{};

  increment_nonce_number(nonce.data(), 0x1F5);
  EXPECT_EQ(
      nonce,
      (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xF5}}));

  increment_nonce_number(nonce.data(), 0x1F5);
  EXPECT_EQ(
      nonce,
      (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xEA}}));

  increment_nonce_number(nonce.data(), 0x12345678);
  EXPECT_EQ(nonce, (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0,    0,    0,    0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x5A, 0x62}}));
}

}  // namespace
