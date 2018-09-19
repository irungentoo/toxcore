#include "crypto_core.h"

#include <algorithm>

#include <gtest/gtest.h>

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

clock_t memcmp_time(void *a, void *b, size_t len) {
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
void memcmp_median(void *src, void *same, void *not_same, size_t len, clock_t *same_median,
                   clock_t *not_same_median) {
  clock_t same_results[CRYPTO_TEST_MEMCMP_ITERATIONS];
  clock_t not_same_results[CRYPTO_TEST_MEMCMP_ITERATIONS];

  for (size_t i = 0; i < CRYPTO_TEST_MEMCMP_ITERATIONS; i++) {
    same_results[i] = memcmp_time(src, same, len);
    not_same_results[i] = memcmp_time(src, not_same, len);
  }

  std::sort(same_results, same_results + CRYPTO_TEST_MEMCMP_ITERATIONS);
  *same_median = same_results[CRYPTO_TEST_MEMCMP_ITERATIONS / 2];
  std::sort(not_same_results, not_same_results + CRYPTO_TEST_MEMCMP_ITERATIONS);
  *not_same_median = not_same_results[CRYPTO_TEST_MEMCMP_ITERATIONS / 2];
}

/**
 * This test checks whether crypto_memcmp takes the same time for equal and
 * non-equal chunks of memory.
 */
TEST(CryptoCore, MemcmpTimingIsDataIndependent) {
  // A random piece of memory.
  auto *src = new uint8_t[CRYPTO_TEST_MEMCMP_SIZE];
  random_bytes(src, CRYPTO_TEST_MEMCMP_SIZE);

  // A separate piece of memory containing the same data.
  auto *same = new uint8_t[CRYPTO_TEST_MEMCMP_SIZE];
  memcpy(same, src, CRYPTO_TEST_MEMCMP_SIZE);

  // Another piece of memory containing different data.
  auto *not_same = new uint8_t[CRYPTO_TEST_MEMCMP_SIZE];
  random_bytes(not_same, CRYPTO_TEST_MEMCMP_SIZE);

  clock_t same_median;
  clock_t not_same_median;
  memcmp_median(src, same, not_same, CRYPTO_TEST_MEMCMP_SIZE, &same_median, &not_same_median);

  delete[] not_same;
  delete[] same;
  delete[] src;

  clock_t const delta =
      same_median > not_same_median ? same_median - not_same_median : not_same_median - same_median;

  EXPECT_LT(delta, CRYPTO_TEST_MEMCMP_EPS)
      << "Delta time is too long (" << delta << " >= " << CRYPTO_TEST_MEMCMP_EPS << ")\n"
      << "Time of the same data comparison: " << same_median << " clocks\n"
      << "Time of the different data comparison: " << not_same_median << " clocks";
}

}  // namespace
