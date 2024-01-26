#include "util.h"

#include <gtest/gtest.h>

#include "crypto_core.h"
#include "crypto_core_test_util.hh"

namespace {

TEST(Util, TwoRandomIdsAreNotEqual)
{
    Test_Random rng;
    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk2[CRYPTO_SECRET_KEY_SIZE];

    crypto_new_keypair(rng, pk1, sk1);
    crypto_new_keypair(rng, pk2, sk2);

    EXPECT_FALSE(pk_equal(pk1, pk2));
}

TEST(Util, IdCopyMakesKeysEqual)
{
    Test_Random rng;
    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE] = {0};

    crypto_new_keypair(rng, pk1, sk1);
    pk_copy(pk2, pk1);

    EXPECT_TRUE(pk_equal(pk1, pk2));
}

TEST(Cmp, OrdersNumbersCorrectly)
{
    EXPECT_EQ(cmp_uint(1, 2), -1);
    EXPECT_EQ(cmp_uint(0, UINT32_MAX), -1);
    EXPECT_EQ(cmp_uint(UINT32_MAX, 0), 1);
    EXPECT_EQ(cmp_uint(UINT32_MAX, UINT32_MAX), 0);
    EXPECT_EQ(cmp_uint(0, UINT64_MAX), -1);
    EXPECT_EQ(cmp_uint(UINT64_MAX, 0), 1);
    EXPECT_EQ(cmp_uint(UINT64_MAX, UINT64_MAX), 0);
}

}  // namespace
