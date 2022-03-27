#include "util.h"

#include <gtest/gtest.h>

#include "crypto_core.h"

namespace {

TEST(Util, TwoRandomIdsAreNotEqual)
{
    const Random *rng = system_random();
    ASSERT_NE(rng, nullptr);
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
    const Random *rng = system_random();
    ASSERT_NE(rng, nullptr);
    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE] = {0};

    crypto_new_keypair(rng, pk1, sk1);
    pk_copy(pk2, pk1);

    EXPECT_TRUE(pk_equal(pk1, pk2));
}

}  // namespace
