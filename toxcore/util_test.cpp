#include "util.h"

#include "crypto_core.h"

#include <gtest/gtest.h>

TEST(Util, UnixTimeIncreasesOverTime)
{
    unix_time_update();
    uint64_t const start = unix_time();

    while (start == unix_time()) {
        unix_time_update();
    }

    uint64_t const end = unix_time();
    EXPECT_GT(end, start);
}

TEST(Util, IsTimeout)
{
    uint64_t const start = unix_time();
    EXPECT_FALSE(is_timeout(start, 1));

    while (start == unix_time()) {
        unix_time_update();
    }

    EXPECT_TRUE(is_timeout(start, 1));
}

TEST(Util, TwoRandomIdsAreNotEqual)
{
    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk2[CRYPTO_SECRET_KEY_SIZE];

    crypto_new_keypair(pk1, sk1);
    crypto_new_keypair(pk2, sk2);

    EXPECT_FALSE(id_equal(pk1, pk2));
}

TEST(Util, IdCopyMakesKeysEqual)
{
    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE] = {0};

    crypto_new_keypair(pk1, sk1);
    id_copy(pk2, pk1);

    EXPECT_TRUE(id_equal(pk1, pk2));
}
