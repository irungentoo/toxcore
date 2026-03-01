// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "crypto_core.h"
// clang-format on

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#include "crypto_core_test_util.hh"

namespace {

using HmacKey = std::array<std::uint8_t, CRYPTO_HMAC_KEY_SIZE>;
using Hmac = std::array<std::uint8_t, CRYPTO_HMAC_SIZE>;
using SecretKey = std::array<std::uint8_t, CRYPTO_SECRET_KEY_SIZE>;
using Signature = std::array<std::uint8_t, CRYPTO_SIGNATURE_SIZE>;
using Nonce = std::array<std::uint8_t, CRYPTO_NONCE_SIZE>;

using tox::test::SimulatedEnvironment;

TEST(PkEqual, TwoRandomIdsAreNotEqual)
{
    SimulatedEnvironment env{12345};
    auto &rng = env.fake_random();

    std::uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];

    rng.bytes(pk1, sizeof(pk1));
    rng.bytes(pk2, sizeof(pk2));

    EXPECT_FALSE(pk_equal(pk1, pk2));
}

TEST(PkEqual, IdCopyMakesKeysEqual)
{
    SimulatedEnvironment env{12345};
    auto &rng = env.fake_random();

    std::uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE] = {0};

    rng.bytes(pk1, sizeof(pk1));

    pk_copy(pk2, pk1);

    EXPECT_TRUE(pk_equal(pk1, pk2));
}

TEST(CryptoCore, EncryptLargeData)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    auto c_rng = env.fake_random().c_random();

    Nonce nonce{};
    PublicKey pk;
    SecretKey sk;
    crypto_new_keypair(&c_rng, pk.data(), sk.data());

    // 100 MiB of data (all zeroes, doesn't matter what's inside).
    std::vector<std::uint8_t> plain(100 * 1024 * 1024);
    std::vector<std::uint8_t> encrypted(plain.size() + CRYPTO_MAC_SIZE);

    encrypt_data(
        &c_mem, pk.data(), sk.data(), nonce.data(), plain.data(), plain.size(), encrypted.data());
}

TEST(CryptoCore, IncrementNonce)
{
    Nonce nonce{};
    increment_nonce(nonce.data());
    EXPECT_EQ(
        nonce, (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}));

    for (int i = 0; i < 0x1F4; ++i) {
        increment_nonce(nonce.data());
    }

    EXPECT_EQ(nonce,
        (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xF5}}));
}

TEST(CryptoCore, IncrementNonceNumber)
{
    Nonce nonce{};

    increment_nonce_number(nonce.data(), 0x1F5);
    EXPECT_EQ(nonce,
        (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xF5}}));

    increment_nonce_number(nonce.data(), 0x1F5);
    EXPECT_EQ(nonce,
        (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xEA}}));

    increment_nonce_number(nonce.data(), 0x12345678);
    EXPECT_EQ(nonce,
        (Nonce{
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x5A, 0x62}}));
}

TEST(CryptoCore, Signatures)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();

    Extended_Public_Key pk;
    Extended_Secret_Key sk;

    EXPECT_TRUE(create_extended_keypair(&pk, &sk, &c_rng));

    std::vector<std::uint8_t> message{0};
    message.clear();

    // Try a few different sizes, including empty 0 length message.
    for (std::uint8_t i = 0; i < 100; ++i) {
        Signature signature;
        EXPECT_TRUE(crypto_signature_create(
            signature.data(), message.data(), message.size(), get_sig_sk(&sk)));
        EXPECT_TRUE(crypto_signature_verify(
            signature.data(), message.data(), message.size(), get_sig_pk(&pk)));

        message.push_back(random_u08(&c_rng));
    }
}

TEST(CryptoCore, Hmac)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();

    HmacKey sk;
    new_hmac_key(&c_rng, sk.data());

    std::vector<std::uint8_t> message{0};
    message.clear();

    // Try a few different sizes, including empty 0 length message.
    for (std::uint8_t i = 0; i < 100; ++i) {
        Hmac auth;
        crypto_hmac(auth.data(), sk.data(), message.data(), message.size());
        EXPECT_TRUE(crypto_hmac_verify(auth.data(), sk.data(), message.data(), message.size()));

        message.push_back(random_u08(&c_rng));
    }
}

}  // namespace
