#include "crypto_core.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

#include "crypto_core_test_util.hh"
#include "util.h"

namespace {

using HmacKey = std::array<uint8_t, CRYPTO_HMAC_KEY_SIZE>;
using Hmac = std::array<uint8_t, CRYPTO_HMAC_SIZE>;
using SecretKey = std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE>;
using Signature = std::array<uint8_t, CRYPTO_SIGNATURE_SIZE>;
using Nonce = std::array<uint8_t, CRYPTO_NONCE_SIZE>;

TEST(CryptoCore, EncryptLargeData)
{
    Test_Random rng;

    Nonce nonce{};
    PublicKey pk;
    SecretKey sk;
    crypto_new_keypair(rng, pk.data(), sk.data());

    // 100 MiB of data (all zeroes, doesn't matter what's inside).
    std::vector<uint8_t> plain(100 * 1024 * 1024);
    std::vector<uint8_t> encrypted(plain.size() + CRYPTO_MAC_SIZE);

    encrypt_data(pk.data(), sk.data(), nonce.data(), plain.data(), plain.size(), encrypted.data());
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
    Test_Random rng;

    Extended_Public_Key pk;
    Extended_Secret_Key sk;

    EXPECT_TRUE(create_extended_keypair(&pk, &sk, rng));

    std::vector<uint8_t> message{0};
    message.clear();

    // Try a few different sizes, including empty 0 length message.
    for (uint8_t i = 0; i < 100; ++i) {
        Signature signature;
        EXPECT_TRUE(crypto_signature_create(
            signature.data(), message.data(), message.size(), get_sig_sk(&sk)));
        EXPECT_TRUE(crypto_signature_verify(
            signature.data(), message.data(), message.size(), get_sig_pk(&pk)));

        message.push_back(random_u08(rng));
    }
}

TEST(CryptoCore, Hmac)
{
    Test_Random rng;

    HmacKey sk;
    new_hmac_key(rng, sk.data());

    std::vector<uint8_t> message{0};
    message.clear();

    // Try a few different sizes, including empty 0 length message.
    for (uint8_t i = 0; i < 100; ++i) {
        Hmac auth;
        crypto_hmac(auth.data(), sk.data(), message.data(), message.size());
        EXPECT_TRUE(crypto_hmac_verify(auth.data(), sk.data(), message.data(), message.size()));

        message.push_back(random_u08(rng));
    }
}

}  // namespace
