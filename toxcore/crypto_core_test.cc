#include "crypto_core.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

namespace {

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
