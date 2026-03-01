#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_TEST_UTIL_H

#include <algorithm>
#include <array>
#include <cstdint>
#include <iosfwd>

#include "attributes.h"
#include "crypto_core.h"
#include "test_util.hh"

struct PublicKey : private std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE> {
    using Base = std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE>;

    using Base::begin;
    using Base::data;
    using Base::end;
    using Base::size;
    using Base::operator[];

    PublicKey() = default;
    explicit PublicKey(std::uint8_t const (&arr)[CRYPTO_PUBLIC_KEY_SIZE])
        : PublicKey(to_array(arr))
    {
    }
    explicit PublicKey(std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE> const &arr)
    {
        std::copy(arr.begin(), arr.end(), begin());
    }

    PublicKey(std::initializer_list<std::uint8_t> const &arr)
    {
        std::copy(arr.begin(), arr.end(), begin());
    }

    Base const &base() const { return *this; }
};

inline bool operator!=(PublicKey const &pk1, PublicKey const &pk2)
{
    return pk1.base() != pk2.base();
}

inline bool operator==(PublicKey const &pk1, PublicKey const &pk2)
{
    return pk1.base() == pk2.base();
}

inline bool operator==(PublicKey::Base const &pk1, PublicKey const &pk2)
{
    return pk1 == pk2.base();
}

std::ostream &operator<<(std::ostream &out, PublicKey const &pk);

PublicKey random_pk(const Random *_Nonnull rng);

std::array<std::uint8_t, CRYPTO_SECRET_KEY_SIZE> random_sk(const Random *_Nonnull rng);

#endif  // C_TOXCORE_TOXCORE_CRYPTO_CORE_TEST_UTIL_H
