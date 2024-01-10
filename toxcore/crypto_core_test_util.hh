#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_TEST_UTIL_H

#include <algorithm>
#include <array>
#include <iosfwd>
#include <random>

#include "crypto_core.h"
#include "test_util.hh"

struct Random_Class {
    static Random_Funcs const vtable;
    Random const self;

    operator Random const *() const { return &self; }

    Random_Class(Random_Class const &) = default;
    Random_Class()
        : self{&vtable, this}
    {
    }

    virtual ~Random_Class();
    virtual crypto_random_bytes_cb random_bytes = 0;
    virtual crypto_random_uniform_cb random_uniform = 0;
};

/**
 * A very simple, fast, and deterministic PRNG just for testing.
 *
 * We generally don't want to use system_random(), since it's a
 * cryptographically secure PRNG and we don't need that in unit tests.
 */
class Test_Random : public Random_Class {
    std::minstd_rand lcg;

    void random_bytes(void *obj, uint8_t *bytes, size_t length) override;
    uint32_t random_uniform(void *obj, uint32_t upper_bound) override;
};

struct PublicKey : private std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> {
    using Base = std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE>;

    using Base::begin;
    using Base::data;
    using Base::end;
    using Base::size;
    using Base::operator[];

    PublicKey() = default;
    explicit PublicKey(uint8_t const (&arr)[CRYPTO_PUBLIC_KEY_SIZE])
        : PublicKey(to_array(arr))
    {
    }
    explicit PublicKey(std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> const &arr)
    {
        std::copy(arr.begin(), arr.end(), begin());
    }

    PublicKey(std::initializer_list<uint8_t> const &arr)
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

PublicKey random_pk(const Random *rng);

#endif  // C_TOXCORE_TOXCORE_CRYPTO_CORE_TEST_UTIL_H
