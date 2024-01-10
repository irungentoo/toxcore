#ifndef C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H

#include <iosfwd>

#include "crypto_core.h"
#include "network.h"
#include "test_util.hh"

template <>
struct Deleter<Networking_Core> : Function_Deleter<Networking_Core, kill_networking> { };

IP_Port random_ip_port(const Random *rng);

class increasing_ip_port {
    uint8_t start_;
    const Random *rng_;

public:
    explicit increasing_ip_port(uint8_t start, const Random *rng)
        : start_(start)
        , rng_(rng)
    {
    }

    IP_Port operator()();
};

std::ostream &operator<<(std::ostream &out, IP const &v);
std::ostream &operator<<(std::ostream &out, IP_Port const &v);

#endif  // C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
