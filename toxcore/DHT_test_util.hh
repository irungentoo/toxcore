#ifndef C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H

#include <iosfwd>

#include "DHT.h"
#include "crypto_core.h"
#include "test_util.hh"

template <>
struct Deleter<DHT> : Function_Deleter<DHT, kill_dht> { };

bool operator==(Node_format const &a, Node_format const &b);

std::ostream &operator<<(std::ostream &out, Node_format const &v);

Node_format random_node_format(const Random *rng);

#endif  // C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H
