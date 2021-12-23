#include "friend_connection.h"

#include <gtest/gtest.h>

namespace {

// TODO(Jfreegman) make this useful or remove it after NGC is merged
TEST(friend_connection, NullTest) {
  (void)friend_conn_get_onion_friendnum;
  (void)friend_conn_get_dht_ip_port;
}

}  // namespace
