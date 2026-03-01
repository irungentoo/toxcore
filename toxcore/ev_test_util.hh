/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_EV_TEST_UTIL_HH
#define C_TOXCORE_TOXCORE_EV_TEST_UTIL_HH

#include <cstddef>

#include "net.h"

/**
 * @brief Creates a connected pair of sockets (like socketpair or a TCP loopback connection).
 * @param rs [out] The read-side socket.
 * @param ws [out] The write-side socket.
 * @return 0 on success, -1 on failure.
 */
int create_pair(Socket *rs, Socket *ws);

/**
 * @brief Closes the socket pair.
 */
void close_pair(Socket s1, Socket s2);

/**
 * @brief Closes a single socket.
 */
void close_socket(Socket s);

/**
 * @brief Writes data to a socket.
 */
int write_socket(Socket s, const void *buf, std::size_t count);

#endif /* C_TOXCORE_TOXCORE_EV_TEST_UTIL_HH */
