#pragma once

#include <stdbool.h>
#include <stdint.h>

// Settings for the test runner.
struct settings {
    // Print the msgpack object on test failure.
    bool debug;
    // Write test sample files into test-inputs/. These files, one per test
    // method, are used to seed the fuzzer.
    bool collect_samples;
};

// Main loop communicating via read/write file descriptors. The two fds can be
// the same in case of a network socket.
int communicate(struct settings cfg, int read_fd, int write_fd);

// Open a TCP socket on the given port and start communicate().
uint32_t network_main(struct settings cfg, uint16_t port, unsigned int timeout);
