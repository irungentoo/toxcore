#ifndef C_TOXCORE_TESTING_SUPPORT_PUBLIC_FUZZ_HELPERS_H
#define C_TOXCORE_TESTING_SUPPORT_PUBLIC_FUZZ_HELPERS_H

#include "../doubles/fake_memory.hh"
#include "../doubles/fake_random.hh"
#include "../doubles/fake_sockets.hh"
#include "fuzz_data.hh"

namespace tox::test {

// Configures the socket to pull packets from the Fuzz_Data stream
// mimicking the legacy Fuzz_System behavior (2-byte length prefix).
void configure_fuzz_packet_source(FakeUdpSocket &socket, Fuzz_Data &input);

// Configures memory allocator to consume failure decisions from Fuzz_Data.
void configure_fuzz_memory_source(FakeMemory &memory, Fuzz_Data &input);

// Configures random generator to consume bytes from Fuzz_Data.
void configure_fuzz_random_source(FakeRandom &random, Fuzz_Data &input);

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_PUBLIC_FUZZ_HELPERS_H
