#ifndef C_TOXCORE_TESTING_SUPPORT_SIMULATED_ENVIRONMENT_H
#define C_TOXCORE_TESTING_SUPPORT_SIMULATED_ENVIRONMENT_H

#include <memory>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/mem.h"
#include "../../../toxcore/rng.h"
#include "../../../toxcore/tox_private.h"
#include "../doubles/fake_clock.hh"
#include "../doubles/fake_memory.hh"
#include "../doubles/fake_random.hh"
#include "environment.hh"
#include "simulation.hh"

namespace tox::test {

struct ScopedToxSystem {
    // The underlying node in the simulation
    std::unique_ptr<SimulatedNode> node;

    // Direct access to primary socket (for fuzzer injection)
    FakeUdpSocket *_Nullable endpoint;

    // C structs
    struct Network c_network;
    struct Random c_random;
    struct Memory c_memory;

    // The main struct passed to tox_new
    Tox_System system;
};

class SimulatedEnvironment : public Environment {
public:
    explicit SimulatedEnvironment(uint64_t seed);
    ~SimulatedEnvironment() override;

    NetworkSystem &network() override;
    ClockSystem &clock() override;
    RandomSystem &random() override;
    MemorySystem &memory() override;

    FakeClock &fake_clock();
    FakeRandom &fake_random();
    FakeMemory &fake_memory();

    Simulation &simulation() { return *sim_; }

    /**
     * @brief Creates a new virtual node in the simulation bound to the specified port.
     */
    std::unique_ptr<ScopedToxSystem> create_node(uint16_t port);

    void advance_time(uint64_t ms);

private:
    std::unique_ptr<Simulation> sim_;

    // Global instances for Environment interface compliance.
    std::unique_ptr<FakeRandom> global_random_;
    std::unique_ptr<FakeMemory> global_memory_;

    // For network(), we can't return a per-node stack.
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_SIMULATED_ENVIRONMENT_H
