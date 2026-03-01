#include "../public/simulated_environment.hh"

#include <iostream>

namespace tox::test {

SimulatedEnvironment::SimulatedEnvironment(uint64_t seed)
    : sim_(std::make_unique<Simulation>(seed))
    , global_random_(std::make_unique<FakeRandom>(seed))
    , global_memory_(std::make_unique<FakeMemory>())
{
}

SimulatedEnvironment::~SimulatedEnvironment() = default;

NetworkSystem &SimulatedEnvironment::network()
{
    // Return a dummy stack for interface compliance; real networking is per-node.
    static FakeNetworkStack *dummy = nullptr;
    if (!dummy) {
        IP dummy_ip;
        ip_init(&dummy_ip, false);
        dummy = new FakeNetworkStack(sim_->net(), dummy_ip);
    }
    return *dummy;
}

ClockSystem &SimulatedEnvironment::clock() { return sim_->clock(); }
RandomSystem &SimulatedEnvironment::random() { return *global_random_; }
MemorySystem &SimulatedEnvironment::memory() { return *global_memory_; }

FakeClock &SimulatedEnvironment::fake_clock() { return sim_->clock(); }
FakeRandom &SimulatedEnvironment::fake_random() { return *global_random_; }
FakeMemory &SimulatedEnvironment::fake_memory() { return *global_memory_; }

std::unique_ptr<ScopedToxSystem> SimulatedEnvironment::create_node(uint16_t port)
{
    auto scoped = std::make_unique<ScopedToxSystem>();
    scoped->node = sim_->create_node();

    // Bind port
    if (port != 0) {
        Socket s = scoped->node->fake_network().socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        IP_Port addr;
        ip_init(&addr.ip, false);
        addr.ip.ip.v4.uint32 = 0;
        addr.port = net_htons(port);
        scoped->node->fake_network().bind(s, &addr);
    }

    // Get Primary Endpoint for Fuzzer
    scoped->endpoint = scoped->node->get_primary_socket();

    // Use global Random and Memory for legacy compatibility.
    scoped->c_random = global_random_->c_random();
    scoped->c_memory = global_memory_->c_memory();

    // Use Node's Network
    scoped->c_network = scoped->node->c_network;

    // Setup System
    scoped->system.mem = &scoped->c_memory;
    scoped->system.ns = &scoped->c_network;
    scoped->system.rng = &scoped->c_random;

    scoped->system.mono_time_user_data = &sim_->clock();
    scoped->system.mono_time_callback = [](void *_Nullable user_data) -> uint64_t {
        return static_cast<FakeClock *>(user_data)->current_time_ms();
    };

    return scoped;
}

void SimulatedEnvironment::advance_time(uint64_t ms) { sim_->advance_time(ms); }

}  // namespace tox::test
