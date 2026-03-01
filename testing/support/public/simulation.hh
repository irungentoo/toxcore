#ifndef C_TOXCORE_TESTING_SUPPORT_SIMULATION_H
#define C_TOXCORE_TESTING_SUPPORT_SIMULATION_H

#include <atomic>
#include <condition_variable>
#include <functional>
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

#include <string>

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/mem.h"
#include "../../../toxcore/rng.h"
#include "../../../toxcore/tox.h"
#include "../../../toxcore/tox_private.h"
#include "../doubles/fake_clock.hh"
#include "../doubles/fake_memory.hh"
#include "../doubles/fake_network_stack.hh"
#include "../doubles/fake_random.hh"
#include "../doubles/network_universe.hh"
#include "environment.hh"

namespace tox::test {

class SimulatedNode;

struct LogMetadata {
    Tox_Log_Level level;
    const char *_Nonnull file;
    uint32_t line;
    const char *_Nonnull func;
    const char *_Nonnull message;
    uint32_t node_id;
};

using LogPredicate = std::function<bool(const LogMetadata &)>;

struct LogFilter {
    LogPredicate pred;

    LogFilter() = default;
    explicit LogFilter(LogPredicate p)
        : pred(std::move(p))
    {
    }

    bool operator()(const LogMetadata &md) const { return !pred || pred(md); }
};

LogFilter operator&&(const LogFilter &lhs, const LogFilter &rhs);
LogFilter operator||(const LogFilter &lhs, const LogFilter &rhs);
LogFilter operator!(const LogFilter &target);

namespace log_filter {
    LogFilter level(Tox_Log_Level min_level);

    struct LevelPlaceholder {
        LogFilter operator>(Tox_Log_Level rhs) const;
        LogFilter operator>=(Tox_Log_Level rhs) const;
        LogFilter operator<(Tox_Log_Level rhs) const;
        LogFilter operator<=(Tox_Log_Level rhs) const;
        LogFilter operator==(Tox_Log_Level rhs) const;
        LogFilter operator!=(Tox_Log_Level rhs) const;
    };

    LevelPlaceholder level();

    LogFilter file(std::string pattern);
    LogFilter func(std::string pattern);
    LogFilter message(std::string pattern);
    LogFilter node(uint32_t id);
}  // namespace log_filter

/**
 * @brief The Simulation World.
 * Holds the Clock and the Universe.
 */
class Simulation {
public:
    static constexpr uint32_t kDefaultTickIntervalMs = 50;

    explicit Simulation(uint64_t seed);
    ~Simulation();

    // Time Control
    void advance_time(uint64_t ms);
    void run_until(std::function<bool()> condition, uint64_t timeout_ms = 5000);

    // Logging
    void set_log_filter(LogFilter filter);
    const LogFilter &log_filter() const { return log_filter_; }

    // Synchronization Barrier
    // These methods coordinate the lock-step execution of multiple Tox runners.

    /**
     * @brief Registers a new runner with the simulation barrier.
     * @return The current generation ID of the simulation.
     */
    uint64_t register_runner();

    /**
     * @brief Unregisters a runner from the simulation barrier.
     *
     * This ensures the simulation does not block waiting for a terminated runner.
     */
    void unregister_runner();

    using TickListenerId = int;

    /**
     * @brief Registers a callback to be invoked when a new simulation tick starts.
     *
     * @param listener The function to call with the new generation ID.
     * @return An ID handle for unregistering the listener.
     */
    TickListenerId register_tick_listener(std::function<void(uint64_t)> listener);

    /**
     * @brief Unregisters a tick listener.
     */
    void unregister_tick_listener(TickListenerId id);

    /**
     * @brief Blocks until the simulation advances to the next tick.
     *
     * Called by runner threads to wait for the global clock to advance.
     *
     * @param last_gen The generation ID of the last processed tick.
     * @param stop_token Atomic flag to signal termination while waiting.
     * @param timeout_ms Maximum time to wait for the tick.
     * @return The new generation ID, or `last_gen` on timeout/stop.
     */
    uint64_t wait_for_tick(
        uint64_t last_gen, const std::atomic<bool> &stop_token, uint64_t timeout_ms = 10);

    /**
     * @brief Signals that a runner has completed its work for the current tick.
     *
     * @param next_delay_ms The requested delay until the next tick (from `tox_iteration_interval`).
     */
    void tick_complete(uint32_t next_delay_ms = kDefaultTickIntervalMs);

    // Global Access
    FakeClock &clock() { return *clock_; }
    const FakeClock &clock() const { return *clock_; }
    NetworkUniverse &net() { return *net_; }
    const NetworkUniverse &net() const { return *net_; }

    uint64_t seed() const { return seed_; }

    // Node Factory
    std::unique_ptr<SimulatedNode> create_node();

private:
    std::unique_ptr<FakeClock> clock_;
    std::unique_ptr<NetworkUniverse> net_;
    LogFilter log_filter_;
    const uint64_t seed_;
    std::atomic<uint32_t> node_count_{0};

    // Barrier State
    std::mutex barrier_mutex_;
    std::condition_variable barrier_cv_;
    uint64_t current_generation_ = 0;
    int registered_runners_ = 0;
    std::atomic<int> active_runners_{0};
    std::atomic<uint32_t> next_step_min_{kDefaultTickIntervalMs};

    struct TickListener {
        TickListenerId id;
        std::function<void(uint64_t)> callback;
    };
    std::vector<TickListener> tick_listeners_;
    TickListenerId next_listener_id_ = 0;
};

/**
 * @brief Represents a single node in the simulation.
 * Implements the Environment interface for dependency injection.
 */
class SimulatedNode : public Environment {
public:
    explicit SimulatedNode(Simulation &sim, uint32_t node_id);
    ~SimulatedNode() override;

    // Environment Interface
    NetworkSystem &network() override;
    ClockSystem &clock() override;
    RandomSystem &random() override;
    MemorySystem &memory() override;

    // Direct Access to Fakes
    FakeNetworkStack &fake_network() { return *network_; }
    FakeRandom &fake_random() { return *random_; }
    FakeMemory &fake_memory() { return *memory_; }

    // Tox Creation Helper
    // Returns a configured Tox instance bound to this node's environment.
    // The user owns the Tox instance.
    struct ToxDeleter {
        void operator()(Tox *_Nonnull t) const { tox_kill(t); }
    };
    using ToxPtr = std::unique_ptr<Tox, ToxDeleter>;

    ToxPtr create_tox(const Tox_Options *_Nullable options = nullptr);

    Simulation &simulation() { return sim_; }

    // For fuzzing compatibility (exposes first bound UDP socket as "endpoint")
    FakeUdpSocket *_Nullable get_primary_socket();

private:
    Simulation &sim_;
    std::unique_ptr<FakeNetworkStack> network_;
    std::unique_ptr<FakeRandom> random_;
    std::unique_ptr<FakeMemory> memory_;

    // C-compatible views (must stay valid for the lifetime of Tox)
public:
    struct Network c_network;
    struct Random c_random;
    struct Memory c_memory;
    struct IP ip;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_SIMULATION_H
