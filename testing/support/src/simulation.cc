#include "../public/simulation.hh"

#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

namespace tox::test {

// --- LogFilter ---

LogFilter operator&&(const LogFilter &lhs, const LogFilter &rhs)
{
    return LogFilter([=](const LogMetadata &md) { return lhs(md) && rhs(md); });
}

LogFilter operator||(const LogFilter &lhs, const LogFilter &rhs)
{
    return LogFilter([=](const LogMetadata &md) { return lhs(md) || rhs(md); });
}

LogFilter operator!(const LogFilter &target)
{
    return LogFilter([=](const LogMetadata &md) { return !target(md); });
}

namespace log_filter {

    LogFilter level(Tox_Log_Level min_level)
    {
        return LogFilter([=](const LogMetadata &md) { return md.level >= min_level; });
    }

    LevelPlaceholder level() { return {}; }

    LogFilter LevelPlaceholder::operator>(Tox_Log_Level rhs) const
    {
        return LogFilter([=](const LogMetadata &md) { return md.level > rhs; });
    }

    LogFilter LevelPlaceholder::operator>=(Tox_Log_Level rhs) const
    {
        return LogFilter([=](const LogMetadata &md) { return md.level >= rhs; });
    }

    LogFilter LevelPlaceholder::operator<(Tox_Log_Level rhs) const
    {
        return LogFilter([=](const LogMetadata &md) { return md.level < rhs; });
    }

    LogFilter LevelPlaceholder::operator<=(Tox_Log_Level rhs) const
    {
        return LogFilter([=](const LogMetadata &md) { return md.level <= rhs; });
    }

    LogFilter LevelPlaceholder::operator==(Tox_Log_Level rhs) const
    {
        return LogFilter([=](const LogMetadata &md) { return md.level == rhs; });
    }

    LogFilter LevelPlaceholder::operator!=(Tox_Log_Level rhs) const
    {
        return LogFilter([=](const LogMetadata &md) { return md.level != rhs; });
    }

    LogFilter file(std::string pattern)
    {
        return LogFilter([p = std::move(pattern)](const LogMetadata &md) {
            return std::string(md.file).find(p) != std::string::npos;
        });
    }

    LogFilter func(std::string pattern)
    {
        return LogFilter([p = std::move(pattern)](const LogMetadata &md) {
            return std::string(md.func).find(p) != std::string::npos;
        });
    }

    LogFilter message(std::string pattern)
    {
        return LogFilter([p = std::move(pattern)](const LogMetadata &md) {
            return std::string(md.message).find(p) != std::string::npos;
        });
    }

    LogFilter node(uint32_t id)
    {
        return LogFilter([=](const LogMetadata &md) { return md.node_id == id; });
    }

}  // namespace log_filter

// --- Simulation ---

Simulation::Simulation(uint64_t seed)
    : clock_(std::make_unique<FakeClock>())
    , net_(std::make_unique<NetworkUniverse>())
    , seed_(seed)
{
}

Simulation::~Simulation() = default;

void Simulation::advance_time(uint64_t ms)
{
    clock_->advance(ms);
    net_->process_events(clock_->current_time_ms());
}

void Simulation::run_until(std::function<bool()> condition, uint64_t timeout_ms)
{
    uint64_t start_time = clock_->current_time_ms();

    // Initial check
    if (condition())
        return;

    while (true) {
        if (clock_->current_time_ms() - start_time >= timeout_ms) {
            break;
        }

        // 1. Advance Global Time
        // Determine the time step based on the minimum requested delay from all runners
        // during the previous tick. We default to kDefaultTickIntervalMs if no specific request was
        // made. The `exchange` operation resets the minimum accumulator for the current tick.
        uint32_t step = next_step_min_.exchange(kDefaultTickIntervalMs);
        advance_time(step);

        // 2. Start Barrier (Signal Runners)
        // Notify all registered runners that time has advanced and they should proceed
        // with their next iteration.
        {
            std::lock_guard<std::mutex> lock(barrier_mutex_);
            current_generation_++;
            // Initialize the countdown of active runners for this tick.
            active_runners_.store(registered_runners_);

            for (const auto &l : tick_listeners_) {
                l.callback(current_generation_);
            }
        }
        barrier_cv_.notify_all();

        // 3. End Barrier (Wait for Completion)
        // Block until all active runners have reported completion via `tick_complete()`.
        {
            std::unique_lock<std::mutex> lock(barrier_mutex_);
            // We use a lambda predicate to handle spurious wakeups.
            // The wait finishes when `active_runners_` reaches zero.
            // We use a small timeout to avoid permanent hangs if a runner is unregistered mid-tick.
            barrier_cv_.wait_for(lock, std::chrono::milliseconds(100),
                [this] { return active_runners_.load() == 0; });
        }

        // 4. Check condition
        if (condition())
            return;
    }
}

void Simulation::set_log_filter(LogFilter filter) { log_filter_ = std::move(filter); }

Simulation::TickListenerId Simulation::register_tick_listener(
    std::function<void(uint64_t)> listener)
{
    std::lock_guard<std::mutex> lock(barrier_mutex_);
    TickListenerId id = next_listener_id_++;
    tick_listeners_.push_back({id, std::move(listener)});
    return id;
}

void Simulation::unregister_tick_listener(TickListenerId id)
{
    std::lock_guard<std::mutex> lock(barrier_mutex_);
    for (auto it = tick_listeners_.begin(); it != tick_listeners_.end(); ++it) {
        if (it->id == id) {
            tick_listeners_.erase(it);
            break;
        }
    }
}

uint64_t Simulation::register_runner()
{
    std::lock_guard<std::mutex> lock(barrier_mutex_);
    registered_runners_++;
    return current_generation_;
}

void Simulation::unregister_runner()
{
    std::lock_guard<std::mutex> lock(barrier_mutex_);
    assert(registered_runners_ > 0);
    registered_runners_--;

    // If a tick is currently in progress, we need to account for this runner
    // leaving. Otherwise, the barrier will wait for a runner that is no longer
    // active.
    if (active_runners_.load() > 0) {
        if (active_runners_.fetch_sub(1) == 1) {
            barrier_cv_.notify_all();
        }
    }
}

uint64_t Simulation::wait_for_tick(
    uint64_t last_gen, const std::atomic<bool> &stop_token, uint64_t timeout_ms)
{
    std::unique_lock<std::mutex> lock(barrier_mutex_);
    // Wait until generation increases (new tick started) OR we are stopped OR timeout
    bool result = barrier_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
        [&] { return current_generation_ > last_gen || stop_token; });

    if (stop_token)
        return last_gen;
    if (!result)
        return last_gen;  // Timeout
    return current_generation_;
}

void Simulation::tick_complete(uint32_t next_delay_ms)
{
    // Atomic min reduction
    uint32_t current = next_step_min_.load(std::memory_order_relaxed);
    while (
        next_delay_ms < current && !next_step_min_.compare_exchange_weak(current, next_delay_ms)) {
        // If exchange failed, current was updated to actual value, so loop checks again
    }

    // We don't need the mutex to decrement the atomic
    if (active_runners_.fetch_sub(1) == 1) {
        // Last runner to finish: notify main thread
        std::lock_guard<std::mutex> lock(barrier_mutex_);
        barrier_cv_.notify_all();
    }
}

std::unique_ptr<SimulatedNode> Simulation::create_node()
{
    auto node = std::make_unique<SimulatedNode>(*this, ++node_count_);
    if (net_->is_verbose()) {
        uint32_t ip4 = net_ntohl(node->ip.ip.v4.uint32);
        std::cerr << "[Simulation] Created node " << node_count_ << " with IP "
                  << ((ip4 >> 24) & 0xFF) << "." << ((ip4 >> 16) & 0xFF) << "."
                  << ((ip4 >> 8) & 0xFF) << "." << (ip4 & 0xFF) << std::endl;
    }
    return node;
}

// --- SimulatedNode ---

SimulatedNode::SimulatedNode(Simulation &sim, uint32_t node_id)
    : sim_(sim)
    , network_(std::make_unique<FakeNetworkStack>(sim.net(), make_node_ip(node_id)))
    , random_(std::make_unique<FakeRandom>(sim.seed() + node_id))
    , memory_(std::make_unique<FakeMemory>())
    , c_network(network_->c_network())
    , c_random(random_->c_random())
    , c_memory(memory_->c_memory())
    , ip(make_node_ip(node_id))
{
}

SimulatedNode::~SimulatedNode() = default;

NetworkSystem &SimulatedNode::network() { return *network_; }
ClockSystem &SimulatedNode::clock() { return sim_.clock(); }
RandomSystem &SimulatedNode::random() { return *random_; }
MemorySystem &SimulatedNode::memory() { return *memory_; }

SimulatedNode::ToxPtr SimulatedNode::create_tox(const Tox_Options *_Nullable options)
{
    std::unique_ptr<Tox_Options, decltype(&tox_options_free)> local_opts(
        tox_options_new(nullptr), tox_options_free);
    assert(local_opts != nullptr);

    if (options != nullptr) {
        tox_options_copy(local_opts.get(), options);
    } else {
        tox_options_set_ipv6_enabled(local_opts.get(), false);
        tox_options_set_start_port(local_opts.get(), 33445);
        tox_options_set_end_port(local_opts.get(), 55555);
    }

    tox_options_set_log_callback(local_opts.get(),
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            SimulatedNode *node = static_cast<SimulatedNode *>(user_data);
            uint32_t ip4 = net_ntohl(node->ip.ip.v4.uint32);

            LogMetadata md{level, file, line, func, message, ip4 & 0xFF};
            const auto &filter = node->simulation().log_filter();

            bool allow = false;
            if (filter.pred) {
                allow = filter(md);
            } else {
                allow = node->simulation().net().is_verbose() && level >= TOX_LOG_LEVEL_TRACE;
            }

            if (allow) {
                std::cerr << "[Tox Log] [Node " << (ip4 & 0xFF) << "] " << file << ":" << line
                          << " (" << func << "): " << message << std::endl;
            }
        });
    tox_options_set_log_user_data(local_opts.get(), this);

    Tox_Options_Testing opts_testing;
    Tox_System system;
    system.ns = &c_network;
    system.rng = &c_random;
    system.mem = &c_memory;
    system.mono_time_callback = [](void *_Nullable user_data) -> uint64_t {
        return static_cast<FakeClock *>(user_data)->current_time_ms();
    };
    system.mono_time_user_data = &sim_.clock();

    opts_testing.operating_system = &system;

    Tox_Err_New err;
    Tox_Err_New_Testing err_testing;

    Tox *t = tox_new_testing(local_opts.get(), &err, &opts_testing, &err_testing);

    if (!t) {
        std::cerr << "tox_new_testing failed: " << err << " (testing err: " << err_testing << ")"
                  << std::endl;
        return nullptr;
    }
    return ToxPtr(t);
}

FakeUdpSocket *_Nullable SimulatedNode::get_primary_socket()
{
    auto sockets = network_->get_bound_udp_sockets();
    if (sockets.empty())
        return nullptr;
    return sockets.front();  // Return the first one bound
}

}  // namespace tox::test
