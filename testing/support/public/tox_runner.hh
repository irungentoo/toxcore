/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_SUPPORT_TOX_RUNNER_H
#define C_TOXCORE_TESTING_SUPPORT_TOX_RUNNER_H

#include <atomic>
#include <functional>
#include <future>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/tox_events.h"
#include "mpsc_queue.hh"
#include "simulation.hh"

namespace tox::test {

class ToxRunner {
public:
    explicit ToxRunner(SimulatedNode &node, const Tox_Options *_Nullable options = nullptr);
    ~ToxRunner();

    ToxRunner(const ToxRunner &) = delete;
    ToxRunner &operator=(const ToxRunner &) = delete;

    struct ToxEventsDeleter {
        void operator()(Tox_Events *_Nonnull e) const { tox_events_free(e); }
    };
    using ToxEventsPtr = std::unique_ptr<Tox_Events, ToxEventsDeleter>;

    /**
     * @brief Schedules a task for execution on the runner's thread.
     *
     * This method is thread-safe and non-blocking. The task is queued and will
     * be executed during the runner's event loop cycle.
     *
     * @param task The function to execute, taking a raw Tox pointer.
     */
    void execute(std::function<void(Tox *_Nonnull)> task);

    /**
     * @brief Executes a task on the runner's thread and waits for the result.
     *
     * This method blocks the calling thread until the task has been executed
     * by the runner. It automatically handles return value propagation and
     * exception safety (though exceptions are not currently propagated).
     *
     * @tparam Func The type of the callable object.
     * @param func The callable to execute, taking a raw Tox pointer.
     * @return The result of the callable execution.
     */
    template <typename Func>
    auto invoke(Func &&func) -> std::invoke_result_t<Func, Tox *_Nonnull>
    {
        using R = std::invoke_result_t<Func, Tox *_Nonnull>;
        auto promise = std::make_shared<std::promise<R>>();
        auto future = promise->get_future();

        execute([p = promise, f = std::forward<Func>(func)](Tox *_Nonnull tox) {
            if constexpr (std::is_void_v<R>) {
                f(tox);
                p->set_value();
            } else {
                p->set_value(f(tox));
            }
        });

        return future.get();
    }

    /**
     * @brief Retrieves all accumulated Tox event batches.
     *
     * Returns a vector of unique pointers to Tox_Events structures that have
     * been collected by the runner since the last call. Ownership is transferred
     * to the caller. This method is thread-safe.
     *
     * @return A vector of Tox_Events pointers.
     */
    std::vector<ToxEventsPtr> poll_events();

    /**
     * @brief Accesses the underlying Tox instance directly.
     *
     * @warning Thread-Safety Violation: This method provides unsafe access to the
     * Tox instance. It should ONLY be used when the runner thread is known to be
     * idle (e.g., before the loop starts) or for accessing constant/read-only properties.
     * For all other operations, use `execute` or `invoke`.
     */
    Tox *_Nullable unsafe_tox() { return tox_.get(); }

    /**
     * @brief Temporarily stops the runner from participating in the simulation.
     *
     * Unregisters the runner and its tick listener from the simulation.
     * While paused, the runner will not call tox_iterate.
     */
    void pause();

    /**
     * @brief Resumes the runner's participation in the simulation.
     */
    void resume();

    /**
     * @brief Returns true if the runner is currently active.
     */
    bool is_active() const { return active_; }

private:
    void loop();

    SimulatedNode::ToxPtr tox_;
    std::thread thread_;
    std::atomic<bool> active_{true};

    struct Message {
        enum Type { Task, Tick, Stop } type;
        std::function<void(Tox *_Nonnull)> task;
        uint64_t generation = 0;
    };

    MpscQueue<Message> queue_;
    MpscQueue<ToxEventsPtr> events_queue_;

    Simulation::TickListenerId tick_listener_id_ = -1;
    SimulatedNode &node_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_TOX_RUNNER_H
