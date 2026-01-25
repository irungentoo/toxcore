/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "../public/tox_runner.hh"

namespace tox::test {

ToxRunner::ToxRunner(SimulatedNode &node, const Tox_Options *_Nullable options)
    : tox_(node.create_tox(options))
    , node_(node)
{
    node_.simulation().register_runner();

    tick_listener_id_ = node_.simulation().register_tick_listener([this](uint64_t gen) {
        Message msg;
        msg.type = Message::Tick;
        msg.generation = gen;
        queue_.push(std::move(msg));
    });

    thread_ = std::thread([this] { loop(); });
}

ToxRunner::~ToxRunner()
{
    // Unregister first to prevent new ticks and update simulation counters
    node_.simulation().unregister_tick_listener(tick_listener_id_);
    node_.simulation().unregister_runner();

    Message msg;
    msg.type = Message::Stop;
    queue_.push(std::move(msg));

    if (thread_.joinable()) {
        thread_.join();
    }
}

void ToxRunner::execute(std::function<void(Tox *_Nonnull)> task)
{
    Message msg;
    msg.type = Message::Task;
    msg.task = std::move(task);
    queue_.push(std::move(msg));
}

std::vector<ToxRunner::ToxEventsPtr> ToxRunner::poll_events()
{
    std::vector<ToxEventsPtr> ret;
    ToxEventsPtr ptr;
    while (events_queue_.try_pop(ptr)) {
        ret.push_back(std::move(ptr));
        ptr = nullptr;  // Reset ptr to avoid use-after-move warning, although try_pop overwrites
                        // it.
    }
    return ret;
}

void ToxRunner::pause()
{
    if (!active_.exchange(false)) {
        return;
    }

    node_.simulation().unregister_tick_listener(tick_listener_id_);
    node_.simulation().unregister_runner();
    tick_listener_id_ = -1;
}

void ToxRunner::resume()
{
    if (active_.exchange(true)) {
        return;
    }

    node_.simulation().register_runner();
    tick_listener_id_ = node_.simulation().register_tick_listener([this](uint64_t gen) {
        Message msg;
        msg.type = Message::Tick;
        msg.generation = gen;
        queue_.push(std::move(msg));
    });
}

void ToxRunner::loop()
{
    while (true) {
        Message msg = queue_.pop();  // Blocking wait

        switch (msg.type) {
        case Message::Stop:
            return;

        case Message::Task:
            if (msg.task && tox_) {
                msg.task(tox_.get());
            }
            break;

        case Message::Tick: {
            if (!tox_) {
                node_.simulation().tick_complete();
                break;
            }

            // Run Tox Events
            Tox_Err_Events_Iterate err;
            Tox_Events *events = tox_events_iterate(tox_.get(), nullptr, &err);
            if (events) {
                events_queue_.push(ToxEventsPtr(events));
            }

            uint32_t interval = tox_iteration_interval(tox_.get());
            node_.simulation().tick_complete(interval);
            break;
        }
        }
    }
}

}  // namespace tox::test
