/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */
#ifndef C_TOXCORE_TESTING_SUPPORT_MPSC_QUEUE_H
#define C_TOXCORE_TESTING_SUPPORT_MPSC_QUEUE_H

#include <condition_variable>
#include <deque>
#include <mutex>

namespace tox::test {

/**
 * @brief Multiple Producer, Single Consumer Queue.
 *
 * This queue implementation provides thread-safe access for multiple producers
 * pushing items and a single consumer popping items. It uses a `std::mutex`
 * and `std::condition_variable` for synchronization.
 *
 * @tparam T The type of elements stored in the queue.
 */
template <typename T>
class MpscQueue {
public:
    MpscQueue() = default;
    ~MpscQueue() = default;

    // Disable copy/move to prevent accidental sharing/slicing issues
    MpscQueue(const MpscQueue &) = delete;
    MpscQueue &operator=(const MpscQueue &) = delete;

    /**
     * @brief Pushes a value onto the queue.
     * Thread-safe (Multiple Producers).
     */
    void push(T value)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(std::move(value));
        }
        cv_.notify_one();
    }

    /**
     * @brief Pops a value from the queue, blocking if empty.
     * Thread-safe (Single Consumer).
     */
    T pop()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty(); });
        T value = std::move(queue_.front());
        queue_.pop_front();
        return value;
    }

    /**
     * @brief Tries to pop a value from the queue without blocking.
     * Thread-safe (Single Consumer).
     *
     * @param out Reference to store the popped value.
     * @return true if a value was popped, false if the queue was empty.
     */
    bool try_pop(T &out)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty())
            return false;
        out = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }

private:
    std::deque<T> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_MPSC_QUEUE_H
