#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace devdisc {

/// Fixed-size thread pool with a thread-safe task queue.
///
/// Tasks are submitted with submit() which returns a std::future. Exceptions
/// thrown by a task are captured in the associated future, so they never escape
/// a worker thread and never terminate the process.
class ThreadPool {
public:
    explicit ThreadPool(std::size_t worker_count);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    /// Submit a task. Throws std::runtime_error once the pool is shut down.
    template <typename F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>> {
        using Result = std::invoke_result_t<F, Args...>;

        auto task = std::make_shared<std::packaged_task<Result()>>(
            [fn = std::forward<F>(f),
             tup = std::make_tuple(std::forward<Args>(args)...)]() mutable -> Result {
                return std::apply(std::move(fn), std::move(tup));
            });

        std::future<Result> future = task->get_future();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                throw std::runtime_error("ThreadPool: submit() after shutdown");
            }
            tasks_.emplace([task]() { (*task)(); });
        }
        cv_.notify_one();
        return future;
    }

    /// Stop accepting work, drain the queue and join all workers. Idempotent.
    void shutdown();

    std::size_t worker_count() const { return workers_.size(); }
    std::size_t pending_tasks() const;

private:
    void worker_loop();

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<std::function<void()>> tasks_;
    std::vector<std::thread> workers_;
    bool stopping_ = false;
};

}  // namespace devdisc
