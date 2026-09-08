#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#include "test_support.hpp"
#include "threading/thread_pool.hpp"

using devdisc::ThreadPool;

namespace {

void test_multiple_tasks() {
    ThreadPool pool(4);
    std::vector<std::future<int>> futures;
    for (int i = 0; i < 100; ++i) {
        futures.push_back(pool.submit([i]() { return i * 2; }));
    }
    int sum = 0;
    for (auto& future : futures) {
        sum += future.get();
    }
    CHECK_EQ(sum, 9900);
}

void test_empty_queue_shutdown() {
    ThreadPool pool(8);
    CHECK_EQ(pool.worker_count(), std::size_t{8});
    CHECK_EQ(pool.pending_tasks(), std::size_t{0});
    pool.shutdown();
    pool.shutdown();  // Idempotent.
    bool threw = false;
    try {
        pool.submit([]() { return 1; });
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

void test_task_exception_is_propagated() {
    ThreadPool pool(2);
    auto future = pool.submit([]() -> int { throw std::runtime_error("boom"); });
    bool caught = false;
    try {
        (void)future.get();
    } catch (const std::runtime_error& error) {
        caught = std::string(error.what()) == "boom";
    }
    CHECK(caught);

    // The pool must still be usable after a failing task.
    CHECK_EQ(pool.submit([]() { return 7; }).get(), 7);
}

void test_concurrent_execution() {
    constexpr int kWorkers = 4;
    ThreadPool pool(kWorkers);
    std::atomic<int> concurrent{0};
    std::atomic<int> peak{0};
    std::vector<std::future<void>> futures;
    for (int i = 0; i < kWorkers * 4; ++i) {
        futures.push_back(pool.submit([&]() {
            const int now = ++concurrent;
            int previous = peak.load();
            while (now > previous && !peak.compare_exchange_weak(previous, now)) {
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            --concurrent;
        }));
    }
    for (auto& future : futures) {
        future.get();
    }
    CHECK(peak.load() > 1);
    CHECK(peak.load() <= kWorkers);
}

void test_all_tasks_run_before_shutdown_completes() {
    std::atomic<int> executed{0};
    {
        ThreadPool pool(2);
        for (int i = 0; i < 50; ++i) {
            pool.submit([&executed]() { ++executed; });
        }
    }  // Destructor drains the queue and joins.
    CHECK_EQ(executed.load(), 50);
}

}  // namespace

int main() {
    test_multiple_tasks();
    test_empty_queue_shutdown();
    test_task_exception_is_propagated();
    test_concurrent_execution();
    test_all_tasks_run_before_shutdown_completes();
    return testing::finish("thread_pool");
}
