#pragma once

// Minimal assertion helpers so the test suite has no external dependency.

#include <cstdlib>
#include <iostream>
#include <string>

namespace testing {

inline int& failure_count() {
    static int failures = 0;
    return failures;
}

inline void report(bool condition, const std::string& expression, const char* file, int line) {
    if (!condition) {
        ++failure_count();
        std::cerr << "FAILED " << file << ":" << line << ": " << expression << "\n";
    }
}

template <typename A, typename B>
void report_equal(const A& actual, const B& expected, const std::string& expression,
                  const char* file, int line) {
    if (!(actual == expected)) {
        ++failure_count();
        std::cerr << "FAILED " << file << ":" << line << ": " << expression << "\n"
                  << "  actual:   " << actual << "\n"
                  << "  expected: " << expected << "\n";
    }
}

inline int finish(const char* suite) {
    if (failure_count() == 0) {
        std::cout << suite << ": all checks passed\n";
        return EXIT_SUCCESS;
    }
    std::cerr << suite << ": " << failure_count() << " check(s) failed\n";
    return EXIT_FAILURE;
}

}  // namespace testing

#define CHECK(expr) ::testing::report((expr), #expr, __FILE__, __LINE__)
#define CHECK_EQ(actual, expected) \
    ::testing::report_equal((actual), (expected), #actual " == " #expected, __FILE__, __LINE__)
