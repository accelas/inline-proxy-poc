#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace testing {

struct TestCase {
    const char* suite;
    const char* name;
    void (*func)();
};

inline std::vector<TestCase>& Registry() {
    static auto* registry = new std::vector<TestCase>();
    return *registry;
}

inline int& FailureCount() {
    static int* failures = new int(0);
    return *failures;
}

inline void ReportFailure(const char* file, int line, const std::string& message) {
    std::cerr << file << ':' << line << ": Failure\n" << message << '\n';
    ++FailureCount();
}

inline bool RegisterTest(const char* suite, const char* name, void (*func)()) {
    Registry().push_back(TestCase{suite, name, func});
    return true;
}

inline void InitGoogleTest(int* /*argc*/, char** /*argv*/) {}

inline int RunAllTests() {
    for (const auto& test : Registry()) {
        try {
            test.func();
        } catch (const std::exception& ex) {
            ReportFailure(test.suite, 0, std::string("Unhandled exception in test ") + test.suite + "." + test.name + ": " + ex.what());
        } catch (...) {
            ReportFailure(test.suite, 0, std::string("Unhandled unknown exception in test ") + test.suite + "." + test.name);
        }
    }
    return FailureCount() == 0 ? 0 : 1;
}

}  // namespace testing

#define TEST(test_suite_name, test_name)                                             \
    static void test_suite_name##_##test_name##_Test();                              \
    static const bool test_suite_name##_##test_name##_registered =                   \
        ::testing::RegisterTest(#test_suite_name, #test_name,                        \
                                &test_suite_name##_##test_name##_Test);               \
    static void test_suite_name##_##test_name##_Test()

#define EXPECT_TRUE(condition)                                                       \
    do {                                                                             \
        if (!(condition)) {                                                          \
            ::testing::ReportFailure(__FILE__, __LINE__,                             \
                                     std::string("Expected true: ") + #condition);  \
        }                                                                            \
    } while (false)

#define EXPECT_EQ(lhs, rhs)                                                          \
    do {                                                                             \
        auto _lhs = (lhs);                                                           \
        auto _rhs = (rhs);                                                           \
        if (!(_lhs == _rhs)) {                                                       \
            std::ostringstream _os;                                                  \
            _os << "Expected equality of " #lhs " and " #rhs;                      \
            ::testing::ReportFailure(__FILE__, __LINE__, _os.str());                 \
        }                                                                            \
    } while (false)
