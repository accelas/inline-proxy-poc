#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

#include <unistd.h>

#include "bpf/tc_attach.hpp"

namespace {

std::string MakeTempPinDir() {
    std::string path = std::string("/tmp/tc-attach-test-") +
                       std::to_string(::getpid()) + "-" +
                       std::to_string(std::rand());
    std::filesystem::create_directories(path);
    return path;
}

}  // namespace

TEST(TcAttacherTest, WaitForPinnedProgTimesOutWhenAbsent) {
    const auto dir = MakeTempPinDir();
    inline_proxy::TcAttacher attacher(dir);
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(attacher.WaitForPinnedProg(std::chrono::seconds(1)));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_GE(elapsed, std::chrono::milliseconds(900));
    EXPECT_LE(elapsed, std::chrono::milliseconds(2000));
    std::filesystem::remove_all(dir);
}

TEST(TcAttacherTest, WaitForPinnedProgReturnsImmediatelyWhenPresent) {
    const auto dir = MakeTempPinDir();
    {
        std::ofstream(dir + "/prog") << "stub";
    }
    inline_proxy::TcAttacher attacher(dir);
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(attacher.WaitForPinnedProg(std::chrono::seconds(5)));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LE(elapsed, std::chrono::milliseconds(300));
    std::filesystem::remove_all(dir);
}
