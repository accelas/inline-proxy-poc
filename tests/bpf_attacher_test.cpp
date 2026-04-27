#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <utility>

#include <stdlib.h>
#include <unistd.h>

#include "bpf/tc_attach.hpp"

namespace {

std::string MakeTempPinDir() {
    char tmpl[] = "/tmp/tc-attach-test-XXXXXX";
    if (::mkdtemp(tmpl) == nullptr) {
        return {};
    }
    return tmpl;
}

class TempDir {
public:
    explicit TempDir(std::string path) : path_(std::move(path)) {}
    ~TempDir() {
        if (!path_.empty()) std::filesystem::remove_all(path_);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const std::string& path() const { return path_; }
private:
    std::string path_;
};

}  // namespace

TEST(TcAttacherTest, WaitForPinnedProgTimesOutWhenAbsent) {
    TempDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    inline_proxy::TcAttacher attacher(guard.path());
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(attacher.WaitForPinnedProg(std::chrono::seconds(1)));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_GE(elapsed, std::chrono::milliseconds(900));
    EXPECT_LE(elapsed, std::chrono::milliseconds(2000));
}

TEST(TcAttacherTest, WaitForPinnedProgReturnsImmediatelyWhenPresent) {
    TempDir guard{MakeTempPinDir()};
    ASSERT_FALSE(guard.path().empty());
    {
        std::ofstream(guard.path() + "/prog") << "stub";
    }
    inline_proxy::TcAttacher attacher(guard.path());
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_TRUE(attacher.WaitForPinnedProg(std::chrono::seconds(5)));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LE(elapsed, std::chrono::milliseconds(300));
}
